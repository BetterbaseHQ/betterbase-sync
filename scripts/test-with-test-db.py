"""Verify database ownership, failure cleanup, and exit status without Docker."""
import os
from pathlib import Path
import subprocess
import signal
import time
import tempfile
import unittest

SCRIPT = Path(__file__).with_name("with-test-db.sh").resolve()


class DatabaseRunnerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        root = Path(self.directory.name)
        self.log = root / "docker.log"
        docker = root / "docker"
        docker.write_text('''#!/usr/bin/env bash
printf '%s\\n' "$*" >> "$MOCK_DOCKER_LOG"
case "$1" in
    run) echo owned-container ;;
    exec) [[ "${MOCK_NOT_READY:-}" != 1 ]] ;;
    inspect) echo false ;;
    port) echo 127.0.0.1:54321 ;;
    rm) [[ "$2 $3" == '-f owned-container' ]] ;;
    logs) echo 'startup failed' ;;
    *) exit 99 ;;
esac
''')
        docker.chmod(0o755)
        self.env = dict(os.environ, PATH=f"{root}:{os.environ['PATH']}", MOCK_DOCKER_LOG=str(self.log))
        self.env.pop("DATABASE_URL", None)
        self.env.pop("BB_TEST_REQUIRE_DB", None)

    def run_command(self, command, **env):
        return subprocess.run(["bash", str(SCRIPT), *command], env=dict(self.env, **env), capture_output=True, text=True, timeout=10)

    def assert_owned_cleanup(self):
        self.assertEqual(self.log.read_text().splitlines()[-1], "rm -f owned-container")

    def test_success_exports_database_and_enforced_flag_then_cleans(self):
        result = self.run_command(["bash", "-c", 'test "$BB_TEST_REQUIRE_DB" = 1 && test "$DATABASE_URL" = "postgres://sync:sync@127.0.0.1:54321/sync_test?sslmode=disable"'])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("-p 127.0.0.1::5432", self.log.read_text())
        self.assertIn("pg_isready -h 127.0.0.1", self.log.read_text())
        self.assert_owned_cleanup()

    def test_failure_preserves_exit_status_and_cleans(self):
        result = self.run_command(["bash", "-c", "exit 17"])
        self.assertEqual(result.returncode, 17, result.stderr)
        self.assert_owned_cleanup()

    def test_termination_cleans(self):
        result = self.run_command(["bash", "-c", 'kill -TERM "$PPID"'])
        self.assertEqual(result.returncode, 143, result.stderr)
        self.assert_owned_cleanup()

    def interrupt_running_command(self, sig, external=False, ignore=False):
        root = Path(self.directory.name)
        child_file, grandchild_file = root / "child.pid", root / "grandchild.pid"
        command = (
            'trap "" INT TERM; echo $$ > "$MOCK_CHILD_PID"; exec sleep 60'
            if ignore else
            """trap 'echo child_stopped >> "$MOCK_DOCKER_LOG"; exit 0' INT TERM;
            echo $$ > "$MOCK_CHILD_PID";
            bash -c 'echo $$ > "$MOCK_GRANDCHILD_PID"; exec sleep 60'
            """
        )
        env = dict(self.env, MOCK_CHILD_PID=str(child_file), MOCK_GRANDCHILD_PID=str(grandchild_file))
        if external:
            env["DATABASE_URL"] = "postgres://external"
        runner = subprocess.Popen(
            ["bash", str(SCRIPT), "bash", "-c", command], env=env,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True,
        )
        child_pid = None
        try:
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                if child_file.exists() and child_file.read_text().strip().isdigit():
                    child_pid = int(child_file.read_text())
                    if ignore or (grandchild_file.exists() and grandchild_file.read_text().strip().isdigit()):
                        break
                time.sleep(0.01)
            else:
                self.fail("child processes did not start")
            # Signal only the wrapper, as an external cancellation does. The
            # child is deliberately still running when the signal arrives.
            runner.send_signal(sig)
            stdout, stderr = runner.communicate(timeout=8)
            self.assertEqual(runner.returncode, 128 + sig, stdout + stderr)
            with self.assertRaises(ProcessLookupError):
                os.killpg(child_pid, 0)
            if not ignore:
                self.assertIn("child_stopped", self.log.read_text())
            if external:
                self.assertNotIn("rm -f", self.log.read_text())
                self.assertNotIn("run -d", self.log.read_text())
            else:
                self.assert_owned_cleanup()
        finally:
            if child_pid is not None:
                try:
                    os.killpg(child_pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            if runner.poll() is None:
                os.killpg(runner.pid, signal.SIGKILL)
            runner.communicate(timeout=5)

    def test_sigterm_stops_running_child_and_grandchild_before_cleanup(self):
        self.interrupt_running_command(signal.SIGTERM)

    def test_sigint_stops_running_child_and_grandchild_before_cleanup(self):
        self.interrupt_running_command(signal.SIGINT)

    def test_external_database_cancellation_stops_child_without_docker_cleanup(self):
        self.interrupt_running_command(signal.SIGTERM, external=True)

    def test_unresponsive_child_is_killed_and_reaped_before_cleanup(self):
        self.interrupt_running_command(signal.SIGTERM, ignore=True)

    def test_existing_database_is_never_owned_or_removed(self):
        result = self.run_command(["bash", "-c", 'test "$BB_TEST_REQUIRE_DB" = 1 && exit 19'], DATABASE_URL="postgres://external")
        self.assertEqual(result.returncode, 19, result.stderr)
        self.assertFalse(self.log.exists())

    def test_failed_startup_never_runs_tests_and_cleans(self):
        result = self.run_command(["bash", "-c", "echo TESTS_RAN"], MOCK_NOT_READY="1")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertNotIn("TESTS_RAN", result.stdout)
        self.assertIn("startup failed", result.stderr)
        self.assert_owned_cleanup()

    def test_missing_command_fails_without_creating_database(self):
        result = self.run_command([])
        self.assertEqual(result.returncode, 2)
        self.assertFalse(self.log.exists())


if __name__ == "__main__":
    unittest.main()
