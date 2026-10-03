#!/usr/bin/env bash
# Run a command with enforced PostgreSQL tests. Own only the container we create.
set -euo pipefail

if [[ $# -eq 0 ]]; then
    echo "Usage: bash scripts/with-test-db.sh COMMAND [ARGS...]" >&2
    exit 2
fi

export BB_TEST_REQUIRE_DB=1
container_id=""
command_pid=""
cleanup() {
    local status=$?
    trap - EXIT
    if [[ -n "$container_id" ]]; then
        if ! docker rm -f "$container_id" >/dev/null; then
            echo "Failed to remove test PostgreSQL container $container_id" >&2
            [[ $status -ne 0 ]] || status=1
        fi
    fi
    exit "$status"
}
trap cleanup EXIT
terminate_command() {
    local status=$1
    local signal=$2
    # Complete cleanup even if the caller sends another interrupt.
    trap '' INT TERM
    if [[ -n "$command_pid" ]]; then
        # The command has its own process group; Cargo's test binaries and any
        # subprocesses must stop before their database is removed.
        kill -s "$signal" -- "-$command_pid" 2>/dev/null || true
        for ((attempt = 0; attempt < 50; attempt++)); do
            if ! kill -0 -- "-$command_pid" 2>/dev/null; then
                break
            fi
            sleep 0.1
        done
        kill -KILL -- "-$command_pid" 2>/dev/null || true
        wait "$command_pid" 2>/dev/null || true
        command_pid=""
    fi
    exit "$status"
}
trap 'terminate_command 130 INT' INT
trap 'terminate_command 143 TERM' TERM

run_command() {
    local status
    # Job control gives this child a distinct process group and prevents
    # asynchronous commands from inheriting an ignored SIGINT disposition.
    set -m
    "$@" &
    command_pid=$!
    set +m
    # Bash's wait builtin is interrupted promptly by a trapped signal, unlike
    # waiting on a foreground external command.
    if wait "$command_pid"; then
        status=0
    else
        status=$?
    fi
    command_pid=""
    return "$status"
}

if [[ -n "${DATABASE_URL:-}" ]]; then
    run_command "$@"
    exit $?
fi

# Docker assigns a free loopback port; simultaneous suites never share a DB.
container_id=$(docker run -d --rm \
    --label betterbase-sync.test-db=true \
    -p 127.0.0.1::5432 \
    -e POSTGRES_USER=sync -e POSTGRES_PASSWORD=sync -e POSTGRES_DB=sync_test \
    postgres:17-alpine)

ready=false
for ((attempt = 0; attempt < 300; attempt++)); do
    # The temporary initialization server only listens on a Unix socket.
    if docker exec "$container_id" pg_isready -h 127.0.0.1 -U sync -d sync_test >/dev/null 2>&1; then
        ready=true
        break
    fi
    if [[ $(docker inspect --format '{{.State.Running}}' "$container_id") != true ]]; then
        break
    fi
    sleep 0.2
done
if [[ "$ready" != true ]]; then
    echo "Test PostgreSQL failed to become ready" >&2
    docker logs "$container_id" >&2 || true
    exit 1
fi

binding=$(docker port "$container_id" 5432/tcp)
port=${binding##*:}
export DATABASE_URL="postgres://sync:sync@127.0.0.1:$port/sync_test?sslmode=disable"
echo "Running with disposable PostgreSQL on port $port"
run_command "$@"
