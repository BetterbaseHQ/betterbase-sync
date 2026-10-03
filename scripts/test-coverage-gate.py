"""Check that coverage enforcement cannot be masked by aggregate totals."""
import copy
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("coverage_gate", Path(__file__).with_name("check-rust-coverage.py"))
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class CoverageGateTests(unittest.TestCase):
    def setUp(self):
        self.llvm = {"data": [{"totals": {metric: {"covered": 91, "count": 100}
                    for metric in ("lines", "regions", "functions")}}]}
        self.llvm["data"][0]["files"] = [
            {"filename": f"{group}/src/main.rs", "summary": copy.deepcopy(self.llvm["data"][0]["totals"])}
            for group in gate.CRITICAL_GROUPS
        ]
        self.production = {"groups": {group: [91, 100] for group in gate.CRITICAL_GROUPS}}

    def test_complete_reports_above_threshold_pass(self):
        self.assertEqual(gate.failures(self.llvm, self.production), [])

    def test_ninety_percent_is_not_above_threshold(self):
        self.production["groups"]["crates/storage"] = [90, 100]
        self.assertEqual(len(gate.failures(self.llvm, self.production)), 1)

    def test_each_llvm_dimension_is_required(self):
        for metric in ("lines", "regions", "functions"):
            with self.subTest(metric=metric):
                report = copy.deepcopy(self.llvm)
                report["data"][0]["totals"][metric]["covered"] = 89
                errors = gate.failures(report, self.production)
                self.assertEqual(len(errors), 1)
                self.assertIn(metric, errors[0])

    def test_high_aggregates_cannot_hide_a_crate_regression(self):
        for group in gate.CRITICAL_GROUPS:
            with self.subTest(group=group):
                report = copy.deepcopy(self.production)
                report["groups"][group] = [89, 100]
                errors = gate.failures(self.llvm, report)
                self.assertEqual(len(errors), 1)
                self.assertIn(group, errors[0])

    def test_each_crate_must_pass_each_llvm_metric(self):
        for group in gate.CRITICAL_GROUPS:
            for metric in ("lines", "regions", "functions"):
                with self.subTest(group=group, metric=metric):
                    report = copy.deepcopy(self.llvm)
                    file = next(file for file in report["data"][0]["files"] if file["filename"].startswith(group))
                    file["summary"][metric]["covered"] = 90
                    errors = gate.failures(report, self.production)
                    self.assertEqual(len(errors), 1)
                    self.assertIn(group, errors[0])
                    self.assertIn(metric, errors[0])

    def test_missing_empty_or_impossible_counters_fail(self):
        for counters in ([], [0, 0], [101, 100], [-1, 100], [91.0, 100], [None, 100]):
            with self.subTest(counters=counters):
                report = copy.deepcopy(self.production)
                report["groups"]["crates/auth"] = counters
                self.assertTrue(gate.failures(self.llvm, report))
        self.assertTrue(gate.failures({"data": []}, {"groups": {}}))
        del self.production["groups"]["bins/server"]
        self.assertTrue(gate.failures(self.llvm, self.production))


if __name__ == "__main__":
    unittest.main()
