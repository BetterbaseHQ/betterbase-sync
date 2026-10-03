"""Require >90% LLVM and production coverage in every Rust crate.

LLVM line, region, and function totals include test code. Production counters
come from summarize-rust-coverage.py, which excludes test sources. Stable Rust
currently provides no branch counters in these reports; regions are not branches.
"""
import collections
import json
from pathlib import Path
import sys

CRITICAL_GROUPS = (
    "crates/core", "crates/auth", "crates/storage", "crates/realtime",
    "crates/api", "crates/app", "bins/server", "bins/migrate", "bins/federation-keygen",
)


def failures(llvm_report, production_report):
    errors = []

    def check(label, covered, total):
        if type(covered) is not int or type(total) is not int or not 0 <= covered <= total or total <= 0:
            errors.append(f"{label}: missing or invalid coverage counters")
        elif covered * 100 <= total * 90:
            errors.append(f"{label}: {covered}/{total} ({100 * covered / total:.2f}%) must exceed 90%")

    data = llvm_report.get("data", [])
    totals = data[0].get("totals", {}) if len(data) == 1 else {}
    for metric in ("lines", "regions", "functions"):
        counters = totals.get(metric, {})
        check(f"LLVM {metric}", counters.get("covered"), counters.get("count"))
    # Each critical crate must pass independently in all three LLVM metrics.
    # These counters include tests, so production-only lines are checked below.
    crate_metrics = collections.defaultdict(lambda: collections.defaultdict(lambda: [0, 0]))
    root = Path(__file__).resolve().parent.parent
    for file in data[0].get("files", []) if len(data) == 1 else []:
        path = Path(file["filename"])
        if path.is_absolute():
            if not path.is_relative_to(root):
                continue
            path = path.relative_to(root)
        group = "/".join(path.parts[:2])
        if group not in CRITICAL_GROUPS:
            continue
        for metric in ("lines", "regions", "functions"):
            counters = file.get("summary", {}).get(metric, {})
            covered, total = counters.get("covered"), counters.get("count")
            if type(covered) is not int or type(total) is not int or not 0 <= covered <= total:
                errors.append(f"LLVM {group} {metric}: missing or invalid coverage counters")
                continue
            crate_metrics[group][metric][0] += covered
            crate_metrics[group][metric][1] += total
    for group in CRITICAL_GROUPS:
        for metric in ("lines", "regions", "functions"):
            check(f"LLVM {group} {metric}", *crate_metrics[group][metric])
    groups = production_report.get("groups", {})
    for group in CRITICAL_GROUPS:
        counters = groups.get(group, [None, None])
        if not isinstance(counters, list) or len(counters) != 2:
            counters = [None, None]
        check(f"production {group}", *counters)
    return errors


def main():
    directory = Path(__file__).resolve().parent.parent / "target/coverage/rust"
    try:
        llvm = json.loads((directory / "coverage.json").read_text())
        production = json.loads((directory / "production-summary.json").read_text())
        errors = failures(llvm, production)
    except (OSError, ValueError, TypeError, AttributeError) as error:
        print(f"Coverage gate could not read valid reports: {error}", file=sys.stderr)
        return 1
    if errors:
        for error in errors:
            print(f"Coverage gate failed: {error}", file=sys.stderr)
        return 1
    print("Coverage gate passed: every crate exceeds 90% LLVM lines/regions/functions and production lines.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
