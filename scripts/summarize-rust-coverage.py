"""Summarize unique mapped production lines, without counting inline tests.

LLVM's overall report also counts overlapping function mappings. This metric
uses LCOV source-line counters; async_trait macro mappings can be sparse.
"""
import collections
import json
from pathlib import Path
import re
import sys

root = Path(__file__).resolve().parent.parent
report_dir = root / "target/coverage/rust"
files = []
for record in (report_dir / "lcov.info").read_text().split("end_of_record"):
    match = re.search(r"^SF:(.+)$", record, re.MULTILINE)
    if not match:
        continue
    path = Path(match[1])
    if not path.is_relative_to(root):
        continue
    relative = path.relative_to(root)
    if relative.parts[0] not in ("crates", "bins"):
        continue
    if path.name in ("tests.rs", "test_support.rs") or path.stem.endswith("_tests"):
        continue
    source = path.read_text()
    # In this workspace inline test modules follow the production code;
    # external `mod tests;` declarations are ignored.
    match = re.search(r"#\[cfg\(test\)\]\s*mod\s+\w+\s*\{", source)
    cutoff = source[:match.start()].count("\n") + 1 if match else sys.maxsize
    counts = {int(line): int(count) for line, count in re.findall(r"^DA:(\d+),(\d+)", record, re.MULTILINE) if int(line) < cutoff}
    if counts:
        files.append({"path": str(relative), "covered": sum(count > 0 for count in counts.values()), "total": len(counts), "missing": [line for line, count in counts.items() if count == 0]})

groups = collections.defaultdict(lambda: [0, 0])
for file in files:
    group = "/".join(Path(file["path"]).parts[:2])
    groups[group][0] += file["covered"]
    groups[group][1] += file["total"]
covered = sum(file["covered"] for file in files)
total = sum(file["total"] for file in files)
print(f"Mapped production lines (excluding tests): {covered}/{total} ({100 * covered / total:.2f}%)")
for group, (covered, total) in sorted(groups.items()):
    print(f"  {group}: {covered}/{total} ({100 * covered / total:.2f}%)")
(report_dir / "production-summary.json").write_text(json.dumps({"method": __doc__.strip(), "groups": dict(groups), "files": files}, indent=2) + "\n")
