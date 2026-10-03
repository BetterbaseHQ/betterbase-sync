#!/usr/bin/env bash
set -euo pipefail

report_dir=target/coverage/rust
mkdir -p "$report_dir"
cargo llvm-cov clean --workspace
cargo llvm-cov --workspace --no-report
cargo llvm-cov report --html --output-dir "$report_dir"
cargo llvm-cov report --json --output-path "$report_dir/coverage.json"
cargo llvm-cov report --lcov --output-path "$report_dir/lcov.info"
python3 scripts/summarize-rust-coverage.py
cargo llvm-cov report
python3 scripts/check-rust-coverage.py
