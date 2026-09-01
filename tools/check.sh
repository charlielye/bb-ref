#!/usr/bin/env bash
# The standalone gate: unit tests must pass with no bb binary, no corpus, no tests/data.
# CI runs this in a bare checkout; the differential suites (cargo test --release) are a separate,
# artifact-dependent job.
set -euo pipefail
cd "$(dirname "$0")/.."
# Hide the fixture layer so a test that quietly depends on it fails here, not on a contributor's machine.
tmp=$(mktemp -d)
trap 'mv "$tmp/data" tests/data 2>/dev/null || true; rm -rf "$tmp"' EXIT
[ -d tests/data ] && mv tests/data "$tmp/data"
# Warning-free is part of the gate: incremental builds hide warnings that every fresh build
# (coverage, CI, a contributor) re-emits. Own target dir so the flag doesn't churn the main cache.
RUSTFLAGS=-Dwarnings CARGO_TARGET_DIR=target/warnfree cargo check --all-targets --quiet
cargo test --lib
