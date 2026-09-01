#!/usr/bin/env bash
# Line coverage of the STANDALONE test set: inline unit tests plus the soundness, relations and
# API-boundary suites — everything that runs with no bb binary, no corpus, no tests/data. The
# differential suites drive most remaining lines but prove bb-equivalence, not standalone claims,
# so they are deliberately excluded here. Report-only; no threshold.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo llvm-cov clean --workspace
cargo llvm-cov --release --no-report --lib
cargo llvm-cov --release --no-report --test soundness
cargo llvm-cov --release --no-report --test relations
cargo llvm-cov --release --no-report --test msgpack_server -- api_boundary
cargo llvm-cov report --release --summary-only
