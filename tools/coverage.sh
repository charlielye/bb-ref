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
# The raw report is 13 columns wide; keep filename, functions and lines.
slim() { awk 'NF >= 10 && $1 !~ /^-+$/ && $1 != "Filename" { printf "%-36s %10s %8s %8s\n", $1, $7, $9, $10 }'; }
printf '%-36s %10s %8s %8s\n' Filename Functions Missed Lines
cargo llvm-cov report --release | slim

# Two denominators, matching the goals: ~80% standalone overall, >95% on the core.
# - infra (msgpack, the CLI, io/timing, testutil) is excluded outright: generated code and thin
#   adapters whose bytes are pinned harder by conformance.
# - the in-circuit recursion layer (stdlib, acir, the rollup recursive verifiers) is
#   differential-owned: its claim is gate-exactness vs bb, which line coverage cannot establish.
INFRA='(^|/)src/(msgpack/|bin/|testutil\.rs|base/io\.rs|base/timing\.rs)'
IN_CIRCUIT='(^|/)src/(stdlib/|acir/|rollup/(mod|ipa_recursive)\.rs)'
echo
echo "== standalone (infra excluded) =="
cargo llvm-cov report --release --summary-only --ignore-filename-regex "$INFRA" | slim | tail -1
echo
echo "== core (infra + in-circuit recursion layer excluded; the >95% target) =="
cargo llvm-cov report --release --summary-only --ignore-filename-regex "$INFRA|$IN_CIRCUIT" | slim | tail -1
