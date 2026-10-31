#!/usr/bin/env bash
# Side-by-side line counts, like for like: bb's C++ vs bb-ref's Rust over the scope bb-ref ports,
# and the ratio the port claims. Left out on both sides: generated code (every `generated/`
# directory, and any file whose head marks it generated or not for editing: bb's ACIR serde and
# aztec_constants, bb-ref's Poseidon2 constants) and benchmarks. Left out of bb: vendored
# third-party code (`deps/`, the CLI11 header), the AVM's simulation and trace generation (bb-ref
# links them from bb: libbb-avm-sim.a), and the components bb-ref has no counterpart for (SMT and
# formal verification, analysis tools, world-state DBs, Solidity, Starknet, the node module, the
# AVM fuzzer). Tests are included on both sides unless --no-tests, which drops bb's *.test.cpp and
# bb-ref's tests/ (inline #[cfg(test)] modules cannot be excluded by cloc and remain counted in
# src/ -- noted in the output).
set -euo pipefail
cd "$(dirname "$0")/.."

BB=pin/aztec-packages/barretenberg/cpp/src/barretenberg
RUST_DIRS=(src tests)
SKIP_CPP='\.bench\.cpp$'
[ "${1:-}" = "--no-tests" ] && { RUST_DIRS=(src); SKIP_CPP='\.(bench|test)\.cpp$'; }
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
# The files cloc counts: everything but generated/ dirs and files whose head marks them generated.
mark='^\s*\(//\|/\*\|\*\)!\?\s*auto-\?generated\|do not edit'
OUT='generated|benchmark|deps|avm_fuzzer|smt_verification|boomerang_value_detection|acir_formal_proofs|acir_components_check|world_state_reference|wsdb|vm2_wsdb|cdb|solidity_helpers|nodejs_module|grumpkin_srs_gen|starknet'
VM2_SIM='/vm2/(simulation|tracegen|common|tooling)/|/vm2/(simulation_helper|tracegen_helper|avm_sim_api)\.[ch]pp$'
files() { find "$@" -type d -regextype egrep -regex ".*/($OUT)" -prune -o -type f -print | grep -Ev "$VM2_SIM" |
    while read -r f; do head -5 "$f" | grep -qi "$mark" || echo "$f"; done; }
files "$BB" | grep -Ev "$SKIP_CPP" > "$tmp/cpp.list"
files "${RUST_DIRS[@]}" > "$tmp/rust.list"

echo "=== bb C++ ($BB, the scope bb-ref ports${1:+, no tests}) ==="
cloc --list-file="$tmp/cpp.list" --include-lang='C++,C/C++ Header' | tee "$tmp/cpp.txt"
echo
echo "=== bb-ref Rust (${RUST_DIRS[*]}, no generated code) ==="
cloc --list-file="$tmp/rust.list" --include-lang=Rust | tee "$tmp/rust.txt"
echo

cpp=$(awk '/^SUM|^C\+\+|^C\/C\+\+ Header/ {code=$NF} /^SUM/ {print code}' "$tmp/cpp.txt")
rust=$(awk '/^Rust/ {print $NF}' "$tmp/rust.txt")
[ "${1:-}" = "--no-tests" ] && echo "(bb-ref's inline #[cfg(test)] modules stay counted in src/, ~1k lines)"
awk -v c="$cpp" -v r="$rust" 'BEGIN { printf "bb-ref is %.1f%% of bb (%s vs %s code lines)\n", 100*r/c, r, c }'
