#!/usr/bin/env bash
# Side-by-side line counts: bb's C++ (minus benchmarks and the AVM fuzzer) vs bb-ref's Rust, and
# the ratio the port claims. Generated code is excluded on both sides: every `generated/`
# directory, and any file whose head marks it generated or not for editing (bb's ACIR serde, bb-ref's
# Poseidon2 constants). Tests are included on both sides unless --no-tests, which drops bb's
# *.test.cpp and bb-ref's tests/ (inline #[cfg(test)] modules cannot be excluded by cloc and
# remain counted in src/ — noted in the output).
set -euo pipefail
cd "$(dirname "$0")/.."

BB=pin/aztec-packages/barretenberg/cpp/src/barretenberg
RUST_DIRS=(src tests)
SKIP_CPP='\.bench\.cpp$'
[ "${1:-}" = "--no-tests" ] && { RUST_DIRS=(src); SKIP_CPP='\.(bench|test)\.cpp$'; }
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
# The files cloc counts: everything but generated/ dirs and files whose head marks them generated.
mark='^\s*\(//\|/\*\|\*\)!\?\s*auto-\?generated\|do not edit'
files() { find "$@" -type d \( -name generated -o -name avm_fuzzer -o -name benchmark \) -prune -o -type f -print |
    while read -r f; do head -5 "$f" | grep -qi "$mark" || echo "$f"; done; }
files "$BB" | grep -Ev "$SKIP_CPP" > "$tmp/cpp.list"
files "${RUST_DIRS[@]}" > "$tmp/rust.list"

echo "=== bb C++ ($BB, no benchmarks, no generated code${1:+, no tests}) ==="
cloc --list-file="$tmp/cpp.list" --include-lang='C++,C/C++ Header' | tee "$tmp/cpp.txt"
echo
echo "=== bb-ref Rust (${RUST_DIRS[*]}, no generated code) ==="
cloc --list-file="$tmp/rust.list" --include-lang=Rust | tee "$tmp/rust.txt"
echo

cpp=$(awk '/^SUM|^C\+\+|^C\/C\+\+ Header/ {code=$NF} /^SUM/ {print code}' "$tmp/cpp.txt")
rust=$(awk '/^Rust/ {print $NF}' "$tmp/rust.txt")
[ "${1:-}" = "--no-tests" ] && echo "(bb-ref's inline #[cfg(test)] modules stay counted in src/, ~1k lines)"
awk -v c="$cpp" -v r="$rust" 'BEGIN { printf "bb-ref is %.1f%% of bb (%s vs %s code lines)\n", 100*r/c, r, c }'
