#!/usr/bin/env bash
# Side-by-side line counts: bb's C++ (minus the AVM and benchmarks) vs bb-ref's Rust, and the
# ratio the port claims. Tests are included on both sides unless --no-tests, which drops bb's
# *.test.cpp and bb-ref's tests/ (inline #[cfg(test)] modules cannot be excluded by cloc and
# remain counted in src/ — noted in the output).
set -euo pipefail
cd "$(dirname "$0")/.."

BB=pin/aztec-packages/barretenberg/cpp/src/barretenberg
CPP_ARGS=(--include-lang='C++,C/C++ Header' --exclude-dir=vm2,avm_fuzzer,benchmark --not-match-f='\.bench\.cpp$')
RUST_DIRS=(src tests)
if [ "${1:-}" = "--no-tests" ]; then
    CPP_ARGS=(--include-lang='C++,C/C++ Header' --exclude-dir=vm2,avm_fuzzer,benchmark --not-match-f='\.(bench|test)\.cpp$')
    RUST_DIRS=(src)
fi

echo "=== bb C++ ($BB, no AVM, no benchmarks${1:+, no tests}) ==="
cloc "$BB" "${CPP_ARGS[@]}" | tee /tmp/loc_cpp.txt
echo
echo "=== bb-ref Rust (${RUST_DIRS[*]}) ==="
cloc "${RUST_DIRS[@]}" --include-lang=Rust | tee /tmp/loc_rust.txt
echo

cpp=$(awk '/^SUM|^C\+\+|^C\/C\+\+ Header/ {code=$NF} /^SUM/ {print code}' /tmp/loc_cpp.txt)
rust=$(awk '/^Rust/ {print $NF}' /tmp/loc_rust.txt)
[ "${1:-}" = "--no-tests" ] && echo "(bb-ref's inline #[cfg(test)] modules stay counted in src/, ~1k lines)"
awk -v c="$cpp" -v r="$rust" 'BEGIN { printf "bb-ref is %.1f%% of bb (%s vs %s code lines)\n", 100*r/c, r, c }'
