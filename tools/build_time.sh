#!/usr/bin/env bash
# Fresh-rebuild times, side by side: bb (the C++ binary, no AVM) vs bb-ref.
#
#   tools/build_time.sh
#
# Both builds are from-scratch compiles into their own scratch directories, so the working
# build trees (pin/.../build, target/) are untouched and nothing is cached between runs:
#   bb      cmake (default preset settings) into barretenberg/cpp/build-buildtime, `ninja bb`
#   bb-ref  `cargo build --release` with CARGO_TARGET_DIR=target-buildtime
# The timed span is compile+link only — cmake configure is run first and not counted (cargo
# has no separate configure step). Both use all cores.
set -euo pipefail
cd "$(dirname "$0")/.."
CPP=pin/aztec-packages/barretenberg/cpp
[ -d "$CPP" ] || { echo "pin/aztec-packages not checked out (run tools/regen/regen_corpus.sh first)" >&2; exit 1; }

BB_BUILD=$CPP/build-buildtime
rm -rf "$BB_BUILD" target-buildtime

echo "=== configuring bb (not timed)"
# the constants-generation step in bb's CMakeLists resolves paths from the working directory
(cd "$CPP" && CC=clang CXX=clang++ cmake -G Ninja -DCMAKE_BUILD_TYPE=Release -DENABLE_PIC=ON \
    -S . -B build-buildtime > /dev/null)

elapsed() { awk -v a="$1" -v b="$2" 'BEGIN { printf "%.1f", b - a }'; }

echo "=== building bb"
bb_start=$(date +%s.%N)
ninja -C "$BB_BUILD" bb
bb_secs=$(elapsed "$bb_start" "$(date +%s.%N)")

echo "=== building bb-ref"
ref_start=$(date +%s.%N)
CARGO_TARGET_DIR=target-buildtime cargo build --release --quiet
ref_secs=$(elapsed "$ref_start" "$(date +%s.%N)")

rm -rf "$BB_BUILD" target-buildtime

printf '\n%-8s %10s\n' '' 'seconds'
printf '%-8s %10s\n' bb "$bb_secs"
printf '%-8s %10s\n' bb-ref "$ref_secs"
awk -v a="$bb_secs" -v b="$ref_secs" 'BEGIN { printf "%-8s %9.1fx\n", "ratio", a / b }'
