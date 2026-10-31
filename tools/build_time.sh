#!/usr/bin/env bash
# From-scratch build times, like for like: bb's binaries against bb-ref's, with and without the AVM,
# with their third-party dependencies and without (own code only: the dependencies already built).
#
#   tools/build_time.sh [--jobs n]   (default 16: a consumer-class machine; run on a bench box)
#
#   bb-avm / bb          `ninja bb-avm` / `ninja bb`, bb's release preset (zig's clang, libc++); own
#                        code only: every object, library and binary outside its _deps/ rebuilt
#   bb-ref               `cargo build --release [--features bb-avm]`; own code only: the crate
#                        rebuilt (`cargo clean -p bb-ref`)
#
# bb-ref with the AVM links bb's AVM simulation and trace generation (libbb-avm-sim.a), which is
# bb's code: it is built first and not timed, as bb's avm-transpiler (prebuilt in the tree) is not.
# Every build is into its own scratch directory, with ccache off; configure is not timed (cargo has
# none). The working build trees are untouched. Each binary's size is printed too, stripped
# (`strip --strip-all`). KEEP=<dir> keeps the four binaries (bb-avm, bb, bb-ref-avm, bb-ref).
set -euo pipefail
cd "$(dirname "$0")/.."
JOBS=16
[ "${1:-}" = --jobs ] && JOBS=$2
CPP=pin/aztec-packages/barretenberg/cpp
[ -d "$CPP/src" ] || { echo "build_time: pin/aztec-packages is not checked out" >&2; exit 1; }
export CCACHE_DISABLE=1
unset RUSTC_WRAPPER
T=$(mktemp -d)
PATCH=$PWD/pin/bb-avm-sim.patch
cleanup() { git -C pin/aztec-packages apply -R --check "$PATCH" 2>/dev/null && git -C pin/aztec-packages apply -R "$PATCH"; rm -rf "$T" "$CPP"/build-bt-*; }
trap cleanup EXIT

secs() { local s=$(date +%s.%N); "$@" > "$T/log" 2>&1 || { tail -20 "$T/log" >&2; exit 1; }; awk -v a="$s" -v b="$(date +%s.%N)" 'BEGIN { printf "%.0f", b - a }'; }
configure() { (cd "$CPP" && cmake --preset "$1" -B "build-bt-$2" > /dev/null); }
# bb: from scratch, then its own code again (everything built outside _deps/ removed).
bb() {
  local d=$CPP/build-bt-$1
  configure clang20 "$1"
  echo "$(secs ninja -C "$d" -j "$JOBS" "$2")"
  find "$d" -path "$d/_deps" -prune -o -type f \( -name '*.o' -o -name '*.a' \) -print0 | xargs -0 rm -f
  rm -rf "$d/bin"
  echo "$(secs ninja -C "$d" -j "$JOBS" "$2")"
}
# bb-ref: from scratch, then the crate again.
ref() {
  echo "$(CARGO_TARGET_DIR=$T/$1 secs cargo build --release -j "$JOBS" "${@:2}")"
  CARGO_TARGET_DIR=$T/$1 cargo clean --release -q -p bb-ref
  echo "$(CARGO_TARGET_DIR=$T/$1 secs cargo build --release -j "$JOBS" "${@:2}")"
}

read -r bb_avm bb_avm_own < <(bb avm bb-avm | xargs)
read -r bb bb_own < <(bb bb bb | xargs)
git -C pin/aztec-packages apply "$PATCH"
configure clang20-no-avm sim && secs ninja -C "$CPP/build-bt-sim" -j "$JOBS" bb-avm-sim-lib > /dev/null
git -C pin/aztec-packages apply -R "$PATCH"
export BB_AVM_LIB_DIR=$PWD/$CPP/build-bt-sim/lib
read -r ref_avm ref_avm_own < <(ref avm --features bb-avm | xargs)
read -r ref ref_own < <(ref plain | xargs)

echo "$JOBS jobs, $(nproc) CPUs ($(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | xargs))"
printf '%-17s %24s   %24s\n' '' 'from scratch' 'own code only'
printf '%-17s %7s %7s %8s   %7s %7s %8s\n' '' bb bb-ref ratio bb bb-ref ratio
row() { awk -v n="$1" -v a="$2" -v b="$3" -v c="$4" -v d="$5" 'BEGIN { printf "%-17s %6ds %6ds %7.2fx   %6ds %6ds %7.2fx\n", n, a, b, b / a, c, d, d / c }'; }
row 'with the AVM' "$bb_avm" "$ref_avm" "$bb_avm_own" "$ref_avm_own"
row 'without the AVM' "$bb" "$ref" "$bb_own" "$ref_own"

mb() { strip --strip-all -o "$T/stripped" "$1" && awk -v n="$(stat -c%s "$T/stripped")" 'BEGIN { printf "%.1f MB", n / 1e6 }'; }
echo
printf '%-17s %10s %10s\n' 'binary, stripped' bb bb-ref
printf '%-17s %10s %10s\n' 'with the AVM' "$(mb "$CPP/build-bt-avm/bin/bb-avm")" "$(mb "$T/avm/release/bb-ref")"
printf '%-17s %10s %10s\n' 'without the AVM' "$(mb "$CPP/build-bt-bb/bin/bb")" "$(mb "$T/plain/release/bb-ref")"
[ -z "${KEEP:-}" ] || { mkdir -p "$KEEP"; cp "$CPP/build-bt-avm/bin/bb-avm" "$CPP/build-bt-bb/bin/bb" "$KEEP/"; cp "$T/avm/release/bb-ref" "$KEEP/bb-ref-avm"; cp "$T/plain/release/bb-ref" "$KEEP/bb-ref"; }
