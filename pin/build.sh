#!/bin/bash
# Build the conforming toolchain from the pinned barretenberg checkout: the `bb` binary the
# differential tests compare against, and the `nargo`/`noir-execute` that compile and execute the circuits
# they use. Everything comes from `pin/aztec-packages` (a submodule at an exact commit), so a clone
# reproduces the same binaries without installing anything system-wide.
#
#   ./pin/build.sh            # bb only — enough for the conformance suite
#   ./pin/build.sh --noir     # also nargo + noir-execute, needed to (re)compile circuits
#   ./pin/build.sh --avm-lib  # also libbb-avm-sim.a (the AVM's simulation and trace generation),
#                             # which bb-ref's `bb-avm` feature links
#   ./pin/build.sh --avm      # also bb-avm and the AVM archives: the oracle the AVM regens use
#
# Set AZTEC_REPO to point at an existing checkout instead (a dev box with the tree already built);
# the tests honour the same variable.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
repo=${AZTEC_REPO:-$here/aztec-packages}
build_noir=false
build_avm_lib=false
build_avm=false
for a in "$@"; do
  case $a in
    --noir) build_noir=true ;;
    --avm-lib) build_avm_lib=true ;;
    --avm) build_avm=true ;;
  esac
done

if [ ! -d "$repo/barretenberg/cpp" ]; then
  echo "pin: $repo is not a barretenberg checkout." >&2
  echo "     Run: git submodule update --init --depth 1 pin/aztec-packages" >&2
  exit 1
fi

# A preset sets the compiler only on a dir's first configure, so a dir configured another way
# (e.g. the system clang++ and libstdc++) would silently stay that way. The AVM's trace generation
# sorts with ties, so its output follows the C++ library: refuse anything but bb's release toolchain.
release_toolchain() {
  local c=$repo/barretenberg/cpp/$1/CMakeCache.txt
  if [ -f "$c" ] && ! grep -q '^CMAKE_CXX_COMPILER:.*zig-c++\.sh$' "$c"; then
    echo "pin: $1/ was configured with $(grep -m1 '^CMAKE_CXX_COMPILER:' "$c" | cut -d= -f2)," \
      "not bb's release toolchain (zig + libc++): rm -rf $repo/barretenberg/cpp/$1" >&2
    exit 1
  fi
}
release_toolchain build
$build_avm_lib && release_toolchain build-avm-sim

echo "pin: building bb from $(git -C "$repo" rev-parse --short HEAD)"
# bb's release preset (`clang20`: zig's clang and libc++), as bb's release and bb.js build bb. Configure from inside the source dir: the constants
# generator resolves its paths relative to the working directory, not to -S.
(
  cd "$repo/barretenberg/cpp"
  cmake --preset clang20 -B build > /dev/null
  ninja -C build bb
)

# The AVM's simulation and trace generation as one static archive (pin/bb-avm-sim.patch moves
# trace generation into vm2_sim and adds the target and its C entry point), built with the patch
# applied and the checkout restored afterwards. It needs no AVM=ON: none of the AVM's constraining
# code is in it.
if $build_avm_lib; then
  echo "pin: building libbb-avm-sim.a"
  patch=$here/bb-avm-sim.patch
  git -C "$repo" apply "$patch"
  trap 'git -C "$repo" apply -R "$patch"' EXIT
  (
    cd "$repo/barretenberg/cpp"
    cmake --preset clang20-no-avm -B build-avm-sim > /dev/null
    ninja -C build-avm-sim bb-avm-sim-lib
  )
  git -C "$repo" apply -R "$patch"
  trap - EXIT
fi

# bb's own AVM, unpatched: bb-avm and the archives regen_avm.sh links.
if $build_avm; then
  echo "pin: building bb-avm"
  (
    cd "$repo/barretenberg/cpp"
    cmake --preset clang20 -B build > /dev/null
    ninja -C build bb-avm barretenberg vm2 vm2_sim env
  )
fi

if $build_noir; then
  echo "pin: building nargo + noir-execute"
  git -C "$repo" submodule update --init --depth 1 noir/noir-repo
  cargo build --release --manifest-path "$repo/noir/noir-repo/Cargo.toml" --bin nargo --bin noir-execute
fi

echo "pin: done"
echo "  bb:   $repo/barretenberg/cpp/build/bin/bb"
$build_avm && echo "  bb-avm: $repo/barretenberg/cpp/build/bin/bb-avm"
$build_avm_lib && echo "  avm:  $repo/barretenberg/cpp/build-avm-sim/lib/libbb-avm-sim.a" \
  "(portable bb-ref: CXXSTDLIB=c++ cargo zigbuild --release --features bb-avm --target x86_64-unknown-linux-gnu.2.35)"
$build_noir && echo "  nargo/noir-execute: $repo/noir/noir-repo/target/release/"
