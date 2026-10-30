#!/bin/bash
# Build the conforming toolchain from the pinned barretenberg checkout: the `bb` binary the
# differential tests compare against, and the `nargo`/`noir-execute` that compile and execute the circuits
# they use. Everything comes from `pin/aztec-packages` (a submodule at an exact commit), so a clone
# reproduces the same binaries without installing anything system-wide.
#
#   ./pin/build.sh            # bb only — enough for the conformance suite
#   ./pin/build.sh --noir     # also nargo + noir-execute, needed to (re)compile circuits
#   ./pin/build.sh --avm-lib  # also libbb-external-avm.a, which bb-ref's `bb-avm` feature links
#
# Set AZTEC_REPO to point at an existing checkout instead (a dev box with the tree already built);
# the tests honour the same variable.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
repo=${AZTEC_REPO:-$here/aztec-packages}
build_noir=false
build_avm_lib=false
for a in "$@"; do
  case $a in
    --noir) build_noir=true ;;
    --avm-lib) build_avm_lib=true ;;
  esac
done

if [ ! -d "$repo/barretenberg/cpp" ]; then
  echo "pin: $repo is not a barretenberg checkout." >&2
  echo "     Run: git submodule update --init --depth 1 pin/aztec-packages" >&2
  exit 1
fi

echo "pin: building bb from $(git -C "$repo" rev-parse --short HEAD)"
# bb's release preset (`clang20`: zig's clang and libc++), as bootstrap.sh builds bb and the
# `bb-external` archive barretenberg-rs links; the `default` preset's system clang + libstdc++ build
# proves the AVM ~12% slower under load. Configure from inside the source dir: the constants
# generator resolves its paths relative to the working directory, not to -S.
(
  cd "$repo/barretenberg/cpp"
  cmake --preset clang20 -B build > /dev/null
  # bb-avm is a separate target: the stock `bb` refuses AVM proving, which the fixture-harvest path
  # needs. It is not required by the conformance suite itself.
  ninja -C build bb
)

# bb's static FFI archive with the AVM linked in (pin/bb-avm.patch adds the target and a CRS entry
# point), built with the patch applied and the checkout restored afterwards.
if $build_avm_lib; then
  echo "pin: building libbb-external-avm.a"
  patch=$here/bb-avm.patch
  git -C "$repo" apply "$patch"
  trap 'git -C "$repo" apply -R "$patch"' EXIT
  (
    cd "$repo/barretenberg/cpp"
    cmake --preset clang20 -B build -DAVM=ON > /dev/null
    ninja -C build bb-external-avm
  )
fi

if $build_noir; then
  echo "pin: building nargo + noir-execute"
  git -C "$repo" submodule update --init --depth 1 noir/noir-repo
  cargo build --release --manifest-path "$repo/noir/noir-repo/Cargo.toml" --bin nargo --bin noir-execute
fi

echo "pin: done"
echo "  bb:   $repo/barretenberg/cpp/build/bin/bb"
$build_avm_lib && echo "  avm:  $repo/barretenberg/cpp/build/lib/libbb-external-avm.a" \
  "(portable bb-ref: CXXSTDLIB=c++ cargo zigbuild --release --features bb-avm --target x86_64-unknown-linux-gnu.2.35)"
$build_noir && echo "  nargo/noir-execute: $repo/noir/noir-repo/target/release/"
