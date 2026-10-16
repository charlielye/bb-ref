#!/bin/bash
# Build the conforming toolchain from the pinned barretenberg checkout: the `bb` binary the
# differential tests compare against, and the `nargo`/`noir-execute` that compile and execute the circuits
# they use. Everything comes from `pin/aztec-packages` (a submodule at an exact commit), so a clone
# reproduces the same binaries without installing anything system-wide.
#
#   ./pin/build.sh            # bb only — enough for the conformance suite
#   ./pin/build.sh --noir     # also nargo + noir-execute, needed to (re)compile circuits
#
# Set AZTEC_REPO to point at an existing checkout instead (a dev box with the tree already built);
# the tests honour the same variable.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
repo=${AZTEC_REPO:-$here/aztec-packages}
build_noir=false
[[ ${1:-} == "--noir" ]] && build_noir=true

if [ ! -d "$repo/barretenberg/cpp" ]; then
  echo "pin: $repo is not a barretenberg checkout." >&2
  echo "     Run: git submodule update --init --depth 1 pin/aztec-packages" >&2
  exit 1
fi

echo "pin: building bb from $(git -C "$repo" rev-parse --short HEAD)"
# Configure from inside the source dir: the constants generator resolves its paths relative to the
# working directory, not to -S.
(
  cd "$repo/barretenberg/cpp"
  cmake --preset default -B build > /dev/null
  # bb-avm is a separate target: the stock `bb` refuses AVM proving, which the fixture-harvest path
  # needs. It is not required by the conformance suite itself.
  ninja -C build bb
)

if $build_noir; then
  echo "pin: building nargo + noir-execute"
  git -C "$repo" submodule update --init --depth 1 noir/noir-repo
  cargo build --release --manifest-path "$repo/noir/noir-repo/Cargo.toml" --bin nargo --bin noir-execute
fi

echo "pin: done"
echo "  bb:   $repo/barretenberg/cpp/build/bin/bb"
$build_noir && echo "  nargo/noir-execute: $repo/noir/noir-repo/target/release/"
