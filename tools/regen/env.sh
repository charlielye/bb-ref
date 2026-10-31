# Shared paths for the regen scripts (sourced). Every fixture is generated from the pinned tree:
# pin/aztec-packages unless AZTEC_REPO names another checkout of the same commit, built in place
# unless BB_BUILD names the build dir. Fixtures land in tests/data/<pin7>/, the directory
# tests/common/mod.rs reads.
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
REPO=${AZTEC_REPO:-$ROOT/pin/aztec-packages}
BUILD=${BB_BUILD:-$REPO/barretenberg/cpp/build}
PIN7=$(cut -c1-7 "$ROOT/tools/PIN")
DATA=$ROOT/tests/data/$PIN7
SCRIPTS=$ROOT/tests/data/scripts
FLOWS=${BB_FLOWS:-$REPO/barretenberg/cpp/chonk-pinned-flows}
# Fixtures come from bb's release toolchain (zig + libc++) only: the AVM's trace generation sorts
# with ties, so a libstdc++ build's fixtures are valid but not byte-equal (pin/build.sh).
if [ -d "$BUILD" ] && ! grep -qs '^CMAKE_CXX_COMPILER:.*zig-c++\.sh$' "$BUILD/CMakeCache.txt"; then
    echo "regen: $BUILD is not a release-toolchain build (zig + libc++): rebuild it with pin/build.sh" >&2
    exit 1
fi
