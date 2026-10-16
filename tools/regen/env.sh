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
