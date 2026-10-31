#!/usr/bin/env bash
# Regenerates the AVM verifier fixtures: tests/data/<pin7>/avm/ (committed: the AVM proving inputs,
# bb's proof of them and the flattened public-input columns) and instance/avm_inner/ (gitignored,
# ~0.5 GB: bb's inner MegaAvm recursive verifier circuit for that proof).
#
#   regen_avm.sh            reuse the committed avm/avm_inputs.bin
#   regen_avm.sh --inputs   re-dump fresh inputs from yarn-project's AVM test first (needs labs built)
#
# The dumper (avm_dump.cpp) links the pin's AVM build (`pin/build.sh --avm`: bb's release
# toolchain, zig's clang and libc++). bb's AVM trace depends on the C++ standard library, so the
# fixture proof is the one the published bb-avm gives.
set -euo pipefail
F=$(cd "$(dirname "$0")" && pwd)
source "$F/env.sh"
CPP=$REPO/barretenberg/cpp
LIBS="vm2 vm2_sim barretenberg env"
for l in $LIBS; do
  [ -f "$BUILD/lib/lib$l.a" ] || { echo "missing $BUILD/lib/lib$l.a: run pin/build.sh --avm" >&2; exit 1; }
done
OUT=$DATA/avm
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$OUT"

if [ "${1:-}" = "--inputs" ]; then
  (cd "$REPO/labs/yarn-project/bb-prover" &&
    BB_AVM_SIM_PATH=$BUILD/bin/bb-avm-sim BB_DEBUG_OUTPUT_DIR=$TMP/dump NODE_NO_WARNINGS=1 \
      node --experimental-vm-modules ../node_modules/.bin/jest --maxWorkers=1 --forceExit \
      src/avm_proving_tests/avm_check_circuit1.test.ts -t "too many storage writes")
  cp "$TMP"/dump/avm-check-circuit-001/avm_inputs.bin "$OUT/avm_inputs.bin"
fi

"$CPP/scripts/zig-c++.sh" -target x86_64-linux-gnu.2.35 -DMSGPACK_NO_BOOST -DMSGPACK_USE_STD_VARIANT_ADAPTOR -DNO_PAR_ALGOS \
  -I"$CPP/src" -I"$BUILD/_deps/msgpack-c/src/msgpack-c/include" -I"$BUILD/_deps/tracy-src/public" \
  -I"$BUILD/_deps/libdeflate-src" -I"$BUILD/_deps/nlohmann_json-src/include" -I"$REPO/ipc-runtime/cpp" \
  -O2 -std=gnu++20 -fbracket-depth=1024 -march=skylake -pthread -fconstexpr-steps=100000000 \
  -Wno-deprecated-declarations -Wno-vla-cxx-extension \
  "$F/avm_dump.cpp" -Wl,--start-group $(for l in $LIBS; do echo "$BUILD/lib/lib$l.a"; done) -Wl,--end-group \
  "$BUILD/_deps/libdeflate-build/libdeflate.a" -o "$TMP/avm_dump"

# Seeded so the op queue's random ops are reproducible (the test masks them anyway).
BB_RNG_SEED=1 "$TMP/avm_dump" "$OUT/avm_inputs.bin" "$TMP/out" --inner
cp "$TMP/out/proof.bin" "$TMP/out/public_inputs.bin" "$OUT/"
rm -rf "$DATA/instance/avm_inner"
mkdir -p "$DATA/instance"
mv "$TMP/out/inner" "$DATA/instance/avm_inner"
echo "regen_avm: wrote $OUT and $DATA/instance/avm_inner"
