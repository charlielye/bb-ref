#!/bin/bash
# bb's view of the mock-protocol circuits (tests/data/<pin7>/acir/, committed):
#   programs/*.json          the Noir artifacts (noir-projects/fnd/mock-protocol-circuits/target)
#   vks/<name>.vk            `bb write_vk --scheme chonk --circuit_kind ...` per artifact
#   mock_<c>_<r>/            ivc-inputs.msgpack (tools/regen/write_mock_ivc_inputs.mjs over labs' ivc-integration), bb's proof + vk
#   mock_1_1_tape/           the same flow proven with bb's draws recorded via BB_RNG_TAPE_OUT (in the pinned tree)
#   mock_1_1_seed/           the same flow proven with bb's seeded debug engine (BB_RNG_SEED=12345)
#   rust_1_1/                bb verifies the Rust proof of mock_1_1 when tests/acir.rs has written it
set -e
F=$(cd "$(dirname "$0")" && pwd)
source "$F/env.sh"
BB=$BUILD/bin/bb
OUT=$DATA/acir
MOCK=$REPO/noir-projects/fnd/mock-protocol-circuits/target
LABS=${LABS:-$REPO/labs}
mkdir -p "$OUT/vks" "$OUT/programs"
for name in app_creator app_reader mock_private_kernel_init mock_private_kernel_inner mock_private_kernel_reset mock_private_kernel_tail mock_hiding; do
  cp "$MOCK/$name.json" "$OUT/programs/$name.json"
done
# The mock transactions: witnesses from labs' ivc-integration (needs `make labs-yarn-project`).
for flow in mock_1_1:1:1 mock_2_2:2:2; do
  name=${flow%%:*}; c=$(echo "$flow" | cut -d: -f2); r=$(echo "$flow" | cut -d: -f3)
  mkdir -p "$OUT/$name"
  (cd "$LABS/yarn-project/ivc-integration" && node "$F/write_mock_ivc_inputs.mjs" "$LABS" "$c" "$r" "$OUT/$name/ivc-inputs.msgpack")
done
# A flow's VK is its hiding kernel's precomputed VK, carried in the inputs (bb's chonk `prove` has
# no --write_vk).
hiding_vk() {
  python3 -c 'import msgpack, sys; s = msgpack.unpackb(open(sys.argv[1], "rb").read()); open(sys.argv[2], "wb").write(s[-1]["vk"])' "$1" "$2"
}
for n in app_creator:app app_reader:app mock_private_kernel_init:kernel mock_private_kernel_inner:kernel mock_private_kernel_reset:kernel mock_private_kernel_tail:kernel mock_hiding:hiding; do
  name=${n%%:*}; kind=${n##*:}
  "$BB" write_vk --scheme chonk --circuit_kind "$kind" -b "$OUT/programs/$name.json" -o "$OUT/vks"
  mv "$OUT/vks/vk" "$OUT/vks/$name.vk"
done
for flow in mock_1_1 mock_2_2; do
  echo "== $flow"
  "$BB" prove --scheme chonk --ivc_inputs_path "$OUT/$flow/ivc-inputs.msgpack" -o "$OUT/$flow"
  hiding_vk "$OUT/$flow/ivc-inputs.msgpack" "$OUT/$flow/vk"
done
mkdir -p "$OUT/mock_1_1_tape"
echo "== mock_1_1 (tape)"
HARDWARE_CONCURRENCY=1 BB_RNG_TAPE_OUT="$OUT/mock_1_1_tape/rng_tape.bin" "$BB" prove --scheme chonk --ivc_inputs_path "$OUT/mock_1_1/ivc-inputs.msgpack" -o "$OUT/mock_1_1_tape"
cp "$OUT/mock_1_1/vk" "$OUT/mock_1_1_tape/vk"
mkdir -p "$OUT/mock_1_1_seed"
echo "== mock_1_1 (seed)"
# BB_RNG_SEED makes bb draw from its seeded debug engine (mt19937_64), which bb-ref mirrors via DebugRng.
HARDWARE_CONCURRENCY=1 BB_RNG_SEED=12345 "$BB" prove --scheme chonk --ivc_inputs_path "$OUT/mock_1_1/ivc-inputs.msgpack" -o "$OUT/mock_1_1_seed"
cp "$OUT/mock_1_1/vk" "$OUT/mock_1_1_seed/vk"
if [ -f "$OUT/rust_1_1/proof" ]; then
  echo "== bb verifies the Rust proof"
  "$BB" verify --scheme chonk -p "$OUT/rust_1_1/proof" -k "$OUT/rust_1_1/vk"
fi
