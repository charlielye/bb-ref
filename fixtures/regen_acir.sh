#!/bin/bash
# M15: bb's view of the mock-protocol circuits (fixtures/data/<pin7>/acir/, committed):
#   programs/*.json          the Noir artifacts (noir-projects/fnd/mock-protocol-circuits/target)
#   vks/<name>.vk            `bb write_vk --scheme chonk --circuit_kind ...` per artifact
#   mock_<c>_<r>/            ivc-inputs.msgpack (fixtures/write_mock_ivc_inputs.mjs), bb's proof + vk
#   mock_1_1_tape/           the same flow proven with bb's RNG tape recorded (fixtures/bb-patch/engine.cpp)
#   rust_1_1/                bb verifies the Rust proof of mock_1_1 when tests/m15_acir.rs has written it
set -e
F=$(cd "$(dirname "$0")" && pwd)
BB=${BB_BUILD:-$F/../../aztec-packages2/barretenberg/cpp/build}/bin/bb
OUT=$F/data/$(cut -c1-7 "$F/PIN")/acir
mkdir -p "$OUT/vks"
for n in app_creator:app app_reader:app mock_private_kernel_init:kernel mock_private_kernel_inner:kernel mock_private_kernel_reset:kernel mock_private_kernel_tail:kernel mock_hiding:hiding; do
  name=${n%%:*}; kind=${n##*:}
  "$BB" write_vk --scheme chonk --circuit_kind "$kind" -b "$OUT/programs/$name.json" -o "$OUT/vks"
  mv "$OUT/vks/vk" "$OUT/vks/$name.vk"
done
for flow in mock_1_1 mock_2_2; do
  echo "== $flow"
  "$BB" prove --scheme chonk --ivc_inputs_path "$OUT/$flow/ivc-inputs.msgpack" -o "$OUT/$flow" --write_vk
done
mkdir -p "$OUT/mock_1_1_tape"
echo "== mock_1_1 (tape)"
# no --write_vk: bb would re-derive the hiding VK from ACIR afterwards, drawing mock-proof randomness onto the tape
HARDWARE_CONCURRENCY=1 BB_RNG_TAPE_OUT="$OUT/mock_1_1_tape/rng_tape.bin" "$BB" prove --scheme chonk --ivc_inputs_path "$OUT/mock_1_1/ivc-inputs.msgpack" -o "$OUT/mock_1_1_tape"
cp "$OUT/mock_1_1/vk" "$OUT/mock_1_1_tape/vk"
if [ -f "$OUT/rust_1_1/proof" ]; then
  echo "== bb verifies the Rust proof"
  "$BB" verify --scheme chonk -p "$OUT/rust_1_1/proof" -k "$OUT/rust_1_1/vk"
fi
