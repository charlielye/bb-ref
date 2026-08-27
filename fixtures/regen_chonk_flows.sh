#!/bin/bash
# M12: bb Chonk proofs of the pinned real transaction flows (verifier-side oracle for Rust). With the
# fixture engine patch, BB_RNG_SEED makes bb draw from its seeded debug engine single-threaded, so the
# proofs are also the byte-exact targets of `tests/m12_chonk.rs::pinned_flows_byte_exact_with_seed`.
# Requires the flows downloaded via `barretenberg/cpp/scripts/chonk_inputs.sh download`.
set -e
F=$(cd "$(dirname "$0")" && pwd)
BB=${BB_BUILD:-$F/../../aztec-packages2/barretenberg/cpp/build}/bin/bb
FLOWS=${BB_FLOWS:-$F/../../aztec-packages2/barretenberg/cpp/chonk-pinned-flows}
OUT=$F/data/$(cut -c1-7 "$F/PIN")/chonk_flows
for d in "$FLOWS"/*/; do
  name=$(basename "$d")
  [ -f "$d/ivc-inputs.msgpack" ] || continue
  mkdir -p "$OUT/$name"
  echo "== $name"
  HARDWARE_CONCURRENCY=1 BB_RNG_SEED=12345 "$BB" prove --scheme chonk --ivc_inputs_path "$d/ivc-inputs.msgpack" -o "$OUT/$name" --write_vk
done
