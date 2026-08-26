#!/bin/bash
# M12: bb Chonk proofs of the pinned real transaction flows (verifier-side oracle for Rust).
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
  "$BB" prove --scheme chonk --ivc_inputs_path "$d/ivc-inputs.msgpack" -o "$OUT/$name" --write_vk
done
