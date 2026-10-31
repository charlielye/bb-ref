#!/usr/bin/env bash
# The pin's build outputs the tests read, vendored under tests/data/<pin7>/inputs/ so the suite needs
# no pin build: the acir_tests programs (program.json, witness.gz) the VK sweeps and builder tests
# read, the protocol circuit artifacts without a tests/data/<pin7>/backend/ copy (the kernels and the
# smaller rollup circuits), and the pinned Chonk flows' ivc-inputs.msgpack. Needs the acir_tests
# compiled, the protocol circuits compiled and the flows downloaded in the pinned tree.
set -euo pipefail
F=$(cd "$(dirname "$0")" && pwd)
source "$F/env.sh"
OUT=$DATA/inputs
rm -rf "$OUT/acir_tests" "$OUT/protocol_circuits" "$OUT/chonk_flows"
mkdir -p "$OUT/acir_tests" "$OUT/protocol_circuits" "$OUT/chonk_flows"

ACIR=$REPO/barretenberg/acir_tests/acir_tests
for p in $( (ls "$DATA/vk_hash"; ls "$DATA/vk_sha256_mega_app") | sort -u); do
  mkdir -p "$OUT/acir_tests/$p/target"
  cp "$ACIR/$p/target/program.json" "$OUT/acir_tests/$p/target/"
  [ ! -f "$ACIR/$p/target/witness.gz" ] || cp "$ACIR/$p/target/witness.gz" "$OUT/acir_tests/$p/target/"
done

T=$REPO/noir-projects/fnd/noir-protocol-circuits/target
for n in $(ls "$DATA/protocol/vks" | sed 's/\.vk$//') $(ls "$DATA/backend_vk_hash"); do
  [ -f "$DATA/backend/$n/program.json" ] || cp "$T/$n.json" "$OUT/protocol_circuits/"
done

for d in "$FLOWS"/*/; do
  mkdir -p "$OUT/chonk_flows/$(basename "$d")"
  cp "$d/ivc-inputs.msgpack" "$OUT/chonk_flows/$(basename "$d")/"
done
"$F/pack.sh" inputs/acir_tests inputs/protocol_circuits inputs/chonk_flows
