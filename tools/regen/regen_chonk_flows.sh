#!/bin/bash
# Bb Chonk proofs of the pinned real transaction flows (verifier-side oracle for Rust). With the
# fixture engine patch, BB_RNG_SEED makes bb draw from its seeded debug engine single-threaded, so the
# proofs are also the byte-exact targets of `tests/chonk.rs (native)::pinned_flows_byte_exact_with_seed`.
# Requires the flows at $FLOWS (bb's pinned chonk inputs, `barretenberg/cpp/scripts/chonk_inputs.sh download`).
set -e
F=$(cd "$(dirname "$0")" && pwd)
source "$F/env.sh"
BB=$BUILD/bin/bb
OUT=$DATA/chonk_flows
for d in "$FLOWS"/*/; do
  name=$(basename "$d")
  [ -f "$d/ivc-inputs.msgpack" ] || continue
  mkdir -p "$OUT/$name"
  echo "== $name"
  HARDWARE_CONCURRENCY=1 BB_RNG_SEED=12345 "$BB" prove --scheme chonk --ivc_inputs_path "$d/ivc-inputs.msgpack" -o "$OUT/$name"
  # The flow's VK is the hiding kernel's precomputed VK, carried in the inputs (bb's chonk `prove`
  # dropped --write_vk; it proves against the pinned VKs).
  python3 -c 'import msgpack, sys; s = msgpack.unpackb(open(sys.argv[1], "rb").read()); open(sys.argv[2], "wb").write(s[-1]["vk"])' \
    "$d/ivc-inputs.msgpack" "$OUT/$name/vk"
done
