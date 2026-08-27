#!/bin/bash
# M16: `bb write_vk --scheme chonk --circuit_kind ...` on the real protocol kernels
# (noir-projects/fnd/noir-protocol-circuits/target, referenced in place; the artifacts are large).
set -e
F=$(cd "$(dirname "$0")" && pwd)
BB=${BB_BUILD:-$F/../../aztec-packages2/barretenberg/cpp/build}/bin/bb
T=${PROTOCOL_CIRCUITS:-$F/../../aztec-packages2/noir-projects/fnd/noir-protocol-circuits/target}
OUT=$F/data/$(cut -c1-7 "$F/PIN")/protocol/vks
mkdir -p "$OUT"
for n in private_kernel_init:kernel private_kernel_inner:kernel private_kernel_reset:kernel private_kernel_reset_4_4_4_4_4_4_0_0_0:kernel private_kernel_reset_tail:kernel private_kernel_reset_tail_to_public:kernel hiding_kernel_to_public:hiding hiding_kernel_to_rollup:hiding; do
  name=${n%%:*}; kind=${n##*:}
  echo "== $name"
  "$BB" write_vk --scheme chonk --circuit_kind "$kind" -b "$T/$name.json" -o "$OUT"
  mv "$OUT/vk" "$OUT/$name.vk"
done
# per-circuit instance dumps for the gate-level diff (gitignored, large); needs dsl_tests with fixtures/bb-patch
BIN=${BB_BUILD:-$F/../../aztec-packages2/barretenberg/cpp/build}/bin/dsl_tests
for n in private_kernel_init:kernel private_kernel_inner:kernel hiding_kernel_to_rollup:hiding ${BBREF_ALL_KERNELS:+private_kernel_reset:kernel private_kernel_reset_4_4_4_4_4_4_0_0_0:kernel private_kernel_reset_tail:kernel private_kernel_reset_tail_to_public:kernel hiding_kernel_to_public:hiding}; do
  name=${n%%:*}; kind=${n##*:}
  BBREF_PROGRAM=$T/$name.json BBREF_KIND=$kind BBREF_OUT=$F/data/$(cut -c1-7 "$F/PIN")/instance/protocol/$name "$BIN" --gtest_filter='BbRefDump.AcirMega'
done
