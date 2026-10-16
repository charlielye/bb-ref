#!/bin/bash
# M16: `bb write_vk --scheme chonk --circuit_kind ...` on the real protocol kernels
# (noir-projects/fnd/noir-protocol-circuits/target, referenced in place; the artifacts are large).
set -e
F=$(cd "$(dirname "$0")" && pwd)
source "$F/env.sh"
BB=$BUILD/bin/bb
T=${PROTOCOL_CIRCUITS:-$REPO/noir-projects/fnd/noir-protocol-circuits/target}
OUT=$DATA/protocol/vks
mkdir -p "$OUT"
for n in private_kernel_init:kernel private_kernel_inner:kernel private_kernel_reset:kernel private_kernel_reset_4_4_4_4_4_4_0_0_0:kernel private_kernel_reset_tail:kernel private_kernel_reset_tail_to_public:kernel hiding_kernel_to_public:hiding hiding_kernel_to_rollup:hiding; do
  name=${n%%:*}; kind=${n##*:}
  echo "== $name"
  "$BB" write_vk --scheme chonk --circuit_kind "$kind" -b "$T/$name.json" -o "$OUT"
  mv "$OUT/vk" "$OUT/$name.vk"
done
# per-circuit instance dumps for the gate-level diff (gitignored, large); needs dsl_tests from the pinned tree (carries BbRefDump)
BIN=$BUILD/bin/dsl_tests
for n in private_kernel_init:kernel private_kernel_inner:kernel hiding_kernel_to_rollup:hiding ${BBREF_ALL_KERNELS:+private_kernel_reset:kernel private_kernel_reset_4_4_4_4_4_4_0_0_0:kernel private_kernel_reset_tail:kernel private_kernel_reset_tail_to_public:kernel hiding_kernel_to_public:hiding}; do
  name=${n%%:*}; kind=${n##*:}
  BBREF_PROGRAM=$T/$name.json BBREF_KIND=$kind BBREF_OUT=$DATA/instance/protocol/$name "$BIN" --gtest_filter='BbRefDump.AcirMega'
done
