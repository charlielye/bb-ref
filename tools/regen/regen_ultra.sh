#!/bin/bash
# M1: bb UltraHonk proofs of acir_tests programs, ZK and non-ZK, for the verifier oracle
# (tests/ultra_honk/verify.rs, vk_format.rs): tests/data/<pin7>/ultra/<program>/{zk,nozk}/
# {proof,public_inputs,vk,vk_hash}. Seeded and single-threaded so a rerun writes the same bytes.
set -e
F=$(cd "$(dirname "$0")" && pwd)
source "$F/env.sh"
BB=$BUILD/bin/bb
ACIR_TESTS=${ACIR_TESTS:-$REPO/barretenberg/acir_tests/acir_tests}
for prog in a_1_mul array_dynamic no_predicates_numeric_generic_poseidon embedded_curve_ops ecdsa_secp256k1 unsafe_range_constraint uhashmap; do
  T=$ACIR_TESTS/$prog/target
  for mode in zk nozk; do
    out=$DATA/ultra/$prog/$mode
    mkdir -p "$out"
    flags=()
    [ "$mode" = nozk ] && flags=(--disable_zk)
    HARDWARE_CONCURRENCY=1 BB_RNG_SEED=12345 "$BB" prove --scheme ultra_honk "${flags[@]}" --write_vk \
      -b "$T/program.json" -w "$T/witness.gz" -o "$out"
  done
  echo "ultra $prog"
done
