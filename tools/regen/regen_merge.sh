#!/usr/bin/env bash
# Regenerates the M6 merge / batch merge fixtures under tests/data/<pin7>/instance/merge/ (gitignored) with the
# bb-side dumper (BbRefDump in the pinned tree, built into dsl_tests).
set -euo pipefail
F=$(cd "$(dirname "$0")" && pwd)
source "$F/env.sh"
BIN=$BUILD/bin/dsl_tests
OUT=$DATA/instance/merge
gen() { BBREF_MODE=$1 BBREF_NUM_SUBTABLES=$2 BBREF_MAX=$3 BBREF_OUT=$OUT/$4 "$BIN" --gtest_filter='BbRefDump.Merge'; }
gen merge 3 9 merge_3
gen batch 3 9 batch_3_of_9
gen batch 5 56 batch_5_of_max
# M7: TripleIPA over Grumpkin
ipa() { BBREF_LOG_N=$1 BBREF_OUT=$DATA/instance/ipa/log_$1 "$BIN" --gtest_filter='BbRefDump.TripleIpa'; }
ipa 4
ipa 15
# M8: ECCVM columns
vm() { BBREF_CASE=$1 BBREF_OUT=$DATA/instance/eccvm/$1 "$BIN" --gtest_filter='BbRefDump.Eccvm'; }
vm base
vm msm9
# M9: ECCVM proof (bb dump; then `cargo test --test eccvm proof` writes rust_base/, verified by the last line)
BBREF_CASE=base BBREF_OUT=$DATA/instance/eccvm_proof/base "$BIN" --gtest_filter='BbRefDump.EccvmProof'
[ -f "$DATA/instance/eccvm_proof/rust_base/eccvm_proof.bin" ] && BBREF_IN=$DATA/instance/eccvm_proof/rust_base "$BIN" --gtest_filter='BbRefDump.EccvmProof'
# M10: Translator circuit + key columns (~90MB)
BBREF_OUT=$DATA/instance/translator "$BIN" --gtest_filter='BbRefDump.Translator'
# M11: BatchedHonkTranslator joint proof (bb dump; then `cargo test --test joint_proof` writes rust/, verified by the last line)
BBREF_SCRIPT=$SCRIPTS/mega_zk.txt BBREF_OUT=$DATA/instance/batched "$BIN" --gtest_filter='BbRefDump.Batched'
[ -f "$DATA/instance/batched/rust/joint_proof.bin" ] && BBREF_SCRIPT=$SCRIPTS/mega_zk.txt BBREF_IN=$DATA/instance/batched/rust "$BIN" --gtest_filter='BbRefDump.Batched'
# M12/M14: Chonk end-to-end (bb mock IVC with real kernels, 2 apps, per-circuit instance dumps); then
# `cargo test --test chonk kernels` rebuilds the same IVC in Rust, writes rust_kernels/ (verified by the last line)
BBREF_DUMP_CIRCUITS=1 BBREF_NUM_APPS=2 BBREF_OUT=$DATA/instance/chonk/bb_2apps "$BIN" --gtest_filter='BbRefDump.Chonk'
[ -f "$DATA/instance/chonk/rust_kernels/proof_fields.bin" ] && BBREF_IN=$DATA/instance/chonk/rust_kernels "$BIN" --gtest_filter='BbRefDump.Chonk'
# Pinned real flows: tools/regen/regen_chonk_flows.sh (needs the flows downloaded)
# RNG tapes (bb CSPRNG byte stream recorded by the patched numeric/random/engine.cpp; single-threaded): the
# Rust ZK provers replay them and must reproduce bb's proofs byte for byte.
T=$DATA/instance
mkdir -p $T/eccvm_proof/base_tape $T/batched_tape
HARDWARE_CONCURRENCY=1 BB_RNG_TAPE_OUT=$T/eccvm_proof/base_tape/rng_tape.bin BBREF_CASE=base BBREF_OUT=$T/eccvm_proof/base_tape "$BIN" --gtest_filter='BbRefDump.EccvmProof'
HARDWARE_CONCURRENCY=1 BB_RNG_TAPE_OUT=$T/batched_tape/rng_tape.bin BBREF_SCRIPT=$SCRIPTS/mega_zk.txt BBREF_OUT=$T/batched_tape "$BIN" --gtest_filter='BbRefDump.Batched'
ACIR=$REPO/barretenberg/acir_tests/acir_tests
# full ChonkProof byte-exactness (no per-circuit dumps: the MegaZK dump would draw masking)
mkdir -p $T/chonk/bb_2apps_tape
HARDWARE_CONCURRENCY=1 BB_RNG_TAPE_OUT=$T/chonk/bb_2apps_tape/rng_tape.bin BBREF_NUM_APPS=2 BBREF_OUT=$T/chonk/bb_2apps_tape "$BIN" --gtest_filter='BbRefDump.Chonk'
for prog in array_dynamic a_1_mul; do
  mkdir -p $T/${prog}_tape
  HARDWARE_CONCURRENCY=1 BB_RNG_TAPE_OUT=$T/${prog}_tape/rng_tape.bin BBREF_PROGRAM=$ACIR/$prog/target/program.json BBREF_WITNESS=$ACIR/$prog/target/witness.gz BBREF_OUT=$T/${prog}_tape "$BIN" --gtest_filter='BbRefDump.UltraInstance'
done
# M13: stdlib programs (gate-exact primitives); the list mirrors tests/stdlib.rs PROGRAMS
for prog in field_ops poseidon2_hash_1 poseidon2_hash_2 poseidon2_hash_3 poseidon2_hash_4 poseidon2_hash_7 poseidon2_hash_16 poseidon2_hash_20 transcript goblin_batch_mul_1 goblin_batch_mul_2 goblin_batch_mul_7 aggregate_multiple_2 aggregate_multiple_3 aggregate_multiple_7 io_app_default io_kernel_default io_hiding_default kernel_io_set hiding_io_set bool_ops cycle_group_add cycle_group_mul_1 cycle_group_mul_3 cycle_group_mul_witness; do
  BBREF_STDLIB=$prog BBREF_OUT=$T/stdlib/$prog "$BIN" --gtest_filter='BbRefDump.Stdlib'
done
# lookup-table programs are dumped as MegaApp (MegaKernel has no lookups)
for prog in sha256_block bigfield_ops biggroup_ops secp256r1_mul ecdsa_r1 ecdsa_k1 keccak_permutation logic_ops blake2s_hash_5 blake2s_hash_65 blake3_hash_5 blake3_hash_65 aes128_cbc_2; do
  HARDWARE_CONCURRENCY=1 BB_RNG_SEED=12345 BBREF_FLAVOR=app BBREF_STDLIB=$prog BBREF_OUT=$T/stdlib/$prog "$BIN" --gtest_filter='BbRefDump.Stdlib'
done
# B4b micro-oracles: isolated bigfield expression repros, dumped as Ultra (the divergent context)
# biggroup_bn254_ops is Ultra too; BB_RNG_SEED: it draws its mask_points offset from the seeded engine
# (DebugRng(12345) in Rust)
for prog in biggroup_bn254_ops row_disabling_fq wnaf_range_fq; do
  HARDWARE_CONCURRENCY=1 BB_RNG_SEED=12345 BBREF_FLAVOR=ultra BBREF_STDLIB=$prog BBREF_OUT=$T/stdlib/$prog "$BIN" --gtest_filter='BbRefDump.Stdlib'
done
# B2: the Ultra recursive verifier over an a_1_mul inner proof (seeded: batch_mul masking draws)
mkdir -p $T/ultra_recursion/a_1_mul
HARDWARE_CONCURRENCY=1 BB_RNG_SEED=12345 BBREF_INNER_PROGRAM=$ACIR/a_1_mul/target/program.json BBREF_INNER_WITNESS=$ACIR/a_1_mul/target/witness.gz BBREF_OUT=$T/ultra_recursion/a_1_mul "$BIN" --gtest_filter='BbRefDump.UltraRecursion'
# B3: Ultra recursion with IPA accumulation (RollupIO; seeded inner witnesses + IPA randomness)
mkdir -p $T/ultra_rollup_recursion
HARDWARE_CONCURRENCY=1 BB_RNG_SEED=12345 BBREF_OUT=$T/ultra_rollup_recursion "$BIN" --gtest_filter='BbRefDump.UltraRollupRecursion'
