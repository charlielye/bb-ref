#!/usr/bin/env bash
# Regenerates the M6 merge / batch merge fixtures under fixtures/data/<pin7>/instance/merge/ (gitignored) with the
# bb-side dumper (fixtures/bb-patch/bbref_dump.test.cpp, built into dsl_tests).
set -euo pipefail
F=$(cd "$(dirname "$0")" && pwd)
BIN=${BB_BUILD:-$F/../../aztec-packages2/barretenberg/cpp/build}/bin/dsl_tests
OUT=$F/data/$(cut -c1-7 "$F/PIN")/instance/merge
gen() { BBREF_MODE=$1 BBREF_NUM_SUBTABLES=$2 BBREF_MAX=$3 BBREF_OUT=$OUT/$4 "$BIN" --gtest_filter='BbRefDump.Merge'; }
gen merge 3 9 merge_3
gen batch 3 9 batch_3_of_9
gen batch 5 56 batch_5_of_max
# M7: TripleIPA over Grumpkin
ipa() { BBREF_LOG_N=$1 BBREF_OUT=$F/data/$(cut -c1-7 "$F/PIN")/instance/ipa/log_$1 "$BIN" --gtest_filter='BbRefDump.TripleIpa'; }
ipa 4
ipa 15
# M8: ECCVM columns
vm() { BBREF_CASE=$1 BBREF_OUT=$F/data/$(cut -c1-7 "$F/PIN")/instance/eccvm/$1 "$BIN" --gtest_filter='BbRefDump.Eccvm'; }
vm base
vm msm9
# M9: ECCVM proof (bb dump; then `cargo test --test m9_eccvm_proof` writes rust_base/, verified by the last line)
BBREF_CASE=base BBREF_OUT=$F/data/$(cut -c1-7 "$F/PIN")/instance/eccvm_proof/base "$BIN" --gtest_filter='BbRefDump.EccvmProof'
[ -f "$F/data/$(cut -c1-7 "$F/PIN")/instance/eccvm_proof/rust_base/eccvm_proof.bin" ] && BBREF_IN=$F/data/$(cut -c1-7 "$F/PIN")/instance/eccvm_proof/rust_base "$BIN" --gtest_filter='BbRefDump.EccvmProof'
# M10: Translator circuit + key columns (~90MB)
BBREF_OUT=$F/data/$(cut -c1-7 "$F/PIN")/instance/translator "$BIN" --gtest_filter='BbRefDump.Translator'
# M11: BatchedHonkTranslator joint proof (bb dump; then `cargo test --test m11_batched` writes rust/, verified by the last line)
BBREF_SCRIPT=$F/scripts/mega_zk.txt BBREF_OUT=$F/data/$(cut -c1-7 "$F/PIN")/instance/batched "$BIN" --gtest_filter='BbRefDump.Batched'
[ -f "$F/data/$(cut -c1-7 "$F/PIN")/instance/batched/rust/joint_proof.bin" ] && BBREF_SCRIPT=$F/scripts/mega_zk.txt BBREF_IN=$F/data/$(cut -c1-7 "$F/PIN")/instance/batched/rust "$BIN" --gtest_filter='BbRefDump.Batched'
