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
