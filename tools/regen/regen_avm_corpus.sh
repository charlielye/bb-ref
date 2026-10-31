#!/usr/bin/env bash
# The AVM corpus: bb's answers to the AVM commands on recorded proving inputs, replayed by
# tools/conformance.sh like the rollup corpus. Per input: AvmProve, AvmCheckCircuit, then AvmVerify
# of bb's proof and of a tampered one.
#
#   tools/regen/regen_avm_corpus.sh <avm_inputs.bin>...   (default: the fixture's inputs)
#
# bb is the pin's bb-avm ($BB_AVM, default $BUILD/bin/bb-avm): bb's release toolchain (the clang20
# preset, libc++), as the published bb-avm. bb's AVM trace depends on the C++ standard library it
# was built with, so a libstdc++ bb-avm proves the same inputs differently (both proofs valid).
set -euo pipefail
F=$(cd "$(dirname "$0")" && pwd)
source "$F/env.sh"
BB_AVM=${BB_AVM:-$BUILD/bin/bb-avm}
[ $# -gt 0 ] || set -- "$DATA/avm/avm_inputs.bin"
OUT=$ROOT/tools/corpus/avm-$PIN7
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
LIB=$ROOT/tools/lib/avm_corpus.py
run() { "$BB_AVM" msgpack run --input "$1" > "$2"; }

python3 "$LIB" prove "$TMP/prove.req" "$@"
run "$TMP/prove.req" "$TMP/prove.resp"
python3 "$LIB" verify "$TMP/verify.req" "$TMP/prove.req" "$TMP/prove.resp"
run "$TMP/verify.req" "$TMP/verify.resp"
cat "$TMP/prove.req" "$TMP/verify.req" | zstd -19 -q -f -o "$OUT.corpus.zst"
python3 "$LIB" goldens "$TMP/goldens" "$TMP/prove.resp" "$TMP/verify.resp"
zstd -19 -q -f -o "$OUT.goldens.zst" "$TMP/goldens"
echo "regen_avm_corpus: $OUT.corpus.zst ($(du -h "$OUT.corpus.zst" | cut -f1)), $(python3 "$ROOT/tools/lib/replay.py" --count "$TMP/goldens") frames"
echo "verify it:  tools/conformance.sh $OUT.corpus.zst"
