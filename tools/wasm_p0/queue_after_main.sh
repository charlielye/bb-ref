#!/usr/bin/env bash
# On bbbench: the profile + memtrace jobs, each taking ~/bench.lock in turn (they queue behind the main run).
set -uo pipefail
B=~/ab-bin
REF=$B/p0-ref-port.4748d55c1283.wasm
GOLF=$B/p0-golfbb-stripped.1fbe2899ea80.wasm
GOLFN=$B/p0-golfbb-named.02fa6b14945a.wasm
PIN=$B/p0-pinbb-stripped.0d2849599696.wasm
T1=ecdsar1+transfer_1_recursions+private_fpc
SP=ecdsar1+storage_proof_7_layers+sponsored_fpc
mkdir -p ~/wasm-p0/mem ~/wasm-p0/prof
for f in $T1 $SP; do
    ~/wasm-p0/memtrace.sh $REF $f ~/wasm-p0/mem/ref-port.$f.log
    ~/wasm-p0/memtrace.sh $GOLF $f ~/wasm-p0/mem/golfbb.$f.log
    ~/wasm-p0/memtrace.sh $PIN $f ~/wasm-p0/mem/pinbb.$f.log
done
for f in $T1 $SP; do
    ~/wasm-p0/prof.sh $REF $f ~/wasm-p0/prof/ref-port.$f
    ~/wasm-p0/prof.sh $GOLFN $f ~/wasm-p0/prof/golfbb.$f
done
echo QUEUE_DONE
