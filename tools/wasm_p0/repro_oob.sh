#!/usr/bin/env bash
# On bbbench: repeat a wasm prove N times, count traps ("memory access out of bounds" etc.).
#   repro_oob.sh <module> <flow> <N> <tag>
set -uo pipefail
M=$1 F=$2 N=$3 TAG=$4
export PATH=/usr/local/bin:$PATH BB_RNG_SEED=12345 HARDWARE_CONCURRENCY=8 RAYON_NUM_THREADS=8 CRS_PATH=$HOME/.bb-crs WASM_MAX_PAGES=65536
mkdir -p ~/wasm-p0/repro
fails=0
for i in $(seq "$N"); do
    L=~/wasm-p0/repro/$TAG.$i.log
    if ! flock ~/bench.lock node ~/wasm-p0/runwasi_threads.mjs "$M" prove --scheme chonk --ivc_inputs_path ~/chonk-pinned-flows/$F/ivc-inputs.msgpack -o /tmp/p0-repro-$TAG >/dev/null 2>"$L"; then
        fails=$((fails + 1)); echo "$TAG run $i FAILED: $(grep -m1 Error "$L")"
    fi
done
echo "$TAG: $fails / $N failed"
