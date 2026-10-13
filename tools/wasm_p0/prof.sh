#!/usr/bin/env bash
# On bbbench, under flock: profiles of one wasm module on one flow, production tiering (plain node).
#   prof.sh <module> <flow> <outdir>
# 1. V8 CPU profile: WASI_CPU_PROF=<outdir>/cpuprof -> one .cpuprofile per worker (tools/runwasi_threads.mjs).
# 2. perf + --perf-basic-prof: V8 names wasm code "<name>-<index>-liftoff|turbofan" in /tmp/perf-<pid>.map,
#    so `perf report --sort sym` splits samples by tier. perf.data + the map are kept in <outdir>.
set -euo pipefail
M=$1 F=$2 O=$3
mkdir -p "$O/cpuprof"
export PATH=/usr/local/bin:$PATH BB_RNG_SEED=12345 HARDWARE_CONCURRENCY=8 RAYON_NUM_THREADS=8 CRS_PATH=$HOME/.bb-crs WASM_MAX_PAGES=65536
IN=~/chonk-pinned-flows/$F/ivc-inputs.msgpack
flock ~/bench.lock env WASI_CPU_PROF="$O/cpuprof" node ~/wasm-p0/runwasi_threads.mjs "$M" prove --scheme chonk --ivc_inputs_path "$IN" -o /tmp/p0-prof-out >/dev/null 2>"$O/cpuprof.log"
flock ~/bench.lock sudo -E env PATH=$PATH perf record -F 1999 -o "$O/perf.data" -- node --perf-basic-prof ~/wasm-p0/runwasi_threads.mjs "$M" prove --scheme chonk --ivc_inputs_path "$IN" -o /tmp/p0-prof-out >/dev/null 2>"$O/perf.log"
sudo chown ubuntu "$O/perf.data"
P=$(ls -t /tmp/perf-*.map | head -1)
sudo cp "$P" "$O/" && sudo chown ubuntu "$O/$(basename "$P")"
sudo perf report -f -i "$O/perf.data" --no-children --sort sym --stdio 2>/dev/null | grep -v '^#' | grep -v '^$' > "$O/perf-sym.txt"
echo done
