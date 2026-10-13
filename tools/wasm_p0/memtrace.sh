#!/usr/bin/env bash
# On bbbench: one run of a wasm module under runwasi_memtrace.mjs (linear-memory growth trace interleaved
# with the prover's stderr). bb-ref modules get BBREF_TIMING=1 phase marks; bb prints its own (mem: ...) lines.
#   memtrace.sh <module> <flow> <out.log> [extra prove args...]
set -euo pipefail
M=$1 F=$2 O=$3; shift 3
export PATH=/usr/local/bin:$PATH BB_RNG_SEED=12345 HARDWARE_CONCURRENCY=8 RAYON_NUM_THREADS=8 CRS_PATH=$HOME/.bb-crs WASM_MAX_PAGES=65536 BBREF_TIMING=1
flock ~/bench.lock node ~/wasm-p0/runwasi_memtrace.mjs "$M" prove --scheme chonk --ivc_inputs_path ~/chonk-pinned-flows/$F/ivc-inputs.msgpack -o /tmp/p0-memtrace "$@" >/dev/null 2>"$O"
