#!/usr/bin/env bash
# Chonk proving on WASM, bb vs bb-ref over the pinned flows — same table as bench_chonk.sh.
#
#   tools/bench_chonk_wasm.sh wasmtime|v8 [flow ...]
#
# Both provers run the identical CLI on 8 threads. "wasmtime" runs the wasip1-threads binaries
# under wasmtime; "v8" runs them under node via tools/runwasi_threads.mjs (worker_threads +
# shared memory — the browser shape). Whole-process wall including module compile and SRS load,
# identical treatment for both provers. RSS is the host-process peak (%M) — noisy for wasm
# runtimes; compare walls, treat memory columns as indicative only.
set -euo pipefail
cd "$(dirname "$0")/.."

RUNTIME=${1:?usage: bench_chonk_wasm.sh wasmtime|v8 [flow ...]}
shift || true
FLOWS_DIR=$(cd "${BB_FLOWS:-../aztec-packages2/barretenberg/cpp/chonk-pinned-flows}" && pwd)
BB_WASM=$(cd "$(dirname "${BB_WASM:-../aztec-packages2/barretenberg/cpp/build-wasm-threads/bin/bb}")" && pwd)/$(basename "${BB_WASM:-bb}")
REF_WASM=${REF_WASM:-$PWD/target/wasm32-wasip1-threads/release/bb-ref.wasm}
: "${BB_RNG_SEED:=12345}"
: "${THREADS:=8}"
export BB_RNG_SEED HARDWARE_CONCURRENCY=$THREADS RAYON_NUM_THREADS=$THREADS CRS_PATH=$HOME/.bb-crs
# bb-ref.wasm is linked with --max-memory=4GB (the biggest flow needs >1GB linear memory).
export WASM_MAX_PAGES=${WASM_MAX_PAGES:-65536}

if [ $# -gt 0 ]; then FLOWS=("$@"); else
    FLOWS=()
    for d in "$FLOWS_DIR"/*/; do [ -f "$d/ivc-inputs.msgpack" ] && FLOWS+=("$(basename "$d")"); done
fi

OUT=$(mktemp -d)
trap 'rm -rf "$OUT"' EXIT

run_one() { # binary inputs outdir -> "seconds maxrss_kb"
    case $RUNTIME in
    wasmtime)
        /usr/bin/time -f '%e %M' -o "$3.time" \
            wasmtime run -S threads -W max-wasm-stack=8388608 --dir / \
            --env BB_RNG_SEED --env HARDWARE_CONCURRENCY --env RAYON_NUM_THREADS --env CRS_PATH \
            "$1" prove --scheme chonk --ivc_inputs_path "$2" -o "$3" >/dev/null 2>"$3.log" \
            || { cat "$3.log" >&2; exit 1; } ;;
    v8)
        /usr/bin/time -f '%e %M' -o "$3.time" \
            node tools/runwasi_threads.mjs "$1" prove --scheme chonk --ivc_inputs_path "$2" -o "$3" \
            >/dev/null 2>"$3.log" \
            || { cat "$3.log" >&2; exit 1; } ;;
    esac
    cat "$3.time"
}

echo "runtime: $RUNTIME, threads: $THREADS (both provers), seed: $BB_RNG_SEED, flows: ${#FLOWS[@]}"
printf '%-62s %8s %8s %7s %8s %8s %7s\n' flow bb bb-ref ratio "bb rss" "ref rss" mem
total_bb=0
total_ref=0
for flow in "${FLOWS[@]}"; do
    inputs=$FLOWS_DIR/$flow/ivc-inputs.msgpack
    mkdir -p "$OUT/bb" "$OUT/ref"
    read -r bb_s bb_kb <<< "$(run_one "$BB_WASM" "$inputs" "$OUT/bb")"
    read -r ref_s ref_kb <<< "$(run_one "$REF_WASM" "$inputs" "$OUT/ref")"
    awk -v f="$flow" -v a="$bb_s" -v b="$ref_s" -v ak="$bb_kb" -v bk="$ref_kb" \
        'BEGIN { printf "%-62s %8.2f %8.2f %6.2fx %7.2fG %7.2fG %6.2fx\n", f, a, b, b / a, ak / 1048576, bk / 1048576, bk / ak }'
    total_bb=$(awk -v t="$total_bb" -v a="$bb_s" 'BEGIN { printf "%.2f", t + a }')
    total_ref=$(awk -v t="$total_ref" -v a="$ref_s" 'BEGIN { printf "%.2f", t + a }')
done
awk -v a="$total_bb" -v b="$total_ref" \
    'BEGIN { printf "%-62s %8.2f %8.2f %6.2fx\n", "TOTAL", a, b, b / a }'
