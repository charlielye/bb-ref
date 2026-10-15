#!/usr/bin/env bash
# Chonk proving on WASM, bb vs bb-ref over the pinned flows — same table as bench_chonk.sh.
#
#   tools/bench_chonk_wasm.sh wasmtime|v8 [flow ...]      (REPS=n for best-of-n wall)
#
# Columns: wall (best of $REPS) and proving-only (one instrumented run each) with both ratios, plus
# memory. bb's wall module is $BB_WASM (use a *stripped* module: bb's release module ships a 100 MB
# name section that costs ~2% of wall in load); bb's proving comes from $BB_WASM_BENCH (an
# ENABLE_WASM_BENCH build) via --bench_out, or "-" if unset.
#
# Both provers run the identical CLI on 8 threads. "wasmtime" runs the wasip1-threads binaries
# under wasmtime; "v8" runs them under node via tools/runwasi_threads.mjs (worker_threads +
# shared memory — the browser shape). Whole-process wall including module compile and SRS load,
# identical treatment for both provers. Memory columns: under v8 the wasm linear-memory peak
# (final memory.buffer size — linear memory only grows), the browser-relevant number; under
# wasmtime the host-process peak RSS (wasmtime has no linear-memory report) — noisy, indicative.
# NODE overrides the v8 command, flags included (e.g. NODE="node27 --wasm-wide-arithmetic").
set -euo pipefail
cd "$(dirname "$0")/.."

RUNTIME=${1:?usage: bench_chonk_wasm.sh wasmtime|v8 [flow ...]}
shift || true
FLOWS_DIR=$(cd "${BB_FLOWS:-../aztec-packages2/barretenberg/cpp/chonk-pinned-flows}" && pwd)
BB_WASM=$(cd "$(dirname "${BB_WASM:-../aztec-packages2/barretenberg/cpp/build-wasm-threads/bin/bb}")" && pwd)/$(basename "${BB_WASM:-bb}")
REF_WASM=${REF_WASM:-$PWD/target/wasm32-wasip1-threads/release/bb-ref.wasm}
BB_WASM_BENCH=${BB_WASM_BENCH:-}
: "${REPS:=1}"
: "${BB_RNG_SEED:=12345}"
: "${THREADS:=8}"
read -ra NODE_CMD <<< "${NODE:-node}"
export BB_RNG_SEED HARDWARE_CONCURRENCY=$THREADS RAYON_NUM_THREADS=$THREADS CRS_PATH=$HOME/.bb-crs
# bb-ref.wasm is linked with --max-memory=4GB (the biggest flow needs >1GB linear memory).
export WASM_MAX_PAGES=${WASM_MAX_PAGES:-65536}
tools/wasm_check.sh "$REF_WASM"

if [ $# -gt 0 ]; then FLOWS=("$@"); else
    FLOWS=()
    for d in "$FLOWS_DIR"/*/; do [ -f "$d/ivc-inputs.msgpack" ] && FLOWS+=("$(basename "$d")"); done
fi

OUT=$(mktemp -d)
trap 'rm -rf "$OUT"' EXIT

run_wasm() { # module inputs outdir extra-args... -> runs once; logs in $3.log
    case $RUNTIME in
    wasmtime)
        wasmtime run -S threads -W max-wasm-stack=8388608 --dir / \
            --env BB_RNG_SEED --env HARDWARE_CONCURRENCY --env RAYON_NUM_THREADS --env CRS_PATH --env BBREF_BENCH --env WASM_MAX_PAGES \
            "$1" prove --scheme chonk --ivc_inputs_path "$2" -o "$3" "${@:4}" >/dev/null 2>"$3.log" ;;
    v8)
        "${NODE_CMD[@]}" tools/runwasi_threads.mjs "$1" prove --scheme chonk --ivc_inputs_path "$2" -o "$3" "${@:4}" >/dev/null 2>"$3.log" ;;
    esac
}
prove_only() { # bb|ref module inputs outdir -> proving-only seconds
    if [ "$1" = bb ]; then
        [ -n "$BB_WASM_BENCH" ] || { echo "-"; return; }
        run_wasm "$BB_WASM_BENCH" "$3" "$4" --bench_out "$4.json" || { echo "-"; return; }
        bb_proving_from_json "$4.json"
    else
        BBREF_BENCH=1 run_wasm "$2" "$3" "$4" || { echo "-"; return; }
        ref_proving_from_log "$4.log"
    fi
}
# Proving-only seconds from one instrumented run of each prover, so a table can show wall and
# proving side by side. bb: `--bench_out` (BB_BENCH, native and ENABLE_WASM_BENCH builds) ->
# create_circuit + Chonk::accumulate + ChonkProve - ChonkVerifier::verify (bb self-verifies inside
# ChonkProve and counts witness decode outside create_circuit). bb-ref: BBREF_BENCH=1 ->
# create_circuit - create_circuit/decode_witness + Chonk::accumulate + ChonkProve.
bb_proving_from_json() { # json -> seconds
    python3 - "$1" <<'EOF'
import json, sys
d = {k: v / 1e9 for k, v in json.load(open(sys.argv[1])).items()}
print("%.3f" % (d.get("create_circuit", 0) + d.get("Chonk::accumulate", 0) + d.get("ChonkProve", 0) - d.get("ChonkVerifier::verify", 0)))
EOF
}
ref_proving_from_log() { # stderr log with the BBREF_BENCH flat table -> seconds
    awk '/^create_circuit /{c=$2} /^create_circuit\/decode_witness/{dw=$2} /^Chonk::accumulate /{a=$2} /^ChonkProve /{p=$2}
         END { gsub("s","",c); gsub("s","",dw); gsub("s","",a); gsub("s","",p); printf "%.3f\n", c - dw + a + p }' "$1"
}

run_one() { # binary inputs outdir -> "seconds maxrss_kb" (best wall of $REPS, max memory)
    best=""; mem=0
    for _ in $(seq "$REPS"); do
    case $RUNTIME in
    wasmtime)
        /usr/bin/time -f '%e %M' -o "$3.time" \
            wasmtime run -S threads -W max-wasm-stack=8388608 --dir / \
            --env BB_RNG_SEED --env HARDWARE_CONCURRENCY --env RAYON_NUM_THREADS --env CRS_PATH \
            "$1" prove --scheme chonk --ivc_inputs_path "$2" -o "$3" >/dev/null 2>"$3.log" \
            || { cat "$3.log" >&2; exit 1; } ;;
    v8)
        /usr/bin/time -f '%e %M' -o "$3.time" \
            "${NODE_CMD[@]}" tools/runwasi_threads.mjs "$1" prove --scheme chonk --ivc_inputs_path "$2" -o "$3" \
            >/dev/null 2>"$3.log" \
            || { cat "$3.log" >&2; exit 1; }
        # Replace host RSS with the wasm linear-memory peak reported by the harness.
        mem_kb=$(( $(grep -oE '\[wasm-mem\] [0-9]+' "$3.log" | tail -1 | grep -oE '[0-9]+') / 1024 ))
        sed -i "s/ [0-9]*\$/ $mem_kb/" "$3.time" ;;
    esac
    read -r t m < "$3.time"
    best=$(awk -v b="$best" -v t="$t" 'BEGIN { if (b == "" || t < b) print t; else print b }')
    mem=$(( m > mem ? m : mem ))
    done
    echo "$best $mem"
}

echo "runtime: $RUNTIME ($(case $RUNTIME in wasmtime) wasmtime --version ;; v8) echo "node $("${NODE_CMD[@]}" --version)${NODE_CMD[1]:+ ${NODE_CMD[*]:1}}" ;; esac)), threads: $THREADS (both provers), seed: $BB_RNG_SEED, flows: ${#FLOWS[@]}, wall = best of $REPS, proving = one instrumented run"
echo "date: $(date -u +%Y-%m-%d), host: $(hostname), bb module: $(basename "$BB_WASM") ($(stat -c %s "$BB_WASM" 2>/dev/null) bytes), bb bench module: ${BB_WASM_BENCH:-none}, bb-ref module: $(basename "$REF_WASM") ($(stat -c %s "$REF_WASM" 2>/dev/null) bytes), bb-ref: ${BBREF_COMMIT:-$(git rev-parse --short HEAD 2>/dev/null || echo unknown)}"
printf '%-62s %7s %7s %6s %7s %7s %6s %7s %7s %6s\n' flow "bb" "bb-ref" ratio "bb prv" "ref prv" ratio "bb mem" "ref mem" mem
total_bb=0; total_ref=0; total_bbp=0; total_refp=0
for flow in "${FLOWS[@]}"; do
    inputs=$FLOWS_DIR/$flow/ivc-inputs.msgpack
    mkdir -p "$OUT/bb" "$OUT/ref"
    read -r bb_s bb_kb <<< "$(run_one "$BB_WASM" "$inputs" "$OUT/bb")"
    read -r ref_s ref_kb <<< "$(run_one "$REF_WASM" "$inputs" "$OUT/ref")"
    bb_p=$(prove_only bb "$BB_WASM" "$inputs" "$OUT/bbp")
    ref_p=$(prove_only ref "$REF_WASM" "$inputs" "$OUT/refp")
    awk -v f="$flow" -v a="$bb_s" -v b="$ref_s" -v ap="$bb_p" -v bp="$ref_p" -v ak="$bb_kb" -v bk="$ref_kb" \
        'BEGIN { printf "%-62s %7.2f %7.2f %5.2fx %7s %7.2f %6s %6.2fG %6.2fG %5.2fx\n", f, a, b, b / a, ap, bp, (ap + 0 > 0 ? sprintf("%5.2fx", bp / ap) : "-"), ak / 1048576, bk / 1048576, bk / ak }'
    total_bb=$(awk -v t="$total_bb" -v a="$bb_s" 'BEGIN { printf "%.2f", t + a }')
    total_ref=$(awk -v t="$total_ref" -v a="$ref_s" 'BEGIN { printf "%.2f", t + a }')
    total_bbp=$(awk -v t="$total_bbp" -v a="$bb_p" 'BEGIN { printf "%.3f", t + (a + 0) }')
    total_refp=$(awk -v t="$total_refp" -v a="$ref_p" 'BEGIN { printf "%.3f", t + a }')
done
awk -v a="$total_bb" -v b="$total_ref" -v ap="$total_bbp" -v bp="$total_refp" \
    'BEGIN { printf "%-62s %7.2f %7.2f %5.2fx %7.2f %7.2f %5.2fx\n", "TOTAL", a, b, b / a, ap, bp, (ap > 0 ? bp / ap : 0) }'
