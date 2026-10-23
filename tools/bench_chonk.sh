#!/usr/bin/env bash
# Time chonk (client IVC) proving, bb vs bb-ref side by side, over the pinned real transaction
# flows -- the same ivc-inputs.msgpack stacks bb's own benchmarks prove.
#
#   tools/bench_chonk.sh [flow ...] [--threads <n>] [--reps <n>]   # default: every flow in $BB_FLOWS
#
# Columns: wall (best of --reps runs, default 1) and proving-only (one instrumented run per prover;
# see bb_proving_from_json / ref_proving_from_log) with both ratios, plus peak RSS.
#
# Flows come from $BB_FLOWS (default: pin/aztec-packages/barretenberg/cpp/chonk-pinned-flows,
# where bb's TS harness writes them). Both binaries run the identical CLI command sequentially
# on pinned threads and seed, so rows are directly comparable:
#   bb     prove --scheme chonk --ivc_inputs_path <flow>/ivc-inputs.msgpack -o <tmp>
#   bb-ref prove --scheme chonk --ivc_inputs_path <flow>/ivc-inputs.msgpack -o <tmp>
set -euo pipefail
cd "$(dirname "$0")/.."

FLOWS_DIR=${BB_FLOWS:-pin/aztec-packages/barretenberg/cpp/chonk-pinned-flows}
BB=${BB:-./bin/bb}
BBREF=${BBREF:-./target/release/bb-ref}

ARGS=()
THREADS_FLAG=""
REPS=1
while [ $# -gt 0 ]; do
    if [ "$1" = "--threads" ]; then
        THREADS_FLAG=${2:?--threads needs a value}
        shift 2
    elif [ "$1" = "--reps" ]; then
        REPS=${2:?--reps needs a value}
        shift 2
    else
        ARGS+=("$1")
        shift
    fi
done

[ -d "$FLOWS_DIR" ] || { echo "no flows at $FLOWS_DIR (set BB_FLOWS, or regenerate with tools/regen/regen_chonk_flows.sh)" >&2; exit 1; }
[ -x "$BB" ] || { echo "no bb at $BB (run tools/regen/regen_corpus.sh to build the pin)" >&2; exit 1; }
[ "$BBREF" != ./target/release/bb-ref ] || cargo build --release --quiet

if [ ${#ARGS[@]} -gt 0 ]; then
    FLOWS=("${ARGS[@]}")
else
    FLOWS=()
    for d in "$FLOWS_DIR"/*/; do
        [ -f "$d/ivc-inputs.msgpack" ] && FLOWS+=("$(basename "$d")")
    done
fi

: "${BB_RNG_SEED:=12345}"
: "${THREADS:=${THREADS_FLAG:-8}}"  # chonk is the client-side prover: 8 threads is the profile that matters
export BB_RNG_SEED HARDWARE_CONCURRENCY=$THREADS RAYON_NUM_THREADS=$THREADS
echo "threads: $THREADS (both binaries), seed: $BB_RNG_SEED, flows: ${#FLOWS[@]}, wall = best of $REPS, proving = one instrumented run"
echo "date: $(date -u +%Y-%m-%d), host: $(hostname), bb: $BB ($("$BB" --version 2>/dev/null | head -1)), bb-ref: $BBREF (${BBREF_COMMIT:-$(git rev-parse --short HEAD 2>/dev/null || echo unknown)})"

OUT=$(mktemp -d)
trap 'rm -rf "$OUT"' EXIT

# One unmeasured warmup per binary: SRS load and allocator growth must not bill the first flow.
warm=${FLOWS[0]}
"$BB" prove --scheme chonk --ivc_inputs_path "$FLOWS_DIR/$warm/ivc-inputs.msgpack" -o "$OUT/bb" > /dev/null 2>&1
"$BBREF" prove --scheme chonk --ivc_inputs_path "$FLOWS_DIR/$warm/ivc-inputs.msgpack" -o "$OUT/ref" > /dev/null 2>&1

time_one() { # binary inputs outdir -> "seconds maxrss_kb": best wall of $REPS runs, max RSS
    best=""; rss=0
    for _ in $(seq "$REPS"); do
        /usr/bin/time -f '%e %M' -o "$3.time" \
            "$1" prove --scheme chonk --ivc_inputs_path "$2" -o "$3" > /dev/null 2> "$3.log" \
            || { cat "$3.log" >&2; exit 1; }
        read -r t m < "$3.time"
        best=$(awk -v b="$best" -v t="$t" 'BEGIN { if (b == "" || t < b) print t; else print b }')
        rss=$(( m > rss ? m : rss ))
    done
    echo "$best $rss"
}
prove_only() { # bb|ref binary inputs outdir -> proving-only seconds
    if [ "$1" = bb ]; then
        "$2" prove --scheme chonk --ivc_inputs_path "$3" -o "$4" --bench_out "$4.json" > /dev/null 2>&1 || { echo "-"; return; }
        bb_proving_from_json "$4.json"
    else
        BBREF_BENCH=1 "$2" prove --scheme chonk --ivc_inputs_path "$3" -o "$4" > /dev/null 2> "$4.bench" || { echo "-"; return; }
        ref_proving_from_log "$4.bench"
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
print("%.3f" % (d.get("create_circuit", d.get("create_mega_circuit", 0)) + d.get("Chonk::accumulate", 0) + d.get("ChonkProve", 0) - d.get("ChonkVerifier::verify", 0)))
EOF
}
ref_proving_from_log() { # stderr log with the BBREF_BENCH flat table -> seconds
    awk '/^create_circuit /{c=$2} /^create_circuit\/decode_witness/{dw=$2} /^Chonk::accumulate /{a=$2} /^ChonkProve /{p=$2}
         END { gsub("s","",c); gsub("s","",dw); gsub("s","",a); gsub("s","",p); printf "%.3f\n", c - dw + a + p }' "$1"
}


printf '%-62s %7s %7s %6s %7s %7s %6s %7s %7s %6s\n' flow "bb" "bb-ref" ratio "bb prv" "ref prv" ratio "bb rss" "ref rss" mem
total_bb=0; total_ref=0; total_bbp=0; total_refp=0
for flow in "${FLOWS[@]}"; do
    inputs=$FLOWS_DIR/$flow/ivc-inputs.msgpack
    [ -f "$inputs" ] || { echo "skipping $flow: no ivc-inputs.msgpack" >&2; continue; }
    read -r bb_s bb_kb <<< "$(time_one "$BB" "$inputs" "$OUT/bb")"
    read -r ref_s ref_kb <<< "$(time_one "$BBREF" "$inputs" "$OUT/ref")"
    bb_p=$(prove_only bb "$BB" "$inputs" "$OUT/bb")
    ref_p=$(prove_only ref "$BBREF" "$inputs" "$OUT/ref")
    awk -v f="$flow" -v a="$bb_s" -v b="$ref_s" -v ap="$bb_p" -v bp="$ref_p" -v ak="$bb_kb" -v bk="$ref_kb" \
        'BEGIN { printf "%-62s %7.2f %7.2f %5.2fx %7.2f %7.2f %5.2fx %6.2fG %6.2fG %5.2fx\n", f, a, b, b / a, ap, bp, (ap > 0 ? bp / ap : 0), ak / 1048576, bk / 1048576, bk / ak }'
    total_bb=$(awk -v t="$total_bb" -v a="$bb_s" 'BEGIN { printf "%.2f", t + a }')
    total_ref=$(awk -v t="$total_ref" -v a="$ref_s" 'BEGIN { printf "%.2f", t + a }')
    total_bbp=$(awk -v t="$total_bbp" -v a="$bb_p" 'BEGIN { printf "%.3f", t + a }')
    total_refp=$(awk -v t="$total_refp" -v a="$ref_p" 'BEGIN { printf "%.3f", t + a }')
done
awk -v a="$total_bb" -v b="$total_ref" -v ap="$total_bbp" -v bp="$total_refp" \
    'BEGIN { printf "%-62s %7.2f %7.2f %5.2fx %7.2f %7.2f %5.2fx\n", "TOTAL", a, b, b / a, ap, bp, bp / ap }'
