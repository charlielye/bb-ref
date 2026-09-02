#!/usr/bin/env bash
# Time chonk (client IVC) proving, bb vs bb-ref side by side, over the pinned real transaction
# flows -- the same ivc-inputs.msgpack stacks bb's own benchmarks prove.
#
#   tools/bench_chonk.sh [flow ...] [--threads <n>]   # default: every flow in $BB_FLOWS
#
# Flows come from $BB_FLOWS (default: ../aztec-packages2/barretenberg/cpp/chonk-pinned-flows,
# where bb's TS harness writes them). Both binaries run the identical CLI command sequentially
# on pinned threads and seed, so rows are directly comparable:
#   bb     prove --scheme chonk --ivc_inputs_path <flow>/ivc-inputs.msgpack -o <tmp>
#   bb-ref prove --scheme chonk --ivc_inputs_path <flow>/ivc-inputs.msgpack -o <tmp>
set -euo pipefail
cd "$(dirname "$0")/.."

FLOWS_DIR=${BB_FLOWS:-../aztec-packages2/barretenberg/cpp/chonk-pinned-flows}
BB=./bin/bb
BBREF=${BBREF:-./target/release/bb-ref}

ARGS=()
THREADS_FLAG=""
while [ $# -gt 0 ]; do
    if [ "$1" = "--threads" ]; then
        THREADS_FLAG=${2:?--threads needs a value}
        shift 2
    else
        ARGS+=("$1")
        shift
    fi
done

[ -d "$FLOWS_DIR" ] || { echo "no flows at $FLOWS_DIR (set BB_FLOWS, or regenerate with dev/regen_chonk_flows.sh)" >&2; exit 1; }
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
: "${THREADS:=${THREADS_FLAG:-$(( $(nproc) < 32 ? $(nproc) : 32 ))}}"
export BB_RNG_SEED HARDWARE_CONCURRENCY=$THREADS RAYON_NUM_THREADS=$THREADS
echo "threads: $THREADS (both binaries), seed: $BB_RNG_SEED, flows: ${#FLOWS[@]}"

OUT=$(mktemp -d)
trap 'rm -rf "$OUT"' EXIT

# One unmeasured warmup per binary: SRS load and allocator growth must not bill the first flow.
warm=${FLOWS[0]}
"$BB" prove --scheme chonk --ivc_inputs_path "$FLOWS_DIR/$warm/ivc-inputs.msgpack" -o "$OUT/bb" > /dev/null 2>&1
"$BBREF" prove --scheme chonk --ivc_inputs_path "$FLOWS_DIR/$warm/ivc-inputs.msgpack" -o "$OUT/ref" > /dev/null 2>&1

time_one() { # binary inputs outdir -> seconds (logs kept quiet unless the run fails)
    local t0 t1
    t0=$(date +%s.%N)
    "$1" prove --scheme chonk --ivc_inputs_path "$2" -o "$3" > /dev/null 2> "$3.log" \
        || { cat "$3.log" >&2; exit 1; }
    t1=$(date +%s.%N)
    awk -v a="$t0" -v b="$t1" 'BEGIN { printf "%.2f", b - a }'
}

printf '%-58s %8s %8s %7s\n' flow bb bb-ref ratio
total_bb=0
total_ref=0
for flow in "${FLOWS[@]}"; do
    inputs=$FLOWS_DIR/$flow/ivc-inputs.msgpack
    [ -f "$inputs" ] || { echo "skipping $flow: no ivc-inputs.msgpack" >&2; continue; }
    bb_s=$(time_one "$BB" "$inputs" "$OUT/bb")
    ref_s=$(time_one "$BBREF" "$inputs" "$OUT/ref")
    awk -v f="$flow" -v a="$bb_s" -v b="$ref_s" \
        'BEGIN { printf "%-58s %8.2f %8.2f %6.2fx\n", f, a, b, b / a }'
    total_bb=$(awk -v t="$total_bb" -v a="$bb_s" 'BEGIN { printf "%.2f", t + a }')
    total_ref=$(awk -v t="$total_ref" -v a="$ref_s" 'BEGIN { printf "%.2f", t + a }')
done
awk -v a="$total_bb" -v b="$total_ref" \
    'BEGIN { printf "%-58s %8.2f %8.2f %6.2fx\n", "TOTAL", a, b, b / a }'
