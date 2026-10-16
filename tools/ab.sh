#!/usr/bin/env bash
# A/B kernel ladder: matched bb (C++) and bb-ref (Rust) wasm benches, run back to back on the
# idle bench box under the same node/V8. Each rung answers "is this layer at parity?" in seconds
# — iterate here, not on full flows.
#
#   tools/ab.sh l0          field kernels: scalar/packed mul-add-sub, pack, wrapper overhead
#   tools/ab.sh msm [log_n] Pippenger at 2^log_n (default 16), 8 threads
#   tools/ab.sh relations   relation-set accumulate per edge (bb relations_bench vs relbench)
#   tools/ab.sh bb <bench> [gbench args]   any bb bench binary, e.g. add_scaled_bench
#   tools/ab.sh ours <example> [args]      any bb-ref example
#
# Both sides run single-threaded unless the rung says otherwise. AB_HOST overrides the box.
set -euo pipefail
cd "$(dirname "$0")/.."

HOST=${AB_HOST:-bbbench}
BBBIN=pin/aztec-packages/barretenberg/cpp/build-wasm-threads/bin

build_ours() { # example name
    if ! cargo build --release --target wasm32-wasip1-threads --example "$1" >/tmp/ab-build.log 2>&1; then
        grep -E "^error" -A5 /tmp/ab-build.log >&2
        exit 1
    fi
    rsync -q --checksum "target/wasm32-wasip1-threads/release/examples/$1.wasm" "$HOST:ab-$1.wasm"
}
push_bb() { # bench binary name
    rsync -q --checksum "$BBBIN/$1" "$HOST:ab-$1.wasm"
}
run() { # threads wasm args...
    local threads=$1 wasm=$2
    shift 2
    ssh "$HOST" "export PATH=/usr/local/bin:\$PATH; cd ~/bb-ref; \
        RAYON_NUM_THREADS=$threads HARDWARE_CONCURRENCY=$threads BB_RNG_SEED=12345 CRS_PATH=\$HOME/.bb-crs \
        BBREF_MSMBENCH_NO_ARK=1 node --no-liftoff tools/runwasi_threads.mjs ~/ab-$wasm $* 2>/dev/null"
}

case "${1:?rung}" in
l0)
    build_ours fieldbench
    push_bb fr_bench
    push_bb vector_field_bench
    echo "=== ours (fieldbench) ==="
    run 1 fieldbench.wasm 8000000
    echo "=== bb fr_bench ==="
    run 1 fr_bench.wasm --benchmark_filter="${2:-.}" --benchmark_min_time=0.2s
    echo "=== bb vector_field_bench ==="
    run 1 vector_field_bench.wasm --benchmark_filter="${2:-.}" --benchmark_min_time=0.2s
    ;;
msm)
    build_ours msmbench
    push_bb pippenger_bench
    echo "=== ours 2^${2:-16} (8t) ==="
    run 8 msmbench.wasm "${2:-16}" 4
    echo "=== bb pippenger_bench (8t) ==="
    run 8 pippenger_bench.wasm --benchmark_filter=".*${2:-16}.*" --benchmark_min_time=0.2s
    ;;
relations)
    build_ours relbench
    push_bb relations_bench
    echo "=== ours (relbench) ==="
    run 1 relbench.wasm
    echo "=== bb relations_bench ==="
    run 1 relations_bench.wasm --benchmark_min_time=0.1s
    ;;
bb)
    push_bb "$2"
    run "${THREADS:-1}" "$2.wasm" "${@:3}"
    ;;
ours)
    build_ours "$2"
    run "${THREADS:-1}" "$2.wasm" "${@:3}"
    ;;
*)
    echo "unknown rung: $1" >&2
    exit 1
    ;;
esac
