#!/usr/bin/env bash
# Build locally, push to the remote bench box, and run the standard perf probes there.
#
#   tools/remote_bench.sh [host]           # gates: one chonk flow + one rollup frame (~30s)
#   tools/remote_bench.sh [host] msm ...   # msmbench, extra args = log_n values (default 12 17 20)
#
# The host (default $BENCH_HOST or "bbbench") is an ssh alias to an idle machine provisioned with
# ~/bb-ref (bin/bb + tools), ~/chonk-pinned-flows, ~/PrivateTxBaseRollup.frame and ~/.bb-crs.
# Every remote run is capped at 60s: a probe that needs longer is a broken probe.
set -euo pipefail
cd "$(dirname "$0")/.."

HOST=${1:-${BENCH_HOST:-bbbench}}
MODE=${2:-gates}
R="timeout 60 env BB_RNG_SEED=12345 HARDWARE_CONCURRENCY=32 RAYON_NUM_THREADS=32"

case "$MODE" in
gates)
    cargo build --release --quiet
    rsync -az target/release/bb-ref "$HOST":bb-ref/target/push-bb-ref
    ssh "$HOST" "cd bb-ref && IN=\$HOME/chonk-pinned-flows/ecdsar1+transfer_0_recursions+sponsored_fpc/ivc-inputs.msgpack \
      && printf 'chonk flow: ' && $R /usr/bin/time -f '%es' ./target/push-bb-ref prove --scheme chonk --ivc_inputs_path \$IN -o /tmp/push_out 2>&1 >/dev/null | tail -1 \
      && printf 'PTBR frame: ' && $R /usr/bin/time -f '%es' ./target/push-bb-ref msgpack run --input \$HOME/PrivateTxBaseRollup.frame 2>&1 >/dev/null | tail -1"
    echo "references: bb chonk 1.79s, bb PTBR 8.53s (same box, 32 threads)"
    ;;
msm)
    cargo build --release --quiet --example msmbench
    rsync -az target/release/examples/msmbench "$HOST":bb-ref/msmbench
    shift 2 || true
    ssh "$HOST" "cd bb-ref && for ln in ${*:-12 17 20}; do $R ./msmbench \$ln 4; done 2>&1 | paste - -"
    ;;
*)
    echo "usage: remote_bench.sh [host] [gates|msm [log_n ...]]" >&2
    exit 2
    ;;
esac
