#!/usr/bin/env bash
# Time every operation in a corpus against one server and print a per-circuit table.
#
#   tools/bench.sh <corpus[.zst]> [binary]        # defaults to ./bin/bb
#
# The corpus is real recorded traffic, so this measures the operations a prover actually performs,
# in the proportions it performs them -- a rollup benchmark that needs no separate harness. Run it
# against bb and against bb-ref for a directly comparable pair; the corpus, seed and thread policy
# are identical by construction.
#
# Timing comes from the replay driver rather than the server's own logs so that both servers are
# measured the same way: it writes one frame, waits for that response, and records the interval.
set -euo pipefail
cd "$(dirname "$0")/.."

CORPUS=${1:?usage: bench.sh <corpus[.zst]> [binary]}
BIN=${2:-./bin/bb}
: "${BB_RNG_SEED:=12345}"
# The two binaries default to DIFFERENT thread caps (bb: min(32, cores); bb-ref: rayon min(48,
# cores)), so a fair comparison pins both to one explicit count. THREADS=<n> overrides; 32 is
# bb's production default cap.
: "${THREADS:=32}"
export BB_RNG_SEED HARDWARE_CONCURRENCY=$THREADS RAYON_NUM_THREADS=$THREADS
echo "threads: $THREADS (both binaries)"
exec python3 tools/lib/bench.py "$CORPUS" "$BIN" "${@:3}"
