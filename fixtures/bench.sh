#!/usr/bin/env bash
# Time every operation in a corpus against one server and print a per-circuit table.
#
#   fixtures/bench.sh <corpus[.zst]> [binary]        # defaults to ./bin/bb
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
export BB_RNG_SEED
# Unset for benchmarking: production thread counts are the point, unlike a conformance replay.
exec python3 fixtures/lib/bench.py "$CORPUS" "$BIN" "${@:3}"
