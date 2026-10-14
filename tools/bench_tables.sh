#!/usr/bin/env bash
# Regenerate the tables of record in bench-results/ on the bench box, each run owning the machine.
#
#   tools/bench_tables.sh [table ...]     # default: all seven
#
# Tables: native v8 wasmtime rollup (bb-ref vs the pinned bb) and golf-native golf-v8 golf-wasmtime
# (bb-ref vs the chonk-golf-patched bb, a temporary state-of-the-art reference; same format), written
# to bench-results/chonk-<table>.txt and bench-results/rollup.txt.
#
# Builds bb-ref natively and as the lto wasm module, pushes them and tools/ to $BENCH_HOST (default
# bbbench) under ~/bb-ref, runs there under flock ~/bench.lock, and copies the tables back. The box
# holds the reference binaries; override their paths with the variables below.
set -euo pipefail
cd "$(dirname "$0")/.."

HOST=${BENCH_HOST:-bbbench}
PIN_BB=${PIN_BB:-'~/bb-ref/bin/bb'}
PIN_BB_WASM=${PIN_BB_WASM:-'~/bb-stripped.wasm'}
PIN_BB_WASM_BENCH=${PIN_BB_WASM_BENCH:-'~/bench-bb.wasm'}
GOLF_BB=${GOLF_BB:-'~/ab-bin/golf'}
GOLF_BB_WASM=${GOLF_BB_WASM:-'~/ab-bin/p0-golfbb-stripped.1fbe2899ea80.wasm'}
GOLF_BB_WASM_BENCH=${GOLF_BB_WASM_BENCH:-'~/ab-bin/p0-golfbb-bench.97c6a1f7c850.wasm'}
TABLES=("$@")
[ ${#TABLES[@]} -gt 0 ] || TABLES=(native v8 wasmtime rollup golf-native golf-v8 golf-wasmtime)

cargo build --release --quiet --bin bb-ref
cargo build --profile lto --target wasm32-wasip1-threads --quiet --bin bb-ref
tools/wasm_check.sh target/wasm32-wasip1-threads/lto/bb-ref.wasm
COMMIT=$(git rev-parse --short HEAD)$(git diff --quiet HEAD -- src || echo +dirty)
rsync -a --exclude corpus tools/ "${HOST}:bb-ref/tools/"
rsync -a target/release/bb-ref "${HOST}:bb-ref/tables-bb-ref"
rsync -a target/wasm32-wasip1-threads/lto/bb-ref.wasm "${HOST}:bb-ref/tables-bb-ref.wasm"

GOLF_NOTE="bb = chonk-golf final2 (the pinned bb plus the chonk-golf patch series): a temporary state-of-the-art reference"
WASM_NOTE="basis: bb wall from the stripped module (the release module carries a 100 MB name section that costs ~2% of wall to load); bb proving-only from its ENABLE_WASM_BENCH module via --bench_out"
remote() { # table -> the command that writes it
    local chonk="BBREF=\$HOME/bb-ref/tables-bb-ref tools/bench_chonk.sh --threads 8 --reps 3"
    local wasm="REPS=3 REF_WASM=\$HOME/bb-ref/tables-bb-ref.wasm tools/bench_chonk_wasm.sh"
    case $1 in
    native) echo "BB=$PIN_BB $chonk > bench-results/chonk-native.txt" ;;
    golf-native) echo "{ echo '$GOLF_NOTE'; BB=$GOLF_BB $chonk; } > bench-results/chonk-golf-native.txt" ;;
    v8 | wasmtime) echo "{ echo '$WASM_NOTE'; BB_WASM=$PIN_BB_WASM BB_WASM_BENCH=$PIN_BB_WASM_BENCH $wasm $1; } > bench-results/chonk-$1.txt" ;;
    golf-v8 | golf-wasmtime)
        echo "{ echo '$GOLF_NOTE'; echo '$WASM_NOTE'; BB_WASM=$GOLF_BB_WASM BB_WASM_BENCH=$GOLF_BB_WASM_BENCH $wasm ${1#golf-}; } > bench-results/chonk-$1.txt" ;;
    rollup) echo "{ echo \"rollup corpus rollup-3b2c553, sequential replay, 16 threads, seed 12345, \$(date -u +%Y-%m-%d), host \$(hostname), bb: pinned bb (\$($PIN_BB --version)), bb-ref: $COMMIT\"; tools/bench.sh tools/corpus/rollup-3b2c553.corpus.zst --pair $PIN_BB \$HOME/bb-ref/tables-bb-ref --threads 16; } > bench-results/rollup.txt" ;;
    *) echo "unknown table: $1" >&2; exit 2 ;;
    esac
}
for t in "${TABLES[@]}"; do
    echo "== $t $(date -u +%T)"
    ssh "$HOST" "cd ~/bb-ref && mkdir -p bench-results && export PATH=\$HOME/.wasmtime/bin:/usr/local/bin:\$PATH BB_FLOWS=\$HOME/chonk-pinned-flows BBREF_COMMIT=$COMMIT && flock ~/bench.lock bash -c $(printf %q "$(remote "$t")")"
    f=$([ "$t" = rollup ] && echo rollup.txt || echo "chonk-$t.txt")
    rsync -a "${HOST}:bb-ref/bench-results/$f" bench-results/
    tail -1 "bench-results/$f"
done
