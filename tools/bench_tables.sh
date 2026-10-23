#!/usr/bin/env bash
# Regenerate the tables of record in bench-results/ on the bench box, each run owning the machine.
#
#   tools/bench_tables.sh [table ...]     # default: all five
#
# Tables: native v8 wasmtime v8-wide rollup (bb-ref vs the pinned bb), written to
# bench-results/chonk-<table>.txt and bench-results/rollup.txt. v8-wide runs the wide-arithmetic
# module (`--cfg wasm_wide`, a second build) under a node with --wasm-wide-arithmetic ($NODE_WIDE), with
# bb unchanged: the speed-up waiting on engines shipping the proposal.
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
NODE_WIDE=${NODE_WIDE:-'$HOME/node27/bin/node'} # needs a node whose V8 has the proposal (27 nightly)
TABLES=("$@")
[ ${#TABLES[@]} -gt 0 ] || TABLES=(native v8 wasmtime v8-wide rollup)

cargo build --release --quiet --bin bb-ref
cargo build --profile lto --target wasm32-wasip1-threads --quiet --bin bb-ref
tools/wasm_check.sh target/wasm32-wasip1-threads/lto/bb-ref.wasm
COMMIT=$(git rev-parse --short HEAD)$(git diff --quiet HEAD -- src || echo +dirty)
PIN7=$(cut -c1-7 tools/PIN)
rsync -a --exclude corpus tools/ "${HOST}:bb-ref/tools/"
rsync -a target/release/bb-ref "${HOST}:bb-ref/tables-bb-ref"
rsync -a target/wasm32-wasip1-threads/lto/bb-ref.wasm "${HOST}:bb-ref/tables-bb-ref.wasm"
if [[ " ${TABLES[*]} " == *" v8-wide "* ]]; then
    # RUSTFLAGS replaces .cargo/config.toml's wasm flags, so they are all restated; its own target
    # dir keeps the default build's artifacts.
    RUSTFLAGS="-C target-feature=+simd128,+wide-arithmetic -C link-arg=--max-memory=4294967296 -C llvm-args=-max-store-memcpy=48 -C llvm-args=-max-store-memset=48 --cfg wasm_wide" \
        CARGO_TARGET_DIR=target/wide cargo build --profile lto --target wasm32-wasip1-threads --quiet --bin bb-ref 2>&1 |
        grep -v -e 'wide-arithmetic' -e 'not stably supported' -e '^ *|*$' -e '^warning: unstable feature' || true
    tools/wasm_check.sh target/wide/wasm32-wasip1-threads/lto/bb-ref.wasm
    rsync -a target/wide/wasm32-wasip1-threads/lto/bb-ref.wasm "${HOST}:bb-ref/tables-bb-ref-wide.wasm"
fi

WASM_NOTE="basis: bb wall from the stripped module (the release module carries a 100 MB name section that costs ~2% of wall to load); bb proving-only from its ENABLE_WASM_BENCH module via --bench_out"
remote() { # table -> the command that writes it
    local chonk="BBREF=\$HOME/bb-ref/tables-bb-ref tools/bench_chonk.sh --threads 8 --reps 3"
    local wasm="REPS=3 REF_WASM=\$HOME/bb-ref/tables-bb-ref.wasm tools/bench_chonk_wasm.sh"
    case $1 in
    native) echo "BB=$PIN_BB $chonk > bench-results/chonk-native.txt" ;;
    v8-wide)
        echo "{ echo '$WASM_NOTE'; echo 'bb-ref: the wide-arithmetic module (--cfg wasm_wide); bb: the same modules as chonk-v8.txt'; NODE=\"$NODE_WIDE --wasm-wide-arithmetic\" BB_WASM=$PIN_BB_WASM BB_WASM_BENCH=$PIN_BB_WASM_BENCH REF_WASM=\$HOME/bb-ref/tables-bb-ref-wide.wasm REPS=3 tools/bench_chonk_wasm.sh v8; } > bench-results/chonk-v8-wide.txt" ;;
    v8 | wasmtime) echo "{ echo '$WASM_NOTE'; BB_WASM=$PIN_BB_WASM BB_WASM_BENCH=$PIN_BB_WASM_BENCH $wasm $1; } > bench-results/chonk-$1.txt" ;;
    rollup) echo "{ echo \"rollup corpus rollup-$PIN7, sequential replay, 16 threads, seed 12345, \$(date -u +%Y-%m-%d), host \$(hostname), bb: pinned bb (\$($PIN_BB --version)), bb-ref: $COMMIT\"; tools/bench.sh tools/corpus/rollup-$PIN7.corpus.zst --pair $PIN_BB \$HOME/bb-ref/tables-bb-ref --threads 16; } > bench-results/rollup.txt" ;;
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
