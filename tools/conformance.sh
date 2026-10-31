#!/usr/bin/env bash
# Replay the pin's corpora through bb-ref and compare its responses with bb's, byte for byte.
#
#   tools/conformance.sh [corpus.zst] [--with-bb]
#
# With no corpus, every corpus of the pin (tools/corpus/{rollup,avm}-<pin7>): the full check. Each
# corpus is a recorded wire stream ([u32 len][u64 request_id][payload] frames) with bb's answers
# beside it (`.goldens.zst`); --with-bb re-proves through bb ($BB, default ./bin/bb, the pin's
# bb-avm) instead of reading them. bb-ref is built here with `--features bb-avm` (it needs
# libbb-avm-sim.a: ./pin/build.sh --avm-lib), or is $BBREF, which must have the AVM too. Anything
# missing fails. A difference is reported as the frame index and command that first diverged --
# `tools/lib/replay.py --extract N` cuts that frame (with the preceding frames of its connection,
# since Chonk sequences are stateful) into a standalone corpus for a fast repro loop.
set -euo pipefail
cd "$(dirname "$0")/.."

WITH_BB=false
CORPORA=()
for a in "$@"; do
    case $a in --with-bb) WITH_BB=true ;; *) CORPORA+=("$a") ;; esac
done
PIN7=$(cut -c1-7 tools/PIN)
[ ${#CORPORA[@]} -gt 0 ] || CORPORA=(tools/corpus/rollup-$PIN7.corpus.zst tools/corpus/avm-$PIN7.corpus.zst)
BB=${BB:-./bin/bb}
: "${BB_RNG_SEED:=12345}" # the corpus was recorded seeded; replays must match it
export BB_RNG_SEED
# Threads are deliberately NOT pinned. Non-ZK proving -- the whole rollup tree -- is
# thread-count independent, and forcing a thread count only exercises a configuration the
# recording never used. A corpus carrying ZK or Chonk proving does need the thread count it was
# recorded at (those masking draws are per-thread): set HARDWARE_CONCURRENCY to match it.

fail() { echo "conformance: $*" >&2; exit 1; }
for c in "${CORPORA[@]}"; do
    [ -f "$c" ] || fail "$c missing (tools/regen/regen_corpus.sh, tools/regen/regen_avm_corpus.sh)"
    $WITH_BB || [ -f "${c%.corpus.zst}.goldens.zst" ] || fail "${c%.corpus.zst}.goldens.zst missing"
done
if [ -z "${BBREF:-}" ]; then
    CARGO_TARGET_DIR=target/bb-avm cargo build -q --release --features bb-avm --bin bb-ref ||
        fail "bb-ref --features bb-avm did not build (libbb-avm-sim.a: ./pin/build.sh --avm-lib)"
    BBREF=target/bb-avm/release/bb-ref
fi
! grep -qa 'unsupported command: BbAvmProve' "$BBREF" || fail "$BBREF has no AVM: build it with --features bb-avm"
$WITH_BB && { [ -x "$BB" ] || fail "$BB missing (./pin/build.sh --avm)"; }

# Kept on divergence: the two streams ARE the evidence, and regenerating them costs minutes.
out=$(mktemp -d); trap 'rm -rf "$out"' EXIT
keep() { trap - EXIT; echo "streams kept in $out"; }
for CORPUS in "${CORPORA[@]}"; do
    echo "corpus:  $CORPUS"
    if $WITH_BB; then
        zstd -dcq "$CORPUS" | "$BB" msgpack run --input - > "$out/bb.resp" 2>"$out/bb.err" || {
            echo "bb failed:"; tail -3 "$out/bb.err"; exit 1; }
        # bb's AVM responses carry its stage timings; the goldens and bb-ref leave them empty.
        python3 tools/lib/avm_corpus.py goldens "$out/bb.norm" "$out/bb.resp" && mv "$out/bb.norm" "$out/bb.resp"
    else
        zstd -dcq "${CORPUS%.corpus.zst}.goldens.zst" > "$out/bb.resp"
    fi
    zstd -dcq "$CORPUS" | "$BBREF" msgpack run --input - > "$out/ref.resp" 2>"$out/ref.err" || {
        echo "bb-ref failed:"; tail -3 "$out/ref.err"; exit 1; }
    if ! cmp -s "$out/bb.resp" "$out/ref.resp"; then
        echo "DIVERGED:"
        python3 tools/lib/replay.py --diff "$CORPUS" "$out/bb.resp" "$out/ref.resp"
        keep
        exit 1
    fi
    echo "CONFORMANT: $(python3 tools/lib/replay.py --count "$out/bb.resp") responses byte-identical"
done
