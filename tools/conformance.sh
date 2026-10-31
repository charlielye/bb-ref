#!/usr/bin/env bash
# Replay a corpus through bb and through bb-ref and compare their response streams.
#
#   tools/conformance.sh <corpus.zst|corpus> [bb-binary]
#
# The corpus is a recorded wire stream ([u32 len][u64 request_id][payload] frames); both servers
# read that framing from a file or stdin, so the check is a pipe into each and a byte compare of
# what comes back. A difference is reported as the frame index and command that first diverged --
# `tools/lib/replay.py --extract N` cuts that frame (with the preceding frames of its connection,
# since Chonk sequences are stateful) into a standalone corpus for a fast repro loop.
set -euo pipefail
cd "$(dirname "$0")/.."

CORPUS=${1:?usage: conformance.sh <corpus[.zst]> [bb-binary]}
BB=${2:-./bin/bb}
# The AVM corpus needs a `--features bb-avm` build.
BBREF=${BBREF:-./target/release/bb-ref}
: "${BB_RNG_SEED:=12345}" # the corpus was recorded seeded; replays must match it
export BB_RNG_SEED
# Threads are deliberately NOT pinned. Non-ZK proving -- the whole rollup tree -- is
# thread-count independent, and forcing a thread count only exercises a configuration the
# recording never used. A corpus carrying ZK or Chonk proving does need the thread count it was
# recorded at (those masking draws are per-thread): set HARDWARE_CONCURRENCY to match it.

decompress() { case "$CORPUS" in *.zst) zstd -dcq "$CORPUS";; *) cat "$CORPUS";; esac; }

# Kept on divergence: the two streams ARE the evidence, and regenerating them costs minutes.
out=$(mktemp -d); trap 'rm -rf "$out"' EXIT
keep() { trap - EXIT; echo "streams kept in $out"; }
echo "corpus:  $CORPUS"
# Fast path: a goldens file recorded at capture time is bb's answer to these exact frames, so only
# bb-ref needs to run. Pass --with-bb (or delete the goldens) to re-prove through bb as well.
GOLDENS=${CORPUS%.corpus.zst}.goldens.zst
if [ -f "$GOLDENS" ] && [ "${3:-}" != "--with-bb" ]; then
    echo "goldens: $GOLDENS (bb replay skipped; --with-bb forces it)"
    decompress | "$BBREF" msgpack run --input - > "$out/ref.resp" 2>"$out/ref.err" || {
        echo "bb-ref failed:"; tail -3 "$out/ref.err"; exit 1; }
    zstd -dcq "$GOLDENS" > "$out/bb.resp"
    if cmp -s "$out/bb.resp" "$out/ref.resp"; then
        echo "CONFORMANT: $(python3 tools/lib/replay.py --count "$out/bb.resp") responses byte-identical"
        exit 0
    fi
    echo "DIVERGED:"
    python3 tools/lib/replay.py --diff "$CORPUS" "$out/bb.resp" "$out/ref.resp"
    keep
    exit 1
fi
echo "bb:      $BB"
decompress | "$BB" msgpack run --input - > "$out/bb.resp" 2>"$out/bb.err" || {
    echo "bb failed:"; tail -3 "$out/bb.err"; exit 1; }
# bb's AVM responses carry its stage timings; the goldens and bb-ref leave them empty.
python3 tools/lib/avm_corpus.py goldens "$out/bb.norm" "$out/bb.resp" && mv "$out/bb.norm" "$out/bb.resp"
decompress | "$BBREF" msgpack run --input - > "$out/ref.resp" 2>"$out/ref.err" || {
    echo "bb-ref failed:"; tail -3 "$out/ref.err"; exit 1; }

if cmp -s "$out/bb.resp" "$out/ref.resp"; then
    echo "CONFORMANT: $(python3 tools/lib/replay.py --count "$out/bb.resp") responses byte-identical"
else
    echo "DIVERGED:"
    python3 tools/lib/replay.py --diff "$CORPUS" "$out/bb.resp" "$out/ref.resp"
    keep
    exit 1
fi
