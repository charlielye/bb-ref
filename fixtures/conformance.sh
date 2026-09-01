#!/usr/bin/env bash
# Replay a corpus through bb and through bb-ref and compare their response streams.
#
#   fixtures/conformance.sh <corpus.zst|corpus> [bb-binary]
#
# The corpus is a recorded wire stream ([u32 len][u64 request_id][payload] frames); both servers
# read that framing from a file or stdin, so the check is a pipe into each and a byte compare of
# what comes back. A difference is reported as the frame index and command that first diverged --
# `fixtures/lib/replay.py --extract N` cuts that frame (with the preceding frames of its connection,
# since Chonk sequences are stateful) into a standalone corpus for a fast repro loop.
set -euo pipefail
cd "$(dirname "$0")/.."

CORPUS=${1:?usage: conformance.sh <corpus[.zst]> [bb-binary]}
BB=${2:-./bin/bb}
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
echo "bb:      $BB"
decompress | "$BB" msgpack run --input - > "$out/bb.resp" 2>"$out/bb.err" || {
    echo "bb failed:"; tail -3 "$out/bb.err"; exit 1; }
decompress | ./target/release/bb-ref msgpack run --input - > "$out/ref.resp" 2>"$out/ref.err" || {
    echo "bb-ref failed:"; tail -3 "$out/ref.err"; exit 1; }

if cmp -s "$out/bb.resp" "$out/ref.resp"; then
    echo "CONFORMANT: $(python3 fixtures/lib/replay.py --count "$out/bb.resp") responses byte-identical"
else
    echo "DIVERGED:"
    python3 fixtures/lib/replay.py --diff "$CORPUS" "$out/bb.resp" "$out/ref.resp"
    keep
    exit 1
fi
