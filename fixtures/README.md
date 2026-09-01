# fixtures

Three commands, in the order you use them.

```
regen_corpus.sh              rebuild the corpus from the pinned aztec-packages (~13 min)
conformance.sh <corpus>      replay it into bb and bb-ref; compare responses byte for byte
bench.sh <corpus> [binary]   replay it frame by frame and print per-operation timings
```

A **corpus** is the exact bytes a real prover sent to bb: `[u32 len][u64 request_id][payload]`
frames, recorded off a live proving run. bb and bb-ref both read that framing from a file, a pipe,
a socket or shared memory, so a corpus replays into either with nothing in between — no format of
our own, no rehydration step, and what we test is what the node actually sent.

| path | what it is |
|---|---|
| `PIN` | the aztec-packages commit everything is generated from |
| `corpus/driver.ts` | composes the recipe epochs and proves them through one pooled bb |
| `corpus/leaf-assets/` | real client-proven txs + the chain state they anchor to (regenerated rarely) |
| `corpus/*.corpus.zst` | the corpus itself; gitignored, ~83 MB |
| `lib/` | support: `replay.py` (list/diff/extract), `bench.py`, `bb_capture_proxy.py` (records a run) |
| `legacy/` | the per-milestone generators and `legacy/data/`, described below |

## Diagnosing a divergence

`conformance.sh` names the frame and command that differ and keeps both response streams.
`lib/replay.py --extract <corpus> <frame>` cuts that frame out on its own — usually a few hundred
KB against a 1.7 GB corpus — so the repro loop is seconds, not minutes. A frame that passes alone
but fails in sequence means the two sides are consuming the seeded RNG at different rates:
`BB_RNG_COUNT=1` (bb) and `BBREF_RNG_COUNT=1` (bb-ref) print draws per command, and comparing those
two sequences finds the first real mismatch directly.

## legacy/

The milestone-era fixtures: per-circuit dumps under `legacy/data/` (76 MB, committed) and the
`regen_*.sh` scripts that produce them. Around twenty `tests/m*.rs` and `tests/b*.rs` still read
them, which is the only reason they are here. They retire together once corpus replay is shown to
cover the same ground — do not add to them.
