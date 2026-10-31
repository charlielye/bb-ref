[◄ bb-ref](../README.md)

# tools

The main commands, in the order you use them.

```
regen/regen_corpus.sh [--harvest]       rebuild the corpus from the pinned aztec-packages (~13 min once built)
conformance.sh <corpus> [bb] [--with-bb]  replay it into bb-ref against the recorded goldens (--with-bb re-proves bb too)
bench.sh <corpus> [bb|--both|--pair <bb> <bb-ref>] [--threads n]   per-operation timings, frame by frame
bench_chonk.sh [flow ...] [--threads n] [--reps n]   chonk (client IVC) proving over the pinned tx flows, bb vs bb-ref
```

Regeneration only *produces* the artifact (corpus + goldens); it never replays it — verification
belongs to conformance.sh and bench.sh alone.

A **corpus** is the exact bytes a real prover sent to bb: `[u32 len][u64 request_id][payload]`
frames, recorded off a live proving run. bb and bb-ref both read that framing from a file, a pipe,
a socket or shared memory, so a corpus replays into either with nothing in between — no format of
our own, no rehydration step, and what we test is what the node actually sent.

| path | what it is |
|---|---|
| `PIN` | the aztec-packages commit everything is generated from |
| `corpus/driver.ts` | composes the recipe epochs and proves them through one pooled bb |
| `corpus/harvest.ts` | proves the leaf assets (`regen_corpus.sh --harvest`, or when they are missing) |
| `corpus/leaf-assets/` | real client-proven txs + the chain state they anchor to; gitignored, regenerated rarely |
| `corpus/rollup-<pin7>.corpus.zst` | the corpus itself; gitignored, ~80 MB (1.6 GB raw) |
| `corpus/rollup-<pin7>.goldens.zst` | bb's recorded responses to it, committed: conformance replays only bb-ref |
| `corpus/avm-<pin7>.{corpus,goldens}.zst` | the AVM corpus (AvmProve, AvmCheckCircuit, AvmVerify of real and tampered proofs on recorded inputs), both committed; replays into a `--features bb-avm` build (`BBREF=… conformance.sh`) |
| `lib/` | support: `replay.py` (list/diff/extract), `bench.py`, `bb_capture_proxy.py` (records a run), `avm_corpus.py` (AVM corpus frames, normalized goldens) |
| `regen/` | all regenerators: `regen_corpus.sh`, `regen_avm_corpus.sh`, plus the `tests/data/` fixture generators (`regen_*.sh`, `env.sh`, `avm_dump.cpp`) |

## The rest

| script | what it does |
|---|---|
| `check.sh` | the standalone gate: warning-free build, unit tests with `tests/data` hidden |
| `coverage.sh` | line coverage of the standalone test set (report only) |
| `loc.sh [--no-tests]` | bb C++ (no AVM, no benchmarks) vs bb-ref Rust line counts |
| `build_time.sh` | from-scratch build times, bb vs bb-ref |
| `build_bb_ref_js.sh` | generate + build `js/bb-ref.js` (see [js/README.md](../js/README.md)) |
| `wasm_check.sh [module]` | fails a wasm module built without `.cargo/config.toml`'s wasm flags |
| `bench_chonk_wasm.sh wasmtime\|v8 [flow ...]` | `bench_chonk.sh` on wasm, under wasmtime or node |
| `runwasi_threads.mjs` | runs a wasip1-threads CLI under node (worker_threads, the browser shape) |
| `bench_tables.sh [table ...]` | regenerates `bench-results/` on the bench box |
| `ab.sh <rung>` | kernel-level A/B ladder, matched bb and bb-ref wasm benches on the bench box |
| `ab_chonk.sh name=path ...` | interleaved paired A/B of chonk binaries on the bench box, golden-gated |
| `remote_bench.sh [host] [gates\|msm]` | build, push, and run the quick perf probes on the bench box |
| `heap_agg.py` | a dhat heap profile (`--features heap-profile`) grouped by allocation site |
| `wasm_strip.py in.wasm out.wasm` | drops a wasm module's custom sections (how bb's module is compared) |

## Diagnosing a divergence

`conformance.sh` names the frame and command that differ and keeps both response streams.
`lib/replay.py --extract <corpus> <frame> [-o out]` cuts that frame out on its own (behind its
predecessors if a Chonk frame precedes it) — usually a few hundred KB against a 1.6 GB corpus — so
the repro loop is seconds, not minutes. A frame that passes alone
but fails in sequence means the two sides are consuming the seeded RNG at different rates:
`BB_RNG_COUNT=1` (bb) and `BBREF_RNG_COUNT=1` (bb-ref) print draws per command, and comparing those
two sequences finds the first real mismatch directly.
