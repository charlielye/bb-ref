# Conformance

Where [oracle.md](oracle.md) describes the *development* microscope (per-polynomial trace
diffs against a dev pin), this describes the **conformance suite**, now built: anyone clones
this repo and mechanically verifies that bb-ref and barretenberg are bit-identical across the
proving stack. The commands are `tools/regen/regen_corpus.sh` (produce the corpus + goldens),
`tools/conformance.sh` (replay + byte-compare) and `tools/bench.sh` (timings); this document
records the design and its rationale. The dev oracles remain the divergence-hunting layer
underneath.

## The shape

1. **Pin = a released barretenberg**, downloaded by `bootstrap.sh` for tier 1. The same commit is
   available as the optional `pin/aztec-packages` submodule for tiers 2-3, currently tracking a
   branch until its three additions land upstream.

   *(historical framing:)* **Pin = a branch in aztec-packages, submoduled here.** The branch is an official
   nightly/release tag plus (temporarily) two commits: the bb server schema-gen migration
   and the deterministic-RNG env hook. As those land upstream the branch converges to a
   bare tag. bb-ref records the exact commit via the submodule (shallow clone); `pin/build.sh`
   builds bb, and nargo/acvm from the submodule's own noir submodule — the *conforming
   toolchain*, no system installs.
2. **One schema defines the surface.** `barretenberg/.../bbapi/bb_schema.json` (friendly
   ipc-codegen dialect, 64 commands) types the whole bb API. The conformance subset is the
   proving surface: `CircuitProve { circuit{name, bytecode, verification_key}, witness,
   settings{ipa_accumulation, oracle_hash_type, disable_zk} }`, `CircuitComputeVk`,
   `CircuitVerify`, and the `Chonk*` family; the rest answer "unsupported". bb's server is
   generated from this schema by `/ipc-codegen`; **bb-ref's is generated from the same
   schema** — `ipc-codegen --lang rust --server` emits a `Handler` trait, `dispatch()` and
   `handle_request(handler, bytes) -> Vec<u8>`, the exact analogue of bb's `make_bb_handler`,
   importing only the generated types (no transport dependency). One schema, two
   implementations, byte-identical wire format by construction.
   *(Generator gotcha: `generate.ts` dies under the documented `--experimental-strip-types`
   because of a TS parameter property; use `--experimental-transform-types`.)*
3. **Fixtures = one crafted rollup, captured whole.** The corpus is one coherent epoch —
   tx inputs through the private kernels to a Chonk proof, fed into crafted rollup shapes up
   to a single root — captured as an ordered stream of bb operations with their inputs and
   responses. A seeded e2e run already yields this for 12 of 13 in-scope circuits (see
   *Capture status*). Full coverage needs shapes a live chain cannot cut, which is the
   recipe-driven generator: jaws' `mkfixtures` method (committed real leaf txs + the chain
   state they are anchored to, replayed onto explicitly composed checkpoints) transcribed
   onto prover-client's orchestrator, whose `makeCheckpoint(numBlocks, {numTxsPerBlock, …})`
   sets shape directly with no cadence. jaws' recipe table is directly portable, including
   its second epoch that exists solely for `checkpoint_padding`.
4. **The corpus is a recorded wire stream, replayed over the real transport.** Capture tees
   the bytes between the prover stack and bb at the pipe/UDS layer — envelopes included — so
   the corpus is literally production traffic, `CircuitProve` frames carrying their own
   bytecode and witness, and `Chonk*` sequences recorded in the order the node issued them
   (no reconstruction, nothing to guess). Replay is a byte pump: feed the stream to
   `bb msgpack run -` (or a `.sock`), collect the response stream, repeat against bb-ref,
   compare. This works verbatim because the transport has no handshake and the envelope's
   request id is client-assigned and merely echoed on the response — so recorded ids replay
   as-is. Both sides therefore run the same `ipc-runtime` transports (bb-ref via the Rust
   crate's `IpcServer::from_path` over the same C++ bb uses), which is also what makes bb-ref
   droppable into the prover stack via `BB_BINARY_PATH`.

   *Capture must be a single sequential session*: the node runs several proving agents, so a
   naive tee interleaves connections and makes response ordering ambiguous. Record per
   connection (the tee has the client id) and/or pin the capture run to one agent. SHM has no
   byte stream to record, so capture belongs at pipe or UDS; replaying there exercises the
   same dispatch regardless.

## Determinism: seeds, not tapes

All bb randomness already routes through one engine (`numeric/random/engine.cpp`), which
even contains a seeded `DebugEngine` — but the switch is a *comment* ("uncomment the line
to return the debug engine"), not an env var. The RNG hook commit adds runtime selection
(`BB_UNSAFE_DETERMINISTIC_RNG=<seed>`-style: loud name, startup warning — it is a
production footgun by design). bb-ref mirrors the seeded engine bit-for-bit (`DebugRng`).
With both sides seeded, every response — ZK proofs, witness gap-fills, in-circuit masks,
the per-constraint arbitrary-valid draws — is bit-reproducible.

**Reproducibility is per-operation, and thread count is part of it.** Measured against bb at
the dev pin, seed fixed:

| operation class | 16 threads | 1 thread |
|---|---|---|
| non-ZK `ultra_honk` (the rollup tree) | **deterministic** | n/a — `rollup_root` (2²³) trips a slab-allocator bound at 1 thread |
| `ultra_honk` with ZK | **nondeterministic** (bb disagrees with itself) | deterministic |
| `chonk` (MegaZK + ECCVM + Translator masking) | **nondeterministic** | deterministic |

So ZK proving draws from parallel phases while non-ZK proving does not. The corpus therefore
carries a **per-operation thread policy in its manifest**, and the runner honours it: non-ZK
rollup operations run multithreaded (and `rollup_root` *must*), ZK and Chonk operations run at
concurrency 1 on both sides. Goldens for ZK operations must be generated single-threaded — the
node-captured Chonk artifacts from a multithreaded run are **not** golden-quality and need
regenerating; the non-ZK rollup artifacts are (verified: re-proving at the same seed reproduces
the node-captured proof, public inputs and VK byte-for-byte).

**Deliberately span both modes.** `--disable_zk` is the *rollup tree's* production setting, not a
corpus policy. Chonk operations already exercise most of the ZK machinery (the hiding kernel is
MegaZK, the ECCVM is always ZK, the Translator carries the Libra/small-subgroup-IPA masking), but
UltraZK — which bb-ref implements and claims byte-exactness for — appears nowhere in production
Aztec traffic, so the corpus must include ZK `CircuitProve` operations explicitly or that path
goes unverified.

Note also that only the *goldens* need determinism; the corpus inputs (bytecode + witness) are
static data.

Notes that will save someone a day:

- **Even non-ZK proofs are not replay-deterministic unseeded**: bb fills unconstrained
  witness-map gaps with `random_element()`, and those cells enter the witness commitments.
- **Seeding assumes draw-order determinism**: one global engine plus threads means
  interleaved draws, and for ZK proving that is not theoretical — see the table above.
- **Tapes are retired.** A recorded tape is just the PRNG stream; anything a tape enables
  (offset scanning, ledger analysis) works on the stream generated from the seed. Tapes
  were scaffolding for reproducing *unseeded* runs (the pre-seed-hook harvests) and go away
  with them.
- Until the seed hook is in the pinned branch, responses embedding randomness are compared
  at a weaker tier (structural + verifies-under-golden-VK); the manifest tags each
  response's tier so the suite tightens to bit-exact automatically.

## Phases

1. Submodule the pin branch (shallow) + `pin/build.sh`; rewire `tools/PIN`/regen/tests
   to derive from the submodule (keep an `AZTEC_REPO` override for dev boxes).
2. Generate the bb-ref server from `bb_schema.json` (separate thin crate; core stays
   IPC-free); wire handlers onto existing prove/write_vk/verify/chonk functions, and serve
   the `-`/`.sock`/`.shm` transports through the `ipc-runtime` Rust crate.
3. Corpus: capture a shaped epoch's wire stream (upstream tee, one sequential session);
   close the coverage gap with the recipe generator (real leaf txs + explicitly composed
   checkpoints).
4. The replay runner + CI: clone → submodule init → build → replay → bit-compare.
   Then the live transports, so bb-ref is droppable into the prover stack via
   `BB_BINARY_PATH` and can be run against e2e or jaws' lane-bench.
5. Upstream: the RNG env hook; landing the bbapi→ipc-codegen migration (the schema-gen
   branch); publishing `@aztec/ipc-codegen`. Each one shrinks the pin branch.

## The runner is also the benchmark

Replay walks the corpus frame by frame, so every run times every operation. Two modes over the
same corpus: **conformance** (seeded, manifest thread policy, single pass, byte-verdicts +
timings) and **bench** (unseeded, production thread counts, warmup + N reps, timings only — ZK
and Chonk operations get honest multithreaded numbers that the concurrency-1 conformance pass
cannot give). Reports are JSON plus a rendered table (frame, circuit, bb, bb-ref, ratio), so
bb-vs-bb-ref and pin-to-pin regressions are diffable. The chonk pinned flows (tools/flows/ (planned),
downloaded at bb's own hash) give benchmark parity with bb's chonk bench on identical inputs.

Diagnosis when a frame diverges: verdicts are per frame ("frame 37, CircuitProve
rollup_tx_merge, proof differs at byte N"), `--extract <n>` writes a self-contained one-frame
mini-corpus (bytecode + witness + settings) for a seconds-long repro loop, and beneath that the
dev microscope takes over (instance dump -> per-polynomial diff -> first divergent row -> op
tracers). Chonk frames are stateful: extraction takes the whole dependent sequence, whose
boundaries the manifest records.

## Three tiers of setup

Only the first is the common case; the other two exist so that heavier work is opt-in.

| tier | who | needs | how |
|---|---|---|---|
| **1. Verify bb-ref** | anyone with a clone | the corpus + goldens pair (`tools/corpus/*.zst`) | `tools/conformance.sh tools/corpus/rollup-<pin7>.corpus.zst` — replays bb-ref only, against the recorded bb answers |
| **2. Re-prove bb too** | anyone distrusting the goldens, or testing an unreleased bb | + a bb built from the `pin/aztec-packages` submodule | same, `--with-bb` |
| **3. Rebuild the corpus** | maintainers, once per pin | + the pin's labs workspace built, an AVM-capable bb, a ~15 min proving run | `tools/regen/regen_corpus.sh [--harvest]` |

Tier 1 needs no submodule, no C++ toolchain and no acvm: the goldens ARE bb's recorded answers, so
only bb-ref runs. Tier 3 is produce-only (harvest + drive + pack; it never replays) and works from
a clean checkout — the pinned tree carries nothing but reviewable commits.

*(Future: pin = a released bb tag with a downloaded binary, once the pin branch's commits land
upstream; the branch converges to a bare tag.)*

## The corpus

The recipe-driven generator (`tools/corpus/{harvest,driver}.ts`) composes exact epoch shapes over
real harvested leaf txs and proves them through ONE pooled bb behind the capture proxy: 62 frames
covering all 13 in-scope rollup circuits — including `checkpoint_padding`, which no live-chain
shape can reach (it needs an epoch holding exactly one checkpoint) and which the recipe's second
epoch exists solely to produce. Regeneration is deterministic in content (identical witnesses;
only job-dispatch order varies) and takes ~5 min of harvest (rare; only a protocol change
invalidates the leaf assets) plus ~11 min of proving.

## Open items

- Land the pin branch's commits upstream (BB_RNG_SEED, BB_RNG_COUNT, envelope file framing, the
  BB_POOL_SIZE labs patch, the dumper), converging the pin to a bare release tag with a
  downloadable binary.
- Extend the corpus beyond the private rollup path: public txs (AVM-adjacent frames stay
  replay-skipped), and the chonk wire sessions as a second recorded stream.
