[◄ bb-ref](../README.md)

# Conformance

Where [oracle.md](oracle.md) describes the *development* microscope (per-polynomial trace
diffs against the pin), this describes the **conformance suite**: anyone mechanically verifies
that bb-ref and barretenberg are bit-identical across the proving stack. The commands are `tools/regen/regen_corpus.sh` (produce the corpus + goldens),
`tools/conformance.sh` (replay + byte-compare) and `tools/bench.sh` (timings); this document
records the design and its rationale. The dev oracles remain the divergence-hunting layer
underneath.

## The shape

1. **Pin = a branch in aztec-packages, submoduled here** (`pin/aztec-packages`, shallow, branch
   `cl/bb-ref-conformance`): bb's `next` plus the bb.js-api PR (aztec-packages#25433) and the
   test-support commits listed under *Open items*. As those land upstream the branch converges to a
   bare release tag, which `pin/VERSION` will name so `bootstrap.sh` can download it; until then
   `pin/VERSION` is empty and `pin/build.sh` builds bb (and, with `--noir`, nargo/noir-execute from
   the submodule's own noir) — the *conforming toolchain*, no system installs.
2. **One schema defines the surface.** `barretenberg/.../bbapi/bb_schema.json` (friendly
   ipc-codegen dialect, 65 commands) types the whole bb API. bb-ref serves the proving surface:
   `CircuitProve { circuit{name, bytecode, verification_key}, witness,
   settings{ipa_accumulation, oracle_hash_type, disable_zk} }`, `CircuitComputeVk`,
   `CircuitVerify`, the Chonk session (`ChonkStart/Load/Accumulate/Prove/Verify/ComputeVk`,
   proof compression), the VK-as-fields and Poseidon2 helpers, `Init` and SRS init; the rest
   (AVM, other crypto helpers, batch verification, Solidity) answer "unsupported command".
   With `--features bb-avm` the AVM commands run bb's simulation and trace generation linked
   in-process, and bb-ref proves and verifies (`src/msgpack/bb_avm.rs`). Circuits that verify an AVM proof (the public tx base rollup) are
   bb-ref's own in every build.
   bb's server is generated from this schema by `/ipc-codegen`; **bb-ref's is generated from
   the same schema** — `ipc-codegen --lang rust --server` emits a `Handler` trait, `dispatch()` and
   `handle_request(handler, bytes) -> Vec<u8>`, the exact analogue of bb's `make_bb_handler`,
   importing only the generated types (no transport dependency). One schema, two
   implementations, byte-identical wire format by construction (`dev/regen_msgpack.sh`
   regenerates `src/msgpack/generated/`).
3. **Fixtures = one crafted rollup, captured whole.** The corpus is one coherent epoch —
   real client-proven leaf txs fed into crafted rollup shapes up to a single root — captured as an ordered stream of bb operations with their inputs and
   responses. Full coverage needs shapes a live chain cannot cut, hence the recipe-driven
   generator (*The corpus*, below): jaws' `mkfixtures` method (committed real leaf txs + the chain
   state they are anchored to, replayed onto explicitly composed checkpoints) transcribed
   onto prover-client's orchestrator, whose `makeCheckpoint(numBlocks, {numTxsPerBlock, …})`
   sets shape directly with no cadence. jaws' recipe table is directly portable, including
   its second epoch that exists solely for `checkpoint_padding`.
4. **The corpus is a recorded wire stream.** Capture (`tools/lib/bb_capture_proxy.py`, interposed
   as `BB_BINARY_PATH`) tees the bytes between the prover stack and bb on its UDS — envelopes
   included — so the corpus is literally production traffic, `CircuitProve` frames carrying
   their own bytecode and witness, and any `Chonk*` sequences recorded in the order the node issued them
   (no reconstruction, nothing to guess). Replay is a byte pump: feed the stream to
   `bb msgpack run --input -` and `bb-ref msgpack run --input -`, compare the response streams.
   This works verbatim because the transport has no handshake and the envelope's request id is
   client-assigned and merely echoed on the response — so recorded ids replay as-is. bb-ref
   serves only that file/stdin mode today; serving `.sock`/SHM (what the node spawns, and so
   what dropping bb-ref in via `BB_BINARY_PATH` needs) is open.

   *Capture must be a single sequential session*: with several requests in flight, response
   order is nondeterministic even against one bb. The proxy records per connection, and the
   capture run uses one pooled bb (`BB_POOL_SIZE=1`). SHM has no byte stream to record, so
   capture is at the UDS; replay exercises the same dispatch regardless.

## Determinism: seeds, not tapes

All bb randomness already routes through one engine (`numeric/random/engine.cpp`), which
even contains a seeded `DebugEngine` — but the switch is a *comment* ("uncomment the line
to return the debug engine"), not an env var. The pin branch's hook adds runtime selection
(`BB_RNG_SEED=<u64>`, with a loud startup warning — it is a production footgun by design).
bb-ref mirrors the seeded engine bit-for-bit (`DebugRng`).
With both sides seeded, every response — ZK proofs, witness gap-fills, in-circuit masks,
the per-constraint arbitrary-valid draws — is bit-reproducible.

**Reproducibility is per-operation, and thread count is part of it.** Measured against bb at
the dev pin, seed fixed:

| operation class | 16 threads | 1 thread |
|---|---|---|
| non-ZK `ultra_honk` (the rollup tree) | **deterministic** | n/a — `rollup_root` (2²³) trips a slab-allocator bound at 1 thread |
| `ultra_honk` with ZK | **nondeterministic** (bb disagrees with itself) | deterministic |
| `chonk` (MegaZK + ECCVM + Translator masking) | **nondeterministic** | deterministic |

So ZK proving draws from parallel phases while non-ZK proving does not. The current corpus is the
non-ZK rollup tree only, so `conformance.sh` leaves threads unpinned (and `rollup_root` *must* run
multithreaded); a corpus carrying ZK or Chonk operations needs them at the thread count they were
recorded at (`HARDWARE_CONCURRENCY`), and their goldens generated single-threaded — the fixture
regens prove Chonk and ZK at `HARDWARE_CONCURRENCY=1`. The non-ZK rollup goldens are
golden-quality (verified: re-proving at the same seed reproduces the node-captured proof, public
inputs and VK byte-for-byte).

**Deliberately span both modes.** `--disable_zk` is the *rollup tree's* production setting, not a
corpus policy. Chonk operations already exercise most of the ZK machinery (the hiding kernel is
MegaZK, the ECCVM is always ZK, the Translator carries the Libra/small-subgroup-IPA masking), but
UltraZK — which bb-ref implements and claims byte-exactness for — appears nowhere in production
Aztec traffic, so the corpus must include ZK `CircuitProve` operations explicitly or that path
goes unverified by it (today the differential fixtures cover it).

Note also that only the *goldens* need determinism; the corpus inputs (bytecode + witness) are
static data.

Notes that will save someone a day:

- **Even non-ZK proofs are not replay-deterministic unseeded**: bb fills unconstrained
  witness-map gaps with `random_element()`, and those cells enter the witness commitments.
- **Seeding assumes draw-order determinism**: one global engine plus threads means
  interleaved draws, and for ZK proving that is not theoretical — see the table above.
- **The corpus uses seeds, not tapes.** A recorded tape is just the PRNG stream; anything a tape
  enables (offset scanning, ledger analysis) works on the stream generated from the seed. Tapes
  (`BB_RNG_TAPE_OUT`/`_IN`) survive only in some fixture regens.

## The runner is also the benchmark

The same corpus drives `tools/bench.sh`: one frame at a time, seeded, both binaries pinned to one
thread count (`min(32, cores)`, `--threads` overrides), a per-circuit timing table for bb, bb-ref
or both (`--both`, `--pair`). Chonk proving is benched separately over bb's pinned flows
(`tools/bench_chonk.sh`, the same inputs as bb's chonk bench).

Diagnosis when a frame diverges: `conformance.sh` names the first divergent frame and command and
keeps both response streams; `tools/lib/replay.py --extract <corpus> <n> -o <out>` cuts that frame
into a standalone corpus (KBs, not GBs) for a seconds-long repro loop, and beneath that the dev
microscope takes over (instance dump -> per-polynomial diff -> first divergent row -> op tracers).
Chonk frames are stateful: extraction keeps every preceding frame. A frame that passes alone but
fails in sequence is an RNG-rate mismatch: `BB_RNG_COUNT=1` / `BBREF_RNG_COUNT=1` print draws per
command on each side.

## Three tiers of setup

Only the first is the common case; the other two exist so that heavier work is opt-in.

| tier | who | needs | how |
|---|---|---|---|
| **1. Verify bb-ref** | anyone with the corpus | the corpus + goldens pair (`tools/corpus/rollup-<pin7>.{corpus,goldens}.zst`; goldens committed, the ~80 MB corpus gitignored) | `tools/conformance.sh tools/corpus/rollup-<pin7>.corpus.zst` — replays bb-ref only, against the recorded bb answers |
| **2. Re-prove bb too** | anyone distrusting the goldens, or testing an unreleased bb | + a bb built from the `pin/aztec-packages` submodule | `tools/conformance.sh <corpus> ./bin/bb --with-bb` |
| **3. Rebuild the corpus** | maintainers, once per pin | + the pin's labs workspace built, an AVM-capable bb, ~13 min | `tools/regen/regen_corpus.sh [--harvest]` |

Tier 1 needs no submodule, no C++ toolchain and no noir: the goldens ARE bb's recorded answers, so
only bb-ref runs. Tier 3 is produce-only (harvest + drive + pack; it never replays) and works from
a clean checkout — the pinned tree carries nothing but reviewable commits.

## The corpus

The recipe-driven generator (`tools/corpus/{harvest,driver}.ts`) composes exact epoch shapes over
real harvested leaf txs and proves them through ONE pooled bb behind the capture proxy: 63 frames (`Init`, 30 `CircuitProve`,
32 `CircuitVerify`) covering all 12 in-scope rollup circuits — including `checkpoint_padding`,
which no live-chain shape can reach (it needs an epoch holding exactly one checkpoint) and which the recipe's second
epoch exists solely to produce. Regeneration is deterministic in content (identical witnesses;
only job-dispatch order varies) and takes ~6 min of harvest (rare; only a protocol change
invalidates the leaf assets) plus ~7 min of proving.

## Open items

- Land the pin branch's commits upstream (the bb.js-api PR with `Init`, BB_RNG_SEED, the RNG tape,
  BB_RNG_COUNT, envelope file framing, the BB_POOL_SIZE labs patch, the dumper), converging the pin
  to a bare release tag with a downloadable binary.
- Extend the corpus beyond the private rollup path: public txs (AVM-adjacent frames stay
  replay-skipped), and the chonk wire sessions as a second recorded stream.
