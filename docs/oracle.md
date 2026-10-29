[◄ bb-ref](../README.md)

# The oracle: how correctness is established

bb-ref's correctness claim is differential, not axiomatic: **barretenberg at the pin is the
oracle**, and every module ships with a test that compares bb-ref's output against bb's,
byte for byte. There is no "we believe this implements the paper" step anywhere — if the
bytes match across the fixture corpus, the port is right; if they don't, one side has a bug
and the tooling below finds which operation diverged.

## The claim hierarchy

Not everything can be compared the same way, because bb draws randomness. Three levels:

1. **Bit-exact structure** (always): verification keys, and every deterministic polynomial
   of a proving instance — selectors, permutation (sigma/id), tables. This holds even in
   write-VK mode with mock witnesses, and is what the VK-hash sweeps check.
2. **Byte-exact proofs** (non-ZK): non-ZK UltraHonk proving is fully deterministic, so
   proofs compare byte-for-byte with no RNG games.
3. **Byte-exact everything** (seeded or taped): witness gap-fills, in-circuit masking, random
   IPA claims, and ZK masking all draw from bb's single global engine. Seeding both sides
   (`BB_RNG_SEED`: bb's debug engine, mirrored by `DebugRng`) or recording bb's draws
   (`BB_RNG_TAPE_OUT`) and replaying them (`TapeRng`, via `BB_RNG_TAPE_IN`) through bb-ref's
   global source (`set_global`, with `GlobalProxy` routing explicit-rng call sites to it) makes
   even ZK proofs and witness columns byte-identical.

## Fixture machinery

- **The pin** ([`tools/PIN`](../tools/PIN)): one bb commit. Every fixture is generated
  from it; tests read `tests/data/<pin7>/` (`PIN` in `tests/common/mod.rs`).
- **The dumper** (`BbRefDump`, in the pinned tree at
  `barretenberg/cpp/src/barretenberg/dsl/acir_format/bbref_dump.test.cpp`, built by
  `ninja dsl_tests`): a test-only C++ file carried as a commit on the pin branch rather than a
  patch applied over it.
  Its `BbRefDump.*` tests dump whatever a fixture set needs — full proving instances
  (`UltraInstance`: every polynomial, VK, proof), write-VK circuit shapes (`UltraWriteVk`),
  named stdlib micro-programs (`Stdlib`), op-queue/merge/ECCVM/translator/chonk fixtures —
  driven by `BBREF_*` env vars. Beyond the bb.js-api PR, the pin branch touches bb production
  code only with env-gated hooks (`BB_RNG_SEED`/`BB_RNG_TAPE_*` in `numeric/random/engine.cpp`,
  `BB_RNG_COUNT` in `api/api_msgpack.cpp`) and the msgpack file mode's envelope framing.
- **Regen scripts** (`tools/regen/regen_*.sh`): rebuild every fixture from the pin. Small
  fixtures are committed under `tests/data/<pin7>/`; bulky instance dumps are gitignored
  and regenerated on demand.
- **Harvested fixtures**: circuits whose witnesses embed real recursive proofs (the rollup
  tree) cannot be executed from sample inputs — they are harvested from a live proving run
  (`BB_DEBUG_OUTPUT_DIR` on yarn-project's prover test dumps each operation's bytecode,
  witness, and equivalent CLI command). **Always sanity-check a harvested witness by proving
  it with stock bb first**: the repo's committed CI sample `Prover.toml`s look usable but
  embed stale recursive proofs that bb itself rejects (`nargo execute` doesn't constrain
  `verify_proof`, so CI never notices).

## Oracle patterns, cheapest first

| pattern | what it proves | cost |
|---|---|---|
| VK-hash sweep (`backend_vk_hash_sweep`) | circuit structure equals bb's, per artifact, no witnesses needed | seconds/circuit |
| write-VK instance diff (`backend_write_vk_instance_diff`) | every deterministic polynomial over the full trace; pinpoints the first divergent gate row | ~1 min |
| instance + proof diff (`check_nozk*`) | everything: witness columns, VK, proof bytes | minutes |
| stdlib micro-oracle (`BbRefDump.Stdlib` programs, `tests/stdlib.rs`) | one expression or gadget, gate-exact, in isolation | ~10 s round trip |
| end-to-end flows (pinned chonk flows: `tests/chonk/native.rs`, `tests/flows.rs`) | whole transactions verify and re-prove byte-exact | minutes |

When a big oracle fails, **reduce to a micro-oracle**: add a named program to the dumper
reproducing the suspect expression over deterministic witnesses, mirror it in
`tests/stdlib.rs`, and iterate at ten-second cadence instead of minutes.

## Debugging a divergence

The write-VK differ (`tests/common::assert_polys_equal`) reports the first differing row
with a gate-level window (`BBREF_DIFF_ROWS`, `BBREF_DIFF_BEFORE`, `BBREF_DIFF_ALL`,
`BBREF_DIFF_AT`). From there, the escalation ladder that has resolved every divergence so
far:

1. **Bracket by phase**: `BBREF_TRACE_GATES=1` prints gate counts at `trace_phase` marks;
   temporary finer marks narrow the divergent row to one statement.
2. **Op-level trace**: add matching env-gated prints at bigfield/field_t operation entries
   on both sides (op name + arith/nnf gate counts), capture both streams, and window-diff
   them at the divergent row. This names the exact operation — the divergence classes it
   exposes are catalogued in [gate-exactness.md](gate-exactness.md). bb-side prints are
   transient local edits: never committed, reverted after use.
3. **Draw-ledger analysis** (witness-value divergences): the tape *is* bb's draw ledger.
   If gates match but witness values differ, one side consumed a different number of draws
   before the value's site — find each side's tape offset (scan candidate offsets through
   the sampler until it reproduces the observed value) and probe draw-count positions at
   known sites to locate the phantom consumer.

## Re-pinning

Re-pointing bb-ref at a new bb commit is a deliberate procedure, in this order:

1. Rebase the pin branch onto it (drop patches that landed upstream), update `tools/PIN`, rename
   `tests/data/<pin7>` and `tests/common/mod.rs`'s `PIN`, and stage the submodule (`regen_corpus.sh`
   runs `git submodule update`, which would otherwise reset the tree to the old pin).
2. Build in the tree: `pin/build.sh --noir`, `dsl_tests` (the dumper), the protocol and mock
   circuits (`noir-projects/fnd/*/bootstrap.sh build`), `barretenberg/acir_tests` (compile), and
   `make labs-yarn-project` (the mock-stack witness generator and the corpus driver). Download the
   pinned flows: `barretenberg/cpp/scripts/chonk_inputs.sh download
   barretenberg/cpp/chonk-pinned-flows` (where the regen scripts look; `BB_FLOWS` overrides).
3. `dev/regen_msgpack.sh` and `dev/regen_avm.py`, then every `tools/regen/regen_*.sh`: chonk flows, protocol, ultra, acir
   (mock stack), merge, vk hashes, mega-app VKs, corpus (`--harvest` after any protocol change),
   and backend last (its rollup circuits are extracted from the corpus).
4. Run the full suite and `tools/conformance.sh` on the new corpus.

Divergences found are chased with the ladder above — they are the changelog of what bb changed,
which is half the value of maintaining the mirror. The 2026-10-16 re-pin (3b2c553 → d43209d, the
bb.js-api PR head) needed no prover change: every flow and the corpus came out byte-exact; the ports
were wire (`Init`, replacing `Warmup`; `Poseidon2AbsorbChain`) and SRS ingress (bb now authenticates pushed points
against pinned chunk hashes), and most of the time went to tooling drift in labs (package renames,
`noir-execute`, the block builder's API).

The 2026-10-21 re-pin (d43209d → 1117683, onto `next` with the private-repo security batch, ~50 bb
commits) did change the prover: new ECCVM, Translator and databus subrelations, batch-merge
separator ops (and the verifier's concatenation identity over them), per-point pairing-point
aggregation on Ultra, trusted-constant `cycle_group::batch_mul`, and deterministic mock proofs; plus
verifier/validation checks with bb's own error text (canonical field and VK decoding, Chonk proof
structure and trailing data, the ZK keccak log_n floor, per-kind ACIR rejection, RAM initialization,
one writer per bus column). The fixture tooling needed the per-kind builders and Foundry 1.8.5.
