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
3. **Byte-exact everything** (with the tape): witness gap-fills, in-circuit masking, random
   IPA claims, and ZK masking all draw from bb's single global engine. Recording bb's draws
   (`BB_RNG_TAPE_OUT`) and replaying them through bb-ref's global source (`TapeRng` set via
   `set_global`, with `GlobalProxy` routing explicit-rng call sites to it) makes even ZK
   proofs and witness columns byte-identical.

## Fixture machinery

- **The pin** ([`tools/PIN`](../tools/PIN)): one bb commit. Every fixture is generated
  from it; tests assert the fixture pin matches.
- **The dumper** (`BbRefDump`, in the pinned tree at
  `barretenberg/cpp/src/barretenberg/dsl/acir_format/bbref_dump.test.cpp`, built by
  `ninja dsl_tests`): a test-only C++ file carried as a commit on the pin branch rather than a
  patch applied over it.
  Its `BbRefDump.*` tests dump whatever a milestone needs — full proving instances
  (`UltraInstance`: every polynomial, VK, proof), write-VK circuit shapes (`UltraWriteVk`),
  named stdlib micro-programs (`Stdlib`), op-queue/merge/ECCVM/translator/chonk fixtures —
  driven by `BBREF_*` env vars. bb production code is never modified (the one exception is
  the env-gated RNG seed/tape patch in `numeric/random/engine.cpp`).
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
| stdlib micro-oracle (`m13` named programs) | one expression or gadget, gate-exact, in isolation | ~10 s round trip |
| end-to-end flows (pinned chonk flows, `m20`) | whole transactions verify and re-prove byte-exact | minutes |

When a big oracle fails, **reduce to a micro-oracle**: add a named program to the dumper
(both copies!) reproducing the suspect expression over deterministic witnesses, mirror it in
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

Re-pointing bb-ref at a new bb commit is a deliberate procedure: rebase the pin branch onto it,
update `tools/PIN`, run `tools/regen_corpus.sh` and every `regen_*.sh`, re-harvest
witness-bearing fixtures, and run the full suite. Divergences found are chased with the ladder above — they are the changelog
of what bb changed, which is half the value of maintaining the mirror.
