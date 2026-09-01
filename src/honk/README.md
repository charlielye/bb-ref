# honk — the proving system core

The Honk protocol itself: turn a finished circuit into polynomials, commit to them, run sumcheck
over the relations, open everything with Shplemini/KZG. Plus HyperNova, the folding scheme Chonk
uses to defer that work. [Tour, Act I](../../docs/tour.md#act-i--one-ultrahonk-proof) walks one
proof through this module end to end.

Everything is written once, generically: the verifiers over [`base`](../base/README.md)'s `FieldLike`/`Curve`
traits (so [`rollup`](../rollup/README.md) and [`chonk`](../chonk/README.md) can instantiate them in-circuit with
[`stdlib`](../stdlib/README.md) types), and sumcheck over a `RelationSet` (so [`goblin`](../goblin/README.md)'s ECCVM
and Translator reuse it with their own relations).

| file | what it is |
|---|---|
| `flavor.rs` | **flavors as data**: a flavor is a relation list + a few constants; the entity layout (polynomial/commitment/evaluation order) is *derived* from it by the same algorithm as bb's flavor codegen |
| `relations.rs` | the Honk relations, one body each, shared by prover, native verifier, and in-circuit verifier |
| `prover_instance.rs` | circuit → polynomials at the dyadic size, plus the metadata Oink needs |
| `oink.rs`, `oink_prover.rs` | the pre-sumcheck phase: bind the VK, commit to wires, derive lookup inverses and the grand product |
| `sumcheck.rs` | prover + verifier, pointwise over extended edges; the committed-univariate variant for the ECCVM |
| `pcs.rs` | Shplemini (Gemini + Shplonk in one MSM), SmallSubgroupIPA consistency for ZK, the KZG reduction to pairing points |
| `ultra_prover.rs`, `ultra_verifier.rs`, `decider.rs` | the composed pipelines |
| `hypernova.rs`, `multilinear_batching.rs` | folding: each circuit becomes a *claim*, claims are batched by one sumcheck into an accumulator, the decider opens it |
| `circuit_checker.rs` | asserts every subrelation vanishes row-by-row on an instance — the localization workhorse of the standalone tests |
| `quad_params.rs` | derived constants of the compressed Poseidon2 gate encoding |

## What makes this layer delicate

- **The layout is derived, not written down.** Entity order, proof length, and commitment
  positions all fall out of `flavor.rs`'s derivation. Editing a relation list reorders the wire
  format; the length-pin tests in `tests/` exist to trip exactly that.
- **Relation bodies follow bb's *verifier* operation order** (in-circuit, every operation is a
  gate). Algebraically equivalent rewrites change gate counts — don't "simplify"; see
  [docs/gate-exactness.md](../../docs/gate-exactness.md).
- **Transcript order is the protocol** ([base/README](../base/README.md)): every commitment and
  evaluation enters the duplex in layout order, and ZK flavors interleave masking draws from the
  session RNG — an extra or missing draw shifts every later challenge.
