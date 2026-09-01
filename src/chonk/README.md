# chonk — client IVC

The client-side scheme that proves a whole private transaction — a chain of app and kernel
circuits — as one proof. Each kernel *recursively verifies* the circuits since the previous
kernel (cheaply, via [`honk`](../honk/README.md)'s HyperNova folding instead of full verification), and
the final "hiding kernel" is proven jointly with [`goblin`](../goblin/README.md)'s Translator, producing
the five-part `ChonkProof`. [Tour, Act III](../../docs/tour.md#act-iii--the-client-side-chonk)
is the narrative version of this module.

Upstream, [`acir`](../acir/README.md) feeds it circuits lowered from Noir bytecode; downstream, the tube
circuit (a rollup circuit, [Act IV](../../docs/tour.md#act-iv--the-server-side-the-rollup-tree))
verifies the `ChonkProof` in-circuit — which is why `verifier.rs` is written over the generic
traits.

| file | what it is |
|---|---|
| `ivc.rs` | the driver: `accumulate(circuit)` per circuit, `prove()` at the end; owns the op queue, the folding state, and the running merge hash |
| `kernel.rs` | what a kernel circuit *contains*: the recursive folding/merge/decider verifications of the circuits before it, plus its public-input tail |
| `batched.rs` | the joint MegaZK + Translator proof: one ZK sumcheck over both circuits' relations at 2^17, one Shplemini/KZG opening of everything |
| `proof.rs` | `ChonkProof` — the five sub-proofs (hiding-kernel Oink, merge, ECCVM, TripleIPA, joint) as fields or msgpack |
| `verifier.rs` | native verification of a `ChonkProof` against the hiding kernel's VK |
| `compression.rs` | `ProofCompressor`: the proof as compact bytes, 32 per element, points as x + sign bit — the layout walk *is* the format |

## What makes this layer delicate

- **A kernel's VK depends on the shape of what it verifies**, not the values — which is why
  [`acir/mock.rs`](../acir/mock.rs) can compute kernel VKs from proofs full of garbage, provided
  every length and every branch-controlling value (subtable sizes) is right.
- **The joint proof zero-extends MegaZK from 2^16 to 2^17 variables** to share the Translator's
  sumcheck; the row-disabling and masking logic near that boundary is the fiddliest transcript
  code in the tree.
- **Order of accumulation is protocol**: the merge hash, the databus commitments and the folding
  transcript all bind the exact sequence of circuits; the same circuits in a different order
  produce a valid-looking but unverifiable proof.
