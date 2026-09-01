# goblin — deferred EC arithmetic

Goblin is how client circuits avoid paying for elliptic-curve arithmetic in gates. A Mega circuit
*records* its EC ops into the op queue instead of constraining them ([`circuit`](../circuit)
holds the queue, [`stdlib`](../stdlib)'s goblin elements do the recording); this module proves,
once per IVC, that the recorded table was computed honestly.
[Tour, Act III](../../docs/tour.md#act-iii--the-client-side-chonk) shows where each proof slots
into a Chonk proof.

Three proofs tie it together:

1. **Merge** — the op-queue *table* is well-formed: each circuit's subtable was appended at the
   right offset (`merge.rs` for the hiding kernel's single step; `batch_merge.rs` for the batched
   per-IVC version, checked against the running hash the kernels computed).
2. **ECCVM** — the *operations* are correct: a Grumpkin-field circuit re-executes every op
   (wNAF tables, Straus MSM rows) and proves it with committed-univariate sumcheck.
3. **Translator** — the two live on different curves, so a bn254-Fr circuit re-computes the
   ECCVM's batched evaluation in 68-bit limbs, tying the ECCVM's claim to the Merge's table.

| file | what it is |
|---|---|
| `merge.rs`, `batch_merge.rs` | the table-consistency proofs: `M = L + X^k·R`, degree checks, subtable-hash binding |
| `eccvm/trace.rs` | op queue → ECCVM trace rows (transcript, precomputed point tables, MSM rows) |
| `eccvm/relations.rs`, `prover.rs`, `verifier.rs`, `check.rs` | the ECCVM relations, its ZK sumcheck pipeline, and the row-checker |
| `translator/builder.rs`, `key.rs` | two rows per op with limbs, accumulators, quotients, micro-limbs; then the 2^17-row concatenated proving key |
| `translator/relations.rs`, `check.rs` | decomposition/accumulation/permutation relations and their row-checker |
| `ipa.rs` | the Grumpkin inner-product argument + TripleIPA, which opens the ECCVM's three claims with one proof |

All three provers reuse [`honk`](../honk)'s sumcheck and PCS machinery — this module contributes
traces and relations, not new protocol.

## What makes this layer delicate

- **Grumpkin has no pairing**, so ECCVM openings end in IPA, not KZG — and the *client* verifies
  IPA natively while the *rollup* only accumulates it ([`rollup`](../rollup) discharges it later).
- **The Translator's limb bookkeeping is exact**: micro-limb ranges, quotient bounds and the
  16-fold concatenation are sized to the pinned constants (`CONST_TRANSLATOR_LOG_N`); a value
  that fits mathematically but not in its micro-limb budget fails rows far from the bad op.
- **Everything meets at the transcript**: ECCVM, Translator, and TripleIPA share evaluation
  challenges through one running transcript, which is why they're proven together in
  [`chonk`](../chonk)'s joint proof rather than independently.
