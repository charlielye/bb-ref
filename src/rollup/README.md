[◄ bb-ref](../../README.md)

# rollup — server-side recursion

The backend's flavor of recursion. Rollup circuits are plain Ultra circuits that verify other
proofs in-circuit — [`honk`](../honk/README.md)'s generic verifier instantiated over ULTRA arithmetic with
[`stdlib`](../stdlib/README.md) biggroup commitments and native `FieldT` scalars. This module holds what's
specific to that instantiation, chiefly the IPA story.
[Tour, Act IV](../../docs/tour.md#act-iv--the-server-side-the-rollup-tree) covers the tree.

*Unfamiliar name? Every recurring term is defined in [docs/glossary.md](../../docs/glossary.md).*

The problem it solves: proofs below a rollup node carry Grumpkin IPA claims (from the ECCVM via
the tube), and Grumpkin has no pairing, so they can't be discharged the KZG way. Instead every
rollup circuit *accumulates*: it reduces each nested IPA claim in-circuit, combines the
accumulators into one, and natively re-proves the combined claim — the 64-field IPA proof
appended to every rollup proof. At the root the two nested claims are combined and the result is
*fully* verified in-circuit (`ipa_recursive::full_verify_ct`, an MSM over the SRS), so the root
proof carries no IPA claim.

| file | what it is |
|---|---|
| `mod.rs` | the in-circuit Ultra verifier instantiation, pairing-point aggregation, and bb's `RollupIO` public-input convention (pairing points + IPA claim) every rollup circuit carries; plus `verify_ultra_rollup`, the native check of a rollup proof |
| `ipa.rs` | the native Grumpkin IPA at 2^CONST_ECCVM_LOG_N: the prover behind the appended proof, and the verifier for a rollup proof's IPA tail |
| `ipa_recursive.rs` | the in-circuit IPA over ULTRA arithmetic: bigfield scalars, `cycle_group` commitments; reduce, combine, hand off — or, at the root, full verification |

## What makes this layer delicate

- **Two IPA implementations on purpose**: [`goblin/ipa.rs`](../goblin/ipa.rs) is the client's
  (TripleIPA, native verify), this one is the server's (fixed size, accumulate-and-defer). They
  share the math but not the transcript shape; unifying them would couple the two protocols.
- **RollupIO is a contract with Noir**: the positions of pairing points and IPA claim inside the
  public inputs are fixed by the protocol circuits; the verifier reads them by offset.
- **Everything here is gate-counted**: the recursive verifier and IPA run over `stdlib` types, so
  the gate-exactness rules apply ([docs/gate-exactness.md](../../docs/gate-exactness.md)) — an
  innocent refactor changes the rollup circuits' VKs.
