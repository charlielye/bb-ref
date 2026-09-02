# base — foundations

The layer everything else stands on: field/group abstractions, the Fiat-Shamir transcript,
serialization codecs, the SRS, polynomials, and randomness. No proving logic lives here — but the
*discipline* that makes byte-parity with bb possible does.

*Unfamiliar name? Every recurring term is defined in [docs/glossary.md](../../docs/glossary.md).*

The central design move: [`field.rs`](field.rs)'s `FieldLike` and [`group.rs`](group.rs)'s
`Curve`/`GroupLike` traits are implemented by both native arkworks types and
[`stdlib`](../stdlib/README.md)'s in-circuit types, so every verifier in [`honk`](../honk/README.md)/
[`goblin`](../goblin/README.md)/[`chonk`](../chonk/README.md) is written once and runs natively or inside a circuit.
[Tour, Act I](../../docs/tour.md) shows the pieces in motion.

| file | what it is |
|---|---|
| `field.rs`, `group.rs` | the traits + native bn254/Grumpkin impls; `PairingPoints` and the one pairing check |
| `transcript.rs` | the Fiat-Shamir duplex: `c_{i+1} = H(c_i ‖ round_data)`, generic over transcript field |
| `codec.rs` | how objects become transcript field elements (Fq as two limbs, points as coordinates, infinity as zeros) — the wire-format ground truth |
| `poseidon2.rs`, `poseidon2_params.rs`, `keccak.rs` | the two transcript hashes (Poseidon2 natively-friendly, Keccak for L1-facing proofs) |
| `poly.rs` | dense polynomials, barycentric extension/interpolation |
| `srs.rs` | the trusted setup: point loading, `Srs` pools a server preloads, commitment keys as Arc views |
| `vk.rs` | verification keys: three metadata fields + commitments, their codecs and hash |
| `rng.rs` | prover randomness: OS by default, `BB_RNG_SEED` for reproducible runs, mirroring bb's single global engine |
| `generators.rs`, `io.rs`, `timing.rs` | derived Grumpkin generators, the on-disk proof format, the opt-in `BBREF_TIMING` phase timer |

## What makes this layer delicate

- **The codec is the protocol.** Every `to_fields`/`from_fields` pair defines wire bytes bb must
  agree with: limb splits at 136 bits, big-endian everywhere, infinity as all-zeros, non-canonical
  values rejected exactly where bb rejects them. A "harmless" encoding change breaks every proof.
- **Transcript labels are not hashed** — only data enters the duplex; labels exist for the
  manifest. Challenge equality therefore depends on *data order alone*, and one element sent in
  the wrong order desynchronizes every later challenge.
- **Randomness is a shared session-global**, like bb's engine: witness gap-fills, masking and the
  provers all draw from one stream that is never reset. Consuming a different *number* of draws
  than bb — even for values that never affect a proof — desynchronizes every later proof in a
  session. `BB_RNG_COUNT`/`BBREF_RNG_COUNT` count draws per command; see
  [docs/testing.md](../../docs/testing.md) for the diagnosis ladder this enabled.
