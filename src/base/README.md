[◄ bb-ref](../../README.md)

# base — foundations

The layer everything else stands on: field/group abstractions, the Fiat-Shamir transcript,
serialization codecs, the SRS, polynomials, MSMs, and randomness. No proving logic lives here — but
the *discipline* that makes byte-parity with bb possible does, and so do the hot arithmetic kernels.

*Unfamiliar name? Every recurring term is defined in [docs/glossary.md](../../docs/glossary.md).*

The central design move: [`field.rs`](field.rs)'s `FieldLike` and [`group.rs`](group.rs)'s
`Curve`/`GroupLike` traits are implemented by both the native field/curve types and
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
| `srs.rs` | the trusted setup: point loading and authentication against bb's chunk hash pins, `Srs` pools a server preloads, commitment keys as Arc views |
| `msm.rs`, `endo.rs` | Pippenger MSM with batched-affine buckets (bb's `scalar_multiplication`), GLV scalar splitting |
| `fold.rs` | the IPA SRS fold, two rounds per pass on one shared doubling chain (bb `batch_two_round_fold`) |
| `ifma.rs` | AVX-512 IFMA eight-lane kernels (folds, axpy, MSM chord additions, the permutation relation), runtime-detected on x86-64 |
| `wasm/` | the per-target field backends and SIMD kernels — see below |
| `vk.rs` | verification keys: three metadata fields + commitments, their codecs and hash |
| `rng.rs` | prover randomness: OS by default, `BB_RNG_SEED` (bb's seeded engine) or `BB_RNG_TAPE_IN` (a recorded bb tape) for reproducible runs, mirroring bb's single global engine |
| `generators.rs`, `io.rs` | derived Grumpkin generators, the on-disk proof format |
| `timing.rs`, `bench.rs` | the opt-in `BBREF_TIMING` phase timer and `BBREF_BENCH` scope table (diffable against bb's `--print_bench`) |

**Field backends.** `Fr`/`Fq` are always arkworks' `Fp` container, but the `MontConfig` underneath
is chosen per target in [`wasm/mod.rs`](wasm/mod.rs): on x86-64 with ADX/BMI2 (the default via
`.cargo/config.toml`) `wasm/adx.rs` supplies bb's handwritten Montgomery mul/square/add/sub asm and
a Bernstein–Yang inverse (`wasm/divsteps.rs`), in arkworks' stored form; on wasm `wasm/field.rs`
stores bb's 2^261 domain with bb's 9×29-bit multiply (`mont29.rs`, four-lane `quad261.rs` behind
`packed.rs`/`tree.rs`/`ipafold.rs`/`perm4.rs`), or with `--cfg wasm_wide` a 4×64 multiply (`wide.rs`);
other targets use arkworks' own configs. Curves are arkworks' short-Weierstrass code over these fields
(`wasm/curves.rs` re-declares the configs with arkworks' constants); the pairing is arkworks'.

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
