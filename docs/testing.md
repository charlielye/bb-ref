[◄ bb-ref](../README.md)

# Testing

Two complementary layers, and the claim each one carries:

1. **Differential** (`tests/*.rs` reading `tests/data/`, `tools/conformance.sh` replaying a
   corpus): byte-for-byte equivalence with the pinned bb on real inputs. This is the accept path —
   bb's outputs are all valid, so it can never show that bb-ref *rejects* anything.
2. **Standalone** (inline `#[cfg(test)]` + `tests/{soundness,relations}.rs` + the `api_boundary`
   module): runs with no bb binary, no corpus, no `tests/data` — `tools/check.sh` enforces this by
   hiding the fixture layer. Valid artifacts are proven in-process; this layer carries the
   soundness (rejection) and regression-localization claims.

Run `tools/check.sh` for the standalone gate, `cargo test --release` for everything,
`tools/coverage.sh` for the standalone set's line coverage (report-only, no threshold).

## What the standalone layer covers

`coverage.sh` reports three tiers, matching how the code splits (the figures below are a
snapshot — the script prints the live ones):

- **standalone, infra excluded: 69% of lines.** Infra — the generated msgpack code, the thin
  command adapters, the CLI, io/timing — is excluded outright: its bytes are pinned harder by
  corpus conformance than line coverage could.
- **core (also excluding the in-circuit recursion layer): 95%.** Relations (honk, ECCVM,
  translator) 100%, IPA 99–100%, PCS 98%, oink 99%, sumcheck 95%, plookup tables 97–100%,
  ROM/RAM 99%, transcript/codec/VK/SRS 92–96%, proof compression 96%, chonk accumulate/prove
  91–97%. The remainder is differential-only plumbing (the bb-dump loader, unused builder paths).
- **the in-circuit recursion layer** (stdlib gadgets, ACIR lowering, the recursive verifiers) is
  differential-owned: its correctness claim is gate-exactness against bb, which the differential
  layer pins byte-exactly and line coverage cannot establish. Standalone-covering it needs the
  in-circuit KAT harness, scoped separately.

## Soundness: every verifier decision has a test that trips it

| decision | tripped by |
|---|---|
| sumcheck round sum, final relation value | `soundness.rs` flip-sweeps (every proof element, 4 flavors); `sumcheck.rs` inline round-trip + violating row |
| oink VK-hash / PI-count binding | flip-sweeps (VK metadata + commitment tampers) |
| Shplemini / SmallSubgroupIPA consistency, Shplonk ≤1-claim | flip-sweeps; `pcs.rs` inline wrong-evaluation rejection |
| pairing check, pairing-point aggregation | `group.rs` inline SRS-relation positive + tampered controls; every suite's final pairing |
| IPA (rollup tail): g_zero, round challenges, claim binding | rollup suite sweep spans the 64-field IPA tail |
| merge / batch-merge column identity, degree check, subtable hash | chonk sweep (sections flow through the real merge verifier) |
| ECCVM + translator + joint-proof verification | chonk sweep sections; `relations.rs` per-relation named corruptions |
| chonk databus binding, section structure | chonk sweep + per-section truncation |
| deserialization: off-curve, non-canonical, limb bounds, wrong sizes, truncation | `codec.rs`, `vk.rs`, `compression.rs` inline rejection tests |
| wire boundary: malformed msgpack, unknown command | `msgpack_server.rs::api_boundary` — error response, never a crash |

Conventions: every negative test names the check it trips; every suite ends with an untouched
re-verification (negative control); a verifier panic on malformed structure counts as rejection,
matching the wire boundary's catch_unwind. Helper inputs (crypto commands) REDUCE non-canonical
words like bb does — pinned as KATs; canonicity *rejection* applies to proof and public-input words.

## Localization: a regression names its module

`check_circuit` (honk) and the ECCVM/translator row-checkers report *(relation, subrelation, row)*.
`circuit_checker.rs` pins the contract: a corrupted singleton wire on an arithmetic row is named
Arithmetic at that row; a corrupted copied wire is named Permutation; one corruption per Ultra gate
family (delta-range, memory, lookup, poseidon2 ×2) is caught under its own family. Stage
round-trips (sumcheck, Shplonk+KZG, compression) fail in the stage that broke, not at "proof byte N
differs". When a differential test does diverge, [oracle.md](oracle.md) (fixtures) and
[tools/README.md](../tools/README.md) (corpus frames, RNG draw counts) describe the ladder.

## What is deliberately NOT tested here

bb's per-flavor/per-curve TYPED_TEST replays (one generic body suffices), field axioms over
arkworks, accept-path gadget tests (gate-exactness differentials pin those harder), benches
(`tools/bench.sh` measures real workloads), manifest replays. bb's ~92k lines of `*.test.cpp` (AVM
excluded) compress to ~8k here because the differential layer supplies the oracle bb's tests lack.
