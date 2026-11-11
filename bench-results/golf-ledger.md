# Golf ledger

Every commit of the merged golf season-0 leaders (client-wasm 2eff0e, rollup-c7i 5450b4, avm-c7i 6ea0a2),
ported onto rc7 as `golf/all7` over `golf/base7`, classified against bb-ref:

- **HAVE**: bb-ref already does it (often a port citing the golf ID).
- **NA**: doesn't apply to bb-ref's design.
- **IN RC7**: upstream rc7 already contains it (dropped while porting golf to rc7).
- **CANDIDATE**: bb-ref lacks it; to be measured. Outcomes: **PORTED** (commit), **REJECTED** (measured, no gain).

A new golf leader only needs its new commits classified against this table.

## AVM

| golf | subject | verdict | where / why |
|---|---|---|---|
| 86c7cbd5a63 | MSM duplicate-scalar dedup hint for AVM wires | HAVE | `srs.rs` `commit` → `commit_dedup` when `dedup_pays` |
| 537da1d1d2b | PCS batching without per-thread full-size scratch | HAVE | `poly.rs` `scaled_batch` per-chunk destinations |
| bb7fd5b1245 | reuse an equal-extent unshifted poly as PCS batch dst | PORTED | `avm/prover.rs` `prove`: unshifted batch = shifted batch + the other columns (with 0fb8beecc3f: AVM 1% at 16 threads) |
| c28646b04e8 | lookup inverses in bounded row chunks | HAVE | `avm/prover.rs` `compute_inverses` 2^14-row chunks |
| 7ec5116c597 | reuse lazy edge storage between rows | NA | no per-column heap univariates (`program.rs` regs) |
| 6c698123b5b | inverse edge zero check before extension | HAVE | `avm/relations.rs` `skip` on row0/row1 |
| a3f8a9afc07 | don't zero fully overwritten fold tables | HAVE | `sumcheck.rs` `fold_vec` collects, no zero-fill |
| f2447a5001f | compress lookup tuple endpoints | HAVE | `avm/program.rs` tuple terms by forward differences |
| dcc77a13a49 | parallel execution trace rows after a state prepass | HAVE | `pin/bb-avm-sim.patch` |
| 90d34d22d2d | reuse inverse tuple terms past columns' zero tail | CANDIDATE | `avm/prover.rs` `compute_inverses` |
| 0fb8beecc3f | skip lookup accumulation when contributions are zero | PORTED | `avm/program.rs` Interaction: selectors and counts multiplied first, so the zero short-circuit drops the tuple products |
| b53db7babd5 | fill constant linear edges without repeated adds | HAVE | `avm/program.rs` constant ops computed once |
| b48840e7d1f | cache memory-event sort keys | HAVE | `pin/bb-avm-sim.patch` |

## Client: sumcheck, PCS, Chonk, ECCVM, translator, field kernels

| golf | subject | verdict | where / why |
|---|---|---|---|
| d1e5bf41942 | translator: grand-product columns only (0005) | HAVE | `goblin/translator/check.rs` |
| 2c8252aeb40 | skip fold multiply on bit-identical pairs (0006) | HAVE | `sumcheck.rs`, `wasm/packed.rs` |
| b26fa4ce9ca | batched variable-time divsteps (0007) | HAVE | `wasm/safegcd.rs`, `divsteps.rs` |
| 826dc7b3fe4 | separators folded into Poseidon2 quad relations (0008) | HAVE | `relations.rs`, `sumcheck.rs` |
| 96316d5f886 | skip databus rows of other bus columns (0009) | HAVE | `sumcheck.rs` skip predicate |
| 427b60f0866 | tiled add_scaled_batch, zero sources skipped (0018) | HAVE | `poly.rs` `scaled_batch` |
| 61c398efaa7 | parallel range-limited log-derivative inverses (0019) | HAVE | `oink_prover.rs` |
| d9e13604e25 | grand-product row: permutation columns only (0020) | HAVE | `oink_prover.rs` `compute_grand_product` |
| a3db120ae07 | Horner per thread chunk (0021) | HAVE | `poly.rs` `evaluate_par` |
| 123941ecb07 | memory terms of absent gate types dropped (0022) | HAVE | `relations.rs` |
| bbd60448bb3 | joint: both circuits' tables folded in one region (0027) | HAVE | `chonk/batched.rs` |
| 2506846556b | parallel batched linear quotients (0028) | HAVE | `poly.rs` `add_linear_quotients` |
| 2314cf6475e | Gemini single pass for A0± (0029) | HAVE | `honk/pcs.rs` |
| e169a67034d | ECCVM narrow rows, zero tail (0034) | HAVE | `goblin/eccvm/check.rs` (narrow rows: ~1 ms, not taken) |
| 94918173e10 | ECCVM parallel transcript scalar muls (0035) | HAVE | `goblin/eccvm/trace.rs` |
| 52f058fee9b | ECCVM parallel MSM trace rows (0035) | HAVE | `goblin/eccvm/trace.rs` |
| 027c6b4f9dd | paired recurrences in linear quotients (0039) | NA | measured neutral natively |
| d928124ce62 | Gemini A0 = F + G/X in one pass (0040) | HAVE | `honk/pcs.rs` |
| 9b95d9cf170 | Gemini fold polys without zero-init (0041) | HAVE | `poly.rs` `fold_par` |
| 3f58db043db | work-balanced split in add_scaled_batch (0042) | HAVE | rayon chunks balance it |
| 569c190adad | unit scalars without multiply (0043) | HAVE | `poly.rs` `scaled_batch` |
| 2598995a862 | two interleaved Horner chains (0044) | NA | measured 0% |
| aae1f27c5db | q_arith == 1 fast path (0047) | HAVE | `relations.rs`, `graded.rs` |
| 6eebca8cad1 | log-derivative lookup: absent terms dropped (0048) | HAVE | `Graded` constant-zero products |
| 7aba3835254 | batch the delta-range subrelations (0049) | REJECTED | with 0635286250e: Chonk 0.4% (median 0%), rollup 0%: within noise |
| 2858c20c426 | chunked gate tile storage (0051) | NA | `Vec<GateRow>`, mremap growth |
| 54c647a5749 | wasm: skip packed fold on identical pairs (0053) | HAVE | `wasm/packed.rs` |
| 55baba25d32 | parallel lookup read counts (0057) | HAVE | `prover_instance.rs` |
| c97c46bcba2 | parallel copy-cycle count/fill (0058) | HAVE | `prover_instance.rs` |
| 451dfd8e898 | databus inverse from four columns (0059) | HAVE | `oink_prover.rs` |
| e272749c062 | grand product as running product of ratios (0060) | HAVE | `field.rs` `grand_product_par` |
| ff1afa7c3ca | IFMA stride-2 fold (0061) | HAVE | `ifma.rs` |
| f8193900d9a | IFMA add_scaled_batch tiles (0062) | HAVE | `ifma.rs` |
| 1cdf93a0a23 | IFMA 16-chain Horner (0063) | CANDIDATE | `poly.rs` `evaluate_par` (0044 measured 0%: low) |
| 692fc8536e2 | IFMA short-univariate products (0065) | CANDIDATE | permutation relation laned (`PermLanes`); other relations scalar |
| ecdc6711354 | folded tables on folded support only (0069) | HAVE | `sumcheck.rs` `window_start` |
| 8faecf7202e | materialize tables after two rounds (0074) | HAVE | `sumcheck.rs` late tables (native default off: slower) |
| f0016934531 | Chonk instances free circuit data (0075) | HAVE | `prover_instance.rs` |
| c58d8944186 | wasm: packed deferred folds, folded-view reads | CANDIDATE | `sumcheck.rs` round-1 `folded_value` reads (wasm) |
| e9580a0a4fb | wasm: packed grand-product term rows | CANDIDATE | `oink_prover.rs` `compute_grand_product` (wasm) |
| cc2a9fe9002 | wasm: Fq affine-add square kernel | CANDIDATE | `wasm/tree.rs` slope² |
| 934c0e90cb0 | wasm: reuse identities in cycle links | HAVE | `prover_instance.rs` |
| 7e1357b053f | subrelation batching on packed wasm edges | HAVE | `relations.rs` `quad_batched` on every target |
| 7183bca83c2 | dense lookup tables without a map | PORTED | `prover_instance.rs` `dense_key_width`: row from the key(s), checked against the table (with b0cde44c3af: Chonk 1.1–1.3%) |
| 42727b32b29 | represented field constants in dense validation | NA | C++ codegen fix |
| 17587c84e31 | compact row indices for lookup resolution | NA | the dense path resolves every non-trivial Chonk table; the map is left to tiny ones |
| 0635286250e | batch native Poseidon2 subrelations | REJECTED | internal HAVE; external batching measured within noise (with 7aba3835254) |

## Native: builder, stdlib, fields, MSM

| golf | subject | verdict | where / why |
|---|---|---|---|
| aaddcc65839 | uint256 single-limb divmod | HAVE | `stdlib/keccak.rs` `base11_digits` |
| 77e3b736688 | keccak normalize_sparse chunked | HAVE | `stdlib/keccak.rs` |
| 47a564ee465 | fused scalar batch-affine drain | HAVE | `msm.rs` `tree_reduce_scalar` |
| aa13e4b91fa | ACIR enum moves, string_view | HAVE | serde decodes into owned types |
| b383106ddbe | streaming msgpack decode | HAVE | `rmp_serde::from_slice` |
| 03374585cdc | uintx skip zero-half muls | HAVE | num-bigint sized to operands |
| f1a53a15bda | compile-time field one/neg_one | HAVE | ark consts |
| de61a74b671 | lock-free parallel_for pool, spin then sleep | NA | rayon; longer spin measured (parity at 32 threads, +55% CPU), not taken |
| 8e1ba52c660 | Poseidon2 native shorter critical path | REJECTED | internal rounds' S-box off the sum path: Chonk 0.4% (median 0%), within noise |
| 5e1130037d7 | sha256 SHA-NI | HAVE | `sha2` crate |
| f0e1dc177b4 | keccak ÷11^k by single-limb divisions | CANDIDATE | `stdlib/keccak.rs` `theta` BigUint divisions |
| bc6ae622812 | bigfield cached CRT bounds, unreduced zero | REJECTED | CRT bounds HAVE; the rest measured within noise (with 917e64912e7) |
| e7b0c23c055 | bigfield 512-bit borrow bound | NA | variable-width BigUint |
| a3e233be0fe | keccak runtime slice loop | HAVE | `stdlib/keccak.rs` |
| b53d80e1f8e | field_t compile-time Montgomery ±1 | HAVE | ark consts |
| d662afbceab | multilinear batching merge | HAVE | `honk/multilinear_batching.rs` |
| 1e771588d9a | IFMA batch-affine drain | HAVE | `ifma.rs` `Chords` |
| 83e0ed5cef2 | Poseidon2 interleaved S-box / internal matrix | REJECTED | with 8e1ba52c660 |
| 3ab2961add9 | lower-latency ADX mont mul, split sqr | HAVE | `wasm/adx.rs` |
| 49a89c36140 | MSM 6b batched adds on IFMA drain | HAVE | `msm.rs` |
| e34d0d4c0f7 | IFMA drain edge-case tests | HAVE | `ifma.rs` tests |
| aef7502a3a4 | bigfield without wide divisions | HAVE | `stdlib/bigfield.rs` |
| 74db4e42799 | bigfield limbs via shifts | HAVE | `stdlib/bigfield.rs` |
| 616dcf3b42f | sumcheck gate-like selector tests | NA | tests |
| 05244acbb56 | wasm -O3 | HAVE | `[profile.lto]` |
| 7eea0f8bae6 | wasm packed two-round IPA fold | HAVE | `wasm/ipafold.rs` |
| be54881102b | IFMA two-round SRS fold | HAVE | `ifma.rs` `try_fold_two_rounds` |
| 4b2a953d072 | ACIR opcodes decoded from bytes | HAVE | serde visitors |
| 4692c5617d9 | origin-tag debug IDs | NA | no origin tags |
| 1153cd82bee | zero-scaled terms in AssertZero check | NA | no per-gate check |
| 577773a5bea | release final accumulator after decider | HAVE | `chonk/ivc.rs` |
| c57737d33cd | translator builder lifetime | HAVE | `chonk/ivc.rs` |
| b93a22470bf | bounded reciprocal division | NA | num-bigint division |
| c5da9629d1e | larger small-MSM aggregate workspace | HAVE | `srs.rs` `batch_commit` |
| a4329353966 | CPU shared across concurrent MSMs | HAVE | `srs.rs` `batch_commit` |
| 13a969a09db | wasm: gather into packed queue | CANDIDATE | `msm.rs` 6a + `wasm/tree.rs` staging copy |
| 315870f5bc4 | wasm: cached tile masks | NA | no per-window membership pass |
| 20b7cbda631 | wasm: skip windows above actual bits | CANDIDATE | `msm.rs` `decode` early exit |
| 917e64912e7 | bigfield deferred madd division | REJECTED | `div_rem` and a deferred madd division: rollup 0%, within noise |
| 5c16c504450 | native inverse reused in paired add/sub | CANDIDATE | `stdlib/biggroup.rs` (ROM tables only) |
| 9898083a5d6 | only requested lookup wrappers | CANDIDATE | `stdlib/plookup.rs` |
| 1a010e35ab3 | narrow bounded reciprocal division | NA | num-bigint division |
| c40996aa7c2 | dynamic MSM bucket-window scheduling | NA | one cross-window stream per thread |
| b0cde44c3af | count-sort bounded range lists | PORTED | `circuit/builder.rs` `sorted_range_values`: counting sort over the range, lists sorted in parallel |
| 1674a60df7d | reuse native range sub-limb values | CANDIDATE | `circuit/builder.rs` (negligible) |
| f719fc6e18e | Montgomery conversion by direct REDC | HAVE | ark `into_bigint` |

## Dropped while porting golf to rc7

| golf | subject | verdict |
|---|---|---|
| b96b6e32f55 | write the hiding kernel VK retained by the IVC | NA (rc7 removed `--write_vk` from Chonk prove) |
| 818cbbfa68c | free a step's constraint system before accumulating | IN RC7 |
| b1232d8c8ec | release circuit-construction data after the instance | IN RC7 |
| 18b839f8db2 | decompress each Chonk step just before loading | IN RC7 |
| 00c03b17674 | move the batched HyperNova polynomial out | IN RC7 |
| ffeb1f8ad8c | wasm batched divstep matrix | IN RC7 (equivalent) |
| 95bb329769f | wasm six-bit reciprocal reuse | IN RC7 (equivalent) |
