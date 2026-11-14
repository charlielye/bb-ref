# Golf ledger

Every commit of the merged golf season-0 leaders (client-wasm 2eff0e, rollup-c7i 5450b4, avm-c7i 6ea0a2),
ported onto rc7 as `golf/all7` over `golf/base7`, classified against bb-ref:

- **HAVE**: bb-ref already does it (often a port citing the golf ID).
- **NA**: doesn't apply to bb-ref's design.
- **IN RC7**: upstream rc7 already contains it (dropped while porting golf to rc7).
- **CANDIDATE**: bb-ref lacks it; to be measured. Outcomes: **PORTED** (commit), **REJECTED** (measured, no gain).
- **SKIP**: bb-ref lacks it, but the estimated gain doesn't pay for its code (not measured).

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
| 90d34d22d2d | reuse inverse tuple terms past columns' zero tail | PORTED | `avm/prover.rs` `compute_inverses`: γ past the tuple columns' ends (AVM check 3%, total 2% by ablation) |
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
| 1cdf93a0a23 | IFMA 16-chain Horner (0063) | SKIP | Gemini/Shplonk evaluations only; 0044 measured 0% |
| 692fc8536e2 | IFMA short-univariate products (0065) | SKIP | permutation relation laned (2daadb3); the rest is already ~1.7x golf per edge, full lanes need multi-edge batching |
| ecdc6711354 | folded tables on folded support only (0069) | HAVE | `sumcheck.rs` `window_start` |
| 8faecf7202e | materialize tables after two rounds (0074) | HAVE | `sumcheck.rs` late tables (native default off: slower) |
| f0016934531 | Chonk instances free circuit data (0075) | HAVE | `prover_instance.rs` |
| c58d8944186 | wasm: packed deferred folds, folded-view reads | SKIP | folds packed already; packing round-1 reads ~100 LOC for an est. 0.3-0.6% wasm |
| e9580a0a4fb | wasm: packed grand-product term rows | SKIP | est. 0.3-0.6% wasm for ~40 LOC, while bb-ref leads golf on wasm |
| cc2a9fe9002 | wasm: Fq affine-add square kernel | NA | a hook reusing the multiply; the real square kernel is REJECTED (client-wasm 002) |
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
| f0e1dc177b4 | keccak ÷11^k by single-limb divisions | PORTED | `stdlib/keccak.rs` `theta` on base-11 digits (no BigUint left in keccak; rollup within noise) |
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
| 13a969a09db | wasm: gather into packed queue | SKIP | fusing the first gather level saves one copy, est. <0.3% wasm |
| 315870f5bc4 | wasm: cached tile masks | NA | no per-window membership pass |
| 20b7cbda631 | wasm: skip windows above actual bits | REJECTED | per-scalar decode bound: Chonk 1.003x (median 1.000) with the set |
| 917e64912e7 | bigfield deferred madd division | REJECTED | `div_rem` and a deferred madd division: rollup 0%, within noise |
| 5c16c504450 | native inverse reused in paired add/sub | SKIP | ROM tables only, a few µs |
| 9898083a5d6 | only requested lookup wrappers | SKIP | wrapper Rc clones, <0.1% |
| 1a010e35ab3 | narrow bounded reciprocal division | NA | num-bigint division |
| c40996aa7c2 | dynamic MSM bucket-window scheduling | NA | one cross-window stream per thread |
| b0cde44c3af | count-sort bounded range lists | PORTED | `circuit/builder.rs` `sorted_range_values`: counting sort over the range, lists sorted in parallel |
| 1674a60df7d | reuse native range sub-limb values | SKIP | one conversion per sub-limb, negligible |
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

## Leaders since: client-wasm b517eb, rollup-c7i eeb676, avm-c7i 16c253

The new commits of these leaders' chains (by subject; the rest are rows above), numbered in chain
order. `golf/all8` applies them over `golf/all7`, except the scratch-thread recursion bundle, which
rests on golf's own fixed-seed engine and is left out of the comparison build.

| # | chain | subject | verdict | where / why |
|---|---|---|---|---|
| 000 | client-wasm | Build release WASM with -Oz to fit the memory guard | NA | golf's own wasm opt level vs its memory guard; bb-ref's `[profile.lto]` level is measured separately |
| 001 | client-wasm | perf(msm): skip Montgomery conversions of zero scalars in pippenger_round_parallel | NA | no in-place scalar conversion; zero-heavy inputs compacted first |
| 002 | client-wasm | perf(wasm): square VectorField with a dedicated Karatsuba kernel | REJECTED | built bit-identical to the multiply (quad261 `mont_sqr`, 40 limb products, shared reduction) at the MSM tree\'s slope square: V8 chonk 59.26 vs 59.14 s (0.998x), noise; reverted |
| 003 | client-wasm | perf(common): format failed-assertion messages out of line | NA | C++ assert codegen |
| 004 | client-wasm | perf(wasm): pack staged VectorField lanes with the transpose constructor | HAVE | `wasm/quad261.rs` `QuadFp::pack` is the transpose |
| 005 | client-wasm | perf(wasm): evaluate single live lanes of sparse Poseidon2 relations on the scalar path | HAVE | per-edge scalar evaluation with per-relation skip |
| 006 | client-wasm | perf(plookup): build the secp256r1 fixed-base tables by doubling, windows in parallel | SKIP | one-time secp256r1 table build, <0.2% wasm |
| 007 | client-wasm | perf(circuit): sort range lists by counting and read their values in parallel | HAVE | `circuit/builder.rs` `sorted_range_values`, `ascending_to_fr` |
| 008 | client-wasm | perf(wasm): bound the thread pool's idle spin by a poll count instead of the WASI clock | NA | golf's spin read the WASI clock; rayon counts idle rounds |
| 009 | client-wasm | perf(wasm): build release wasm with -O2 -fno-vectorize instead of -Oz | NA | golf's own wasm opt level vs its memory guard; bb-ref's `[profile.lto]` level is measured separately |
| 010 | rollup-c7i | perf(stdlib): derive missing cycle_group offset generators in parallel | HAVE | `base/generators.rs` derives in parallel |
| 011 | rollup-c7i | perf(stdlib): add the summed offset generators once per Straus round | REJECTED | Straus offset-sum / mixed adds: rollup corpus 127.7 vs 127.4 s with the set, within noise |
| 012 | rollup-c7i | perf(stdlib): cheaper native Straus hints in plookup fixed-base batch_mul | REJECTED | Straus offset-sum / mixed adds: rollup corpus 127.7 vs 127.4 s with the set, within noise |
| 013 | rollup-c7i | refactor(bb): draw the default rollup IPA opening apart from proving it | HAVE | `acir/honk_recursion.rs` `arbitrary_valid_proof_draws` |
| 014 | rollup-c7i | perf(dsl): skip proving the unused mock Honk proof under a constant predicate | HAVE | `acir/honk_recursion.rs` `arbitrary_valid_proof_draws` |
| 015 | rollup-c7i | perf(numeric): slice lookup keys with one division per digit | SKIP | lookup/range bookkeeping, each est. <0.2% |
| 016 | rollup-c7i | perf(plookup): accumulate native lookup columns in place | SKIP | lookup/range bookkeeping, each est. <0.2% |
| 017 | rollup-c7i | perf(builder): reserve the witness index columns of a lookup read | SKIP | lookup/range bookkeeping, each est. <0.2% |
| 018 | rollup-c7i | perf(stdlib): read only the used lookup rows in SHA-256 | SKIP | lookup/range bookkeeping, each est. <0.2% |
| 019 | rollup-c7i | perf(builder): resolve a lookup table once per run of equal table ids | SKIP | lookup/range bookkeeping, each est. <0.2% |
| 020 | rollup-c7i | perf(numeric): visit only set bits in map_into_sparse_form | SKIP | lookup/range bookkeeping, each est. <0.2% |
| 021 | rollup-c7i | perf(ipa): reuse the known commitment when proving a fresh IPA claim | PORTED | `rollup/ipa_recursive.rs`: the fresh claim's commitment, no second MSM (rollup within noise; removes work) |
| 022 | rollup-c7i | perf(builder): convert each limb once in range_constrain_two_limbs | SKIP | lookup/range bookkeeping, each est. <0.2% |
| 023 | rollup-c7i | perf(builder): look up the range list once per small range constraint | SKIP | lookup/range bookkeeping, each est. <0.2% |
| 024 | rollup-c7i | perf(builder): register new sublimbs straight into their range list | SKIP | lookup/range bookkeeping, each est. <0.2% |
| 025 | rollup-c7i | perf(builder): trim the native bookkeeping of create_limbed_range_constraint | HAVE | `circuit/builder.rs`, `stdlib/bigfield.rs` constants without round trips |
| 026 | rollup-c7i | perf(builder): build the integer selector values of gates at compile time | HAVE | `circuit/builder.rs`, `stdlib/bigfield.rs` constants without round trips |
| 027 | rollup-c7i | perf(builder): convert each distinct sorted range value once | HAVE | `circuit/builder.rs` `sorted_range_values`, `ascending_to_fr` |
| 028 | rollup-c7i | test(builder): pin the range-constraint circuits against reference compositions | NA | tests only |
| 029 | rollup-c7i | perf(stdlib): build constant bigfield limbs without Montgomery round trips | HAVE | `circuit/builder.rs`, `stdlib/bigfield.rs` constants without round trips |
| 030 | rollup-c7i | perf(stdlib): build the unreduced zero constant once | SKIP | unreduced_zero once: same idea as bc6ae622812, measured within noise |
| 031 | rollup-c7i | perf(builder): append the delta-range rows of a sort constraint from one prepared row | NA | Rust row literal, no per-row constructor |
| 032 | rollup-c7i | perf(builder): count range-list values in parallel chunks | SKIP | lookup/range bookkeeping, each est. <0.2% |
| 033 | rollup-c7i | perf(builder): append the sorted variables of a range list in one step | SKIP | lookup/range bookkeeping, each est. <0.2% |
| 034 | rollup-c7i | perf(builder): deduplicate range lists through a variable bitmap in parallel chunks | REJECTED | parallel range-list remap/sort/reads: rollup within noise |
| 035 | rollup-c7i | test(builder): pin range-list processing against the serial composition | NA | tests only |
| 036 | rollup-c7i | perf(common): size gzip output from the ISIZE trailer instead of doubling | HAVE | flate2 streaming, presized reads |
| 037 | rollup-c7i | perf(common): read gzip input files in one bulk read | HAVE | flate2 streaming, presized reads |
| 038 | rollup-c7i | perf(srs): read the cached BN254 CRS with parallel pread | HAVE | `srs.rs` maps the Montgomery CRS cache |
| 039 | rollup-c7i | perf(srs): load the native CRS into uninitialised storage | HAVE | `srs.rs` maps the Montgomery CRS cache |
| 040 | rollup-c7i | perf(polynomials): release large polynomial memory from several threads before freeing it | HAVE | `pool.rs` arena keeps and reuses freed blocks within a request |
| 041 | rollup-c7i | perf(srs): release the native CRS's pages in parallel when it is destroyed | NA | the CRS is a file mapping, never dropped in the server |
| 042 | rollup-c7i | perf(ecc): check VectorFieldPushSpan bounds once per walk instead of per access | NA | C++ IFMA container |
| 043 | rollup-c7i | perf(trace): build copy cycles in uninitialised, parallel-touched storage | HAVE | `prover_instance.rs` CSR copy cycles and row-chunk selectors in parallel |
| 044 | rollup-c7i | perf(trace): cap the copy-cycle scans at 16 tasks | REJECTED | copy-cycle cap: no change at 16 threads |
| 045 | rollup-c7i | perf(trace): copy selectors in row-chunk tasks | HAVE | `prover_instance.rs` CSR copy cycles and row-chunk selectors in parallel |
| 046 | rollup-c7i | perf(srs): read and parse the cached Grumpkin CRS in parallel | SKIP | Grumpkin CRS parse, once per server life |
| 047 | rollup-c7i | perf(ipa): convert the random opening's draws to field elements in parallel | SKIP | IPA random-opening draws / blocked fold scratch: <0.1% or memory-only |
| 048 | rollup-c7i | perf(ipa): compute the native IPA opening proof of a rollup circuit in the background | REJECTED | profiled: `rec: ipa claim+proof` is 1.2% of the rollup replay, the most a background proof could hide |
| 049 | rollup-c7i | perf(ipa): fold the SRS in blocks to bound the fold's scratch memory | SKIP | IPA random-opening draws / blocked fold scratch: <0.1% or memory-only |
| 050 | rollup-c7i | test(common): cover DeferredValue's joins, shared result, exceptions and thread count | NA | tests only |
| 051 | rollup-c7i | fix(srs): honour BB_VERIFY_CRS in the BN254 loader, as v6.0.0 does | PORTED | `base/srs.rs` `load_bn254_g1_verified` (security parity with v6.0.0; proofs unchanged) |
| 052 | rollup-c7i | fix(srs): close the Grumpkin CRS descriptor on every exit and guard its test without threads or exceptions | NA | Rust files close on drop |
| 053 | rollup-c7i | perf(polynomials): release an instance's polynomial pages with one team of threads | HAVE | `pool.rs` arena keeps and reuses freed blocks within a request |
| 054 | rollup-c7i | perf(stdlib_circuit_builders): release a builder's large blocks with one team of threads | HAVE | `pool.rs` arena keeps and reuses freed blocks within a request |
| 055 | rollup-c7i | perf(stdlib): keep the offset-generator store alive past exit | NA | C++/platform specific |
| 056 | rollup-c7i | perf(srs): release vector-held BN254 CRS points in parallel before freeing them | NA | the CRS is a file mapping, never dropped in the server |
| 057 | rollup-c7i | feat(numeric): stream positions and per-thread draw scopes on the random engine | SKIP | scratch-thread recursion bundle (with 067) |
| 058 | rollup-c7i | fix(numeric): close each thread's /dev/urandom descriptor when the thread exits | NA | C++/platform specific |
| 059 | rollup-c7i | feat(stdlib): rebind stdlib values to another builder in place | SKIP | scratch-thread recursion bundle (with 067) |
| 060 | rollup-c7i | feat(honk): append translated rows to an execution trace block in bulk | SKIP | scratch-thread recursion bundle (with 067) |
| 061 | rollup-c7i | feat(stdlib_circuit_builders): record what a splice must replay while a circuit is built | SKIP | scratch-thread recursion bundle (with 067) |
| 062 | rollup-c7i | feat(stdlib_circuit_builders): splice a recorded circuit into an Ultra builder | SKIP | scratch-thread recursion bundle (with 067) |
| 063 | rollup-c7i | test(stdlib_circuit_builders): cover a second splice and eight refusals of the splice | NA | tests only |
| 064 | rollup-c7i | perf(stdlib_circuit_builders): release every sizeable block of a recording builder when it is destroyed | NA | no recording builders |
| 065 | rollup-c7i | fix(common): keep the DEBUG_LOG recursion guard per thread | NA | C++/platform specific |
| 066 | rollup-c7i | test(stdlib_circuit_builders): share the all-member Ultra builder comparison | NA | tests only |
| 067 | rollup-c7i | feat(dsl): build leading Honk recursion constraints on scratch threads and splice them | SKIP | ceiling measured from per-constraint timings: 11 of the replay\'s 30 proving requests hold two or more Honk recursion constraints, so perfect overlap saves at most 4.7 of 126 s (3.7%) before the splice\'s copies; ~1-1.5k LOC (the rest of the serial build is single-constraint work, cut instead by the stack `Uint`, 0dbf6b1) |
| 068 | rollup-c7i | test(dsl): cover four refusals of a scratch-built constraint and the entropy its threads draw | NA | tests only |
| 069 | rollup-c7i | perf(dsl): return the memory a scratch thread freed before its builder is destroyed | NA | no recording builders |
| 070 | rollup-c7i | feat(stdlib_circuit_builders): let another thread cancel a build on a recording builder | SKIP | scratch-thread recursion bundle (with 067) |
| 071 | rollup-c7i | feat(dsl): build the first Honk recursion constraint in place when its scratch build is not ready | SKIP | scratch-thread recursion bundle (with 067) |
| 072 | rollup-c7i | fix(dsl): start scratch builds on 8 MiB pthread stacks and only for well-formed constraints | NA | C++/platform specific |
| 073 | rollup-c7i | fix(dsl): cancel scratch builds before joining them and reap them after the Honk recursion constraints | SKIP | scratch-thread recursion bundle (with 067) |
| 074 | rollup-c7i | fix(dsl): keep the message of a scratch build's exception in its refusal | NA | C++/platform specific |
| 075 | rollup-c7i | perf(stdlib_circuit_builders): reserve address space for a builder's per-variable arrays | NA | the arena grows in place |
| 076 | rollup-c7i | perf(msm): run wide members of concurrent batches as chunks | NA | rayon nesting and the arena replace golf's MSM chunking/arenas |
| 077 | rollup-c7i | perf(msm): run a concurrent batch's chunks on one per-worker arena block | NA | rayon nesting and the arena replace golf's MSM chunking/arenas |
| 078 | rollup-c7i | perf(msm): size a concurrent batch's chunks to whole rounds of the pool | NA | rayon nesting and the arena replace golf's MSM chunking/arenas |
| 079 | rollup-c7i | perf(msm): chunk a few-member batch when each member is worth 8/3 threads | NA | rayon nesting and the arena replace golf's MSM chunking/arenas |
| 080 | rollup-c7i | test(msm): draw the concurrent-chunk tests' random inputs on one thread | NA | tests only |
| 081 | rollup-c7i | perf(bb): release process memory on several threads before a successful exit | NA | the corpus server never exits mid-run |
| 082 | rollup-c7i | perf(bb): keep freed heap memory in AVM and UltraHonk proving | HAVE | `pool.rs` arena keeps and reuses freed blocks within a request |
| 083 | avm-c7i | perf(avm): load the CRS while simulating and generating the trace | NA | the server's CRS pool loads once |
| 084 | avm-c7i | perf(avm): absorb the first challenge's known input during the wire commitments | SKIP | AVM: absorb the transcript's known prefix during wire commits, ~60 LOC for ~0.3% |
| 085 | avm-c7i | perf(sumcheck): build large slot accumulators on their threads and sum them in parallel | PORTED | `honk/sumcheck.rs` (with 085/086/099: AVM prove 1-4% by ablation; AVM 16 threads, bbbench: the set 0.94x corpus / 0.89x golf's inputs) |
| 086 | avm-c7i | perf(avm): batch the sumcheck relations in parallel | PORTED | `honk/sumcheck.rs` (with 085/086/099: AVM prove 1-4% by ablation; AVM 16 threads, bbbench: the set 0.94x corpus / 0.89x golf's inputs) |
| 087 | avm-c7i | perf(avm): keep execution events in a deque | PORTED | `pin/bb-avm-sim.patch` (golf's hunks; the remainder of the set's AVM gain, ~3-7%; AVM 16 threads, bbbench: the set 0.94x corpus / 0.89x golf's inputs) |
| 088 | avm-c7i | perf(avm): write the memory trace rows on all threads | PORTED | `pin/bb-avm-sim.patch` (golf's hunks; the remainder of the set's AVM gain, ~3-7%; AVM 16 threads, bbbench: the set 0.94x corpus / 0.89x golf's inputs) |
| 089 | avm-c7i | perf(avm): split large multi-permutation tracegen jobs into parts | SKIP | pin: split multi-permutation tracegen jobs, ~170 lines, mostly past 32 threads |
| 090 | avm-c7i | perf(avm): release the proving polynomials' pages in parallel after the proof | REJECTED | profiled: `pool::trim` is 0.4% of the rollup replay (16 threads, bbbench) |
| 091 | avm-c7i | perf(common): add a helper that releases a large block's pages from several threads | REJECTED | profiled: `pool::trim` is 0.4% of the rollup replay (16 threads, bbbench) |
| 092 | avm-c7i | perf(avm): invert lookup rows in chunks of 2^12 rows | SKIP | the A/B was invalid (both sides at 2^12) and the estimate small: left at 2^14 |
| 093 | avm-c7i | perf(flavor): look up an entity's label by its offset when the entities are one span | NA | no label assertions in AVM key construction |
| 094 | avm-c7i | perf(avm): free the execution events as a job of the tracegen group | PORTED | `pin/bb-avm-sim.patch` (golf's hunks; the remainder of the set's AVM gain, ~3-7%; AVM 16 threads, bbbench: the set 0.94x corpus / 0.89x golf's inputs) |
| 095 | avm-c7i | perf(avm): fill a long bytecode decomposition in parts of the tracegen group | HAVE | pin bytecode decomposition parts; AVM key sized to the proof |
| 096 | avm-c7i | perf(avm): free the interaction jobs and their shared indices on the pool | SKIP | pin: free interaction jobs on the pool, <0.5% |
| 097 | avm-c7i | perf(msm): release the small-member pool's arena slices from their workers | NA | rayon nesting and the arena replace golf's MSM chunking/arenas |
| 098 | avm-c7i | perf(avm): load only the CRS points the proof needs, while building the polynomials | HAVE | pin bytecode decomposition parts; AVM key sized to the proof |
| 099 | avm-c7i | perf(avm): size the sumcheck gate separator table to the rows the rounds read | PORTED | `honk/sumcheck.rs` (with 085/086/099: AVM prove 1-4% by ablation; AVM 16 threads, bbbench: the set 0.94x corpus / 0.89x golf's inputs) |
| 100 | avm-c7i | perf(sumcheck): scale and zero each relation's accumulators in its batching task | NA | no separate scale/zero passes |
| 101 | avm-c7i | perf(polynomials): skip the zero-fill dispatch for an empty polynomial | HAVE | small zeroed allocations bypass the pool |
| 102 | avm-c7i | fix(polynomials): build the page release's fields without the release | NA | C++ build warning |
