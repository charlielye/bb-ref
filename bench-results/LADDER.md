# wasm kernel ladder — bb vs bb-ref, matched rungs

All numbers: idle bench box, same node/V8, single-threaded unless noted. Run with `tools/ab.sh <rung>`.
bb gbench rungs need `--benchmark_min_time=<N>x` (the wasi CPU clock breaks its calibration; an
un-forced run reports one tier-up-polluted iteration). bb `vector_field_bench` is a latency-chain
bench — use `add_scaled_bench`'s decomposition for bb packed throughput instead.

Snapshot 2026-09-04 (bb-ref eb4c163 + q1s1 probe):

| rung | ours | bb | ratio | note |
|---|---|---|---|---|
| L0 scalar mul (throughput) | 52.5 ns | — | — | bb fr_bench is a dependency chain (86 ns), not comparable |
| L0 packed mul | 29.2–33.2 ns/elt | ~25 ns/elt | ~1.25x | bb = q1s1 5-wide: scalar unit runs in parallel with SIMD |
| L0 packed add / sub | 4.3 / 4.1 ns/elt | ~same TNM kernel | ~1x | |
| L0 pack transpose | ~1.6 ns/elt | 11.3 (load_contiguous) | 0.15x | ours faster; bb pays 5-wide AoS load |
| L0 q1s1 naive (2 calls) | 34.2 ns/elt | — | — | no free overlap: must fuse at round granularity in one body |
| L1 axpy / add_scaled 2^16 | 37.6–39.8 ns/elt | 28.3 (bench_add_scaled_full) | 1.35x | tracks the packed-mul ratio |
| L1 fold (sumcheck halve) | 44–47 ns/out | — | — | bb rung TBD |
| L2 relations, per edge | parity: Arithmetic 0.95, DeltaRange 1.02, Elliptic 1.01, Pos2External 0.96, EccOpQueue 0.73 | | | |
| | outliers: **Permutation 2.17**, Lookup/BBEq 1.36, Pos2QuadInternal 1.23, Pos2QIT 1.34, Pos2TransitionEntry 1.30, Memory 1.18 | | | |
| L2 MSM 2^16, 8t | 63.3 ms | 47.1 ms | **1.34x** | full-width random scalars both sides |
| L2 MSM 2^20, 8t | 992 ms | 627 ms | **1.58x** | scale-dependent extra gap — structure, not kernels |
| L3 sumcheck round0 MegaZK 2^17, 8t | rung TBD | 341 ms | ? | bb `sumcheck_iteration_bench`, no-skip random table |
| L4 canonical flow, 8t | 6.26 s | 5.04 s | 1.24x | |

Worklist by ROI (all verifiable on a rung in <30 s):
1. q1s1 fused multiply (packed mul ~29 → ~24; propagates into axpy, MSM drain, everything packed).
2. MSM at 2^20: find the scale-dependent gap (stage timings vs size; window choice, gather block,
   survivor merge).
3. Permutation relation body (2.17x — single function).
4. Lookup 1.36x, poseidon-internal family ~1.3x, Memory 1.18x.
5. Write the round0 L3 rung on our side and iterate the sumcheck harness against bb's 341 ms.
