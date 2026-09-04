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

Update (same day, all rungs under --no-liftoff — REQUIRED: Liftoff tier-up polluted earlier
numbers by up to 30%):

- **L3 round0 (roundbench, matched to bb): OURS 275 ms vs bb 341 ms at 2^17/8t — 1.24x FASTER**
  (12 relations / 46 subrelations both sides, no-skip constant table). The dense sumcheck harness
  is not our problem. Open discrepancy: in real flows our sumcheck family still reads slower than
  bb's — suspects: skip-heavy real tables (bb iterates precomputed active blocks; we pay ~185
  ns/dead-edge in per-edge checks, though tight witness_end covers the tail), later-round shapes,
  or bucket misattribution in the flow profiles.
- q1s1 fused multiply: DEAD, twice — round-interleaved fusion 46 ns/elt (register spills), naive
  two-call interleave perfectly additive (no cross-call ILP). bb gets its 5-wide overlap from
  clang-level scheduling+barriers we can't express from Rust/LLVM-wasm. Also x2 (two fused quad
  muls): flat — the kernel is V8-codegen-bound, not latency-bound.
- Corrected bb add_scaled baselines (TurboFan, 1t): vectorized_inline 31.0 ns/elt, full 28.5 (its
  28.3 earlier was fine; the 48s were Liftoff noise). Ours axpy 37.8 → 1.25x, tracking the mul.
- MSM decomposition (1t): tree 305 ns/pair matches the kernel model exactly; scaling parity
  (7.35x vs bb 7.18x at 8t); the 1.34x @2^16 is mul-kernel-bound; the extra gap at 2^20 is cache
  (per-entry 352→406 ns while bb improves 259→245) — flow MSMs are <=2^19, deprioritized.
- bucket_reduce packing: won its rung (38->30 ms @2^16 1t) but was flow-NEGATIVE via pass_add
  (small batches, closure re-eval); reverted. bucket_reduce is ~0.1% of the flow.
- Index-pair staging in the tree drain: unsafe (in-place compaction clobbers source slots before
  a deferred gather); bb copies into spans for the same reason.

Standing worklist:
1. Packed mul 1.25x = THE systematic blocker (MSM + bulk ops). Only remaining route identified:
   hand-scheduled .wat for the q1s1 body linked into the module — bb-level control, specialized
   effort, unproven.
2. Resolve the flow-vs-rung sumcheck discrepancy (measure real-table skip overhead per circuit;
   if bb's active-block iteration is the difference, port block structure into RoundProver).
3. Relation-body outliers (Permutation 2.17x, Lookup 1.36x, poseidon-internals ~1.3x) — real but
   secondary; flow sumcheck is already rung-faster dense.

Update 2: bbkernel route landed (40c18a5). With `--features bbkernel`, build.rs compiles bb's
vector_field_wasm.cpp + csrc/bb_kernel.cpp with the wasi-sdk (bb's barriers survive — its bytes
by construction) and links them in: axpy 42.8 -> 33.7 ns/elt same-binary; MSM chord drain in two
phases (single inversion Rust-side). The drain loses its isolated 1t rung (+15%/pair vs the
QuadFp chain) but wins the flow at 8t — rung/flow disagreement cuts both ways; flow verdicts
rule. **Canonical flow 6.26 -> 6.12 s (1.215x), byte-exact.** Next: extend the surface (folds),
sumcheck flow-vs-rung discrepancy, then hand-.wat grinding on the mul to go below bb.

Update 3 (full V8 suite, bbkernel, 8t, commit 3b20f45): TOTAL 1.15x across 11 flows (bb 85.1 /
ours 98.0). Per-flow typical 1.23-1.30x; the biggest flow (storage_proof_7_layers) is 0.84x —
WE BEAT BB there (18.5 vs 22.1s): fixed per-flow costs amortize and our thread scaling + IPA/MSM
wins dominate at size. Canonical flow (transfer_0_sponsored) 1.24x is a small-flow worst case.
Journey: morning 1.34x total -> 1.15x. Memory still 1.2-1.4x bb (dlmalloc grow-only vs bb's
allocator; talc swap attempted, deferred — needs the sync/atomics arena config for wasm-threads).

Update 4 (ladder extended to commit_bench — MAJOR NARRATIVE CORRECTION, commit 57fe19c):
The "MSM 1.34x slower" was measured against bb PippengerUnsafe — bb's SYNTHETIC best-case raw
path (preprocessed points, no commit overhead) that real proving never uses. The RIGHT rung is
bb commit_bench bench_commit_random (the realistic commit path). Matched, 8t:
  size   ours    bb commit   verdict
  2^16   70.7ms  89.5ms      ours FASTER
  2^17   138ms   101ms       bb fixed-cost amortizes (bb 2^16==2^17 ~= flat => ~78ms fixed)
  2^18   285ms   192ms       1.48x at scale
Flow commits are 2^16-2^17 => MSM is at/near parity there. NOT the gap.

THE REAL GAP (RE-READ CORRECTLY): both provers run 8 streams of work. Ours = 8 rayon workers
(main blocks), bb = 7 workers + main. During parallel regions both have 8 busy streams; during
serial both have 1. An idle 9th thread costs ZERO wall. Wall ~= serial + parallel_work/8 either
way. RETRACTED: the earlier "excess thread idle ~= the gap / main-thread participation is the
lever" claim — that read aggregate wait CPU (which includes the free 9th thread) as wall time.
use_current_thread() changing nothing is the confirmation. Per-thread re-read:
  serial (main compute)          ours ~2.1s   bb ~2.0s   (bb main 5.1 total - 3.1 parallel share)
  per-stream parallel compute    ours ~3.4s   bb ~3.1s   <- the gap, ~10%, = kernel/loop constants
  per-worker wait                ours ~2.6s   bb ~2.5s   (parity; both idle during serial)
The ~10% per-stream compute is exactly what the rungs measure (MSM 1.23-1.4x at scale, sumcheck
faster, relations mixed). There is no separate parallelism gap; the ladder was complete.

So: the ladder is NOT exhausted (commit rung corrected the MSM story), and the remaining work is
per-stream compute constant factors — kernels and loops — not parallelism.

Update 5 (exact MSM port attempted — bb's full tree structure): implemented the fused single-call
chord kernel (pack operands once, keep dx/dy/xsum/ax/ay as packed VFs in scratch, W Bernstein-Yang
inverses via bb's clean invert_vartime bypassing the zero-assert, BATCH=2048 streaming, double-
buffered read-only-ps classify). = bb's tree_reduce_in_place + drain_batch shape. Results:
  microbench 8t:  2^17 138->127 (1.34x->1.23x), 2^18 285->269 (1.46x->1.38x), 2^19 547->510 (1.50x->1.40x)
Real movement toward parity but NOT parity. (RETRACTED EARLIER CLAIM: I blamed wasm's lack of a
prefetch instruction. That is wrong as an explanation — __builtin_prefetch compiles to NOTHING on
wasm (verified: clang emits an empty body), so bb.wasm gets no prefetch either. It cannot explain
any bb.wasm-vs-bb-ref.wasm difference. The residual is prover-code constant factors, full stop.)
CRUCIALLY it is FLOW-NEGATIVE (back-to-back A/B: base 5.85/5.91 vs fused 5.95/5.93): the pinned
flow's MSMs are SMALL (biggest 78k pts, most <8k) where the port's per-chunk fixed cost (double-
buffer alloc, BY inverses) loses to the simple scatter drain. REVERTED. A size-gated dual path
(fused for n>=2^16, scatter below) would keep both but adds complexity for zero current-flow gain.
CONCLUSION: the structural port helps 2^17+ MSMs; at the small sizes the pinned flows actually use
(<=78k) its per-chunk fixed costs lose. A size-gated dual path would bank both. The MSM gap that
remains is prover-code constant factors — no runtime excuse.
