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

Update 6 — the drain rung, and the MSM gap closed to 1.11x @2^17 (flow-positive this time):
New rung `tools/ab.sh drain` (examples/chordbench.rs): the chord kernel alone on n staged pairs vs
the same linked VectorField mul streaming (bbref_axpy). Old drain: 270 ns/chord flat across sizes
= 45 ns/mul-eq (6 muls/chord: 3 for the batched inverse + slope + x3 + y3), vs 35 ns/elt streaming
— i.e. the drain ran each mul at ~1.3x the streaming rate, exactly the MSM rung ratio. Cause: the
two phases round-tripped every intermediate through UNPACKED Field arrays, so per 5-chord block it
did 9 packs + 5 unpacks around 6 multiplies (bb's 4x64->9x29 transpose is ~10 ns/elt).
Fix (chord1p/chord2p): phase 1 packs the four operands once and stores ax/ay/dx/dy/xsum + prefix
products as PACKED VectorFields in scratch; phase 2 reads them back (copies, not re-packs). 4 packs
+ 2 unpacks. Drain 270 -> 205 ns/chord = 34 ns/mul-eq: at the streaming rate. Wins at EVERY chord
count >= 16 (crossover ~8-16; below that both are inversion-dominated).
Two flow-negative intermediates, both diagnosed and fixed (rung was positive throughout):
 1. level-sized packed scratch: 3.6x the footprint (230 B/chord), grown per rayon split ->
    memory-growth/page-fault churn. Fix: stream in BATCH=4095-chord chunks (bb's BATCH_CAPACITY
    shape), one small scratch, cache-resident. Also lifted 2^17/2^18 further.
 2. fixed batch-sized (~1 MB) scratch per TreeScratch: the flow has thousands of small MSMs whose
    splits previously used a few KB -> first-touch faults x thousands. Fix: size by min(n, batch).
Flow drain-size histogram (worker stderr is NOT captured by the harness — accumulate in shared
statics, print from main): 30.7k drain calls; >1000-chord drains carry 30.8M of 34.3M chords
(90%); <=20-chord drains 0.18%. Tiny drains are irrelevant to the flow.
RESULTS (8t, bb commit_random 103/195/365): 2^17 138->114 ms (1.34x->1.11x), 2^18 285->249
(1.46x->1.28x), 2^19 547->458 (1.50x->1.25x). Flow, paired back-to-back x3: 5.89/5.92/5.89 ->
5.85/5.83/5.85 (-0.06 s), byte-exact. sizeof(VectorField)=192 B (5-wide: scalar lane + 4 SIMD).

Update 7 — post-drain-fix ladder, and two more measured verdicts:
- Gather block locality: at 8 THREADS smaller gather blocks help where a 1t sweep could not see
  it (shared cache): 2^18 244->227 ms (-9%), 2^19 464->441..458 (noise band +-4%), 2^16/2^17
  neutral, flow neutral (+0.02 on 5.88, inside noise). Default GATHER_BLOCK 2^16 -> 2^13
  (BBREF_GATHER_LOG2 overrides).
- Classify walk "128 B per-pair copies": NO-OP (tree 762 vs 755) — LLVM already elided them.
  Reverted. The walk's ~180 ms @2^17 1t is bookkeeping + the AoS staging write, not the copy.
CURRENT MSM RUNG (8t, bb commit_random 91/103/195/365): 2^16 61 (0.67x, bb fixed cost),
2^17 116 (1.12x), 2^18 227 (1.16x), 2^19 458 (1.25x). 1t all-in 2^17: 866 vs bb 663 (1.31x,
was 1.56x this morning). Drain kernel itself is at the streaming mul rate (34 vs 35 ns/mul).
WHERE THE REST IS (1t 2^17, 203 ms excess over bb): classify+staging ~180 (bb: u32 bucket
compares + push_point that PACKS directly into VF spans — no AoS intermediate; we write 128 B/pair
of AoS staging that chord1p re-reads and packs = a 256 B/pair memory round trip bb does not do,
est. 60-100 ms), bucket_reduce 38 (scalar pass_add), stages 1-3 34. Next structural item if
pursuing 2^19 parity: pack-on-push (C `pack5` called per 5 pairs from the classify loop writing
packed VFs straight into the drain scratch; chord1p then starts from packed operands).

Update 8 — pack-on-push (bb's push_point/drain_batch shape) measured NEUTRAL, reverted:
Implemented: classify walk packs each W-block straight into the drain scratch via a C `push5`
(no AoS staging), drains a batch (prefix chain, one inversion, finish+scatter) when it fills or the
level ends; fixed stride per level = min(pair upper bound, batch) so small MSMs stay small.
Byte-exact, suites green. Numbers vs the committed 167a935: 1t 2^17 tree 755->780 / all-in
866->889 (+3%, noise edge); 8t 2^16 61->62, 2^17 116->111, 2^18 227->228, 2^19 458->442; flow
5.91/5.87/5.93 vs 5.91/5.89/5.89. Within the day's +-2-4% bands => no measured win => reverted.
FINDING: the 256 B/pair AoS staging round trip I estimated at 60-100 ms is NOT a cost (cache-hot
writes/reads). The classify walk's ~180 ms @2^17 1t is the loop itself (per-pair branchy
bookkeeping, run structure, Vec pushes), and copying the pair out was already a no-op (Update 7).
Remaining MSM ladder gap @8t: 2^17 1.12x, 2^18 1.16x, 2^19 1.25x; 1t 2^17 1.31x. Field kernels at
parity; drain at streaming rate; what is left is walk/bookkeeping + bucket_reduce (scalar) +
stages 1-3, each ~4-20% of the 1t tree — no single dominant item.

Update 9 — full V8 suite on 167a935 (packed drain + gather 2^13): TOTAL 1.09x (bb 85.66 / ours
93.09 s; was 1.15x this morning, 1.34x at session start). Every flow 1.15-1.24x; storage_proof
0.81x (we win). Canonical 5.85 s (1.15x).
DIRECTION CHANGE (user): stop tuning our MSM; REPLICATE bb's scalar_multiplication_fast.cpp
(3164 lines vs our 1168) stage by stage. Confirmed structural differences, not guesses:
 1. Stage 6b bucket reduce: bb recursive_affine_bucket_reduce_strided (batched affine, VF
    gather/scatter); ours scalar pass_add running sums (14% of MSM @2^16 8t).
 2. Adaptive rounds: bb records an MSB histogram per scalar (record_msb,
    window_bits_tuning_oversub_factor) and sizes rounds to actual bit-lengths; ours always runs
    129 GLV bits. Flow commits have many <=32/<=128-bit scalars.
 3. Dedup of duplicate scalars (pippenger_dedup.hpp, 586 lines).
 4. Per-worker arena with a fixed layout (pippenger_arena_layout.hpp) vs Vec growth.
 5. Seam-overflow merge across thread chunks (merge_overflow) vs our run-structure bookkeeping.

Update 10 — bb MSM replication, stages ported so far (commit below):
 Phase 1 (scalar profile): per working GLV scalar bit length -> effective_num_bits = max actual
   bit length; n_active = nonzero working scalars; choose_window_bits(n_active, bits) with bb's
   exact model (rounds=ceil((bits+2)/c), buckets=2^(c-1)+1, cost=rounds*(4n+12*buckets), c in
   [2,20)); windows = ceil((bits+1)/c) (carry-Booth needs one spare bit; bb budgets +2).
 Stage 5 (chunk partition): each window cut into num_threads chunks by schedule index (seams
   absorbed by the survivor merge) — replaces the 8*half bucket-based chunk size, which starved
   the pool once Phase 1 chose wide windows (64-bit 2^17: +31% -> -3%).
 msmbench 8t base -> now:  32-bit 2^14 7.3->5.0, 2^17 26.3->20.1;  64-bit 2^14 7.8->5.8, 2^17
   36.0->34.9;  128-bit 2^14 14.9->13.0, 2^17 =;  254-bit 2^14 21.3->20.5, 2^17 115.8->112.3,
   2^18 234->215 (1.10x vs bb 195), 2^19 445->449 (1.23x vs 365). Flow neutral (its commits
   carry ~10 full-width masking scalars each, so effective bits stay 128 — same for bb, whose
   schedule is uniform). Byte-exact; suites green.
 Remaining bb stages not yet replicated: 6b recursive_affine_bucket_reduce_strided (ours =
   scalar running sums, ~14% of MSM @2^16 8t), BATCH_CAPACITY 256 (ours 4095), Constantine
   SIMD x4 digit recoder (ours scalar carry-Booth), dedup Phase A, arena.

Update 11 — bb Stages 5/6a/6b/7 replicated (commit below); ours-vs-bb structure now matches:
 Stage 5: per-window chunk bucket ranges [lo,hi] via partition_point on the bucket offsets.
 Stage 6a: per (thread, window): 2048-entry sub-chunks -> gather -> tree_reduce (ours, packed
   drain, handles equal/inverse pairs) -> densify survivors into slot[digit - lo] with a presence
   bitmap; slot collisions -> overflow list; one tree reduce per window folds overflow back (bb
   merge_overflow). No per-job / per-window survivor re-trees any more.
 Stage 6b: rebalanced tasks own uniform digit ranges; gather contributing threads' partials into
   SoA columns (stride = next_pow2), projective-merge seam digits, then
   recursive_affine_bucket_reduce (phases A-D, bb's scalar indexed Montgomery-trick kernels —
   bb also runs the scalar variants on multi-threaded wasm) -> (R, L) per window ->
   L + (lo-1)*R. Stage 7: sum task partials per window. Removed bucket_reduce/pass_add path,
   runs_from_ids, batch_affine_add, batch_add_assign (dead).
 msmbench 8t (bb 91/103/195/365): 2^16 58, 2^17 115, 2^18 217, 2^19 457 (neutral at full
 width, within +-4%); short scalars 2^17: 32-bit 20->18, 64-bit 35->29, 128-bit 76->73.
 Flow neutral; byte-exact; suites green.
 FINDING: the "survivor-merge tail" theory was wrong — 6a is still 418 ms of 476 at 2^19 (bb
 whole MSM 365). The add count is identical to bb's; the remaining ~25% at 2^19 (~10% at
 2^17-18) is per-entry constant factor inside the 6a inner loop: gather (random 64 B point +
 phi reads, DRAM-bound at 8t), classify/run bookkeeping, overflow copies, versus bb's single
 tight clang-compiled tree_reduce_in_place + reduce_chunk. Next replication step if pursued:
 copy bb's reduce_chunk/tree_reduce_in_place/drain_batch (anonymous-namespace templates, ~120
 lines, public-header deps only) into csrc and compile with bb's flags — bb's 6a bytes — with
 an equal-x guard for our general-point callers.

Update 12 — bb 6a inner loop linked from C (OPT-IN, correctness bug pending):
Ported bb's reduce_chunk / tree_reduce_in_place / drain_batch (the Stage 6a gather + batched-
affine tree) into csrc/bb_kernel.cpp, compiled with bb's flags and LINKED WITH THE WASI-SDK
STATIC libc++ (bb's batch_invert error path needs std::string; wasm-ld pulls only the referenced
members; throw_or_abort_impl/assert_failure stubbed to __builtin_trap). Reduce6a<Params,Field>
mirrors bb's ThreadScratch (8 VectorField runs, BATCH_CAPACITY 256, pair_dest). Two bb-ref-only
deltas: outputs reduce_once on write (bb-ref stores canonical), and equal-x / infinity operands
are settled inline (bb's unsafe path assumes them away). Driven from Stage 6a per (thread,
window) sub-chunk; the densify + overflow bookkeeping stays in Rust.
STATUS: mechanism PROVEN — compiles, links libc++ in-module, runs, and the flow is FASTER
(5.72 s vs 5.87 committed). But it computes a WRONG result (matches_ark ark-mismatch; flow proof
differs at byte 41008) — deterministic, not a crash, so a systematic error in the C tree/gather
(NOT beta: both the phi-table flow and the on-the-fly matches_ark path fail; NOT threading). The
Rust 6a is correct on identical input. Gated behind BBREF_C6A=1; default = Rust 6a (byte-exact,
suites 66/76 green). Next: isolate with a tiny reduce_chunk-vs-Rust-tree diff harness (same
gathered block in, compare survivors) — the bug is in ~30 lines of gather/tree, the 5.72 is real.

Update 13 — INSTRUMENTED decomposition of the 2^19 MSM gap (the "1.23x", answering "where does it go"):
Split Stage 6a into gather / tree_reduce / densify (s6a_timing, BBREF_MSM_TIMING) and timed the
linked bb-C 6a (BBREF_C6A=1) against the Rust 6a on identical input. 2^19, 8 threads, ours 455 ms
vs bb 365 ms:
  stage                         CPU (sum/8t)   wall     share   notes
  tree (batch-affine adds)      2230 ms        279 ms   61%     field arith floor ~1950 CPU (65M muls,
                                                                 shared with bb) + ~280 CPU Rust walk
  gather (point fetch+phi+sign)  900 ms        112 ms   25%     random 64B SRS load; memory-latency
                                                                 bound; bb's prefetch is a wasm no-op
  densify                          3 ms          0 ms    0%
  stages 1-3 (digit decode/scatter)            ~28 ms   6%      scalar carry-Booth vs bb Constantine SIMDx4
  6b + horner                                  ~20 ms   4%
CONCLUSION: 61% is batch-affine field arithmetic BOTH provers pay (irreducible floor ~244 ms wall).
Our excess over bb splits: (a) ~38 ms tree-walk orchestration — linked bb-C 6a recovers it
(C path 353 vs Rust 395 ms wall for 6a); (b) gather is memory-bound and ~equal (bb can't prefetch
on wasm either); (c) with bb's EXACT 6a linked, total is 411 vs bb 365 = the residual 46 ms is
OUTSIDE 6a: stages 1-4 digit decode (our scalar carry-Booth vs bb's Constantine SIMDx4) + 6b + horner.
CAVEAT: msmbench uses msm()/None -> on-the-fly phi = a field mul per endo entry that inflates
`gather`; the real flow commits carry a precomputed phi table (no mul), so flow MSM is relatively
better than msmbench's 1.23x. Next replication targets, ranked: fix the linked-6a bug (recovers
~38 ms), then port bb's Constantine SIMDx4 digit recoder (stages 1/4, ~the 46 ms residual).

Update 14 — MSM AT PARITY. Two fixes, both found by instrumenting rather than reasoning:
(a) Linked-6a correctness (see commit 9891833): the gather ignored the endomorphism with no phi
    table, and wrote bb's coarse [0,2p) into bb-ref's canonical storage (a single-entry bucket
    returns its gathered point unreduced). Canonicalising per entry cost 24% — the ark-boundary
    tax. bb's operator== reduces both sides, so the tree now runs coarse end to end like bb's and
    survivors are reduced once each on the way out. With both correct, linked-C 6a == Rust 6a at
    every size, so the earlier "C is 38 ms faster" was the incorrect version doing less work.
(b) THE ACTUAL GAP: bb's GLV_SMALL_N_THRESHOLD. bb runs GLV only for n <= 2^16 on wasm — above
    that the doubled point count (2n gathers, 2n schedule entries) outweighs halving the windows.
    We always used GLV. That is exactly the shape of the gap (it GREW with n: 2^16 0.64x,
    2^17 1.11x, 2^18 1.14x, 2^19 1.21x). Ported with a full-width non-GLV path (4-limb decode,
    no phi entries); BBREF_GLV_LOG2 overrides. Entries at 2^19: 9.44M -> 8.39M, matching bb's
    c=16 / 16 rounds.
  msmbench 8t vs bb commit_random 91/103/195/365:
    2^16  60 ms (0.66x, we win)   2^17 103 (1.00x)   2^18 200 (1.02x)   2^19 376 (1.03x)
  (always-GLV for comparison: 60 / 117 / 226 / 472.) Flow 5.74-5.82 s, byte-exact, suites green.
ANSWER to "is ark forcing extra work": in the MSM, no longer — the only ark-imposed cost was
canonical storage at the kernel boundary, now paid once per surviving bucket instead of per
entry, and the field ops themselves already benchmark at bb's rate (L0 rung). No reason to
replace ark; the vendored parts already let us match bb's representation choices where it counts.

Update 15 — 11-flow V8 suite on the parity build: TOTAL 1.07x (bb 85.08 / ours 91.42 s; was 1.34x
at session start, 1.15x this morning). Every flow 1.13-1.23x, storage_proof 0.80x. MEMORY also
collapsed to 0.97-1.14x of bb (was 1.2-1.44x): dropping GLV above the threshold removes the
doubled point buffer and the phi table.

NATIVE IMPACT of the wasm work (asked: better or worse?). Measured on the idle box with a
natively-built msmbench, session-start (eb4c163) vs now, 8 threads:
    2^14  11.63 -> 10.84 ms (-7%)     2^16  36.22 -> 35.28 (-3%)
    2^18 162.61 -> 131.27 ms (-19%)   2^20 666.76 -> 512.89 (-23%)
Better everywhere, because the big wins are algorithmic and platform-neutral: bb's Phase 1 scalar
profile + choose_window_bits, Stages 5/6a/6b (dense partials, overflow merge, recursive affine
bucket reduce), and the GLV threshold. The wasm-only pieces (2^261 domain, linked C kernels,
coarse tree) are cfg/feature-gated and do not touch native.
ONE REAL RISK FOUND AND FIXED: the GLV threshold was hardcoded 2^16, which on native would keep
GLV where it loses. bb uses 2^13 native, but MEASURED FOR OUR CODE the native crossover is 2^15
(GLV wins at 2^14, ties at 2^15, loses 5% at 2^16; 1t and 8t agree) — bb's native decode is
cheaper so its crossover sits lower. Set 2^16 wasm / 2^15 native rather than copying bb's number.
Gather block (2^13, wasm-tuned) checked native: insensitive (35.23 vs 35.21 @2^16), left alone.

RETRACTED "wasmtime deadlock" (2026-09-05): there is NO bb-ref deadlock. The apparent hangs were
SELF-INFLICTED: `pkill -f <pattern>` run over ssh matches its OWN remote command line, so it
killed the shell executing it before reaching the target (the tell was ssh exit 255). Every
"cleanup" therefore left the previous bench runner alive, and two 8-thread wasmtime processes
then contended on a 16-core box. Once the stale runner was killed BY PID, all 11 flows completed
with zero retries. Operational rules: kill by PID (or a bracket pattern that cannot self-match),
reap wasmtime CHILDREN not just the script, and note a killed wrapper can fall through to its
final `echo DONE` and write a FALSE completion marker over an incomplete table.

Update 16 — full wasmtime table on 84aa016 (per-flow, 3-attempt runner, zero retries needed):
TOTAL 1.10x (bb 99.08 / ours 109.14 s). Per flow 1.21-1.30x; storage_proof_7_layers 0.76x (we
win by 24%). MEMORY: 0.82-1.05x of bb — we use LESS memory than bb on 10 of 11 flows.
Both runtimes now: V8 TOTAL 1.07x, wasmtime TOTAL 1.10x.

Update 17 — WHERE THE REMAINING PER-FLOW GAP IS (typical flow, not the average).
The 1.07x suite total is carried by storage_proof (22 of bb's 85 s, where we win 0.80x); the
TYPICAL flow is 1.13-1.23x. Profiled both provers on transfer_0+sponsored (ours 5.79 / bb 5.04)
and bucketed CPU:
  field arith  21.55 vs 21.59  (PARITY)      MSM 3.47 vs 3.15 (+0.33)
  alloc/memcpy  0.57 vs  0.25  (2.3x)        other 1.48 vs 0.95 (+0.53)
  compute      27.85 vs 26.82  (+3.8%)       WAIT 23.79 vs 16.98
Scaling 1->8 threads: ours 4.14x vs bb 3.92x — OUR SCALING IS BETTER, so the gap is work, not
parallelism (the ratio is flat 1.10-1.16x at every thread count). Per-phase: 171 timed regions,
no dominant one (sumcheck 1.43 s, commits ~1.0, builder ~0.6, pcs ~0.8).
THE ACTUAL DIFFERENCE, from top-self-time on both sides:
  bb:  VectorField<Fr> mul 2.97s + VF<Fr> += 0.32 + store_from_array 0.25 + add_scaled_batch 1.09
       + fold_stride2 0.37   -> bb runs its Fr polynomial AND sumcheck work 5-wide SIMD.
  us:  scalar ark mont_mul_261 across 4 instantiations = 3.63+1.43+1.26+0.58 = 6.90s, of which
       ~5.15s is inlined inside relation/sumcheck bodies (graded 1.19s + accumulate_edge 0.53s
       appear separately as their own self-time).
So the residual ~10% is the PACKED SUMCHECK PLANE: bb evaluates relations on VectorField (5-wide),
we evaluate them scalar. This is the same item flagged at the very start of the session as the
reason for 1.1x rather than 1.0x. Our earlier attempt (QuadF, 4-wide, edge-batched) lost at every
threshold; bb wins with 5-wide VectorField over its ExtendedEdges layout. Retrying it should
reuse the LINKED bb kernels (as the MSM now does) rather than a hand-rolled Rust 4-wide path.
Secondary, smaller: alloc/memcpy at 2.3x bb, and MSM +0.33s (flow MSMs are small/sparse — a
different regime from the msmbench sizes where we now match).

Update 18 — PACKED SUMCHECK DISPROVEN AS THE LEVER (settled with bb's own switch, before building).
bb ships `-DBB_FORCE_SCALAR_LANE=1`, which forces its sumcheck off the VectorField path. Rebuilt
bb's wasm with it and A/B'd the typical flow:
    bb SIMD sumcheck 5.06 / 5.07 / 5.12 s     bb scalar-lane 5.22 / 5.20 / 5.20 s
So bb's 5-wide sumcheck is worth 0.14 s (2.7%) on a real flow, while our gap is ~0.6 s. A perfect
packed sumcheck would recover under a quarter of it. Consistent with our own dense round-0 rung
already BEATING bb (285 vs 341 ms) while scalar, and with bb gating SIMD off whenever the row
manifest is in use (`!USES_ROW_MANIFEST`) — i.e. off for skip-heavy real traces anyway. Our
existing 4-wide QuadF path measures 507 vs 285 ms (1.8x SLOWER) and is not worth reviving.
DO NOT spend more on packed sumcheck; the earlier "storage domain + packed sumcheck plane"
explanation for 1.1x is now falsified on the second half.

Update 19 — the benchmark flatters us: bb carries a startup handicap we do not.
Fixed cost on a trivial invocation (module compile + instantiate): bb 0.41-0.42 s, bb-ref 0.08 s.
bb's wasm module is 122 MB; ours is 10.9 MB. So on the typical flow bb spends ~0.42 s of its
5.06 s before proving starts, and we spend ~0.08 s of our 5.72 s. PROVING-ONLY that is
5.64 vs 4.64 s = 1.21x, not the 1.13x the wall shows. Across the 11-flow V8 suite bb carries
~4.6 s of module-compile in its 85.08 s total. Our real proving-work gap is therefore ~1.2x and
the headline totals understate it. Any future parity claim should be made on proving-only time,
or at least state this handicap.

## Update 20: matched phase instrumentation, bb `--print_bench` vs bb-ref `BBREF_BENCH`

Replaces the two synthetic rungs (folding sumcheck, sparse commit) with instrumentation on the
*real* flow, so no rung has to be argued to match flow conditions.

- bb already has this: `BB_BENCH` scopes plus `--print_bench` / `--bench_out`. The earlier claim
  that it "can't print under wasm because static destructors are disabled" was wrong. The gate is
  `#if !defined(__wasm__) || defined(ENABLE_WASM_BENCH)` in `bb/cli.cpp`; native prints today, and
  wasm needs the supported `-DENABLE_WASM_BENCH=ON` option (OFF in the wasm preset by design).
  Built into a separate `build-wasm-bench` so the pinned bench wasm is untouched.
- bb-ref side: `src/base/bench.rs`, a hierarchical per-thread scope timer matched to bb's, with
  scope names copied from bb's so the tables diff line-for-line. `BBREF_BENCH=1`.

**Reading bb's table correctly.** bb's reported `time` is `time_max` — the largest single thread's
total (`time += entry.time_max`, bb_bench.cpp:311) — not a cross-thread sum. Comparing our
cross-thread sum against it inflated our numbers ~2.5x and produced a phantom "MSM is 2.6x" result.
Our table now prints both `time_max` and `time_sum`; only `time_max` is comparable to bb.

Native, 8 threads, `ecdsar1+transfer_1_recursions+sponsored_fpc`, median of 3, bb's `time_max`:

| phase | bb | bb-ref | ratio |
|---|---|---|---|
| fold: instance->accumulator | 1.138s | 1.307s | 1.15x |
| fold: Oink | 0.845s | 0.796s | 0.94x |
| fold: sumcheck | 0.358s | 0.452s | **1.26x** |
| joint proof (MegaZK+Translator) | 0.761s | 0.767s | 1.01x |
| ECCVM | 0.493s | 0.724s | **1.47x** |
| commit (`CommitmentKey::commit`) | 0.690s | 0.958s | **1.39x** |
| MSM stages 1-4 (schedule) | 0.233s | 0.173s | 0.74x |
| MSM stage 6a (bucket partials) | 1.154s | 0.689s | 0.60x |
| MSM stage 6b+7 (reduce/combine) | 0.179s | 0.142s | 0.79x |

Native wall for the same flow: bb 3.43/3.73s, bb-ref 3.63/3.94s. Instrumentation overhead is
within run-to-run noise.

**What this overturns.**
- *MSM is not the gap.* Every replicated Pippenger stage is faster than bb's on the real flow
  (0.60-0.79x). The MSM rung parity holds and then some.
- *But `commit` is 1.39x* while its MSM stages are 0.6-0.8x, so the cost is in `commit` **outside**
  the Pippenger stages: sparse compaction, the small-MSM path, allocation and setup. That is a
  newly localized, unexplored lever.
- *Sumcheck is not at parity in the flow.* Ours is 1.26x bb's folding sumcheck, even though we beat
  bb 285ms vs 341ms on the synthetic dense round-0 rung (Update 18). The dense single-round rung
  does not predict the flow's skip-heavy all-rounds behaviour, which is exactly the mismatch these
  rungs were built to remove. Update 18's "our sumcheck is faster" holds only for that rung.
- *ECCVM at 1.47x is the largest single ratio* and had no rung at all before now.

## Update 21: wasm phase table (bbbench, the parity-relevant one)

Same instrumentation as Update 20, now on wasm, which is the target. bbbench (16 cores, idle,
load 0.00), 8 threads, V8 via `runwasi_threads.mjs` with `--no-liftoff` on both sides, median of 3,
flow `ecdsar1+transfer_1_recursions+sponsored_fpc`. Comparing bb's `time_max`.

Instrumentation overhead measured, not assumed: pinned wasm bb 11.63/11.68/11.67s vs instrumented
wasm bb 11.66/11.70/11.70s = **0.3%**. Every ratio below is safe from it.

| phase | bb | bb-ref | ratio |
|---|---|---|---|
| fold: instance->accumulator | 2.300s | 2.291s | 1.00x |
| &nbsp;&nbsp;fold: Oink | 1.400s | 1.144s | 0.82x |
| &nbsp;&nbsp;fold: sumcheck | 0.957s | 1.030s | 1.08x |
| joint proof (MegaZK+Translator) | 1.389s | 1.273s | 0.92x |
| ECCVM | 1.483s | 1.792s | **1.21x** |
| commit (all commit scopes) | 2.023s | 1.289s | 0.64x |
| MSM stages 1-4 (schedule) | 0.219s | 0.213s | 0.97x |
| MSM stage 6a (bucket partials) | 1.232s | 0.821s | 0.67x |
| MSM stage 6b+7 (reduce/combine) | 0.309s | 0.225s | 0.73x |

**Trap: bb splits its commits across two scopes**, `CommitmentKey::commit` (0.832s) and
`CommitmentKey::batch_commit` (1.191s), while every bb-ref commit lands in one. Comparing the
single scope reads 1.55x against us; counting both, the commit path is 0.64x and we win it. The
native Update 20 "commit 1.39x" row has the same defect and is retracted.

**Where wasm actually stands.** Every phase is at or better than parity except ECCVM at 1.21x,
with sumcheck at 1.08x. Folding is 1.00x and MSM is faster at every stage. ECCVM is now the
largest single lever and still has no dedicated rung.

**Sumcheck, finally answered for wasm: 1.08x, effectively parity.** Not the 0.84x the synthetic
dense round-0 rung claimed, and not the 1.26x the native flow showed. It is not the lever.

**No wall claim from these runs.** `--no-liftoff` forces full optimizing compilation of bb's
122MB module up front against our 10.9MB, which inflates bb's wall by seconds; the committed
`bench-results/chonk-v8.txt` tables (plain `node`) remain the wall reference. The phase ratios are
unaffected because both sides ran under identical flags.

**Also noted:** bb's `ChonkAPI::prove` includes a full `ChonkVerifier::verify` (1.776s) that
bb-ref's chonk CLI does not perform. The flow harness runs the same `prove` subcommand on both, so
that verify sits inside bb's wall in every published flow table. Worth resolving before the next
wall comparison.

## Update 22: the phase columns reconciled (they do not sum as first presented)

The Update 21 table nests: `commit` and the MSM stages sit inside fold/ECCVM/joint, so adding that
column double-counts. Added the missing top-level scopes (`create_circuit`, `Chonk::accumulate`,
`ChonkProve`, merge, translator construction) so a non-overlapping total exists.

Two nesting facts, read off bb's tree rather than assumed:
- `create_circuit` is a **sibling** of `Chonk::accumulate`, not nested in it
  (2.055 + 3.247 = 5.301 vs `ChonkAccumulate` 5.363, so the decomposition closes).
- `ChonkVerifier::verify` is nested **inside** `ChonkProve`. bb's prove figure therefore carries a
  1.776s self-verify that bb-ref's chonk CLI never performs.

wasm, bbbench, 8t, `--no-liftoff` both sides, median of 3:

| phase (non-overlapping) | bb | bb-ref | ratio |
|---|---|---|---|
| create_circuit (ACIR + builder) | 2.055s | 1.821s | 0.89x |
| Chonk::accumulate (fold loop) | 3.247s | 3.371s | 1.04x |
| ChonkProve, excl. bb self-verify | 3.501s | 3.415s | 0.98x |
| **SUM (proving-only)** | **8.802s** | **8.607s** | **0.98x** |

**This contradicts the published flow tables** (`chonk-v8.txt`: TOTAL 1.07x, typical flow 1.1-1.2x
against us). Both cannot be right. The candidate differences are (a) the published harness runs
plain `node`, so V8 uses Liftoff and tiers up, while these runs force full optimization on both
sides with `--no-liftoff`, and (b) bb's self-verify sits inside bb's published wall. Resolving this
is the next step; no parity claim is made from either number until it is.

## Update 23: RETRACTION of Updates 21-22 numbers; the real wasm standing is 1.25x

Updates 21 and 22 measured with `--no-liftoff` on both sides. That was wrong, and the resulting
"0.98x proving-only / sumcheck 1.08x / ECCVM 1.21x" table is retracted.

Why it was wrong: `--no-liftoff` makes V8 TurboFan-compile each wasm function on first call, so the
compile cost is charged to whichever phase first calls it. bb's module is 122MB and ours is 10.9MB,
so bb absorbed roughly 6s of compilation inside its phase timings against our 3s. The table was
substantially measuring compile time, and it favoured the smaller module.

Walls make it obvious:

| condition | bb | bb-ref | ratio |
|---|---|---|---|
| plain `node` (published harness) | 5.51s | 6.32s | 1.15x |
| `--no-liftoff` | 11.67s | 9.27s | 0.79x |

Tier-up *selection* was tested as an explanation and rejected: `--no-wasm-dynamic-tiering` slows
both slightly and leaves the ratio unchanged.

**Authoritative table — published conditions (plain `node`), wasm, bbbench, 8t, median of 3:**

| phase (non-overlapping) | bb | bb-ref | ratio | gap |
|---|---|---|---|---|
| create_circuit (ACIR + builder) | 0.451s | 0.689s | 1.53x | +0.238s |
| Chonk::accumulate (fold loop) | 2.227s | 2.793s | 1.25x | +0.566s |
| ChonkProve, excl. bb self-verify | 2.141s | 2.554s | 1.19x | +0.413s |
| **SUM (proving-only)** | **4.819s** | **6.036s** | **1.25x** | **+1.217s** |

| sub-phase | bb | bb-ref | ratio | gap |
|---|---|---|---|---|
| ECCVM | 0.791s | 1.160s | 1.47x | +0.369s |
| fold: sumcheck | 0.619s | 0.810s | 1.31x | +0.191s |
| joint proof | 1.004s | 1.087s | 1.08x | +0.083s |
| fold: Oink | 0.966s | 0.961s | 0.99x | -0.005s |
| commit (all scopes) | 1.661s | 1.228s | 0.74x | -0.433s |
| MSM stage 6a | 1.100s | 0.761s | 0.69x | -0.339s |

Commit and MSM are genuinely ahead and stay ahead under real conditions. The addressable gap is
ECCVM, the circuit builder, and the folding sumcheck, together ~0.80s of the 1.22s deficit.
Work order: ECCVM first (largest), then create_circuit, then sumcheck.

## Update 24: full wasm standing, and four sumcheck hypotheses ruled out

**Full 11-flow wasm standing** (bbbench idle, 8t, plain `node`, pinned uninstrumented bb):

| | bb | bb-ref | ratio |
|---|---|---|---|
| TOTAL | 84.92s | 90.96s | 1.07x |
| typical flow | 5.1-8.3s | 5.7-9.8s | **1.12-1.23x** |
| `storage_proof_7_layers` | 21.88s | 17.50s | 0.80x |

The TOTAL is flattered by `storage_proof`, where we win by 20%. The target is the typical flows.

**Where the gap is** (transfer_1+sponsored_fpc, proving-only 1.25x, +1.217s):

| item | gap | note |
|---|---|---|
| ECCVM | +0.369s | its own sumcheck +0.139, PCS/IPA tail +0.12, trace polys +0.052 |
| folding sumcheck rounds 1+ | +0.254s | round 0 is *ahead* (-0.028s), the fold is ahead (-0.060s) |
| create_circuit | +0.238s | unexplored |
| joint proof | +0.083s | |
| commit + MSM | -0.433s | we are ahead and stay ahead |

**Sumcheck: the deficit is entirely rounds 1+.** Our round 0 beats bb (0.275 vs 0.303) and our
fold beats bb (0.089 vs 0.149). bb's later rounds cost 0.60x its round 0; ours cost ~1.6x. Per
edge, bb's later rounds are ~3.3x cheaper than its own round 0 while ours stay flat — and bb
processes *more* edges after round 0, since `compute_effective_round_size` returns the full
round size once the multivariates are partially evaluated.

**Four hypotheses tested and rejected** (each measured on the real flow, not argued):
1. Serial fold for small rounds (`PAR_FOLD_MIN_ELEMS`): no change (6.30s), fold was already ahead.
2. Raising the edge-chunk floor 16 -> 256: **worse**, 6.71s. We are throughput-bound, not
   dispatch-bound, so removing parallelism hurts.
3. 4-wide quad path enabled from round 1/2/3 (`BBREF_QUAD_MIN_ROUND`): worse at every setting
   (6.42/6.38/6.34 vs 6.30). Earlier rejection on round 0 was not the reason it loses.
4. Sweeping chunk floor and divisor (4/8/16 x 16/32/64): all within noise (6.32-6.46).

Also note the native/wasm split: natively our rounds 1+ decay correctly (~0.98x round 0); only on
wasm do they stay flat. Our wasm round 0 is much faster than native (45.8ms vs 71.5ms per
instance) while later rounds are identical, so the wasm field advantage is not reaching the
later-round path. That is the thread to pull next, along with the untouched create_circuit.

## Update 25: why our later sumcheck rounds cannot use SIMD (the real cause)

Two more hypotheses tested and rejected, and between them they identify the actual cause.

**5. Per-round transcript cost — rejected.** 0.037s over 144 rounds (0.26ms/round). Not the fixed
cost that makes small instances' later rounds expensive.

**6. "Later rounds are dense, so drop the skip probe" — rejected, and instructive.** Forcing all
relations active from round 1 (correct, since a skipped row contributes zero, and the test suite
passes with it on) cost **33%**: 8.36s vs 6.29s. So skipping is *still highly effective* after
folding — large zero blocks fold to zero and stay zero. The rows are not dense.

**Measured probe hit rate: 65.7%** (37448/56962 groups in rounds 1+). So four consecutive edges do
usually share a skip pattern and the 4-wide path does engage — and it is *still* a net loss
(6.42s with it on vs 6.30s off).

**Therefore the cause is data layout, not skipping and not scheduling.** Our table stores scalar
columns, so every group of four edges must be transposed into SIMD lanes: per column, four strided
`column_value` reads into `QuadF::lanes`, plus the `row0q`/`deltaq` writes. The raw kernels are
genuinely faster (`QuadF mul` 34.71 vs scalar 52.88 ns/elt; packed add 4.32 vs 10.48), but the
gather overhead exceeds that 1.5x. bb pays none of it: its `PartiallyEvaluatedMultivariates` are
stored as `VectorField` already, so its 5-wide path reads lanes directly.

**The fix is to hold the folded table in packed layout from round 1 on**, so the quad path reads
lanes with no transpose and the fold writes them in place. That is the same structural choice bb
makes and it is the only route to the +0.25s. It is a real change, not a tuning knob.

Per-round data behind this (wasm, 8t, all 7 sumcheck invocations of the flow):

| | round 0 | rounds 1+ | ratio | tail (r>=8) |
|---|---|---|---|---|
| all invocations | 852.8ms | 1203.6ms | 1.41x | 147.7ms |

The tail is only 12% of rounds 1+, so this is mid-round throughput, not small-round overhead.
Every invocation shows the same shape (1.10x to 2.15x) against bb's 0.60x.

Hypotheses rejected so far: serial fold threshold, chunk floor (both directions), chunk divisor,
round-aware quad gating, per-round transcript cost, dropping the skip probe.

## Update 26: CORRECTION to Update 25 — the gather is not the cause either

Update 25 concluded the later-round sumcheck gap was the per-group transpose (data layout). That
conclusion was wrong and is retracted.

**The experiment that refutes it.** Keeping the skip probe but forcing the scalar path afterwards
separates the probe's cost from the quad arithmetic's:

| variant | wall |
|---|---|
| scalar baseline | 6.331s |
| quad from round 1, full | 6.374s |
| quad from round 1, probe only (always falls back) | 6.393s |

All three are within noise. The probe costs ~0.06s and the 4-wide arithmetic is **neutral**, so
the transpose cannot be what makes our later rounds 2.4x bb's. The earlier 6.42-vs-6.30 reading
that suggested the quad path "loses" was also noise.

**A false measurement worth recording.** Stubbing the gather (`QuadF::splat` of one load instead
of four strided loads) appeared to give 6.32s -> 1.72s, a 4.6x speedup. It was a **crashed run**:
the degenerate values panicked the prover, which exited early. Sumcheck is only ~0.8s of this
flow, so no sumcheck change can save 4.6s — the number was impossible on its face and checking the
log confirmed a panic. Always confirm a suspiciously large win completed.

**What is actually established.** Our 4-wide path gives no width benefit in relation evaluation,
even though the raw kernels are faster in isolation (`QuadF mul` 34.71 vs scalar 52.88 ns/elt).
The gain is lost inside the relation bodies, most likely to 192-byte `QuadF` temporaries and the
accumulator machinery spilling. bb gets its later-round speed from `VectorField` relation
evaluation that is SIMD-efficient end to end; matching it means restructuring relation evaluation,
not changing where the table is stored.

Dead ends now total eight: serial fold threshold, chunk floor up and down, chunk divisor,
round-aware quad gating, per-round transcript cost, dropping the skip probe, and the transpose.

## Update 27: ported bb's edge-loop shape — neutral. And a correction to the framing.

**Ported and measured.** bb's `compute_univariate` extends one fixed column set for every edge and
lets each relation's own `skip` gate only accumulation (`sumcheck_round.hpp:1098`); we rebuild the
active column set per edge (push/mark/unmark, per-column branch). Ported bb's shape behind
`BBREF_BB_SHAPED_EDGE`:

| | folding sumcheck | wall |
|---|---|---|
| ours | 0.816s | 6.41-6.43s |
| bb-shaped edge loop | 0.841s | 6.35-6.38s |

Slightly *worse* on the phase, wall difference is noise. Reverted. Ninth dead end.

**Correction to Update 25/26's framing.** I have been reporting "our later rounds are 2.4x bb's",
which invited a mechanism hunt round-by-round. The honest number is the total: folding sumcheck
**bb 0.619s vs ours 0.816s, 1.32x**. bb spends more of its total in round 0 (0.303 vs our 0.275)
and less afterwards (0.182 vs our 0.436); that is a different *distribution* of cost, and treating
the distribution as the defect sent me chasing later-round mechanisms three times.

**Also corrected:** bb is not doing range-based skipping instead of per-edge predicates. It does
both — ranges for the outer iteration *and* `Relation::skip` per edge, exactly as we do. Update 26's
"fundamental difference" claim was wrong too.

**What the numbers actually say now.** Relation evaluation is ~93% of our sumcheck CPU (round 0:
relations ~384ms vs extension ~29ms, thread-summed), dominated by relation 0 at 53%. But on the
matched dense rung our relation evaluation **beats** bb's (roundbench 2^17 MegaZK round 0: 285ms
vs 349ms, both plain `node`). So we are faster on the dense rung and 1.32x slower in the flow. The
deficit is configuration-dependent, not a raw arithmetic deficit, and nothing tried so far has
located what in the flow's configuration causes it.

Dead ends now nine: serial fold threshold, chunk floor up and down, chunk divisor, round-aware quad
gating, per-round transcript cost, dropping the skip probe, the per-group transpose, and bb's
edge-loop shape.

## Update 28: the flow's sumcheck deficit REPRODUCED in a 122ms rung

Built `examples/loopbench.rs`: the whole sumcheck round loop (not round 0 alone), with the two
knobs by which the flow differs from the old dense single-round rung — `active_pct` and bb's
fragmented block shape (`BBREF_FRAG=1` reproduces `make_active_blocks(fragmented=true)`: 18 active
blocks with gaps, 65% active). Matched against bb's `MegaZK/loop_static_blocks`, plain `node`, 8t.

| config | bb | bb-ref | ratio |
|---|---|---|---|
| 2^17 dense | 617ms | 586ms | 0.95x |
| 2^15 dense | 157ms | 158ms | 1.01x |
| 2^17 sparse (65%, 18 blocks) | 400ms | 412ms | 1.03x |
| **2^15 sparse** | **104ms** | **122ms** | **1.18x** |

**The deficit needs small size AND sparsity together.** At 2^17 we are at or ahead of bb in both
dense and sparse; at 2^15 dense we are level; only 2^15 sparse loses. The flow's instances are
2^13-2^16 (bb reports 16, 13, 15, 15 rounds) and its traces are fragmented, so the flow sits
squarely in the losing corner. The rung's rounds1+/round0 ratio there is 1.42, matching the flow's
1.4-1.6, so it reproduces the shape as well as the number.

**Ruled out along the way:**
- *Round count.* Every instance in a Chonk group runs the group's round count (24 for us) while bb
  runs each instance's own (13-16). Our extra rounds past `log_n` are free: 2^17 with
  virtual_log_n 17 / 20 / 24 costs 587 / 594 / 585ms.
- *Prover construction.* `RoundProver::new`, which does a trailing-zero scan over every column and
  which the rung excludes, is 0.004s in the whole flow.
- *Sparsity alone.* Sweeping `active_pct` at 2^17 (100/50/25/10% -> 586/318/185/107ms) scales
  cleanly with the active fraction.

**Why this matters more than the number.** Every previous hypothesis was tested against a 6.3s
flow where a 0.05s effect is noise; nine were rejected partly for that reason. The deficit now
reproduces in 122ms, so the next round of hypotheses can be tested properly.

To get bb's sparse MegaZK numbers, `register_flavor_benches<MegaZKFlavor>("MegaZKFrag",
fragmented=true, ...)` was added to bb's `sumcheck_iteration.bench.cpp`, built in the scratch
`build-wasm-bench` dir, and the bb source restored afterwards.

## Update 29: root cause of the sumcheck deficit — parallel efficiency, not arithmetic

Using the Update 28 rung (2^15, 65% active, fragmented — the flow's regime), thread sweep against
bb's `MegaZKFrag/loop_static_blocks/15`:

| threads | bb | bb-ref | bb speedup | our speedup |
|---|---|---|---|---|
| 1 | 789ms | 674ms | 1.00x | 1.00x |
| 2 | 405ms | 384ms | 1.95x | 1.76x |
| 4 | 203ms | 211ms | 3.88x | 3.20x |
| 8 | 103ms | 122ms | **7.67x** | **5.51x** |

**Single-threaded we are 15% faster than bb.** The entire deficit is parallel efficiency: bb scales
7.67x where we scale 5.51x. That is why the deficit needs small size — at 2^17 there is enough work
per round to hide it, at 2^15 there is not, and the flow's instances are 2^13-2^16.

**Confirmed by profile:** 26.7% of thread time in the rung is workers blocked on a condvar
(1.42s idle against 3.90s busy). Effective parallelism 8 x 0.733 = 5.86x, matching the measured
5.51x. The remaining busy time is ordinary field arithmetic (`mont_mul_261` 30%, graded relation
evaluation 20%, `accumulate_edge` 6.5%); the allocator is 5%.

**Fixes tried on the rung, all rejected:**
- Chunk floor 16 -> 8/4/2/1: 121.5 / 124.2 / 126.1 / 135.7 vs 124.4 baseline. Noise, then worse.
- Chunks per thread 16 -> 8/4/2/1: 124.2 / 128.8 / 117.8 / 119.5. `div=2` is ~4% better, the only
  positive result, and too small to be worth the knob.
- Running small rounds serially to dodge the pool wake-up: strictly worse at every threshold
  (64/256/1024/4096 edges -> 126.7 / 135.7 / 162.7 / 254.9 vs 123.2). Even a 1-2ms round repays
  the dispatch, so the idle is not avoidable wake-up latency.

**Also measured:** fragmentation itself costs ~10-12% at *both* 1 and 8 threads (2^15, 65%:
fragmented 673/123.6ms vs contiguous 613/110.2ms), so it is extra work — the last active block
reaches the end of the table, so the trimmed column spans everything — and not load imbalance.

**Where this leaves the sumcheck gap.** It is a round-barrier efficiency problem: 15 rounds, each a
separate parallel region, with shrinking work and a hard join between them. bb's schedulers
(`STATIC_BLOCKS`, `CHUNK_STEALING`) hold 7.67x through the same shape. Closing it means changing
how a round is scheduled, not what it computes — and the rung makes that measurable in 122ms.

## Update 30: bb's scheduler shape ported — no effect. Scaling gap confirmed by repetition.

**Retraction.** Update 29's follow-up claimed bb's `parallel_for_mutex_pool` shape was worth 7% on
the rung (122.9 -> 114.4ms) from two samples. Eight *paired interleaved* runs say otherwise:

| | median | mean | range |
|---|---|---|---|
| rayon `par_iter` | 122.2ms | 123.4ms | 120.9-127.8 |
| bb pool shape | 124.5ms | 124.8ms | 121.1-130.1 |

bb-pool wins 2 of 8 pairs; the paired median is 2.4ms *against* it. Reverted. Tenth dead end.

**The rung's noise band is ~6%, not the ~1.5% I assumed** from a few early runs. Nothing under
about 10% can be judged from single or paired samples here; it needs n>=8 interleaved.

**What was ported.** bb keeps one persistent pool of `get_num_cpus() - 1` workers and has the
calling thread work alongside them; iterations are claimed one at a time from a shared counter
under a mutex, so uneven per-chunk cost self-balances. We use rayon's split-and-steal over a fixed
list of 16*threads chunk starts with the caller blocked. Replicating bb's claiming changed nothing.

**Confirmed by repetition — the scaling gap is real** (2^15, 65% active, fragmented):

| | 1 thread | 8 threads | scaling |
|---|---|---|---|
| bb | 796ms (791-797) | 103ms (103/103/103) | 7.73x |
| bb-ref | 680ms (672-718) | 122.6ms (121-124) | 5.55x |

Single-threaded we are 15% faster than bb; at 8 threads we are 19% slower. That stands.

**What the failed port does and does not rule out.** It replaced the *work distribution* while
still running on rayon's pool, through `rayon::in_place_scope`, so rayon's sleep/wake policy was
never swapped out. It therefore refutes "the distribution shape is the problem" and leaves "rayon's
pool policy is the problem" untested. The distinguishing experiment is a scheduler that bypasses
rayon entirely (`std::thread::scope`, workers spinning rather than parking between rounds), which
is what bb effectively gets from its own pool.

## Update 31: bypassing rayon entirely — does NOT reach parity. It is not a rayon issue.

Ported bb's `parallel_for_mutex_pool` in full: a persistent pool of `threads - 1` std threads, the
calling thread working alongside them, iterations claimed one at a time from a counter under a
mutex, and a nested call falling back to serial. Not rayon's pool, not rayon's sleep/wake, not
rayon's split-and-steal. Proofs verified identical.

Eight paired interleaved runs, 2^15 / 65% active / fragmented / 8 threads:

| | median | mean | range |
|---|---|---|---|
| rayon `par_iter` | 123.0ms | 123.2ms | 122.1-124.8 |
| bb pool port | 122.5ms | 122.6ms | 122.2-123.2 |
| **bb itself** | **103ms** | | |

0.5%, wins 6/8 — neutral. The port is more *stable* (range 1.0ms vs 2.7ms) but no faster. **The
thread pool is not what separates us from bb.**

Also retested, properly this time: chunk count (128 vs 16 chunks) is neutral too — median 123.0 vs
123.2, wins 5/8. The "4% win from `div=2`" in Update 29 was noise, like the "7% win" in Update 30.
Both were single-sample readings inside a ~6% band.

**Where that leaves the scaling gap.** Confirmed real by repetition (1 thread: ours 680ms vs bb
796ms, we are 15% faster; 8 threads: ours 122.6ms vs bb 103ms, we are 19% slower; scaling 5.55x vs
7.73x). Amdahl on 5.55x implies ~5.6% serial per round against bb's ~0.4%. Now ruled out as the
serial part: pool policy, work distribution, chunk count, and the sequential combine of per-chunk
accumulators. The remaining candidate the profile points at is allocator contention — `dlmalloc`
plus `dlfree` were 5% of busy time, wasm's allocator is globally locked, and we allocate fresh
`Scratch` and `Accumulators` per chunk — but chunk count being neutral argues against allocation
*count* being the driver, so this is a hypothesis and not a finding.

Dead ends now eleven. The `bbpool.rs` port was removed after measuring; it is recoverable from
this commit's parent if the pool question is ever reopened.

## Update 32: the real mechanism — we pay a 39% parallel CPU tax, bb pays 10%

Differential profiling (same rung, 1 thread vs 8, summed busy CPU across all threads) finally
isolates it:

| | busy CPU 1t | busy CPU 8t | parallel tax |
|---|---|---|---|
| bb | 3.54s | 3.88s | **1.10x** |
| bb-ref | 2.21s | 3.07s | **1.39x** |

We do 39% *more total work* when we go parallel; bb does 10% more. That is the whole scaling gap,
and it is not idling — the extra shows up as busy time. At bb's tax our 8-thread number would be
~97ms against bb's 103ms.

**Landed fix: per-worker scratch instead of per-chunk.** `Accumulators` + `Scratch` are ~30KB
together and were built fresh for each of the ~16 chunks a worker handles, so every chunk started
cache-cold and went through the allocator (`dlmalloc`/`dlfree` went from 0.00s at 1 thread to
0.14s at 8). One set per worker, reused across its chunks:

| | median | range |
|---|---|---|
| per-chunk | 121.9ms | 120.2-130.9 |
| per-worker | 119.3ms | 117.8-120.9 |

**8/8 paired wins, 2.4%**, and the spread tightens. Parallel tax 1.39x -> 1.32x.

Also fixed: `relation_stats_enabled()` called `std::env::var_os` **per edge**. Cached in a
`LazyLock` — 7/8 wins, 0.5%. Small here because wasm's env access is not the contended lock it is
on native, but a per-edge environment lookup is wrong regardless.

**Rejected, each on 8 paired runs:**
- rayon `fold` instead of per-thread slots: *worse*, per-thread slots wins 8/8 by 2.5ms. The
  false-sharing theory about the slot mutexes was wrong; `fold` builds one accumulator per split
  job rather than per thread.
- Serial path for the row-disabling head (`trace_offset/2` = 2 edges): neutral, 3/8. rayon already
  runs a single-chunk dispatch inline.

**Flow effect is below noise, as expected:** the sumcheck loop is ~9% of the flow, so 2.4% of it is
~0.2% of the wall (6 paired runs: 2/6, inside noise). The rung is where this is measurable.

**Where the remaining tax is.** After the fix, `accumulate_edge` still costs 1.63x more CPU at 8
threads than at 1, and the graded relation ops 1.51x. That is per-call slowdown, i.e. memory, not
allocation or scheduling. The table is 46 separate column allocations and each edge touches one
cache line in each of them, so eight workers run ~368 concurrent streams. bb backs its
partially-evaluated multivariates with a single buffer. That is the next thing to try.

## Update 33: the residual is L3-domain locality, and bb is insensitive to it

The bench box is an AMD EPYC 9R14: 16 real cores, no SMT, and **64MB L3 in 2 instances** — two
8-core L3 domains. Pinning the whole run to one domain (`taskset -c 0-7`), 2^15 / 65% / fragmented
/ 8 threads:

| | free | pinned |
|---|---|---|
| bb-ref | 117.5 / 118.3 / 117.5 ms | **107.6 / 109.1 / 109.8 ms** |
| bb | 103 / 103 ms | 104 / 106 ms |

**We gain 8% from pinning; bb gains nothing.** Our workers straddle the two L3 domains and pay
cross-domain traffic for the shared table; bb's access pattern does not care. This is the uniform
per-call slowdown the differential profile showed (`accumulate_edge` 1.63x CPU at 8 threads), and
it closes roughly half the remaining 117 -> 103 gap.

**Ruled out on the way here, each measured rather than argued:**
- *Memory bandwidth.* Parallel speedup *improves* with table size (2.67x at 2^11, 4.19x at 2^13,
  5.52x at 2^15). A bandwidth-bound loop degrades as the table grows, so it is not bandwidth.
- *Dispatch cost.* A bare rayon dispatch measured directly (`examples/dispatchbench.rs`) is ~25us
  at 8 threads with real work. The round loop pays three per round, so ~75us/round against the
  ~2.5ms/round the round timings imply. Dispatch is 3% of the overhead, not the cause.
- *SMT.* The box has one thread per core, so there is no sibling contention.

**What this means.** The remaining gap is data movement, not scheduling, not the pool, not the
arithmetic (single-threaded we are 15% faster than bb). We keep 46 separate column allocations and
each edge touches one cache line in each; eight workers drive ~368 concurrent streams over a table
that is 48MB at 2^15, larger than one domain's 32MB L3. bb backs its partially-evaluated
multivariates with a single buffer. Reducing our footprint and stream count is the lever, and
affinity is not controllable from inside the module in production, so the fix has to be the layout.

## Update 34: where the sumcheck round stands, and what is left

Pinning gain is ~5-9% at every size (6MB, 12MB and 46MB tables alike), so the cross-domain cost is
**per-round synchronization traffic**, not the shared table exceeding a domain's L3. Reducing the
pool to match bb's thread count is not the answer either: best-of-3 at 2^15 sparse is 147.8ms at 6
threads, 131.8 at 7, 118.3 at 8 — we genuinely use all eight.

**State of the sumcheck round rung** (2^15, 65% active, fragmented, 8 threads):

| | value |
|---|---|
| bb | 103ms |
| bb-ref, start of session | 122-124ms |
| bb-ref, now | 118-119ms |
| bb-ref, pinned to one L3 domain | 107-109ms |
| bb-ref, single-threaded | 15% *faster* than bb |

**Landed this session**, both verified on 8 paired interleaved runs:
- Per-worker scratch instead of per-chunk: 2.4%, 8/8 wins, parallel CPU tax 1.39x -> 1.32x.
- `relation_stats_enabled()` no longer calls `std::env::var_os` per edge: 0.5%, 7/8 wins.

**Excluded as causes, each by measurement:** rayon's pool policy (a full port of bb's own pool is
neutral), work distribution shape, chunk count and floor, dispatch cost (~25us against ~2.5ms/round
implied), memory bandwidth (speedup improves with size), SMT (one thread per core), serial
sections (univariate and fold scale identically at ~5.5x), per-round transcript, and thread count.

**The one lead left** is the per-round synchronization traffic that pinning avoids. It is worth ~8%
and is not controllable from inside the module in production, so it has to be attacked by doing
less cross-thread work per round: fewer, larger parallel regions per round (currently three), or a
reduce that does not touch every worker's accumulator at the round boundary.

## Update 35: the pinning result, separated — both provers are L3-sensitive

Pinning to cores 0-7 confounds two things: it makes threads domain-local *and* halves available L3
(64MB -> 32MB). Pinning to 8 cores split across both domains separates them. 2^15 / 65% /
fragmented / 8 threads, best-of-3:

| | free | one domain (0-7) | split (0-3,8-11) |
|---|---|---|---|
| bb-ref | 117.6ms | **107.4ms** | 118.6ms |
| bb | 103ms | 103ms | 108ms |

**bb is not insensitive.** Split across domains costs bb ~5% too. The actual asymmetry is that
*unpinned*, bb performs like its one-domain number and we perform like our split number. So the
question is not "why does only bb-ref benefit" but "why do bb's threads end up domain-local when
ours do not".

**Thread count is not the answer**, though it looked like it. bb runs `cpus - 1` workers plus a
working main (8 OS threads for an 8-wide run); rayon blocks the caller, so we run 9. Matching bb's
shape made things *worse*, not better:

| configuration (unpinned) | time |
|---|---|
| 8 rayon workers + blocked main (9 threads, 8 working) | 116.1ms |
| 7 rayon workers + working main (8 threads, 8 working) | 121.2ms |
| 8 rayon workers + working main (9 threads, 9 working) | 111.8ms |

The last row is genuinely faster but uses nine workers against bb's eight, so it is not a parity
result — it is just more cores.

**Consequence for benchmarking: do not pin.** Pinning moves only our number, by ~8%, and would
report an improvement no user sees while hiding the very cross-domain behaviour we need to fix.
The published flow benchmarks stay unpinned; pinning stays a diagnostic, quoted as such.

Why bb's threads land domain-local unpinned is still unexplained. Both provers spawn their threads
through the same wasi-threads harness, and thread count is ruled out.

## Update 36: thread placement measured — the OS is NOT treating the two processes differently

Sampled `/proc/<pid>/task/*/stat` (field `processor`, weighted by the CPU each thread actually
burned) while each prover ran the 2^15 sparse rung unpinned:

| | cores 0-7 | cores 8-15 | distinct CPUs used |
|---|---|---|---|
| bb-ref | 49.0% | 51.0% | 13 |
| bb | 53.3% | 46.7% | 13 |

**Both are split ~50/50 across the two L3 domains and both float over 13 CPUs.** Update 35's
suggestion that bb's threads land domain-local while ours do not is wrong, and so is the thread
count explanation: matching bb's 8-OS-thread shape was measured worse (121.2ms vs 116.1ms).

So the asymmetry is not *where* the threads run — it is that our round loop loses more from running
there. bb free equals bb pinned (103/103); we lose 9% free vs pinned (117.6/107.4). Same placement,
different sensitivity.

**Persistent per-worker state: neutral.** Following the sensitivity to its obvious cause — a fresh
~30KB `Scratch`/`Accumulators` set per worker *per round*, which a migrating thread must fault back
in — the buffers were hoisted onto the prover and reused across all rounds, with `reset()` in place
of reallocation. 3/8 paired wins, median 1.0ms *against*. The zeroing costs about what the
allocation did. Reverted. Twelfth dead end.

**Benchmarking policy: do not pin.** Pinning moves only our number, by ~8%, so it would report a
gain no user sees and hide the behaviour under investigation. Unpinned stays the basis; pinning is
a diagnostic only.

## Update 37: hardware counters + per-round decomposition find it — the barrier idle is our own serial tail

**Clean `perf stat` (startup <5%), 2^15 sparse:**

| | IPC | instr/pass | cycles/pass |
|---|---|---|---|
| bb-ref 1t / 8t | 3.24 / 3.10 | 8.69G / 8.73G | 2.69G / 2.81G |
| bb 1t / 8t | 3.15 / 3.33 | 9.65G / 9.80G | 3.06G / 2.94G |

We execute *fewer* instructions and cycles than bb; neither prover does extra work at 8 threads
(instructions/pass flat) — the sampling profiler's "1.32x CPU tax" was an artefact. Cycles to wall
at 8 cores: ours ~95ms busy of 118 measured, bb ~99 of 103. **We idle ~23ms/pass, bb ~4.** Not IPC,
not contention, not work: threads waiting at round barriers.

**Per-round detail (`BBREF_ROUND_DETAIL`, per-worker busy spread) located the idle:**
- Rounds 7-11 ran on one worker (busy min 0, max = wall) because the chunk floor of 16 left 1-4
  chunks. Floor -> 1 now that per-worker scratch makes small chunks cheap: balance is perfect (r8
  busy 526-590us). Neutral on its own, because of the next item.
- **A constant ~800us per round above the slowest worker**, every round, inside the edges phase.
  That was `flush_graded` run serially over the 8 worker slots on the caller (~2600 Horner muls per
  slot) — the serial tail my per-worker-slots change created. 15 rounds x 0.8ms = 12ms/pass.

**Landed:** parallel flush over the slots. Rung **117.8 -> 113.4ms, 7/7 paired wins, 4.2%**; the
overhead above the slowest worker fell to ~340us/round. Also: chunk floor 1, serial 2-edge head,
serial fold for tiny tables, parallel `pows` doubling (the last neutral, dispatch-bound). Flow:
6.28 -> 6.21s, 4/4; folding sumcheck 0.812 -> 0.769s. 23 suites green, proofs identical.

**Remaining per pass at 8t (bb gap now 10.4ms):** residual dispatch above slowest worker ~340us x
15 = 5ms; `rest` (2-edge head incl. its own flush) ~250us x 15 = 4ms; `pows` ~2ms serial;
big-round per-worker busy inflation (r0 42.5ms vs 35.9 ideal) ~10ms — the only item that is not
a serial section, and the one matching the 4% IPC drop.

## Update 38: sumcheck round rung 122 -> 108ms; residual characterised

**Landed this pass** (all 8-pair interleaved, proofs identical, 23 suites green):
| change | rung | wins |
|---|---|---|
| per-worker scratch (per-chunk before) | 121.9 -> 119.3 | 8/8 |
| parallel graded flush | 117.8 -> 113.4 | 7/7 |
| one dispatch/round: head + flush fused, chunk floor 1, stride-reused `pows` | 112.4 -> 108.6 | 8/8 |
| 32 chunks/thread over 16 | 109.1 -> 107.2 | 6/6 |

bb: 103ms. Rung now **~1.05x**; pinned to one L3 domain **100.6ms, faster than bb**.

**Rejected on 8 pairs:** static round-robin striping (0/8 — mean busy improves 2% from L2 reuse, but
fragmented traces make stripes uneven, r0 spread 9ms); boxed slots against false sharing (3/7);
chunked parallel `pows` build (dispatch-bound); persistent cross-round scratch (3/8).

**Killed by static analysis before building:** row-parallel fold for cross-round row affinity — bb's
`partially_evaluate` is `parallel_for` over polynomials, i.e. column-parallel like ours. Active-range
iteration to skip gap rows — bb's static row manifest is ECCVM-only (`row_skip_active_prefix_end`),
Mega flavors scan rows with `skip_entire_row` like us; and measured gap-visit cost is 0.6-0.8%.

**The residual, with counters.** Clean `perf stat`: ours 1t IPC 3.46 / 8t 3.13; bb 3.15 / 3.33.
Instructions/pass flat for both (no extra work at 8t). We run a denser instruction stream than bb
(fewer instructions, higher IPC single-threaded) and it degrades ~10% at 8 threads where bb's
improves; pinning to one L3 domain recovers most of it (105.6 -> 100.6). Both provers read the
table identically, so this is the price of the denser stream paying proportionally more for the
same added cross-domain latency — not a scheduling defect, and not fixable from inside the module
short of a row-major table layout.

## Update 39: Oink and builder instrumented with bb's scope names; ECCVM anomalies located

Refreshed phase table (current build, 8t, median of 3): proving-only **1.22x (+1.067s)**, from 1.25x.
Folding sumcheck gap 0.254 -> 0.130s. Full 11-flow standing: TOTAL 1.05x, typical 1.10-1.21x.

**Oink was not at parity — a scoping artefact hid +0.175s.** bb's `OinkProver::prove` (0.972s)
includes the hiding kernel's oink (0.154s); ours reports that separately. Round by round (bb's
`commit_to_*` scopes wrap compute + commit):

| Oink round | bb | bb-ref | gap |
|---|---|---|---|
| wire commits | 0.346s | 0.449s | **+0.103** |
| lookup counts / w4 | 0.122s | 0.145s | +0.023 |
| logderiv inverses | 0.159s | 0.115s | -0.044 |
| z_perm (grand product + commit) | 0.308s | 0.404s | **+0.096** |

Both losses are commit-heavy while single MSMs beat bb. **Structural cause found by static
comparison:** bb's `batch_commit` is one `batch_multi_scalar_mul` over all polynomials (one pass over
the SRS points shared by K scalar streams); ours runs up to 8 *independent* MSMs concurrently, each
internally parallel. Concurrency count is not the lever (conc 1/2/4/8 -> wires 0.478/0.468/0.443/
0.447), so the fix is a genuinely batched Pippenger, as bb has. Parked as the next MSM item.

**Builder (+0.17s excl. witness decode, which bb counts elsewhere):** `acir::sha256_compression`
is **3x bb** (0.108 vs 0.036s) with identical gates (proof byte-equality), so it is construction
overhead in `stdlib/sha256`. `range_constraints` +0.022. `ecdsa_r1`, `poseidon2`, `msm` at parity.
~0.26s of ours is still unscoped (quads, blocks, recursion; bb's recursion is 0.123s).

**ECCVM (+0.337s): field ruled out, two anomalies found.** Fq throughput equals Fr on wasm
(52.1 vs 51.9 ns mul), so nothing ECCVM-wide is the field. Per-round detail on the ECCVM sumcheck:
`rest` (batch_over_relations + assembly) is **3.1-3.8ms per round**, serial, against 0.24ms for
MegaZK — ~48ms of the 289ms. And ECCVM's degree-21 set relation exceeds `GRADED_MAX_LEN = 8`, so it
falls to the pointwise path (every point evaluated separately) where bb's `ECCVMShortMonomialFlavor`
keeps all relations in coefficient form.

## Update 40: sha256 lowering 5.7x faster; bb's sumcheck internals instrumented and compared

**Landed: `map_into_sparse_form` precomputes base powers.** It recomputed `power *= base` — 32 field
multiplications — on every call, for every sparse table row and every lookup; the wasm profile put
66% of sha256 lowering in `mont_mul`. Powers are constants of the base (16/28 sha256, 11 keccak), so
they are built once and the map is at most 32 additions. `acir::sha256_compression` **0.108 ->
0.019s** (bb 0.036), `create_circuit` 0.690 -> 0.605s. Proofs identical, 23 suites green.

**bb's own sumcheck round instrumented** (`sumcheck/accumulate_edge_chunks`,
`sumcheck/extend_and_batch_univariates` added to `sumcheck_round.hpp` in the scratch build, source
restored) and compared scope-for-scope, all sumchecks summed, `time_max`:

| scope | bb | bb-ref | ratio |
|---|---|---|---|
| accumulate_edge_chunks | 0.933s | 1.008s | 1.08x |
| extend_and_batch_univariates | 0.036s | 0.072s | 2.02x |
| partially_evaluate (fold) | 0.172s | 0.096s | 0.56x |
| folding sumcheck | 0.632s | 0.744s | 1.18x |
| ECCVM relation-check rounds | 0.176s | 0.293s | 1.66x |

In aggregate our edge loop is within 8% of bb's and our fold is faster; the per-sumcheck skew is
distributional — we win the dense 2^17 joint sumcheck and lose the small/sparse folding and ECCVM
ones, consistent with the parallel-efficiency finding. `extend_and_batch` is 2x but small
(ECCVM's d = 22 makes it ~3ms/round there); parallelizing it over points was measured *worse*
(0.291 -> 0.335s ECCVM sumcheck, 3/3) and reverted.

**Oink concurrency:** independent-MSM concurrency count is not the lever (1/2/4/8 -> wire round
0.478/0.468/0.443/0.447). bb's advantage there is a single batched MSM pass; parked.

**Fq == Fr throughput on wasm** (52.1 vs 51.9 ns mul), so nothing ECCVM-wide is the field.

## Update 41: IPA rung — at parity; scope mismatch had overstated the gap

`examples/ipabench.rs` (classical IPA opening of a random 2^15 polynomial over Grumpkin) matched
to bb's `ipa_open/15`:

| | 1 thread | 8 threads |
|---|---|---|
| bb | 1691ms | 285ms |
| bb-ref | 1383ms | 290-297ms |

Single-threaded we are 18% faster; at 8 threads 1.03x. The same shape as sumcheck: our fold-G
scales 4.3x and the L/R MSMs 5.4x against bb's overall 5.9x. Split at 8t: L/R MSMs ~130ms,
fold-G ~156ms, inner products ~3ms. bb's `batch_two_round_fold` is 0.140s in the flow, so fold-G is
within ~16ms of bb; our fold already exploits the 127-bit short challenges (asserted) with a GLV
joint chain, as bb's does.

**Scope correction:** the earlier "+0.07s IPA" compared our `ECCVM::TripleIPA` (0.349s, which
includes claim assembly) with bb's `IPA::compute_opening_proof` (0.279s, the inner-product proof
only). Like for like — our `inner_product_prove` 0.305s vs 0.279s — the flow gap is **~+0.026s**.

**Rejected:** building the GLV phi table once per MSM when the caller supplies none (the IPA's
folded generators) instead of multiplying by beta per schedule entry: neutral, 0.351 -> 0.349s
TripleIPA, 3/3. Reverted.

## Update 42: commit profile — a ~1ms floor on tiny MSMs; wNAF path halves it

`BBREF_COMMIT_TIMING` on the flow (100 BN254 commits captured): 73 have <= 1024 nonzeros and cost
122ms of 643; a **9-point MSM with 7 nonzeros took 1.0ms**, the same as a 685-point one. Cause:
`serial_pippenger` uses c = 3 below 32 points, so it runs 86 windows of bucket reset, scan,
reduction and 3 doublings — ~2000 Jacobian ops for 7 points.

**Landed:** `tiny_msm_wnaf` for n <= 128 — width-5 wNAF per point over one shared doubling chain
(~254 doublings + ~59 ops per point). Means: 1-16 nnz 1.16 -> 0.58ms, 17-256 nnz 1.85 -> 1.47ms.
Proofs identical. Small in the flow (~23ms captured), kept because it is strictly better and the
tiny-commit count grows with circuit count.

**Oink wire round is not the tiny commits.** Our `batch_commit` (up to 8 concurrent independent
MSMs) versus sequential on a rung: K=10 at 2^13, 99 vs 119ms; at 2^15, 282 vs 289ms — concurrency
buys almost nothing at the flow's sizes, and the 2^17 hiding-kernel wires (78ms each) already beat
bb's `commit_random/17` (88ms). bb's tree shows where its batching pays:
`pippenger_round_parallel_batched/small_members` groups the small/sparse members into one pass
(12.6ms x 12) while large members run concurrently as ours do. Closing the wire round (+0.10s) and
the z_perm round (+0.10s) needs that batched pass — a real MSM implementation item, the largest
well-defined one left.

## Update 43: multilinear batching 0.295 -> 0.163s; median flow 1.10x -> 1.07x

`mlb_prove` has its own hand-rolled sumcheck and got none of the round-loop work. Scoped it:
setup 0.106 / sumcheck 0.173 / post 0.015 against bb's ~0.224 total.

**Landed:**
- Round 0 borrows the claims' own coefficient vectors (`Cow`) instead of padding copies of every
  polynomial up front; the first fold writes a fresh vector regardless. `eq_table` built in place
  with the large levels on the pool. Setup 0.106 -> 0.033s.
- Folds were column-by-column with only 3n columns (n = 2-3 claims), so ~2ms per column per round
  ran on one thread. Element-parallel fold. Sumcheck 0.173 -> 0.116s.

Proofs identical, 23 suites green. `Chonk::accumulate` 2.75 -> 2.63s.

**Scope corrections from this pass:** ECCVM trace construction is at parity (our
`ECCVMProver(CircuitBuilder&)` 0.120 includes row generation that bb counts outside its 0.068);
bb's `acir::recursion_constraints` 0.123 and `Chonk::complete_kernel_circuit_logic` 0.121 are
siblings, so our 0.175 covering both is *faster*. Real builder items left: `range_constraints`
0.038 vs 0.016, and ~0.06s unscoped.

**11-flow standing (unpinned, 8t):** TOTAL **0.99x**, typical 1.04-1.15x, **median 1.07x**
(from 1.10x at the start of this pass, 1.10-1.21x typical at session start).

## Update 44: sigma/id parallel (0.106 -> 0.053s); MAX_LEN=9 rejected; MSM stage parity re-confirmed

- `ProverInstance::from_builder` 0.227 -> 0.180s (bb 0.179): identity fill per wire on the pool,
  cycle links parallel over variables (each (wire,row) is in exactly one cycle). Proofs identical.
- `GRADED_MAX_LEN` 8 -> 9 to bring the ECCVM `Lookup` relation into coefficient form: ECCVM sumcheck
  0.287 -> 0.284s but folding sumcheck 0.772 -> 0.799s (3/3). Wider `Graded` costs more everywhere
  than it saves. Rejected.
- MSM stages compared on the plain-node flow data: schedule 0.91x, bucket partials 0.62x,
  reduce 0.99x, commit total 0.71x — we are faster at every stage. Single-MSM rung under plain
  node: 2^16 57.1 vs bb 57.5ms, 2^17 96.4 vs 90.6ms (bb's own run-to-run spread is 48.8-57.5 at
  2^16). MSM is not a lever. bb's `pippenger_batched.hpp` header also states its batch does NOT
  interleave MSMs — it runs single MSMs in sequence sharing only the GLV-doubled points — so the
  "batched MSM" item is withdrawn; the Oink wire-round +0.10 is still unexplained per instance.
- 11-flow standing: TOTAL 0.99x, median **1.07x**, typical 1.04-1.13x.

## Update 45: max-effort pass — median 1.10x -> 1.06x, proving 1.20x -> 1.15x

Landed this pass (all 8-pair or 3x verified, proofs byte-identical, 23 suites green):
| change | effect |
|---|---|
| multilinear batching: borrow round-0 columns, parallel eq_table, element-parallel fold | mlb 0.295 -> 0.163s (now 0.66x bb) |
| permutation polys (sigma/id) parallel over wires and cycles | from_builder 0.227 -> 0.180s (= bb) |
| blocked-parallel grand product (z_perm) | compute_grand_product 0.131 -> 0.103s |
| parallel batch inversion (batch_invert_par) for ECCVM + Oink denominators | neutral, kept for consistency |
| overlap ECCVM transcript/precompute/msm row construction (rayon::join) | ECCVM trace 0.122 -> 0.102s |

**11-flow standing (bbbench, best-of-3, plain node, 8t):** TOTAL 0.96x, mean 1.02x,
**median 1.063x** (sorted: 0.724 1.025 1.041 1.059 1.060 **1.063** 1.068 1.075 1.078 1.104 1.122).
storage_proof 0.72x (we win big); transfer/deploy cluster 1.04-1.12.

**Rejected on measurement:** GRADED_MAX_LEN 8->9 (wider Graded costs more than the ECCVM
coefficient-form saving); parallel batch_over_relations over subrelations (extra per-round barrier,
worse even at ECCVM's 159 subrelations); MSM dedup (we already win commit-total 0.71x, so it is not
the aggregate lever).

**Proving-only phase gaps (transfer_1, current build, +0.725s / 1.15x):**
| phase | gap |
|---|---|
| ECCVM | +0.308s (sumcheck +0.103) |
| fold: Oink (wire + z_perm commits) | +0.198s |
| fold: sumcheck | +0.117s |
| create_circuit | +0.092s |
| joint proof | +0.022s |
| multilinear batching | -0.066s (we win) |

**The path to median 1.05x (~0.05s off the median flow) is now architectural, not tuning:**
1. **ECCVM short-monomial sumcheck** (bb `USE_SHORT_MONOMIALS`, which the production
   `ECCVMProver` uses): our per-round `rest` is a fixed ~3.25ms x 15 rounds of per-subrelation
   barycentric extension (d=24 x 159 subrelations) that monomial-form accumulation avoids.
   CORRECTION (Update 46): bb's `loop_static_blocks/15` = 521ms is **round 0 only** (the bench
   constructs one `Round(round_size)` and never folds), so the earlier "bb full loop 521 vs ours
   1065" comparison was invalid; round 0 is 520 vs our 495 and bb has no full-loop rung.
2. **Oink wire-commit dedup** (bb Phase-A cluster dedup): the folding wire polys are ~50% duplicate
   scalars (61309 nnz / ~25000 distinct); bb pre-sums cluster points so Stage 6a sees ~half. Worth
   ~0.05-0.08s on the Oink round. ~500 lines of MSM code (hash clusters, batched-affine merge,
   schedule redirect bits).

Both are substantial ports rather than tuning; surfaced for a scope decision rather than started
unverified. Everything cheap-and-parallel has been taken.

## Update 46: coefficient-form batching (bb short monomials) — median 1.043x, target met

**Correction first:** bb's `ECCVMShort/loop_static_blocks/15` (521ms) is round 0 under a block
scheduler — the bench builds one `Round(round_size)` and never folds — so Update 45's "bb full loop
521 vs ours 1065" was invalid. Round 0 is bb 520 vs ours 495; bb has no full-loop rung. Production
bb does use `ECCVMShortMonomialFlavor` (`eccvm_prover.hpp:25`).

**What short monomials buy bb, located in our pipeline:** `flush_graded` evaluated each
coefficient-form `Graded` accumulator at `len` points, and `batch_over_relations` then re-extended
every subrelation to all d points by barycentric dot products — twice per round (main + head). At
d=24 x 159 subrelations that was a fixed ~3.25ms per round, every round, dominating rounds 7-14.

**Landed:** accumulators stay in coefficient form through `flush_graded` (slot k = coefficient of
X^k); batching multiplies each subrelation's coefficients by alpha and by the two *linear* factors
(pow = pe(1+(β−1)X), row-disabling l0+(l1−l0)X) in O(len), sums into one length-d coefficient vector,
and evaluates it once at 0..d−1. Pointwise relations (ECCVM `Set` 22, `Lookup` 9 > GRADED_MAX_LEN)
keep the barycentric path. Same polynomial, exact arithmetic: proofs byte-identical (5/5 acir, 23
suites). One bookkeeping trap: without row disabling the factors are the constants 1 and 0 and must
not grow the polynomial (non-ZK flavors size d = max partial + 1 — bb: BATCHED = MAX + 2 only for ZK).

| scope | before | after | bb |
|---|---|---|---|
| ECCVM rung `rest`/round | ~3250us | ~760us | — |
| ECCVM loop rung | 1065ms | 967ms | (no bb rung) |
| flow ECCVM sumcheck | 0.283s | 0.238s | 0.176 |
| flow folding sumcheck | 0.760s | 0.730s | 0.632 |
| flow `sumcheck/extend_and_batch` | 0.072s | 0.021s | 0.036 |
| `Chonk::accumulate` / `ChonkProve` | 2.57 / 2.45 | 2.51 / 2.39 | — |

**11-flow standing (bbbench, best-of-3, plain node, 8t):** TOTAL **0.964x**, mean 1.021x,
**median 1.043x** (session arc ~1.24x -> 1.10x -> 1.06x -> **1.04x**). Sorted:
0.708 1.019 1.025 1.039 1.040 1.043 1.045 1.056 1.062 1.094 1.101.

**Where the ECCVM sumcheck's remaining +0.06 lives (flow round detail):** edges 34ms + rest 0.9ms
of the 238ms scope — the rest is outside `univariate()`: 15 committed round univariates (tiny MSMs),
libra/ZK per round, transcript, folds, and round-0 column trimming. The deploy_tokenContract flows
(1.09-1.10) remain the tail.

## Update 47: the deploy tail was the builder — range 0.133 -> 0.032, classify 0.104 -> 0.042

Phase table on the worst flow (schnorr+deploy_tokenContract, 1.10x) against transfer_1 showed the
extra gap was **not** the fixed goblin tail (ECCVM was slightly better there) but `create_circuit`
(+0.207 vs +0.092) plus per-instance Oink/sumcheck scaling. The acir::* split then put it on two
scopes: `acir::range_constraints` 0.133 vs bb 0.043 (token contract is range-check heavy) and
`acir::classify` 0.104 (bb's whole `quad_constraints` is 0.029). A main-thread wasm profile made
both ~75-80% `mont_mul`.

**Causes (static, in code):**
- `create_limbed_range_constraint` did `Fr::from(2).pow_u64(shift)` six times per limb triple
  (accumulator update + gate scalings): ~350 muls per u128 check where bb does one conversion per
  coefficient. Fix: static table of 2^0..2^256. Range 0.133 -> 0.032s (now ahead of bb).
- `Expression` keeps coefficients as raw bytes and `field()` -> `from_bytes_be` went through ark's
  `from_be_bytes_mod_order`, whose full-width path reduces in several Montgomery muls. Canonical
  input (all ACIR coefficients, transcript elements) converts exactly with `from_bigint` (one mul);
  non-canonical falls back. classify 0.104 -> 0.042 (deploy), 0.065 -> 0.026 (transfer_1).

Both bit-identical (5/5 acir byte-exact, 23 suites). Builder totals: deploy 0.591 -> 0.421 (bb
0.385); transfer_1 0.541 -> 0.459 (bb 0.449).

**11-flow standing (bbbench, best-of-3, plain node, 8t):** TOTAL **0.944x**, mean **1.000x**,
**median 1.023x**. Sorted: 0.693 0.997 1.016 1.020 1.020 1.023 1.026 1.036 1.037 1.059 1.072.
Session arc ~1.24x -> 1.10x -> 1.06x -> 1.04x -> **1.02x**.

**Remaining tail (deploy_tokenContract 1.06-1.07x):** per-instance items that scale with the app
circuit — Oink wire round +0.15 (bb's Phase-A duplicate-scalar dedup; wire polys are ~50% duplicate
scalars) and folding sumcheck +0.14 (small-instance parallel efficiency). Fixed goblin tail is at
or near parity (ECCVM sumcheck's remaining +0.06 is outside the edge loop: per-round commits,
libra/ZK, transcript, round-0 trimming).

## Update 48: the wasm work carried to native — native median 0.99x bb, 9% faster than before

Native, bbbench (16-core EPYC 9R14), 8 threads, best-of-3, all 11 pinned flows. "before" is
commit 26a79f0 (parent of the first perf commit of the wasm push), "after" is HEAD (2c49cdb);
both built here with the repo's default flags (+bmi2,+adx) and copied to the box; bb is the pinned
native binary (`~/bb-ref/bin/bb`, HARDWARE_CONCURRENCY=8).

| | bb | before | after |
|---|---|---|---|
| TOTAL (11 flows) | 44.7s | 47.0s | **42.7s** |
| after / bb | | | **0.954x** (median 0.993x) |
| after / before | | | **0.909x** (median 0.909x; every flow 0.895-0.930) |

Per flow after/bb: 0.81 (storage_proof) .. 1.02 (amm); the deploy_tokenContract flows are 1.01.
Last native standing before this push was 1.16x (2026-09-03, 62c865b). The optimizations were all
serial-work removal or serial->parallel (sumcheck round loop, mlb, sigma/id, grand product, ECCVM
rows, range/classify arithmetic, coefficient-form batching), none wasm-specific, so they transfer.

## Update 49: the target is proving speed — reconciled to 1.10x; fair wall basis; flags; binaries

**Correction of the headline.** The 1.05x goal was for *proving* speed. Wall (median 1.023x
against the unstripped bb module) nets bb's self-verify and module load against us. Re-measured
on the fair bases:

| basis (bbbench, 8t, best-of-3) | median | TOTAL |
|---|---|---|
| wall, unstripped 123 MB bb module, opt-level-2 build | 1.023x | 0.944x |
| wall, **stripped** 18 MB bb module (fair), opt-level-2 build | **1.048x** | 0.956x |
| wall, stripped bb, `--profile lto` build (opt3 + fat LTO + cgu1) | **1.035x** | 0.945x |
| **proving-only**, transfer_1, current build | | **1.102x** (5.33 vs 4.84s, +0.49s) |

**Binary sizes, precisely.** bb.wasm 122.9 MB on disk = 17.15 MB code + 100 MB `name` section +
5 MB DWARF; stripping it makes bb 0.10-0.13 s/flow faster (2%), which is the 1.023 -> 1.048
difference. Ours 11.4 MB / 9.3 MB code. The native reference is **bb-avm** (`--help`: AVM enabled;
206 MB executable sections, 270 MB on disk) vs our 18.5 MB text; startup 5 ms both, so native
comparisons are unaffected. The wasm reference is vanilla bb (no AVM).

**Flags A/B (transfer_1, interleaved x4, proofs identical):** opt-level 3 alone neutral (5.675 vs
5.678); **opt3 + fat LTO + codegen-units=1: -1.3%, 4/4** (5.603) — adopted as `[profile.lto]`
for release wasm builds; **`wasm-opt -O3`: +11% slower** (6.33) — rejected; native opt-level 3
neutral-to-worse (2.94 -> 2.98). No "dumb flag" explains the gap.

**Rollup corpus, bbbench 16t, serial replay:** bb 298.6s, before this pass 291.9s, **after
258.3s** — after/before **0.885x**, after/bb **0.865x**; every circuit over a second 0.79-0.99x;
the sub-second ops remain 1.08-1.24x. Native frames 8t: PTBR 15.19/14.82/**13.73**, RootRollup
49.5/45.4/**42.6** (bb/before/after).

**Landed:** Lagrange basis cached for committed round univariates (`eccvm-sc/commit` 0.030 ->
0.020; ECCVM sumcheck 0.235 -> 0.222).

**Reconciled proving gap, transfer_1 (+0.49s), children summed against parents on both sides:**
| item | gap | note |
|---|---|---|
| Oink `commit_to_wires` | +0.117 | high-duplicate witness scalars (bb Phase-A dedup) |
| folding `prove_sumcheck` (6 instances) | +0.101 | our scope pairs with bb `sumcheck` 0.628 alone |
| ECCVM like-for-like | +0.169 | sumcheck +0.047 (edge loop 166 ms — pointwise Set/Lookup), wires +0.043, IPA +0.026, PCS/claims ~+0.05 |
| decider (Shplemini/KZG on the accumulator) | +0.05-0.07 | ours 0.346-0.370 vs 0.302 |
| multilinear batching | +0.038 | pairs with bb `finalize` 0.125 (construct_proof is its child) |
| hiding oink / from_builder / create_circuit / joint | +0.028 / +0.021 / +0.014 / +0.012 | |
| wins | | output_to_accumulator -0.055, logderiv -0.088, z_perm -0.030, partially_evaluate -0.075 |

Two attribution errors caught this pass: the "ECCVM edge loop is 34 ms" row was one of two other
15-round 2^15 sumchecks (the ECCVM's is 166 ms), and pairing our folding scope against bb's
`sumcheck + sumcheck_output_to_accumulator` briefly made the folding gap look like a win.

## Update 50: decider split — Gemini evaluation parallel; two neutral probes

Scoped `decider_prove`/`shplemini_prove` with bb's names. Against bb (flow totals):
Shplonk 0.258 vs 0.258 (parity), KZG parity, Gemini ours 0.32 vs bb 0.299 — the excess was
`Gemini::evaluations` 0.060 (serial Horner over 2^17 six times per call) and fold clones.
**Landed:** `Polynomial::evaluate_par` (chunk-wise Horner, recombined with z^L) and clone-free
folds: evaluations 0.060 -> 0.020, folds 0.015 -> 0.011, decider 0.357 -> 0.343, joint 1.022 ->
1.006 (3/3, byte-identical). Our Gemini is now 0.28 vs bb 0.30.

**Neutral, reverted/recorded:** (a) single-threaded small MSMs inside `batch_commit` (bb's
small-member pool shape) — ECCVM wires 0.220 -> 0.220, Oink wires 0.44 -> 0.44; rayon already
handled the nesting. (b) tiny-MSM wNAF threshold 128/512/2048/4096 — ECCVM wire round flat at
0.220-0.227; the ECCVM wire round's +0.043 is not the small-MSM algorithm.

**Proving-only now ~1.09x** (transfer_1 ≈ 5.30 vs 4.84 s). Remaining, by size: ECCVM +0.17
(sumcheck +0.047 with pointwise Set/Lookup, wires +0.043, IPA +0.026, PCS/claims ~+0.05), Oink
wire round +0.117 (dedup), folding prove_sumcheck +0.10, mlb +0.038, hiding oink +0.028,
from_builder +0.021, decider ~+0.03.

## Update 51: wide ECCVM path + dedup — wall parity (median 1.002x fair basis), proving 1.060x

**Landed:** (a) `Graded<F, N>` with a wide (24) variant used only by the ECCVM's set (22) and
lookup (9) relations: dense ECCVM round 0 495 -> 206 ms (bb 520), flow ECCVM sumcheck
0.227 -> 0.168 (bb 0.176). (b) Duplicate-scalar pre-pass in `commit` (sampling-gated):
`commit_to_wires` 0.445 -> 0.39. Both byte-identical, 23 suites.

**Standing, HEAD `--profile lto`, bbbench 8t, best-of-3, vs stripped bb:**
| | |
|---|---|
| wall median | **1.002x** (0.669 0.980 0.995 0.996 0.998 **1.002** 1.005 1.011 1.011 1.041 1.045) |
| wall TOTAL / mean | **0.920x** / 0.978x |
| proving-only, transfer_1 | **5.126 s vs 4.837 = 1.060x** (target 1.05 = 5.08 s) |

Folding sumcheck split (`sc/*`, 6 instances, 144 rounds): univariate 0.622 (edges ~0.575 + per-round
rest/pows ~0.045), fold 0.088 (bb 0.172 for all folds), challenge 0.014, new 0.001. bb 0.628 total.
Remaining named items: Oink wires ~+0.07 (merge is projective; bb's is batched-affine), folding
univariate ~+0.09, ECCVM wires +0.043 (86 polys of <= 3141 rows, below the dedup gate), IPA +0.026,
mlb +0.038, hiding oink +0.028, from_builder +0.021, decider ~+0.03.

## Update 52: definitive standing on df6b253 — wall parity; proving 1.061x

bbbench, 8t, `--profile lto` module, bb re-measured the same hour:
| | |
|---|---|
| proving-only, transfer_1 (5 reps: 5.106-5.120) | **5.114 s vs bb 4.821 = 1.061x** (target 1.05 = 5.06 s) |
| wall vs stripped bb, 11 flows best-of-3 | **median 1.000x**, TOTAL 0.917x, mean 0.974x; sorted 0.670 0.978 0.993 0.996 0.999 1.000 1.004 1.004 1.036 1.037 |

Landed since Update 51: dedup gate 512 (ECCVM wires 0.207 -> 0.190), strided `pows` view (neutral).
Remaining named proving items (~+0.29 s): folding univariate ~+0.09, Oink wires ~+0.07 (projective
merge), ECCVM IPA +0.026 / PCS ~+0.05, mlb +0.038, hiding oink +0.028, from_builder +0.021,
decider ~+0.03.

## Update 53: per-relation graded rung; affine cluster merge; proving 1.059x

**Graded per-edge rung vs bb's `relations_bench` univariate form (1t, ns/edge):** Arithmetic 4573
vs 8718 (0.52x), Bus 4640 vs 4938 (0.94x), Memory 13824 vs 14072 (0.98x), DeltaRange 6221 vs
6406 (0.97x), Elliptic 7599 vs 9234 (0.82x), EccOpQueue 2503 vs 3216 (0.78x), Poseidon2External
9051 vs 10869 (0.83x); **Permutation 6029 vs 4233 (1.42x)**, Poseidon2QuadInternalTerminal 16147
vs 13258 (1.22x), Poseidon2QuadInternal 22929 vs 21234 (1.08x). Permutation is active on every
row: it is the folding sumcheck's per-edge outlier. Its multiplication count matches bb's algebra
(~90), so the excess is `Graded`'s fixed `[F; 8]` moves (264 B per temporary vs bb's exact-sized
64-160 B) — the structural item, not a body bug.

**Neutral (reverted):** slice-iterating the `Graded` inner loops to remove per-coefficient bounds
checks — Permutation 6029 -> 6167, flow unchanged; LLVM had already elided them.

**Landed:** batched-affine cluster merge in the dedup pre-pass (one Montgomery-trick inversion per
tree level): `commit_to_wires` 0.39 -> 0.37 s (3/3), byte-identical.

**Proving-only, transfer_1, HEAD lto (5 reps 5.061-5.115): median 5.105 s = 1.059x vs bb 4.821
(same-hour), 1.055x vs 4.837.** Remaining named items are each <= 0.03 s: Permutation copy traffic,
Oink wire remainder, mlb setup, hiding oink (2^17 MSM 1.06x), IPA, decider, from_builder, ECCVM
PCS/claims. The next real step is exact-size (degree-typed) univariates for the relation bodies.

**Update 53 addendum — neutral (reverted):** in-place `MulAssign` (downward convolution, no
temporary) plus a `*=`-chained Permutation body: Permutation 6029 -> 6181 ns/edge, flow unchanged.
The Permutation excess (1.46x bb) is therefore neither bounds checks nor temporaries; bb's
coefficient-basis products are algebraically cheaper (short-product formulas), which is the same
exact-size-univariate item. **Complexity note on the affine merge (#38):** +70/−20 lines of
tree-reduction bookkeeping for 0.02 s (0.4% of proving) — a weak ratio; the 15-line projective merge
already gave 0.05 of the dedup's 0.07. Candidate for reverting on the gain-for-complexity rule.

**Update 53 — affine merge reverted (Charlie's call, gain-for-complexity): `commit_dedup` keeps the
15-line projective merge; R25 records the 0.02 s / +70 lines trade.**

## Update 54: Karatsuba short products; the re-association trap

`Graded::mul` uses Karatsuba for 2x2 (3 muls) and 3x3 (6 muls) products — bb's
`UnivariateCoefficientBasis` exists only at lengths 2 and 3 and does exactly this (`static_assert
(LENGTH == 2 || LENGTH == 3)`), converting back to evaluation form for higher degrees. Rung: Arithmetic
4573 -> 3976, DeltaRange 6221 -> 5596, Memory 13824 -> 13080, Pos2External 9051 -> 8613 ns/edge;
flow folding sumcheck 0.733 -> 0.720, ECCVM 0.170 -> 0.166 (3/3, byte-identical).

**Trap (R26):** re-associating the Permutation body as `(t1·t2)·(t3·t4)` (to hit the 3x3 Karatsuba,
bb-equivalent 12 muls vs the chain's 17) was byte-identical for the prover but **changed the
circuit**: the relation bodies are shared with the in-circuit recursive verifier, whose gate sequence
must match bb's left-to-right chain — the pinned VKs failed (`mock_protocol_vks_match_bb`). Any
prover-side algebraic restructuring of a relation body must be gated to non-circuit `T`, or the
verifier path must keep bb's operation order.

Why Permutation stays 1.43x bb: bb's hybrid multiplies the first two linear factors in coefficient
form and continues in evaluation form at LENGTH points (a degree-4 x linear product costs 6 muls
there vs our schoolbook 10). Reproducing it means a hybrid univariate type — a design change, not a
tweak.

## Update 55: tables of record regenerated; prover-gated Permutation pairing

`bench-results/{chonk,chonk-v8,corpus}.txt` regenerated at def1d24 with wall and proving-only
columns (tools/bench_chonk*.sh gained `--reps`, instrumented proving runs and both ratios). bbbench,
8t: **native wall 0.92x, native proving 0.96x** (per flow 0.98-1.02x); **wasm/V8 wall 0.91x
(fair stripped-module basis, median 1.00x), proving 0.96x total, per flow 1.04-1.12x (median ~1.06x)**;
corpus 16t **0.86x** vs bb (0.876x vs the pre-push binary). chonk-wasmtime.txt marked stale (no
wasmtime on the box).

**R26 resolved, landed as #40:** bb's Permutation body pairs the factors *only for prover
accumulators* (`if constexpr (IsProverAccumulator)`) and chains them for the verifier. Same split
here via `FieldLike::IS_PROVER`: Permutation 6033 -> 5487 ns/edge, folding sumcheck 0.720 -> 0.710
(3/3), VKs and proofs unchanged.

Remaining per-edge excess (Permutation 1.30x, Poseidon2 internals 1.07-1.21x, ECCVM Set's long
coefficient products) is the representation item: bb evaluates degree > 2 products pointwise at
LENGTH points (a degree-4 x linear product costs 6 muls, our schoolbook 10). Next: a hybrid
`Graded` that switches to evaluation form above length 3 (bb's shape), converting back at flush.

## Update 56: the hybrid coefficient/evaluation `Graded` (bb's shape) measured WORSE — reverted (R27)

Implemented bb's representation dynamically: coefficient form to length 3 (Karatsuba 2x2), then
evaluation form at the relation's partial length (thread-local k set per relation call; forward-
difference conversion; pointwise products; evaluation-form accumulators interpolated back to
coefficients at flush with per-sumcheck Lagrange bases). Byte-identical (5/5 acir, 23 suites) and
slower on every relation: Permutation 5487 -> 5963 ns/edge, Bus 4635 -> 5522 (+19%), Memory
13080 -> 15061, Poseidon2QuadInternal 22653 -> 26946, ECCVM dense round 0 206 -> 224 ms; flow
folding sumcheck 0.709 -> 0.764, ECCVM 0.164 -> 0.201 (3/3).

**Why:** the saved multiplications (a degree-4 x linear product at 6 points vs schoolbook 10) are
outweighed by per-operation mode branches, `to_evals` copies of the full capacity array, k-wide
additions where coefficient form adds 2-3 entries, and the flush interpolation. bb's hybrid is
statically typed (`Univariate<FF, LENGTH>` / `UnivariateCoefficientBasis<FF, 2|3>` chosen at compile
time, no copies, no branches) — not reproducible on stable Rust without `generic_const_exprs`.
The remaining per-edge excess (Permutation 1.30x, Poseidon2 internals 1.07-1.21x) therefore stays
unless bodies are hand-specialized for the prover type, which the minimality rule argues against.
Item #3 of the "beat bb" list is closed as not viable in this form.

## Update 57: dead-code deletion (2026-09-07)

Deleted with no behaviour change — unit (73), `acir` byte-exact (5) and every integration suite
green; native, wasm+`bbkernel` and plain-wasm builds warning-free:

- `honk/quadf/` (the QuadF 4-lane sumcheck plane of R1, default-off since ea0d4e1) with its
  `accumulate_edges_quad` branch, probe counters and `BBREF_QUAD_*` switches; the live `QuadConsts`
  marker moved to `base/quadconsts.rs`.
- `base/mont29.rs` (1,661 lines): the portable 9×29 reference the vendored `wasm_mont` kernel was
  straight-lined from, no caller since 0c7a8d9. Its `fr_matches_ark`/`fq_matches_ark` tests went with
  it; in their place, the end-to-end check: the wasm build (`bbkernel`, simd128, 8 threads under node)
  and the native build produce byte-identical `proof` (80,064 B) and `vk` for
  `ecdsar1+transfer_0_recursions+sponsored_fpc` with `BB_RNG_SEED=12345` — sha256 a5a1588b8db111da…
  on both — so the vendored 29-bit kernel, `quad261` MSM path and bb kernels agree with the 64-bit
  native field on a full flow.
- In the vendored ark-ff: `quad256::mont_mul` (540 lines, the 2^256-domain SIMD multiply superseded
  by `quad261`) and five `#[inline(always)]` on required trait methods (no-ops rustc warns about).
- Examples `quadbench`, `relshape`, `msmmodel`; `ab.sh l0` runs `fieldbench` instead.
- 20 zero-caller functions (`all_polys`, `to_hex`, `read_fields`/`write_fields`, `instance_and_ck`,
  `to_public_inputs`, ...), the transcript `Manifest` recorder and the round tracking that only fed
  it, 22 unused imports, two dead `PackedScratch` fields.

Net: `45 files changed, 48 insertions(+), 3569 deletions(-)`; `tools/loc.sh` 44,278 code lines = 18.2% of bb-with-tests (19.1% at Update 55),
23.0% `--no-tests` (24.3%). The vendored crate is 11,715 lines (1,441 over upstream 0.6.0);
what the delta is and what it would take to drop it is now written up in `docs/performance.md`
("Why ark-ff is vendored").

## Update 58: is the ark-ff fork needed? The inlining half, measured (2026-09-07)

Question: can bb-ref reach the same performance extending ark idiomatically, with no vendoring? The
fork has two halves — (a) `#[inline(always)]` on ark's wrapper layers, (b) the wasm kernel and its
2^261 stored domain. (a) is measurable without building anything new: a worktree with upstream's
`arithmetic.rs`/`fp/mod.rs` restored and the kernel kept.

`ecdsar1+transfer_0_recursions+sponsored_fpc`, 8 threads pinned to cores 0-7 of the local 192-core
box, `perf stat -e instructions,cycles`, best of 2. Wall here is ±15% run to run and useless for a
3% question; instruction counts are the signal (cycles swing ±6% and even move the other way on wasm).

| variant | native instr | `call mul_assign` sites | binary | wasm host instr | module |
|---|---|---|---|---|---|
| A: fork as committed | 129.5 G | 43 | 17.1 MB | 341.2 G | 11.3 MB |
| B: upstream attrs, kernel kept | 133.7 G (+3.2%) | 608 | 15.8 MB | 342.6 G (+0.4%) | 11.1 MB |
| C: B + `-C llvm-args=-inline-threshold=1000` | 131.0 G (+1.2%) | 548 | 20.9 MB | 346.2 G (+1.5%) | 16.2 MB |
| D: A + the same threshold | 129.5 G | 51 | 21.0 MB | — | — |

All four write the identical proof (sha256 a5a1588b8db1…). Reading: the attributes are worth ~3%
native instructions on this flow (the −31G at 98f541d was a rollup merge op — same direction, the
magnitude is flow-dependent) and nothing on wasm, where the wrappers evidently already inline or cost
nothing under V8. The threshold flag recovers two thirds natively for +33% code and hurts wasm.

(b) was not built. From the code: every runtime hook the fork adds (`R`, `R2`, `mul_assign`,
`square_in_place`, `sum_of_products`, `inverse`, `from_bigint`, `into_bigint`) is an overridable
`MontConfig` item, so an own `impl MontConfig<4>` in bb-ref can carry the kernel with ark-ff untouched,
at the price of own field types and therefore own BN254/Grumpkin curve and pairing configs (~600
lines of constants) and re-pointing the direct `ark_bn254::` uses. The one unreachable piece is the
`Fp::new` const path (the fork adds a `shl5_mod` so `MontFp!` constants land in 2^261): without the
fork, store in the 2^256 domain on wasm or define constants as raw limbs.

Verdict: for the wasm goal the attribute half buys nothing and the kernel half can live in bb-ref
behind `MontConfig`; natively the attributes are worth ~3% instructions, ~2% of which a build flag
recovers. The fork is a convenience, not a requirement. Spike left to do: the own-`MontConfig` port,
gated on the byte-exact suites, the wasm/native proof `cmp` and a same-session wasm A/B.

## Update 59: what `bbkernel` is worth today (2026-09-07)

Revisiting `csrc/bb_kernel.cpp` — bb's `VectorField` kernels compiled with the wasi-sdk from the bb
checkout and linked in (MSM stage-6a drain, packed-tree drain, IPA fold passes, axpy/chords). Same
flow and harness as Update 58; 8 rayon threads pinned to 16 cores (node's own threads need the
headroom — on 8 cores identical runs were bimodal, 304 vs 341 G); `node --no-liftoff` so V8 compiles
TurboFan-only and instruction counts are deterministic (dynamic tiering varied ±5% between identical
runs; the up-front compile adds ~45 G and ~3 s to every variant alike). Identical proofs throughout.

| module / switch | instr | cycles | cpu | wall best |
|---|---|---|---|---|
| bbkernel module, C 6a drain (the benchmarked build) | 388.5 G | 140.9 G | 39.4 s | 9.66 s |
| bbkernel module, `BBREF_NO_C6A=1` (Rust drain; C fold/axpy kept) | 388.8 G (+0.1%) | 144.6 G | 40.4 s (+2.5%) | 9.92 s |
| plain module, no `bbkernel` (pure Rust: `quad261` kernels throughout) | 392.1 G (+0.9%) | 142.6 G | 39.8 s (+1.0%) | 9.75 s (+0.9%) |

Production shape (dynamic tiering, 16 cores): 341.2 / 343.3 / 335.5 G and 6.29 / 6.25 / 6.37 s —
the same within noise. When the route landed (Updates 2–3) it was the answer to the mul gap; since
then the Rust `quad261` port of bb's kernel (971a1e6), the packed drain (#10), dedup (#37) and the
tiny-MSM paths took the same ground from the Rust side, and the C object now buys ~1% on this flow.
Its cost: 676 lines of C++ glue plus bb's `vector_field_wasm.cpp` compiled at build time (a hard
dependency on the bb source checkout and `/opt/wasi-sdk`), build.rs, the Rust bindings, and 26 of
the 48 wasm `cfg` sites (`feature = "bbkernel"` in fold.rs, msm.rs, packed.rs). Not re-measured on
bbbench (box stopped): confirm across the 11 flows there before deleting if the last 1% matters.

## Update 60: `bbkernel` removed (2026-09-07)

Acting on Update 59. Gone: `csrc/bb_kernel.cpp` (676 lines) and the stale `bb_kernel.o`, `build.rs`
(the wasi-sdk compile of bb's `vector_field_wasm.cpp`), the `bbkernel` feature, the FFI module in
`packed.rs`, `drain_bbk` and the C stage-6a gather in `msm.rs`, `pass_add_bbk`/`pass_dbl_bbk` and
their scratch in `fold.rs`, the `BBREF_NO_C6A` switch, the two C-kernel tests, `examples/chordbench.rs`
and the `ab.sh drain` rung — 833 lines of Rust plus the C. bb-ref no longer needs the bb checkout or
`/opt/wasi-sdk` to build any target. 26 of the 48 wasm `cfg` sites went with it (22 remain: the packed
tree, the 2^261 SRS fix-ups, `quadconsts`, three `try_*` dispatches, two module gates).

Same harness as Update 59 (`--no-liftoff`, 8 rayon threads on cores 0-15, perf, best of 3; the native
suite was running on the other cores at the time, so wall is noisier than instructions):

| module | instr | cycles | cpu | wall best |
|---|---|---|---|---|
| baseline: `bbkernel` module of b273bd1 | 388.2 G | 143.6 G | 40.2 s | 10.03 s |
| this commit: no C kernels | 391.3 G (+0.8%) | 145.8 G | 40.7 s (+1.2%) | 10.10 s |

Proofs identical across baseline wasm, new wasm and native. Not re-measured on bbbench (box stopped).

## Update 61: the wasm special-casing gathered into `base/wasm` (2026-09-07)

Everything wasm-specific now lives in `src/base/wasm/`: `mod.rs` holds the stored-domain and
GLV-table constants, the SRS-cache domain conversion, the MSM chunk default and the only `cfg`
lines in the tree — five, selecting `packed.rs` + `tree.rs` on wasm+simd128 or `fallback.rs`
elsewhere; `packed.rs` is the streaming `axpy`/fold kernels plus the per-field kernel constants
(formerly `base/packed.rs` + `base/quadconsts.rs`); `tree.rs` is the packed MSM tree drain
(formerly `msm::packed_tree`); `fallback.rs` carries the same names with `false`/`None`/no-op
bodies, `#[inline(always)]`. `msm.rs`, `srs.rs`, `poly.rs`, `sumcheck.rs` and `group.rs` carry no
`cfg` at all: `TreeScratch` owns a `PackedTree` on every target and asks it `try_reduce` before
the scalar tree; the SRS loader asks for the domain multiplier and gets `None` natively. Non-simd
wasm builds keep the 2^261 fix-ups through the `cfg!(target_family = "wasm")` constants.

Repo-wide wasm `cfg` sites: 48 (Update 59) → 22 (Update 60) → 5 in `wasm/mod.rs` plus the
allocator choice in the binary. Behaviour-identical by construction and measured anyway: the
step-1 and step-2 modules execute 392.6 vs 393.0 G instructions on the flow (noise), proofs
identical (wasm == native), native suite green, the moved kernels' unit test green under wasmtime.

## Update 62: the vendored ark-ff retired — own `MontConfig` for the wasm field (2026-09-07)

Step 3 of the plan from Update 59. Natively nothing moved: `Fr`/`Fq`/`G1Config`/`GrumpkinConfig` are
arkworks' own configs (`base/wasm/mod.rs` re-exports them off-wasm; the aliases in `base/field.rs`
and `base/group.rs` point there), so `Fr` *is* `ark_bn254::Fr` and the `asm` feature is untouched.
On wasm the same aliases resolve to bb-ref's own `impl MontConfig<4>` for Fr and Fq
(`base/wasm/field.rs`) — the 2^261 stored domain, bb's 9×29-bit multiply (`mont29.rs`, moved from
the vendored crate minus its unused 2^256 variant) behind `mul_assign`/`square_in_place`/
`sum_of_products`/`inverse`/`from_bigint`/`into_bigint` — and own BN254-G1 (with GLV) and Grumpkin
`SWCurveConfig`s over them (`curves.rs`). The one thing the fork patched that an impl cannot reach,
arkworks' const-context constructor (`Fp::new`, hence `MontFp!`), is handled by `R2 = 2^517 mod p`:
that constructor multiplies by `R2` and divides by 2^256, so constants land in the 2^261 form; the
runtime users of `R2` (`from_bigint`, `inverse`) are overridden to `2^522 mod p`. G2 stays
arkworks' type; `pairing_check` moves G1 points across through canonical coordinates. Sixty direct
`ark_bn254::`/`ark_grumpkin::` uses now go through the base aliases. `vendor/ark-ff` (11,715 lines)
and the `[patch]` are gone; Cargo.lock relocates one package to crates.io.

Correctness: native suite green (23 suites); the module's own tests cross-check every operation and
constant (generator, two-adic root, large-subgroup root, curve constants, scalar multiplication)
against arkworks' bn254/grumpkin types through canonical integers, under wasmtime (6 tests); the
wasm flow proof **and vk are byte-identical** to native and to the step-2 module.

Performance, same harness as Updates 58–61 (`ecdsar1+transfer_0`, 8 threads, perf, best of 3):

| build | instr | cycles | cpu | wall best | size |
|---|---|---|---|---|---|
| wasm, step 2 (vendored ark-ff, forced attrs) | 392.5 G | 146.7 G | 41.0 s | 10.03 s | 11.03 MB |
| wasm, step 3 (own configs, stock ark-ff) | **377.6 G (−3.8%)** | 142.0 G | 39.7 s (−3.2%) | 9.80 s | 10.76 MB |
| native, b273bd1 baseline (vendored, forced attrs) | 129.4 G | 60.8 G | 17.1 s | 3.12 s (3.65 3.12 3.16) | 17.1 MB |
| native, step 3 (stock ark-ff) | 138.9 G (+7.3%) | 59.8 G (−1.6%) | 16.7 s | 2.90 s (3.02 2.91 2.90) | 15.1 MB |

Wasm got faster: the kernel is now called from a concrete `MontConfig` impl instead of through
`MontBackend`'s generic hooks (`N == 4 && MODULUS_HAS_SPARE_BIT` branches at every call). Native
executes 7% more instructions (2,945 `call mul_assign` sites vs 43 — Update 58's variant B still
had the vendored `MontBackend` layer inlined, hence its smaller +3.2%) yet spends fewer cycles and
less wall here, consistently over three runs, with a 2 MB smaller binary; the −31G/−5% recorded at
98f541d was measured on bbbench on a merge op, so the native effect must be re-read from the full
tables there before drawing a conclusion. `-C llvm-args=-inline-threshold=1000` remains available
as a build flag if the native instruction count matters (Update 58: recovers two thirds).

Bookkeeping: `tools/loc.sh` 44,889 lines = 18.5% of bb with tests (the kernels moved into `src/`;
they were vendored before), 23.4% `--no-tests`. Repo-wide wasm `cfg` sites: the lines in
`base/wasm/mod.rs` plus the allocator choice in the binary. The tables of record
(`bench-results/chonk*.txt`, `corpus.txt`) predate Updates 60–62 and need regenerating on bbbench.

## Update 63: the HEAD tables on bbbench — two regressions, one fixed (2026-09-07)

Regenerating the tables of record at a78054c on bbbench (the box was running all along; the
"stopped" note was stale) showed both provers off their def1d24 marks:

| table (bbbench, 8t) | def1d24 | a78054c |
|---|---|---|
| native chonk wall / proving | 0.92x / 0.96x | 0.97x / 1.01x |
| wasm-V8 chonk wall / proving (median per flow) | 0.91x (1.00x) / 0.96x (1.06x) | 0.96x (1.04x) / 1.00x (1.11x) |
| rollup corpus 16t | 0.856x | 0.903x |

**Native: the retired inline attributes, fixed with a build flag.** Stock ark-ff leaves 2,945
outlined `mul_assign` call sites; `-C llvm-args=-inline-threshold=1000` (now in
`.cargo/config.toml` for x86_64) brings them to 499 and the table back to **wall 0.92x, proving
0.95x** (threshold 2000: identical, bigger binary). Binary 20.2 MB vs 17.1 with the fork.

**Wasm: the C kernels, not the field.** Every wasm candidate for the field side landed within 1%
of each other under production tiering (5 instrumented runs, transfer_0 proving-only): HEAD 4.902 s
median, kernel specialised per field 4.886, `-inline-threshold` 500/1000 4.873/4.937, both together
4.906 — against def1d24's 4.642. The per-scope diff put the whole gap in the MSM and IPA paths
(`MSM::batch_accumulate_into_buckets` +21%, `ECCVM::TripleIPA` +28%, `Gemini::commit_folds` +18%,
`CommitmentKey::commit` +10%) while sumcheck got 3–4% faster (Update 62's field work). Same code
with and without the C kernels (the b273bd1 `bbkernel` release module vs the step-1 module, 5 runs
each): **4.667 vs 5.026 s, +7.7%**; bucket accumulation +15%, `TripleIPA` +30%, commits +12%.

So Update 59's "~1%" was wrong for the reference machine. It was measured on this workstation,
which is a Zen 3 EPYC 7R13 with SMT (`lscpu`), not bbbench's Zen 4 EPYC 9R14; bb's clang-scheduled
`VectorField` drains are worth ~7.7% of wasm proving on Zen 4 and ~1% on Zen 3. Update 60 removed
them on the strength of the wrong box and without the bbbench confirmation it said it wanted.
Lesson for the traps list: kernel-level wasm decisions are only measurable on bbbench; this box
disagrees with it by the whole effect size, and V8 tiering (the production shape) adds a second
axis that `--no-liftoff` hides (HEAD and def1d24 are equal under `--no-liftoff` on bbbench, +8% in
ChonkProve under tiering).

Decision pending (owner): restore the C drains as they were (bb source + wasi-sdk at build time),
restore them as frozen wasm objects checked into the repo (no bb-tree or sysroot dependency, an
assembler at most), or close the Rust drain's gap to them. The tables of record stay at def1d24
until the wasm path is settled; native is at 0.92x / 0.95x with the flag.

## Update 64: what the C drains were buying — V8's baseline tier (2026-09-08)

Chasing Update 63's wasm loss on bbbench, `ecdsar1+transfer_0`, 8 threads, proving-only from
`BBREF_BENCH=1`, five runs per module unless noted, production tiering (plain `node`) unless noted.

**It is not TurboFan code quality.** With `--no-liftoff` (V8 compiles every function with TurboFan
before running it; the compile then lands inside the timed scopes, which is why these absolute
numbers are higher) def1d24 and HEAD are equal: ChonkProve 3.20/3.22/3.22 s vs 3.23/3.24/3.25 s.
Under production tiering HEAD is +8.5% in ChonkProve and +4% in accumulate. Same code with and
without the C drains (b273bd1's `bbkernel` release module vs the step-1 module): 4.667 vs 5.026 s
median, bucket accumulation 0.575 → 0.662, `TripleIPA` 0.347 → 0.452, commits 1.087 → 1.215.

**It is not the field-side shape either.** Six lto modules of HEAD's code under tiering, median of
five: HEAD 4.902 s; kernel monomorphised per field (constants as immediates) 4.886; LLVM
`-inline-threshold` 500 / 1000 4.873 / 4.937; both 4.906; def1d24 4.642. Within 1% of each other.

**Force-inlining the Rust SIMD kernels made it worse.** The Rust drains call `quad261::mont_mul`,
`add`, `sub`, `QuadFp::pack/unpack` as separate wasm functions (no inline attribute, 22 call sites);
the hypothesis was that Liftoff pays those calls and the monolithic C functions do not. With
`#[inline(always)]` on the five (no outlined copies remain, module +1%): **5.363 s** — bucket
accumulation 0.785 s against 0.641 (HEAD) and 0.453 (def1d24). Liftoff is a single-pass compiler
with a trivial register allocator: a large SIMD body with many simultaneously live `v128` values
spills relentlessly, and a larger function also waits longer for its TurboFan replacement.

**Working explanation.** bb's `VectorField` body is written with empty-asm barriers that stop
clang/LLVM from interleaving the independent lane chains, so live ranges stay short; Liftoff copes
with that order, and TurboFan does equally well with either order (hence the `--no-liftoff` tie).
Rust cannot pin an order on wasm32: `asm!` is unavailable for the target, `black_box`/volatile
approximations are rescheduled (Update 2 era), and the flow spends enough time in baseline code —
thousands of short MSMs, eight provers competing with TurboFan's background threads on 16 cores —
for the difference to be 7.7% of proving. On the Zen 3 workstation (192 logical CPUs, so the
compile threads never wait) the same modules differ by ~1%, which is what Update 59 measured.
**LLVM flags do not reproduce the order.** Same harness, HEAD's code, lto profile, median of five:

| module | proving | note |
|---|---|---|
| def1d24 (C drains) | 4.627 s | reference |
| HEAD | 4.901 s | |
| `-C llvm-args=-pre-RA-sched=source` | 4.823 s | −1.6%, module +0.4% |
| `-C llvm-args=-enable-misched=false -enable-post-misched=false` | 4.885 s | module differs by bytes only |
| `opt-level = 2` for the lto profile | 4.851 s | −1.0%, module −14% |
| `-C llvm-args=-unroll-threshold=0` | 6.294 s | +28%, the unrolling was doing real work |
| `#[inline(always)]` on the five SIMD kernel entry points | 5.363 s | +9%, see above |

Proofs identical throughout. Best case leaves 4.2% of the 5.9% gap to def1d24 on the table.

**Conclusion.** The C drains' value is their instruction order under V8's baseline tier, and neither
Rust attributes nor LLVM's scheduling knobs reach it from source. What does reproduce it is
clang's bytes: either the C sources compiled at build time (the `bbkernel` path of Update 2, needing
the bb checkout and a wasi-sdk) or those objects frozen in the repo and linked by `build.rs` (no
build-time dependency beyond the linker; an object boundary is a call boundary, which is how the C
path always worked). Hand-restructuring the Rust kernels to shorten live ranges (memory round-trips
as barriers) is untested research. The native side is settled (Update 63); the wasm decision and
the final tables of record wait on the owner's choice between those two forms.

## Update 65: the barriers are the mechanism — measured on bb's own kernel (2026-09-08)

Not a guess any more. bb documents the intent in `vector_field.hpp` (5bb2fc9dd0): its `q1s1` kernel
interleaves one scalar `i64` lane op with one `v128` quad op per statement, and 33 empty
`asm volatile("" : "+r"(...))` barriers keep that interleaving in the emitted wasm, because "V8
keeps v128 live-ranges short only when it sees scalar i64 ops interleaved with v128 ops" while
"LLVM's WASM backend ... will hoist one before the other absent a barrier"; the `"+r"` form also
stops CSE from turning nine fast `extmul_low/high_u32x4` into nine slow `i64x2.mul`. bb measured
~30 vs ~33 ns per element.

Test: the pre-removal tree (b273bd1, `bbkernel`) built twice with the wasi-sdk, once against bb's
source and once against a copy with all 33 barrier expressions replaced by `((void)0)`. Same flow,
production tiering, median of five instrumented runs:

| module | proving | buckets | `TripleIPA` |
|---|---|---|---|
| def1d24 (table of record) | 4.605 s | 0.560 | 0.340 |
| b273bd1 + bb's kernel, barriers intact | 4.610 s | 0.494 | 0.339 |
| b273bd1 + bb's kernel, barriers removed | **4.858 s** | 0.519 | 0.379 |
| HEAD (Rust drains) | 4.870 s | 0.581 | 0.436 |

Removing the barriers from bb's own C++ costs 5.4% of proving and lands within 0.2% of the Rust
drains. The C kernels' whole advantage is the barrier-pinned instruction order; the algorithm and
the 5-wide shape contribute nothing beyond what the Rust 4-lane drains already deliver.

Consequences: (1) Rust source cannot reproduce it on wasm32 — no `asm!` for the target, and every
scheduler-side substitute (Update 64) failed; (2) it can only come back as bytes carrying that
order: bb's objects compiled from its C++ (at build time, or frozen into the repo), or assembly we
write and own for the inner kernels; (3) it is a baseline-tier (first-proof) effect — under
`--no-liftoff` the drains tie — so a warm column belongs in the tables next to the cold one.


## Update 66: chonk-golf ported — native parity with a 0.53×-of-bb C++ prover (2026-10-12)

[chonk-golf](https://github.com/olehmisar/chonk-golf) (`sources/final2/patches`) is a 75-patch,
proof-preserving speedup series for bb's C++ chonk prover, written against bb15fcb (5 weeks past our
pin; 19 bb-source commits apart, none in the prover). Rebased onto the pin (71/73 clean; the two
conflicts are IPC plumbing off the `prove` path; harness 0002 ported so its seeded proofs are
thread-independent) it measures **0.525× pin bb** natively on bbbench (0.680× with its AVX-512
IFMA paths disabled). Goal: take the learnings into bb-ref, A/B each, reach parity with that binary.
Branch `golf-port`; table of record `bench-results/chonk-golf.txt`.

**Result** (bbbench, 8t, 11 flows × 3 interleaved reps, sum of per-flow min wall; every bb-ref and
golf-bb proof equal to the single-threaded pin-bb golden on every run):

| binary | wall | vs bb-ref c96126d |
|---|---|---|
| pin bb (same build config as golf-bb) | 44.74 s | 1.085 |
| bb-ref c96126d | 41.22 s | 1.000 |
| golf-bb | 23.49 s | 0.570 |
| **bb-ref golf-port 5b4b898** | **22.98 s** | **0.558** (33/33) |

bb-ref is 0.978× golf-bb wall and ahead on all 11 flows; golf's wall carries a ~34 ms self-verify,
so proving-only is ≈ parity. Peak RSS did not move (0.33–0.36 G, storage 0.97 G) and is now
~1.5× golf's (0.23 G, 0.59 G) — golf's memory patches are mostly C++ object lifetimes Rust already
had; the rest is open. Cost: +2,531/−650 lines in `src/` (48 commits).

**Method.** Four triage agents classified every patch against bb-ref's code and this file; six
workstreams ported by area in worktrees, each change gated on the full test suite plus
`tools/ab_chonk.sh` (new: paired-median/win-count A/B on bbbench with the golden byte gate,
flock-serialized, content-addressed remote binaries) and phase scopes for anything under flow noise.
A phase-tree comparison against golf-bb (`--print_bench`) and a `perf` gap audit replaced triage estimates once the first ports landed: golf ran ~0.55× pin bb in
*every* phase, which pointed at shared foundations (field, MSM, IFMA) rather than hot spots.

**What paid** (3-flow paired medians on the branch where it landed, before merging):

| change | golf | effect |
|---|---|---|
| IFMA batch-affine MSM drain (8×52-bit lanes, `base/ifma.rs`) + Stage 6b on it | 0031/0037/0038 | **0.821**; MSM 2^18 133→70 ms; drain 35%→15% of CPU |
| ADX Montgomery mul/square (own native `MontConfig`, `base/wasm/adx.rs`) | 0036 | **0.963**; mul 20.3→16.1 ns |
| branchless asm add/sub/double | — | **0.949** |
| Bernstein–Yang safegcd inverse (`MontConfig::inverse`) | 0007 | **0.941**; 4.24→1.18 µs; inverse was 8.4% of samples |
| sumcheck: identical-pair fold skip, databus column skip, q_arith==1 path, memory-relation gate-type skip, Poseidon2 separator folding (all prover-only via `IS_PROVER`/`as_const`) | 0006/0009/0047/0022/0008 | 0.963; folding sumcheck 606→486 ms |
| IFMA sumcheck fold, `add_scaled_batch` tiles, IPA two-round SRS fold, mlb/Gemini folds | 0061/0062/0064 | 0.963 + 0.992 |
| prover instance: parallel copy cycles, read counts, grand product as running ratios, translator GP 12 columns, logderiv columns | 0058/0057/0060/0005/0059 | 0.985 |
| PCS: zero/unit skips in `add_scaled_batch`, one-pass Gemini A₀, parallel Shplonk/KZG quotients, joint folds joined | 0018/0043/0029/0040/0028/0027 | 0.984 |
| ECCVM: parallel transcript muls + `get_msms` + MSM rows; zero-tail GP/inverses | 0035/0034 | 0.989; trace 80→39 ms |
| MSM: gather prefetch, GLV crossover 2^12, no GLV ≤128-bit scalars; batched-affine dedup clusters (bb Phase A — R25 revisited) | — | 0.980; Oink 533→496 (golf 606) |
| multilinear batching: half-width eq product, ρ⁰ start, one-pass columns | 0030-adjacent | 0.976 with the fold routing; now ahead of golf |
| decode/build: witness and constants straight to Fr, per-step just-in-time decode (−100 MB on storage), RNG without 256-step pow, bigfield/secp256r1 fixed-width, field division reuses inverse, fewer Montgomery conversions | 0011/0066/0071/0032/0024/0045/0046 | 0.986 + 0.988 + 0.994; create_circuit 378→322 ms |
| sumcheck edge prefetch (2 ahead), SmallSubgroupIPA parallel, decider frees accumulator | 0073 | 0.989, joint 511→496 ms |

**Rejected, measured** (so they are not retried): golf 0039 (Shplonk recurrence interleave, 150→151
ms), 0044 (two Horner chains: 0% at parallel sizes), 0034's narrow rows (1 ms for 40–70 lines),
0016/0033 Poseidon2 round restructure (11.66→11.96 µs), asm negation, `sum_of_products` override
(0.05%), parallel zeroing / allocation of `from_builder` columns (+37 ms / mixed), sort-based dedup,
tiled digit scatter, second-line point prefetch, 64-byte packed gather, window ±1, looser dedup gate,
gunzip pre-sizing, six `Graded` copy-traffic variants (`MaybeUninit`, in-place `mul`, capacity 7,
`+avx2`: memmove is 8.7% of samples but AVX-512 memmove makes it cheap in wall), program prefetch of
step k+1 (−2% wall, +23 MB on deploy_schnorr — held for the owner), witness prefetch (+60 MB for 10
ms). golf 0069/0074 analysed and declined (0074 adds ~66 muls/edge in round 1). Not attempted: 0065
(IFMA short-univariate products) — needs 8-edge batched relation evaluation, the likely owner of
the remaining later-round sumcheck gap (~90 ms/flow vs golf). Not applicable (C++ only): 0003,
0010, 0012–0015, 0017, 0019–0021, 0023, 0025, 0026, 0052, 0055, 0056, 0067, 0068, 0070, 0072, 0075.

**Traps learned.** (1) **pin bb's seeded chonk proof is not deterministic above one thread**
(parallel `Polynomial::random` draws race on the engine); bb-ref's is, and equals single-threaded
bb's — gate on single-threaded goldens. (2) Two concurrent A/Bs sharing a remote binary name
(`~/ab-bin/port`) swapped binaries mid-run and showed a phantom 4% regression; remote names are
now content-addressed. (3) Triage estimates under-called the work by ~3× — the decisive levers
(field, MSM, IFMA, inverse) were pervasive, and two gaps (startup decode, Graded copies) were found
only by profiling against golf-bb. (4) `adx.rs` once needed 11 GPRs and broke frame-pointer builds;
the 10-register mul fixed it at no cost.

**Platform caveat.** The four largest wins need x86-64 ADX (all x86 since Broadwell/Zen) or AVX-512
IFMA (Zen 4, Ice Lake+), both runtime- or compile-gated with scalar fallbacks (`BBREF_NO_IFMA=1`
forces the fallback). wasm and ARM get only the algorithmic ports and are not yet measured on this
branch; one MSM rule (no GLV for ≤128-bit scalars) also changes the wasm path unmeasured.

## Update 67: wasm golfed to parity with the golf-patched bb (2026-10-13)

Branch `wasm-golf` (off `golf-port`). Table of record `bench-results/chonk-golf-wasm.txt`: wasm chonk,
11 flows × 3 interleaved reps on the bench boxes, node 24 production tiering, 8 threads, every bb-ref
proof equal to the single-threaded pin-bb golden (396 runs).

| module | wall | proving | peak memory (Σ flows) | vs golf-bb wasm (wall / proving / memory) |
|---|---|---|---|---|
| wasm-golf base (golf-port + fixes) | 71.36 s | 67.91 s | 3,753 MiB | 1.170 / 1.208 / 1.304 |
| **wasm-golf 26d57dc** | **60.07 s** | **56.74 s** | **3,210 MiB** | **0.985 / 1.009 / 1.116** |
| golf-bb wasm | 61.01 s | 56.24 s | 2,878 MiB | 1 / 1 / 1 |

Faster wall than golf-bb on 10 of 11 flows (storage_proof 11.47 vs 11.05 s); proving within 1%;
memory at golf's level on the small flows except a 25–45 MiB tail on several, and storage_proof
748 vs 601 MiB. Native also gained: the shared-code commits make native chonk 0.983× golf-port
(11 flows × 3 reps, 31/33 wins, proofs golden) with peak RSS down on every flow (storage 1.00 → 0.88 GB).
Full `cargo test --release` and `tools/check.sh` pass. Cost: +712/−253 in `src/` (12 commits).

**How.** Phase 0 measured the wasm baseline and profiles against golf-bb; Phase 1 fanned nine
analysis agents over angles (field, MSM, sumcheck, streaming/IPA, toolchain, runtime, serial path,
live-peak memory, allocator), each probing its top ideas on the bench boxes; the ranked shortlist was
then ported as production commits, each measured on its own and the stack measured together (the
per-item numbers composed almost exactly).

| commit(s) | change | proving Δ (transfer_1 / storage), alone |
|---|---|---|
| 00bd871 | Bernstein–Yang inverse for the wasm 2^261 field (divstep kernel shared with the native one) | −5.6% / −5.0% |
| 0e6ef7d, d8b6ef5, 07b7cdb | packed-path skips that native golf-port had and wasm lacked (zero axpy groups, identical fold pairs — golf 0053 — packed `fold_par`); packed IPA SRS fold (golf 0054's idea); multilinear batching on each claim's support with the eq table factored | −6.5% / −8.0%; storage −29 MiB |
| 1e109c6, 6df52ef, 1a55d7f | one inversion per MSM tree level + 4096 subchunk (wasm only — natively 4096 raised RSS); φ table only to the GLV threshold; MSM scratch freed at last use | −2.4% / −2.6%; −10 / −29 MiB |
| bf357d7, 46d6d1c | inline memcpy/memset up to 48 B (V8 lowers every `memory.copy` to a C call; every `Graded` temporary moves 264 B) — flags in `.cargo/config.toml`, guarded by `tools/wasm_check.sh`; parallel zeroing of large columns (respecting the allocator's stale-bounds guard), 1 MiB pool stacks, hoisted row counter | −2.9% / −3.7%; −8 MiB |
| 49ed864 | `#[inline(always)]` on the scalar multiply (store-to-load forwarding stall on the out-of-line result) | −1.0% / −0.6% |
| 91ab535, 26d57dc | free the folded instance before multilinear batching; free the joint sumcheck tables before the joint PCS | ±0 over 11 flows; −276 MiB summed (small flows −11%) |

**Harness fix that changed the memory story.** The node runners created shared memory with 1,200
initial pages (75 MiB) where the modules declare 22–37 and bb.js uses 37; the allocators never use the
slack, so every reported peak carried ~73 MiB (5991e08 now reads the declared limits from the
import section). Without it our memory ratio looked 1.25×; on the fair basis the base was 1.30×.

**Bugs found on the way (fixed on golf-port; present on master).** (1) V8 bounds-checks
`memory.fill`/`memory.copy` against a per-thread cached memory size that another thread's
`memory.grow` updates asynchronously (~0.1–1 ms): a thread memsetting freshly grown pages traps
"memory access out of bounds" (`src/base/wasm/alloc.rs` refreshes the view with `memory.grow(0)`;
reproduces in a few lines of raw wasm on node 24 — reportable upstream). (2) The lazily built φ table
was built under `OnceLock::get_or_init` with rayon inside it; a building thread could steal a sibling
commit job that then blocked on the same cell — a silent deadlock (now non-blocking, with a test).

**Measured and rejected** (do not retry without new evidence): f64/FMA field multiply (Emmart et al.;
bit-exact, 18.5% faster only while data stays in its form, ties at the stored-form boundaries every
call site has, +46% at scalar sites, needs relaxed SIMD which Safari lacks); turning auto-vectorisation
off (exactly neutral — golf 0052's lesson doesn't apply); Rust reorderings of the 4-lane multiply to
recover the C drains (2.0–2.3× slower); golf's 5-wide kernel shape; branchless add/sub on wasm
(neutral; −5% natively); Yuval reduction + dedicated square (neutral in flow); `-pre-RA-sched=source`
(no gain on top of inlining); force-inlining `Graded` ops (+0.3–0.45 s TurboFan compile); talc
(+18 MiB, slower); spin-before-sleep / pool replacement (≤0.9%); GLV threshold changes, fewer
concurrent MSMs, v128 point copies, wasm-opt, inline/unroll thresholds, opt-level 2. Not taken:
skipping the gzip CRC (owner: keep the integrity check). Threading is not the wasm gap: rayon is
1.2–2.5% of on-CPU time; the 26–30% "wait" in V8 profiles is idle threads sampled, and ~a quarter of
wall is serial circuit construction in both provers.

**Traps.** Setting `RUSTFLAGS` in the environment silently replaces `.cargo/config.toml`'s target
rustflags — the wasm flags now live there, so wasm builds must not set it (`tools/wasm_check.sh`
catches a lost memcpy flag). Storage_proof's wasm peak varies ±30 MiB between identical runs: use ≥3
runs and medians. `pgrep -f <pattern>` matches the calling shell's own command line.

**Open.** Memory on storage_proof (748 vs 601 MiB): M4 (builder rows freed before columns, branch
`wg-i5-m4`, −16% native RSS on storage) and M6/M7 (sumcheck tables after round 1, selector start
windows) are the measured candidates; the 4-lane multiply at `Graded`/batch-affine call sites
(≈ −4% estimated) and cross-step pipelining of circuit construction (−3 to −9% estimated, memory-
gated) are the larger unbuilt time ideas. Wasm unit tests that catch panics (`catch_unwind`) abort
under wasip1's panic=abort; `codec::tests::keccak_scalar_canonicity` fails that way on master too.

## Update 68: wasm small-flow memory floor removed (2026-10-13)

Branch `wasm-golf`. Every small flow peaked at the same fixed-size point: the first fold of the joint
MegaZK + Translator sumcheck (~240–256 MiB regardless of flow). Two commits, each measured with 5
interleaved reps (medians) against its predecessor, proofs golden:

| commit | change | peak memory Δ (transfer_0+sponsored / token_bridge / transfer_1+sponsored / transfer_1+private / storage) | proving Δ |
|---|---|---|---|
| 5630a7f | joint sumcheck materializes its owned tables after round 1 at quarter size; round 1 reads the round-0 columns folded on access (golf 0074) | −23.0 / −24.1 / −21.2 / −14.7 / noise | within ±0.4% (storage −1.6%, noise) |
| 6dfd68f | `batch_commit` caps in-flight MSM scratch at bb's 32 MiB budget (8 MSMs to 2^16, 4 at 2^17, 1 from 2^19) | −15.8 / −17.7 / −17.5 / +0.5 / noise | ≤ +0.4% |

All 11 flows × 3 reps: peak memory Σ 3,210 → 3,007 MiB (golf-bb 2,878; ratio 1.116 → 1.045), proving
56.82 → 57.00 s (+0.3%, noise). bb-ref now uses less memory than golf-bb on 6 of the 10 small flows.
Native: 1.000× (5 flows × 5 reps), storage RSS 0.90 → 0.87 GB.

Rejected: late tables in every sumcheck (−6 MiB on transfer_1+private for +1.1–1.4% proving); a
16 MiB MSM budget (next stair binds; +0.3–1.5% proving). Remaining above golf: deploy_tokenContract
(248/244 vs 228/223), amm and transfer_0+private (~+4 MiB), storage_proof. Next candidates: skip each
column's leading zeros in the sumcheck tables (golf 0069), start-offset polynomials for the three
tail Lagrange columns (12 MiB at every final-proof stair; design change).
