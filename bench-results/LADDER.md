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
