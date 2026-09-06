[◄ bb-ref](../README.md)

# Performance vs barretenberg

Where the rest of the docs describe *what* bb-ref computes (bit-identically to bb), this records
*how fast*, every optimization that landed and why it works, every attempt that did not pay and
why, and what owns the remaining gap. The raw record — every measurement, retraction and dead end
in the order it happened — is [`bench-results/LADDER.md`](../bench-results/LADDER.md) (Updates
1–49); this file is the curated view of it.

Two machines appear below. **bbbench** is the reference box for everything from 2026-09-05 on: a
16-core AMD EPYC 9R14 (no SMT, two 8-core L3 domains), bb pinned at the bb-ref pin, both provers
seeded (`BB_RNG_SEED=12345`), 8 threads for client flows, best-of-3 per flow, nothing pinned to
cores. Earlier server-profile numbers come from an idle 64-core c7a at 32 threads pinned to cores
0–31. Every optimization here was gated on byte-identical seeded proofs against bb and the full
test suite: none of it changes an output bit.

## Where it stands (2026-09-06)

| benchmark | bb | bb-ref | ratio |
|---|---|---|---|
| chonk client flows, **native**, 11 pinned transactions, 8t (bbbench) | 44.7s | **42.7s** | **0.954×** (median 0.993×, range 0.81–1.02) |
| chonk client flows, **wasm** (V8, `node`), 8t, unstripped bb module | 85.1s | 80.3s | 0.944× total, **median 1.023×** |
| — same, against a *stripped* bb module (**the fair wall basis**) | 83.8s | 80.1s | 0.956× total, **median 1.048×** (range 0.69–1.09) |
| — same, stripped bb, **`--profile lto` build, current HEAD** | 83.8s | **76.8s** | **0.917× total, median 1.000×** (range 0.67–1.04) — wall parity |
| — **proving-only**, typical flow (`transfer_1`), wasm, current HEAD (LTO), bb re-measured same hour | 4.82s | 5.11s | **1.059×** (the number that compares the provers; target 1.05) |
| rollup PrivateTxBaseRollup frame, native 8t (before 14.82s) | 15.19s | **13.73s** | 0.90× |
| rollup RootRollup frame, native 8t (before 45.4s) | 49.5s | **42.6s** | 0.86× |
| rollup corpus (62 recorded server ops), 32t c7a, 2026-09-03 | 237.7s | 221.1s | 0.93× |
| — same corpus, **bbbench 16t**, bb / before this pass / after | 298.6s | 291.9s → **258.3s** | **0.865×** vs bb (before: 0.977×); after/before **0.885×** |
| rollup corpus peak RSS (32t) | 13.0 GB | 17.0 GB | 1.31× |
| chonk client flow peak RSS, native 8t | 290–340 MB | 320–380 MB | ~1.10× |
| chonk client flow wasm memory (11 flows) | | | 0.82–1.05× of bb |

Reading the wall ratios: bb's wall includes a self-verify (~0.14s) that ours does not, and its
wasm module carries a startup cost ours does not (see the traps below), so **proving-only is the
metric that compares the provers**; wall is what a user sees. Session arc for the wasm client
flows (unstripped-module basis, the one measured throughout): 1.34× → 1.15× → 1.07× (MSM parity) →
1.10× typical → 1.06× → 1.04× → 1.02× median; on the fair stripped-module basis the final median
is **1.048×** (the ~0.025× difference is bb's module load, see traps).
Native chonk went from 1.16× (2026-09-03) to 0.95× on the same optimizations, none of which were
wasm-specific.

**Binary sizes, precisely.** The wasm reference is vanilla bb (no AVM): 122.9 MB on disk of which
**100 MB is the `name` custom section** and 5 MB DWARF; its code is **17.2 MB**. Ours is 11.4 MB on
disk, **9.3 MB code**, 1.7 MB names. The native reference on bbbench is **bb-avm** (`--help`: AVM
enabled), 270 MB on disk with 206 MB of executable sections, against our 18.5 MB text; a trivial
invocation costs 5 ms for both, so native size does not affect the comparison. The wasm size does
(below).

## Benchmarking traps (learned the hard way — read before measuring anything)

Provers are measured against each other with matched instrumentation: bb's `BB_BENCH` (`--print_bench`,
`--bench_out`) against our `BBREF_BENCH=1`, with the same scope names. Each of these cost real time
at least once.

- **bb's reported scope `time` is the largest single thread's total (`time_max`), not a sum across
  threads.** Summing our per-thread times against it inflated our numbers ~2.5× and produced a
  phantom "MSM is 2.6×" result. Compare `time_max` to `time_max`.
- **Scope boundaries differ; reconcile before comparing.** bb's `OinkProver::prove` includes the
  hiding kernel's oink (ours is a separate scope: +0.175s hid behind an apparent "parity");
  `create_circuit` excludes witness decode in bb (our `decode_witness` is inside); bb's
  `acir::recursion_constraints` and `Chonk::complete_kernel_circuit_logic` are siblings (our single
  scope covers both — we are *faster* on the pair, not slower on the first); our `TripleIPA`
  includes claim reduction that bb's `IPA::compute_opening_proof` does not (a fake +0.07s). Ranges
  that do not overlap (`create_circuit` + `Chonk::accumulate` + `ChonkProve`) must sum to ~90–96%
  of wall on both sides or the table is wrong.
- **Never phase-measure under `--no-liftoff`.** TurboFan compile time is charged to whichever phase
  first calls each function, which favours the smaller module: it inverted a bb-vs-us result
  (0.79× vs the real 1.15×) and forced a retraction. Plain `node` (Liftoff, dynamic tiering) is the
  production shape; use it.
- **bb's wasm module is shipped to the benchmark unstripped.** The 100 MB name section costs bb
  0.10–0.13s of wall per flow (2%) purely in load; a module with custom sections removed is 18 MB
  and proves identically. Quote wall ratios against the stripped module, or quote proving-only.
- **`ECCVMShort/loop_static_blocks` in bb's sumcheck bench is round 0 only** — it builds one
  `Round(round_size)` and never folds. Treating it as a full loop produced a false "later rounds
  are 2× slower" conclusion (retracted in Update 46).
- **Noise bands.** The sumcheck round rung varies ~6%; flows ~2–3% run to run; bb's own MSM bench
  swings 48.8–57.5ms at 2^16 between runs. Nothing under ~10% can be called from single or paired
  samples: rungs need n≥8 interleaved pairs with the paired median and win count; flows best-of-3
  against bb best-of-3. Two "wins" (7% scheduler, 4% chunk divisor) evaporated under that test.
- **A suspiciously large win is usually a panic.** A stubbed gather "4.6× faster" was a crashed
  run; a coefficient-form batching "win" was measured on a stale binary because `cargo build | grep`
  masked a compile error. Check for `Finished`, abort on `error`, verify the proof bytes.
- **Stale runners on the bench box.** `pkill -f <pattern>` over ssh matches its own command line
  and kills the wrapper instead of the target; killed wrappers fall through to their completion
  marker; orphaned inner loops keep proving. Kill by PID, reap children, verify `pgrep -x node`
  is 0 before launching, and check the box's load average — a foreign 8-thread prover halves your
  numbers silently (it happened with a local `jaws`/`bb-avm` workload during the corpus replay).
- **Worker-thread `eprintln!` is not captured by the harness**; accumulate in shared statics and
  print from main, or a per-call profile silently loses two thirds of its entries.
- **bb's per-op corpus numbers swing ±20% with allocator warmth** (a merge proves in 4.11s after a
  big frame, 5.0–5.1s standalone; ours is state-independent under THP). Use the warm marginal wall
  (`frame×3` stream, (T₃−T₁)/2) or marginal `perf stat` instruction counts.
- **Sumcheck dead-tail skipping is already implemented** (`witness_end` = bb's `end_index`, halved
  per round; the ECCVM's `active_prefix_end`). Traces are ~71% active and both provers skip the
  tail; do not rediscover it.
- **LTO measured flat twice, `#[inline(always)]` did not** — ark-ff outlines every field op behind
  two `#[inline]` wrapper layers that LLVM declines; forcing both: −31G instructions, −3.5% merge,
  −5% chonk. Check the disassembly (`callq mul_assign` count), not the build flag.
- **Instruction counts and wall diverge on the MSM**: 29.8G vs bb's 24.9G per dense 2^20 MSM with
  wall at parity — arkworks' outlined 45-instruction Montgomery multiply costs instructions, not
  time (19.2 vs 20.4ns per op). An earlier "parity" claim scaled a stale number; measure, don't
  scale.
- **Hardware counters, not sampling profilers, for parallel efficiency.** The sampling profiler's
  "1.32× CPU tax at 8 threads" was an artefact: `perf stat` showed instructions per pass flat from
  1 to 8 threads; the real cost was ~23ms per pass of barrier idle from our own serial tail.

## What was done — every optimization that landed

Grouped by area. Each entry says what changed, why it is not obvious, what it measured, and where
it applies: **H** = Honk rollup circuits, **C** = Chonk client flows, **N/W** = native/wasm. Each
also carries a **LoC** line (source lines added/removed by its commits, `src/` + `csrc/` + build
files; docs, benches and tests excluded) and a **shape**: *general* (the code path everyone takes
changed) or *branch* (a new path taken only under a stated condition — the complexity that has to
be kept correct twice). Totals over all perf commits: ≈7,400 lines added / 2,300 removed in `src/`,
plus ≈12,800 vendored (ark-ff, whose own change is a handful of attributes).

### Field arithmetic and representation

1. **arkworks' x86-64 asm (`ark-ff/asm`, `+bmi2,+adx`).** Native field multiply at bb's
   hand-rolled rate. H C N.
    *LoC +1/−1; shape: general — build flag.*
2. **Vendored ark-ff with `#[inline(always)]` on both wrapper layers** (`FpConfig` impl and
   `core::ops`). LTO could not do it (see traps). −31G instructions on a merge op, −3.5% merge
   wall, −5% chonk wall. H C N.
    *LoC vendored ark-ff +12,375 (the change itself: `#[inline(always)]` on ~6 wrapper fns); shape: general.*
3. **bb's 29-bit wasm Montgomery multiply** (nine 29-bit limbs so every product fits one
   `i64.mul`; Karatsuba 5+4; 8×2^29 + 1×2^24 rounds dividing by exactly 2^256 so the stored
   representation and every proof byte match native), then straight-lined. V8 mul 121 → 62ns (bb
   57.5); the canonical wasm flow 19.0 → 10.5–12.2s. The wasm prover is mul-bound, so this was
   the whole first tier of wasm work. H C W.
    *LoC vendored ark-ff ≈+400 (two commits); shape: wasm-only `cfg` path inside the vendored field.*
4. **`bbkernel`: bb's `VectorField` C++ kernels compiled with the wasi-sdk and linked into the
   module** (`csrc/`; bb's memory barriers survive because they are bb's bytes). `axpy` 42.8 →
   33.7 ns/elt; the MSM drain runs at the streaming multiply rate. The benchmark wasm builds use it.
   H C W.
    *LoC +423 (build.rs, csrc glue, Rust bindings) + bb's C++ kernel sources; shape: wasm-only, feature-gated (`bbkernel`).*
5. **Canonical bytes → field element in one Montgomery multiply.** `from_bytes_be` went through
   ark's `from_be_bytes_mod_order`, whose full-width path reduces in several multiplies; every ACIR
   coefficient is canonical, so `from_bigint` is exact (non-canonical input still falls back).
   `acir::classify` 0.104 → 0.042s on the deploy flows, 0.065 → 0.026 on transfer. H C N W.
    *LoC +5/−1; shape: general.*
6. **Batched inversion done right twice.** ark's parallel `batch_inversion` splits even a
   32-element batch into one chunk per thread (a real inversion plus a rayon dispatch each) and the
   MSM tree ran it nested inside its own jobs — 14% of all instructions; serial in-place inversion
   with reused scratch: client 4.20 → 3.98s. Later, the *large* denominators (grand product,
   ECCVM lookups) got `batch_invert_par`: element-wise, so chunks are independent. H C N W.
    *LoC ≈+50/−15 (of +152/−15 across two commits that also carried #21); shape: general.*

### MSM and commitments (`base/msm.rs`, `base/srs.rs`, `base/fold.rs`)

7. **Batched-affine Pippenger in the shape of bb's `scalar_multiplication_fast`**: signed Booth
   digits, counting-sort schedules, pair-tree reduction through one shared Montgomery inversion per
   level (~6 muls per affine add against ~14 for Jacobian). H C N W.
    *LoC +477/−17; shape: general — algorithm replacement.*
8. **bb's Phase 1 and Stages 5–7 replicated stage by stage** (the user's direction, after tuning
   our own structure had stalled at 1.34× on the MSM rung): per-scalar MSB profile with
   `choose_window_bits` (rounds sized to the actual bit length — commit scalars average 6.9 of 16
   nonzero windows), per-window chunk partition, dense per-thread partials with overflow merge, and
   `recursive_affine_bucket_reduce`. Short-scalar MSMs −20–30%; the add count now equals bb's.
   H C N W.
    *LoC +562/−255 (two commits); shape: general — algorithm structure.*
9. **GLV only below a size threshold** (bb's `GLV_SMALL_N_THRESHOLD`): above it the doubled point
   count outweighs halving the windows. This was the entire scale-dependent MSM gap (2^16 0.64×,
   2^19 1.21× before). Threshold **measured for our code**, not copied: 2^16 wasm, 2^15 native (bb
   uses 2^13 native because its decode is cheaper). MSM at parity 2^16–2^19; memory dropped to
   0.97–1.14× of bb because the doubled point buffer and phi table disappeared. H C N W.
    *LoC +60/−25; shape: **branch**: `n > 2^16` (wasm) / `2^15` (native) takes a non-GLV full-width path.*
10. **Packed drain.** The tree's two phases round-tripped every intermediate through unpacked
    field arrays (9 packs + 5 unpacks around 6 multiplies per 5-chord block); phase 1 now packs the
    four operands once and stores packed intermediates. 270 → 205 ns/chord = the streaming rate;
    2^17 1.34× → 1.11×. Two flow-negative intermediates on the way, both diagnosed: level-sized
    scratch grown per rayon split caused page-fault churn (fixed by streaming BATCH-sized chunks),
    and a fixed ~1 MB scratch per tree caused first-touch faults across the flow's thousands of
    small MSMs (fixed by sizing to `min(n, batch)`). C W (drain is the wasm kernel path).
    *LoC +256/−55 (two commits); shape: wasm-only (rides the `bbkernel` drain).*
11. **Structure-of-arrays tree** (bucket ids ∥ points; the pairing scan streams dense u32s):
    −0.15s native client wall from cache behaviour alone, instructions unchanged. Run-length
    `tree_reduce` bookkeeping: −5–10% MSM wall. H C N W.
    *LoC +79/−67 (SoA) and ≈+136/−82 (run-length tree, shared commit with #2); shape: general.*
12. **Gather block 2^16 → 2^13.** Invisible in a single-thread sweep, −9% at 2^18 with 8 threads
    sharing cache; native insensitive. C W.
    *LoC +12/−5; shape: tuning constant, env-overridable.*
13. **Sparse inputs compact to their support** (a 34-nonzero masking polynomial had cost 7ms),
    **small MSMs never touch arkworks' MSM** (it builds a thread pool per call), and **MSMs of
    ≤128 points use width-5 wNAF over one shared doubling chain** — textbook Pippenger at c=3 ran
    86 windows of bucket reset/scan/reduce for 7 points, a ~1ms floor paid on hundreds of tiny
    commits per flow (1.16 → 0.58ms mean). H C N W.
    *LoC +221/−26 (three commits); shape: **three branches**: sparse compaction when nonzeros ≪ length; a non-arkworks path for small n; wNAF when `n ≤ 128`.*
14. **Bounded live scratch**: gathers in blocks, at most 8 concurrent MSMs in `batch_commit`
    (shared-index pull loop — pre-chunking serializes big polynomials behind each other); either
    bound alone saves nothing, together −3.5 GB. Montgomery-converted SRS cached on disk
    (`bn254_g1.ark.mont`), SRS loaded once at server start, the GLV φ(SRS) table precomputed per
    commitment key. H C N W.
    *LoC ≈+130/−47 (four commits); shape: general (resource bounds) plus a disk cache file.*
15. **IPA consumes reduction rounds in pairs** (bb `batch_two_round_fold`): the second round's
    L/R expand linearly over un-folded quarters and both folds land in one four-term combination,
    with the full-width `u1·u2` GLV-split so four ≤128-bit digit streams share a single doubling
    chain. SRS fold 187 → 90ms. The rollup IPA prover delegates to it (padding circuit 0.40 →
    0.32s, single-tx 3.09 → 2.88, merges −0.2s each), and the rollup verifier's 2^15 G_zero MSM
    moved onto our MSM (33 → 25ms; 1.10–1.16× bb per core, which is what the p2p layer sees).
    H C N W.
    *LoC +494/−83 (three commits; the two-round fold is +465); shape: general — bb's algorithm; the GLV split is inside it.*
16. **Parallel fixed-base table precomputation** (2^15 Straus plookup tables and hash-to-curve
    generators for in-circuit IPA verification, 18.6s of the root rollup's 41.5s run serially);
    registration order — gate order — preserved. Root rollup at bb parity. H N.
    *LoC ≈+50/−8 (shared commit with the SRS cache); shape: general — parallelization.*

### Sumcheck (`honk/sumcheck.rs`, `honk/graded.rs`)

17. **The foundations (2026-08-27)**: row skipping (`witness_end`, halved per round), relation
    skipping, partial-length evaluation, precomputed barycentric extension weights, edge
    univariates stepped by addition, hoisted per-call constants, tables borrowing the prover
    polynomials, lazily zeroed columns. H C N W.
    *LoC +1,153/−452 (eight commits, 2026-08-27); shape: general — the prover's baseline shape.*
18. **Coefficient-basis relation evaluation** (`Graded<F>`, bb `UnivariateCoefficientBasis`):
    edge rows become degree-tracked univariates `row0 + X·Δ` and the unchanged relation bodies run
    on them, so each ring operation costs its true degree and a locally-constant selector (Δ = 0)
    stays degree 0. Chosen per relation: Mega −26% single-thread; the Translator's add-heavy
    high-degree relations measured *slower* and keep the pointwise path; ECCVM relations over the
    fixed capacity (`Set` 22, `Lookup` 9) fall back automatically. Length-aware operations. H C N W.
    *LoC +420/−32 (four commits); shape: general representation, chosen **per relation** by partial length (a branch: pointwise fallback above the capacity; Translator opts out).*
19. **One parallel dispatch per round.** The round used three parallel regions and a serial
    `flush_graded` over eight per-worker slots after the loop — ~0.8ms of barrier idle every round,
    located by per-round worker-busy spread (`BBREF_ROUND_DETAIL=1`) after hardware counters had
    ruled out extra work. Now chunks, the 2-edge row-disabling head and each worker's own graded
    flush ride in a single fork-join; per-worker `Scratch`/`Accumulators` instead of per chunk
    (they are ~30KB and started every chunk cache-cold); chunk floor 1 and 32 chunks per thread;
    round-0 `pows` computed once and strided for later rounds; the `BBREF_TIMING_RELATIONS` env
    check cached (it was read **per edge**). Round rung 122 → 108ms (bb 103; pinned to one L3
    domain we beat bb, 100.6). H C N W.
    *LoC +260/−99 (three commits); shape: general restructuring; the 2-edge row-disabling head is a small special case inside it.*
20. **Coefficient-form batching across relations** (what bb's `USE_SHORT_MONOMIALS` buys it).
    `flush_graded` had evaluated each coefficient-form accumulator at `len` points and
    `batch_over_relations` re-extended every subrelation to all d points by barycentric dot
    products, twice per round — a fixed ~3.25ms per round at the ECCVM's d=24 × 159 subrelations,
    dominating its rounds 7–14. Accumulators now stay in coefficient form; α and the two *linear*
    factors (pow, row-disabling) are O(len) coefficient ops; the single batched polynomial is
    evaluated once at 0..d−1. Same polynomial, exact arithmetic, proofs byte-identical. `rest`
    3.25 → 0.76ms/round; `sumcheck/extend_and_batch` 0.072 → 0.021s (bb 0.036); ECCVM sumcheck
    0.283 → 0.238, folding 0.76 → 0.73. The trap: without row disabling the factors are the
    constants 1 and 0 and must not grow the polynomial (non-ZK flavors size d = max partial + 1;
    bb's `BATCHED = MAX + 2` is ZK-only). H C N W.
    *LoC +93/−30; shape: general.*
21. Lazy edge-row fill (only the rows a live relation reads), in-place folds, parallel column
    trimming, sumcheck tables as borrowed views. H C N W.
    *LoC ≈+150/−40 (shared commits); shape: general.*

### Prover phases

22. **Multilinear batching** (Chonk): the hand-rolled sumcheck padded copies of every claim
    polynomial up front and folded its 3n columns one per task (n = 2–3 claims, so ~2ms per
    column per round ran on one thread). Round 0 borrows the claims' vectors (the first fold
    allocates anyway), `eq_table` is built in place with the large levels parallel, folds are
    element-parallel, and the edge evaluation steps small constants (18 → 8 muls per claim-edge).
    0.295 → 0.163s (bb 0.224). C N W.
    *LoC +134/−49 (three commits); shape: general.*
23. **Permutation polynomials (sigma/id)**: an incremental row-value table (one add instead of a
    Montgomery conversion per row), identity fill parallel per wire, cycle links parallel over
    variables (each (wire,row) is in exactly one cycle, so writes never alias).
    `ProverInstance::from_builder` 0.227 → 0.180s (bb 0.179). H C N W.
    *LoC ≈+60/−25; shape: general.*
24. **Grand product** blocked-parallel: per-block prefix products, an exclusive scan over block
    totals, parallel fill, per-chunk inversion (bb's `step1/2a/2b/3`). 0.131 → 0.103s. H C N W.
    *LoC +56/−1; shape: general.*
25. **ECCVM**: transcript/precompute/msm row tables are independent and now overlap via
    `rayon::join` (transcript rows are a sequential accumulator and dominate): trace construction
    0.122 → 0.102s; shifted entities as views instead of copies (−55 MB), `TripleIpaInput` borrows
    the 119-column trace (−125 MB). C N W.
    *LoC +12/−6 for the join (views counted in #26/#32); shape: general.*
26. **Shplemini adds the shifted batch in place; content-sized columns; lifetimes** (builder and
    witness dropped before proving, each execution step after accumulation). H C N W.
    *LoC +201/−51 (two commits); shape: general.*
27. Removed non-arithmetic overheads in the provers and parallelized the remaining serial
    batching loops (2026-08-27). H C N W.
    *LoC counted in #17; shape: general.*

33. **Lagrange basis cached for committed round univariates** (ECCVM): interpolating each 24-point
    round univariate from scratch cost n inversions and an O(n³) product per round; the basis over
    0..n−1 is built once per sumcheck. `eccvm-sc/commit` 0.030 → 0.020s. C N W.
    *LoC ≈+40 (of +64/−3 with scopes); shape: **branch**: committed sumcheck only (the ECCVM).*
34. **`--profile lto` for release wasm builds** (opt-level 3 + fat LTO + one codegen unit): −1.3%
    on the chonk flow, 4/4 interleaved. The default release profile stays opt-level 2 for
    iteration speed (opt-level 3 alone is neutral on both targets). C W.
    *LoC +7 (Cargo.toml); shape: build profile.*

35. **Parallel evaluation of the Gemini batched polynomial and folds** (`evaluate_par`: chunk-wise
    Horner recombined with z^L, exact) and clone-free fold construction. `Gemini::evaluations`
    0.060 → 0.020s; decider 0.357 → 0.343, joint proof 1.022 → 1.006. Our Gemini is now faster
    than bb's (0.28 vs 0.30) with Shplonk and KZG at parity. H C N W.
    *LoC +46/−6; shape: general (a size threshold picks serial vs parallel).*

36. **Wide coefficient-basis path for the ECCVM set and lookup relations.** `Graded` gained a width
    parameter (default 8, unchanged for every other flavor) and the per-worker scratch a wide (24)
    row/accumulator set used only by relations over the narrow capacity, opt-in per relation set.
    The degree-21 set relation and degree-8 lookup relation had been evaluated pointwise at 22 and
    9 points per edge — the last pointwise work in the ECCVM. Dense ECCVM round 0: 495 → 206ms
    (bb 520); flow ECCVM sumcheck 0.227 → 0.168s (bb 0.176 — ahead). Proofs identical. C N W.
    *LoC +188/−57; shape: **branch** — a second (wide) coefficient path for relations with `8 < len ≤ 24`, opt-in per relation set (ECCVM only); the R7 retest condition, now resolved.*
37. **Duplicate-scalar pre-pass for commitments** (bb's dedup): witness wires are ~50% repeated
    scalars, and equal scalars share a bucket in every window, so their points are summed once
    (projective, batch-normalized) and the MSM runs over the distinct scalars with a phi table for
    the merged points. Triggered by a 2,048-coefficient sample showing ≥25% repeats on polynomials
    of ≥4,096 coefficients. `OinkProver::commit_to_wires` 0.445 → 0.39s; exact, proofs identical.
    H C N W.

38. **Batched-affine cluster merge in the dedup** (#37's merge was projective): clusters are reduced
    level by level with affine additions sharing one Montgomery-trick inversion per level; equal-x
    pairs take the projective formula, exactly. `commit_to_wires` 0.39 → 0.37s. H C N W.
    *LoC +70/−20; shape: general within the dedup branch (no new condition). Weak gain-for-complexity:
    ~50 net lines of pair-tree bookkeeping for 0.4% of proving; the 15-line projective merge already
    captured 0.05 of the dedup's 0.07. Revert candidate.*

### Circuit builder and ACIR lowering

28. **sha256 sparse-form powers.** `map_into_sparse_form` recomputed 32 base powers with field
    multiplies per call (66% of sha256 lowering was `mont_mul`); a cached table makes it 32 adds.
    `sha256_compression` 0.108 → 0.019s (bb 0.036). H C N W.
    *LoC +31/−4; shape: table: cached powers for bases 16/28/11 with a generic fallback (a **branch** on the base).*
29. **Powers of two for limbed range constraints.** `create_limbed_range_constraint`
    exponentiated `2^shift` six times per limb triple (~350 muls per u128 check where bb does one
    conversion per coefficient); a static 257-entry table. `acir::range_constraints` 0.133 → 0.032s
    on the range-heavy deploy flows (bb 0.043). H C N W.
    *LoC +16/−1; shape: table (no branch).*
30. Bulk witness ingestion, reference-based passes, sparse plookup helpers. H C N W.
    *LoC +55/−22; shape: general.*

### Memory and the allocator (native server and client)

31. **Transparent huge pages** (`glibc.malloc.hugetlb=1`, self-applied by one re-exec at startup
    since glibc reads `GLIBC_TUNABLES` only at process start). The prover streams gigabytes of
    short-lived multi-megabyte buffers through malloc; on 4KB pages that is millions of refaults
    and 400M+ dTLB misses on the private-tx-base frame (11.0s vs 7.9s at 32 threads, instructions
    equal). mimalloc's entire advantage turned out to be that it madvises its segments
    `MADV_HUGEPAGE`; with glibc given the same hint it is equal-or-slower and holds ~1.6× the
    client RSS in arena retention, so it is an opt-in A/B feature. H C N.
    *LoC +79/−18; shape: native-only; general (one re-exec at startup).*
32. **Client live peak 0.51 → 0.31 GB at 8 threads**: content-sized columns instead of dyadic
    (a 2^17 kernel 268 → ~60 MB), shifted entities as views, borrowed IPA input, lifetime fixes;
    dyadic sizes passed explicitly wherever they had been inferred from a column length. With THP,
    plain glibc is the best allocator on every axis (3.10s / 338 MB vs mimalloc's 3.15s / 534–605
    MB at 8 threads; 552 MB vs 1.2 GB at 32). C N.
    *LoC +186/−50 (main commit) + small follow-ups; overlaps #26; shape: general.*

## Tried and rejected, or not worth the complexity

Each entry: what, what it measured, why, and when it would be worth retesting. "Neutral" means
inside the noise band on the paired test described above.

| # | attempt | result | why | retest if |
|---|---|---|---|---|
| R1 | **Packed (SIMD) sumcheck plane** — 4-wide `QuadF` edge batching; the theory that bb's 5-wide `VectorField` relation evaluation owns the residual | ours 507 vs 285ms (1.8× *slower*) on the dense round-0 rung; **bb's own switch** (`-DBB_FORCE_SCALAR_LANE=1`) shows its SIMD sumcheck is worth 2.7% on a real flow, and bb disables it whenever the row manifest is in use | our scalar round 0 already beats bb's (495 vs 520ms); bb gates SIMD off for skip-heavy real traces anyway | only with the linked bb kernels *and* evidence bb's path helps on real traces |
| R2 | **Fused wasm multiply variants** — q1s1 round-interleaved fusion, two fused quad muls, three SIMD field kernels (two quad layouts, a stay-packed 2^261 Karatsuba) | all correct, none faster; 46 ns/elt with register spills; bb's `VectorField` measures 52.2 vs its scalar 52.7ns on this box and is 1.76× *slower* than its scalar under V8 | V8 codegen-bound, not latency-bound; wasm `extmul` needs lane shuffles on x86 | **on ARM** — `extmul` maps cleanly to NEON and bb's browser users are largely Apple Silicon/phones; every SIMD number here is x86 |
| R3 | **Fused `sum_of_products`** (native) — ark's generic, then a hand-written mulx/adcx/adox 4-limb interleaved Montgomery, then rewiring the graded multiply into a convolution over fused pairs | 48.7 / 41.9 vs 40.0ns for plain mul+add; in situ **+9G instructions** | the fused chain has less ILP than two independent multiplies, and the convolution forfeits the zero-coefficient skip, which is worth more; bb has no fused sum-of-products at this pin either | never, unless a call site has no zero-skip to lose |
| R4 | LTO fat / `codegen-units=1` | flat (wall at 8t, instructions at 32t) | the outlining was the `#[inline]` attribute layers, not link-time visibility | — (the attribute fix is in) |
| R5 | **bb's `parallel_for_mutex_pool` ported**, and separately **bypassing rayon entirely** | neutral on 8 interleaved pairs (2/8 and 6/8 wins, paired medians inside noise); the port was more *stable* (range 1.0 vs 2.7ms) but no faster | dispatch costs ~25µs against ~2.5ms/round implied; the deficit was our own serial tail (#19), not scheduling | a future profile showing work-stealing spin under saturation (it costs ~40% extra *instructions* at 32t, little wall on an under-subscribed box) |
| R6 | Sumcheck round-loop shape variants: static round-robin striping, boxed slots, persistent per-worker state, row-parallel fold, gap-row skipping, chunked-parallel `pows`, serial fold threshold, chunk floor up/down, chunk divisor, round-aware quad, dropping the skip probe, bb's 8-OS-thread shape, per-round transcript as the fixed cost | all neutral or worse on 8 pairs (striping 0/8: imbalance > L2 reuse; gap-row skipping 0.7% and bb's manifest is ECCVM-only; bb's fold is column-parallel too; transcript 0.26ms/round) | twelve hypotheses; the mechanism was the serial flush and per-chunk scratch | — |
| R7 | **`GRADED_MAX_LEN` 8 → 9** to bring the ECCVM `Lookup` relation into coefficient form | ECCVM sumcheck −1%, folding sumcheck **+3.5%** (3/3) | `Graded<F>` is a `Copy` `[F; 8]`+len, so every temporary moves 264 bytes even at degree 1 (bb's `UnivariateCoefficientBasis<F, 2>` moves 64); widening taxes every flavor | **resolved by #36** (width-parameterized `Graded`, wide path only for the ECCVM); the ~30G `[F; 8]` copy traffic in the merge ledger remains a separate item |
| R8 | **Parallel `batch_over_relations`** — over the d points; then over subrelations with fold-over-chunks | worse both times (ECCVM sumcheck 0.287 → 0.335 and → 0.318) | a second barrier per round on 15–24 small rounds costs more than 3ms of work spread eight ways; per-subrelation `Vec` allocation churned the allocator | never — the coefficient-form batching (#20) removed the work instead |
| R9 | MSM structure attempts: fused single-call chord kernel (first tree port), pack-on-push (bb's `push_point`/`drain_batch`), classify-walk copy elision, `bucket_reduce` packing, index-pair staging, per-MSM φ table when the caller has none, more/fewer concurrent MSMs | first port flow-**negative** at the flow's small sizes (fixed later as the packed drain, #10); pack-on-push neutral (the 256 B/pair AoS round trip I estimated at 60–100ms was cache-hot and free); copy elision a no-op (LLVM had done it); bucket packing rung-positive/flow-negative; staging unsafe (bb copies into spans for the same reason); φ table neutral; concurrency within 3% of sequential at flow sizes | the tree's cost is the field math both provers pay (61% of a 2^19 MSM, ~1950 CPU-ms floor), gather is memory-bound for both (wasm has no prefetch — `__builtin_prefetch` compiles to nothing, for bb too) | a rung that isolates the walk/bookkeeping and shows a >10% item |
| R10 | **"Batched MSM" for the Oink wire round** | withdrawn before building: bb's `pippenger_batched.hpp` header states its batch does *not* interleave MSMs — it runs single MSMs in sequence sharing only the GLV-doubled points and a small-member pool | our concurrent independent MSMs are already the more parallel structure | — |
| R11 | **Duplicate-scalar dedup** (bb's Phase A: the folding wire polynomials are ~50% duplicate scalars — 61309 nonzeros / ~25000 distinct — and equal scalars always share a bucket, so pre-summing halves the bucket adds) | not built; a naive projective merge loses (~30ms of mixed adds per big wire poly eats the saving); bb's version is a hash cluster + batched-affine tree-reduce + schedule redirect bits, ~500 lines in the hot MSM path | commit-total is already 0.71× bb, so this is not an aggregate lever — it is worth ~0.05–0.08s on the Oink wire round only | the deploy-flow tail (Oink wire round +0.15s) is the target |
| R12 | Later-rounds theory: "bb's short monomials make ECCVM rounds 1–14 nearly free" | **wrong** — bb's bench number was round 0 only (see traps) | recorded so it is not re-derived; the true mechanism was #20 | — |
| R13 | Windowed (start-index) polynomials like bb's | declined: ~0.3–0.5 GB recovery against a change touching every `coeffs` access; never-written tails are already free via `alloc_zeroed`; now worth ~10% of the client's ~30–40 MB live delta | | memory becomes the binding constraint on the client |
| R14 | bb-style large-block caching allocator (recycle every ≥256KB block + `MADV_HUGEPAGE`) | 9.9s vs 7.9s with the glibc tunable; deleted | the tunable's arena-heap coverage is what closes the rest | — |
| R15 | Cutting allocation churn under mimalloc (12.7 → 8.3 GB total) | moved neither RSS nor wall | the hint that mattered was page size, not churn | — |
| R16 | `talc` wasm allocator | deferred (needs the sync/atomics arena config for wasm-threads); wasm allocator contention measured null (wasm scales 3.95× on 8 threads vs native 3.67×) | | wasm memory growth becomes an issue |
| R17 | Bernstein–Yang inversion, native witgen point arithmetic | 0.8% and 0.7% of a merge op | too small | the ~40G "smeared" merge residue is attacked systematically |
| R18 | Thread placement / L3-domain pinning | pinning both provers to one domain gains us ~8% and bb nothing; `/proc/<pid>/task/*/stat` shows both split 50/50 across domains identically; matching bb's thread shape measured worse | not controllable in production; we run a denser instruction stream (higher IPC) and pay proportionally more for the same cross-domain latency | — (attack by doing less cross-thread work per round, which #19–20 did) |
| R19 | Forcing all later rounds dense / "drop the skip probe" | neutral; the probe costs ~0.06s and 4-wide arithmetic on the later rounds is neutral | | — |
| R20 | **`wasm-opt -O3`** on our module (binaryen 116, all relevant features enabled) | module 11.4 → 8.7 MB but **+11% slower** on the flow (6.33 vs 5.68s), proofs identical | binaryen's rewrites hurt V8's tiering/codegen on this module; bb's toolchain applies it to a different code shape | a newer binaryen/V8 pair, or `-O2`/`-Os` if size ever matters |
| R22 | Single-threaded small MSMs inside `batch_commit` (bb small-member pool shape); tiny-MSM threshold 128→4096 | both neutral on the ECCVM and Oink wire rounds (0.220 → 0.220; 0.44 → 0.44) | rayon already absorbs the nesting; the wire rounds' excess is not the small-MSM algorithm | — |
| R24 | In-place `MulAssign` (downward convolution) + `*=`-chained Permutation body | neutral: Permutation 6029 → 6181 ns/edge, flow unchanged | temporaries are not the cost either; bb's coefficient-basis products use cheaper short-product formulas | with exact-size univariates / Karatsuba-style short products |
| R23 | Slice-iterating the `Graded` inner loops (remove per-coefficient bounds checks) | neutral: Permutation 6029 → 6167 ns/edge, flow unchanged | LLVM had already elided the checks; the Permutation excess (1.42× bb, the folding outlier) is the fixed `[F; 8]` move per temporary | with exact-size (degree-typed) univariates, which is the fix for that traffic |
| R21 | `opt-level = 3` for the default release profile (wasm and native) | neutral both targets (5.675 vs 5.678 wasm; 2.94 → 2.98 native); the 2026-09-04 opt-level-2 choice stands | the win is in LTO + single codegen unit (#34), not the per-function pass level | — |

## What owns the remaining gap

**Chonk, wasm, typical flow (`transfer_1`), proving-only +0.29s = 1.06×** (the table below predates #36/#37 for the items they changed; those rows are updated), children summed against
parents on both sides so nothing hides in a scope boundary:

| item | gap | mechanism |
|---|---|---|
| Oink `commit_to_wires` | ~+0.07s after #37 | the dedup merge is projective (~11 muls per repeated point); bb's is batched-affine |
| folding `prove_sumcheck` (6 instances) | +0.10s | per-edge: the Permutation relation runs 1.42× bb (every row) and the two Poseidon2 internal relations 1.08–1.22×, all other relations at or ahead of bb; the excess is `Graded`'s fixed 264-byte moves vs bb's exact-sized univariates |
| ECCVM (like-for-like, rows excluded) | ~+0.11s | sumcheck −0.008 after #36 (ahead), wire commits +0.043 (86 Grumpkin polys of ≤3141 rows), IPA +0.026, PCS/claims ~+0.05 |
| decider proof (Shplemini/KZG on the accumulator) | ~+0.03s | after #35: Gemini 0.28 vs bb 0.30, Shplonk/KZG parity |
| multilinear batching | +0.038s | pairs with bb's `finalize` (0.125) |
| hiding-kernel oink, from_builder, create_circuit, joint | +0.028, +0.021, +0.014, +0.012 | |
| wins | −0.055 output-to-accumulator, −0.088 logderiv, −0.030 z_perm, −0.075 partially_evaluate | |

The `deploy_tokenContract` flows (the wall tail at 1.07–1.08× fair basis) carry the same
per-instance items scaled by a bigger app circuit; their builder excess was closed by #5 and #29.

**Rollup (native), merge circuits 1.19× warm**, from the instruction ledger (410G vs bb 324G):
~30G MSM tree orchestration, ~30G `Graded` `[F; 8]` copy traffic (R7's real fix), ~40G smeared
(operator-site field ops in recursive-verifier witgen, arkworks' ~250-mul Fermat inverse vs bb's
Bernstein–Yang). The small ops (padding 0.21 vs 0.17s, verify 0.55 vs 0.51 on bbbench 16t) are fixed-cost and
dispatch dominated; every circuit above a second is now 0.79–0.99× bb natively.

**Next levers, ranked by expected value per line of code:** degree-typed const-generic
univariates (R7 + the 30G); bb's Phase-A dedup (R11, the Oink round); the ECCVM's per-round ZK and
commit overhead; Bernstein–Yang inversion inside the smeared 40G.

## Client memory

The chonk client flow is the memory-sensitive target (browsers; wasm linear memory never shrinks,
so *live allocated bytes at peak* — dhat via `--features heap-profile`, aggregated by
`tools/heap_agg.py` — is the metric that transfers, alongside native RSS). The items in #32 took
live peak 0.51 → 0.31 GB at 8 threads. The remaining ~30–40 MB over bb at the peak (the joint
MegaZK+Translator phase): three tail-indexed translator Lagrange columns bb allocates with a start
window (12 MB), leading zeros in gate-selector columns bb's structured trace skips via start
indices (~10 MB per live instance), and larger MSM scratch — all start-window territory (R13).
Server-side, huge pages commit in 2MB units, so the corpus-wide peak reads 17.0 GB against
mimalloc's 15.3 and bb's 13.0; of the live delta, the preloaded 2^23-point SRS pool (~0.6 GB, a
sizing choice) and dense sumcheck round tables plus ~20% dead dyadic tail in the trace polynomials.

## wasm

The client prover runs end to end on `wasm32-wasip1-threads` (V8/`node` is the production shape;
wasmtime is a harness). Per-op it is mul-bound: ark's generic Montgomery multiply was 121ns on wasm
vs 20 native, so the first tier was the field kernel (#3, #4): V8 mul 61.9ns against bb's 57.5;
wasm/native ≈ 2.8× against bb's 2.2×. The second tier was everything in the sumcheck and prover
phases above, most of it serial work made parallel or removed — which is why the same commits took
native chonk from 1.16× to 0.95×. The remaining wasm-specific edge bb keeps is scalar kernel
quality per runtime (within 8% under V8; wider under cranelift, which browsers do not run).
SIMD is dead on x86 by bb's own benchmark (R2) with the ARM caveat standing.

Also settled on the way: wasm allocator contention is a null; wasm memory is 0.82–1.05× of bb's
on the 11 flows; the wasm/native wall ratio equals the per-multiply ratio, i.e. the wasm build is
purely mul-bound. The standalone `base/mont29.rs` is the reference implementation and cross-check
for the kernel. The planned algorithmic tier — GLV over a precomputed φ(SRS) — landed as #9/#14;
protocol-level experiments (GKR for grand products, small-value sumcheck) remain candidates behind
feature flags as upstream proposals for bb itself.
