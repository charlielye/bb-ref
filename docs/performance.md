[◄ bb-ref](../README.md)

# Performance vs barretenberg

Where the rest of the docs describe *what* bb-ref computes (bit-identically to bb), this
records *how fast*, what was done to get there, and — since the goal is ≤1.2× with simple
code, not parity at any cost — exactly which structural differences own the remaining gap.
Numbers are from an idle 64-core c7a (no SMT, single NUMA node; both provers seeded and
pinned to the same 32 cores with `taskset -c 0-31`, measured by `tools/bench.sh` and the flow
loop; the working probes are `tools/remote_bench.sh`).

## Where it stands

| benchmark | bb | bb-ref | ratio |
|---|---|---|---|
| rollup corpus (62 recorded server ops) | 237.7s | 236.5s | **0.99×** |
| — private tx base (9 proofs) | 8.13s | 7.82s | **0.96×** |
| — root rollup (2 proofs) | 26.3s | 23.8s | **0.91×** |
| — checkpoint root | 18.9s | 18.7s | 0.99× |
| chonk client flows (11 pinned transactions, 8 threads) | 46.9s | 51.7s | **1.10×** |
| — canonical flow (ecdsar1 transfer + sponsored fpc) | 2.83s | 3.17s | 1.12× |
| rollup corpus peak RSS | 13.0 GB | 17.0 GB | 1.31× |
| chonk client flow peak RSS, 8 threads | 290–340 MB | 320–380 MB | **~1.10×** |

Chonk is the client-side prover, so its numbers are always at 8 threads (`bench_chonk.sh`'s
default); the rollup corpus runs at the 32-thread server profile.

## What closed the gap (largest first)

1. **Transparent huge pages** (`glibc.malloc.hugetlb=1`, self-applied by one re-exec at
   startup since glibc only reads `GLIBC_TUNABLES` at process start). The prover streams
   gigabytes of short-lived multi-megabyte buffers through malloc; on 4KB pages that cycle
   costs millions of page refaults and 400M+ dTLB misses on the private-tx-base frame
   (11.0s at 32 threads vs 7.9s with the tunable — the whole gap, instructions equal).
   mimalloc was the allocator for most of this project's history and its entire advantage
   turned out to be that it madvises its segments `MADV_HUGEPAGE`; with glibc given the same
   hint it is equal-or-slower and holds ~1.6× the client RSS in arena retention, so it is now
   an opt-in A/B feature rather than the default. A bb-style large-block caching allocator
   was also built and measured on the way: recycling every ≥256KB block plus the same madvise
   only reached 9.9s — the arena-heap coverage of the tunable is what closes the rest —
   so it was deleted.
2. **A batched-affine Pippenger MSM** (`base/msm.rs`) in the shape of bb's
   `scalar_multiplication_fast`: signed Booth digits, counting-sort schedules, pair-tree
   reduction through one shared Montgomery inversion per level. Affine adds cost ~6 muls
   against ~14 for the Jacobian adds in arkworks' MSM. Falls back to arkworks below 1024
   points per thread (the machinery has fixed costs; the crossover scales with threads).
3. **Parallel fixed-base table precomputation.** The root rollup spent 18.6s of 41.5s
   sequentially building 2^15 Straus plookup tables and hash-to-curve offset generators for
   the in-circuit IPA verification; the builder-free halves now run in parallel with
   registration order (= gate order) preserved. Root rollup landed at bb parity.
4. **Bounded live scratch**: MSM point gathers work in 2^16-entry blocks and `batch_commit`
   runs at most 8 MSMs concurrently (a shared-index pull loop — pre-chunking serializes big
   polynomials behind each other). Either bound alone saves nothing; together −3.5GB.
   Lifetime fixes (drop builder/witness before proving, reuse the pooled SRS, add shifted
   batches in place, cache the Montgomery-converted SRS in `bn254_g1.ark.mont`) trim the rest.
5. arkworks' x86-64 asm (`ark-ff/asm` + `+bmi2,+adx`), putting field multiplication at parity
   with bb's hand-rolled assembly.

Every step was gated on byte-identical seeded proofs and the full tape suite: none of this
changes a single output bit.

## What owns the remaining gap

Measured with `BBREF_TIMING=1` (phase walls, `BBREF_TIMING_RSS=1` for RSS at each mark, and
the sumcheck univariate/fold/setup split) plus `perf stat` instruction counts:

- **Relation-body codegen** — the dominant residual on both provers. Sumcheck univariate
  extension+accumulation runs ~1.3–1.6× bb per edge (private tx base: 1.10s vs 0.68s; the
  chonk flows are sumcheck-heavy, hence their higher overall ratio). bb gets there with
  hand-shaped C++ template kernels; matching it in Rust means per-relation specialization.
- **MSM engineering depth** — bb's SIMD digit recoding, duplicate-scalar pre-pass and finer
  task scheduling are worth ~1.2–1.5× on the MSM itself at high thread counts (~0.3s on the
  private tx base).
- **rayon vs bb's parking pool** — ~40% extra *instructions* at 32 threads is work-stealing
  spin between short parallel sections. On an under-subscribed machine it fills idle cores
  and costs little wall; on a saturated one it competes with real work.
- **Memory (server)** — huge pages commit in 2MB units, so the corpus-wide peak reads
  17.0 GB against mimalloc's 15.3 and bb's 13.0; that rounding is the price of the −2% wall
  and the halved client RSS, on the path where physical memory is cheapest. Of the live delta: the preloaded 2^23-point SRS pool (~0.6GB, a
  server sizing choice), and dense sumcheck round tables plus ~20% dead dyadic tail in the
  trace polynomials. A bb-style windowed polynomial was evaluated and declined: it would
  recover only ~0.3–0.5GB against a change touching every `coeffs` access in the crate
  (never-written tails are already free via `alloc_zeroed`).

## Client memory

The chonk client flow is the memory-sensitive target (browsers; wasm linear memory never
shrinks, so *live allocated bytes at peak* — dhat via `--features heap-profile`, aggregated by
`tools/heap_agg.py` — is the metric that transfers, alongside native RSS). Live peak went
0.51 → 0.31 GB at 8 threads, byte-identical proofs throughout:

1. **Content-sized columns instead of dyadic-sized.** Instance polynomials are allocated to
   each column's real extent (a 2^17 kernel: 268 → ~60 MB); the translator's sparse Lagrange
   columns get their bb window's extent; oink sizes the columns it derives. Consumers
   zero-default past a column's end, so the dyadic size is now passed explicitly wherever it
   was inferred from a column length (`prove_sumcheck`, `shplemini_prove`).
2. **Shifted entities as views** on the prove path (translator grand product, ECCVM trace)
   instead of materialized copies (−90 MB and −55 MB at their phase peaks).
3. **`TripleIpaInput` borrows the ECCVM trace** rather than cloning all 119 columns (−125 MB).
4. Lifetime fixes: each execution step is dropped after accumulation, the translator circuit
   after `from_circuit`.

With the huge-page tunable, plain glibc is now the best allocator on every axis measured:
the 8-thread flow runs 3.10s / 338 MB against mimalloc's 3.15s / 534–605 MB (mimalloc's
excess is arena retention over the 314 MB live curve, and no option sweep brought it down
without double-digit wall cost). At 32 threads the gap widens: 552 MB vs 1.2 GB. Under
mimalloc, cutting the allocation churn itself (12.7 → 8.3 GB total) had moved neither RSS
nor wall — the correct hint was page size, not churn. wasm — the target where memory
actually matters — never had an allocator swap either way: its linear-memory peak tracks
the live curve. The remaining ~30–40 MB of live delta over bb at the peak (the joint
MegaZK+Translator phase): three tail-indexed translator Lagrange columns bb allocates with a
start window (12 MB), leading zeros in gate-selector columns bb's structured trace skips via
start indices (~10 MB per live instance), and larger MSM scratch. All are start-window
territory — the same crate-wide `coeffs`-offset change declined above, now worth ~10% rather
than a structural multiple.

The chonk client flow at 8 threads (3.17s vs bb 2.83s = 1.12×, from 4.26s at the start of
this pass; the full 11-flow set at 8 threads sits at 1.10×, with the largest flow faster
than bb)
decomposes the same way, measured by phase marks against bb's `BB_BENCH` tree and
`perf stat` instruction counts (ours 174G vs bb 101G at equal parallel efficiency and better
IPC — the whole gap is extra instructions, not stalls). What landed in this pass, each step
byte-identical:

- **ark's parallel `batch_inversion` splits even 32-element batches into one chunk per
  thread** (a real modular inversion plus a rayon dispatch each), and the MSM tree ran it
  nested inside its own rayon jobs — 14% of all instructions. Serial in-place inversion with
  reused scratch: 4.20 → 3.98s.
- **Coefficient-basis relation evaluation** (`honk/graded.rs`, bb
  `UnivariateCoefficientBasis`): the edge rows become degree-tracked univariates
  `row0 + X·Δ` and the unchanged FieldLike-generic relation bodies run on them, so each ring
  operation costs its true degree instead of the full batched length — and a locally-constant
  selector (Δ = 0) stays degree 0. Mega folding sumchecks −26% single-thread; 3.98 → 3.84s.
  The Translator relation set measured *slower* under coefficient basis (add-heavy,
  high-degree DAGs where schoolbook products exceed the pointwise cost) and keeps the
  pointwise path; the ECCVM's degree-24 univariates don't fit the fixed capacity and fall
  back automatically.
- Sparse commitment inputs compact to their support in `msm` (a 34-nonzero masking poly had
  cost 7ms), and the sumcheck edge loop fills only the rows its skip predicates and active
  relations read.
- **The IPA consumes reduction rounds in pairs** (`base/fold.rs`, bb `batch_two_round_fold`):
  the second round's L/R expand the deferred SRS fold linearly over the un-folded quarters,
  and both folds land in one four-term combination per output — the full-width `u1·u2`
  GLV-split so four ≤128-bit Booth digit streams share a single doubling chain of
  batched-affine passes (SRS fold 187 → 90ms; the passes handle exceptional operands exactly,
  so bb's safe-flag schedule simulation isn't needed). The graded path also chooses per
  relation, letting the ECCVM run six of its eight relation sets in coefficient basis
  (−22% single-thread). 3.84 → 3.72s.

The residue thesis was then proven on the MSM tree kernel: one 2^17 random-scalar MSM at 8
threads costs bb 3.82G instructions, ours 5.15G (arkworks: 7.92G) — same algorithm, same
inputs. Splitting the tree's work list into parallel bucket/point arrays (the pairing scan
streams dense u32s) recovered 0.15s of wall from cache behavior alone; the instruction
surplus itself sits in arkworks' outlined 45-instruction Montgomery multiplication versus
bb's macro-expanded asm — measured at equal per-op wall (19.2ns vs 20.4ns), so it costs
instructions, not time, and neither LTO, codegen-units=1, nor forced inlining moves it.

What owns the remaining ~0.5s: a smear of ~0.02–0.05s items that resisted four successive
micro-passes (a fused gather/tree level, forced inlining, graded-value traffic cuts — all
measured flat). Crossing it needs the rebuild-scale items: compile-time-sized univariates
for the relation kernels (bb's Univariate<N> templates), bb's indexed batched-affine adds
through every tree level, fused multiply-accumulate formulas via `sum_of_products`, and the
translator's short-monomial bodies. A plain batched-affine single-scalar SRS fold was tried before the
two-round port and measured a wash — affine-with-shared-inversion and Jacobian doubling cost
the same ~6.5 muls; the win is entirely the 4-way chain sharing.
The next planned wins are algorithmic rather than micro-architectural — GLV over a
precomputed φ(SRS) (output-preserving), then protocol-level experiments (GKR for grand
products, small-value sumcheck) behind feature flags as upstream candidates for bb itself.
