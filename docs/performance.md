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
| rollup corpus (62 recorded server ops) | 237.7s | 241.6s | **1.02×** |
| — private tx base (9 proofs) | 8.13s | 7.81s | **0.96×** |
| — root rollup (2 proofs) | 26.3s | 24.4s | **0.93×** |
| — checkpoint root | 18.9s | 19.3s | 1.03× |
| chonk client flows (11 pinned transactions) | 29.9s | 35.4s | **1.18×** |
| — single flow at 8 threads | 2.82s | 3.29s | 1.17× |
| rollup corpus peak RSS | 13.0 GB | 15.3 GB | 1.18× |
| chonk client flow peak RSS, 8 threads | 312 MB | 358 MB purged / 314 MB live | **1.15×** |

## What closed the gap (largest first)

1. **mimalloc as the global allocator.** The prover cycles large dense polynomial buffers;
   glibc returns them to the OS and re-faults zeroed pages on the next allocation. mimalloc
   recycles pages per thread: 28× fewer page faults and −30% wall on the rollup base circuit.
   bb-ref now takes 10× *fewer* faults than bb.
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
- **Memory (server)** — of the 1.2GB live delta: the preloaded 2^23-point SRS pool (~0.6GB, a
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

Native RSS reads ~600 MB against bb's 312 while live is 314 MB: the difference is mimalloc
arena retention, not allocations. The full option sweep (8 threads, interleaved):
`MIMALLOC_ARENA_EAGER_COMMIT=0` alone 465 MB at +2% wall, `MIMALLOC_PURGE_DELAY=0` alone
450 MB at +12%, both together 358 MB at +19%. Phase-boundary `mi_collect` — from the main
thread or broadcast to every rayon worker — releases nothing (the pages are arena-level),
and cutting the allocation churn itself (12.7 → 8.3 GB total: reused MSM gather/tree scratch,
reused row buffers in the grand-product and logup loops) moves neither RSS nor wall, since
mimalloc was already recycling those size classes. Since the churn work, mimalloc has stopped mattering much for the *client* flow: a
`--features sysalloc` build (glibc) measures 4.31s / 355 MB at 8 threads and 3.01s / 613 MB
at 32, against mimalloc's 4.20s / 605 MB and 2.75s / 1.3 GB — a 2.5–9% wall cost for half
the RSS. The *server* path still needs mimalloc (the private tx base frame runs 9.7s vs
12.9s on glibc at 32 threads, and no glibc tunable closes it — bb's 8.5s on plain glibc
comes from its lower-churn allocation pattern, which is the real fix). So mimalloc stays
the default for one binary serving both, `sysalloc` is the memory-optics build, and wasm —
the target where memory actually matters — has no mimalloc either way: its linear-memory
peak tracks the 314 MB live curve. The remaining ~30–40 MB of live delta over bb at the peak (the joint
MegaZK+Translator phase): three tail-indexed translator Lagrange columns bb allocates with a
start window (12 MB), leading zeros in gate-selector columns bb's structured trace skips via
start indices (~10 MB per live instance), and larger MSM scratch. All are start-window
territory — the same crate-wide `coeffs`-offset change declined above, now worth ~10% rather
than a structural multiple.

The chonk client flow at 8 threads (3.51s vs bb 2.82s = 1.24×, from 4.26s at the start of
this pass; the full 11-flow set at 32 threads sits at 1.20×, with the largest flow faster
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
