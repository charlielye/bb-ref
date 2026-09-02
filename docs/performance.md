[◄ bb-ref](../README.md)

# Performance vs barretenberg

Where the rest of the docs describe *what* bb-ref computes (bit-identically to bb), this
records *how fast*, what was done to get there, and — since the goal is ≤1.2× with simple
code, not parity at any cost — exactly which structural differences own the remaining gap.
Numbers are from an idle 64-core c7a (both provers pinned to 32 threads, seeded, measured by
`tools/bench.sh` / `tools/bench_chonk.sh`; the working probes are `tools/remote_bench.sh`).

## Where it stands

| benchmark | bb | bb-ref | ratio |
|---|---|---|---|
| rollup corpus (62 recorded server ops) | 254.7s | 300.9s | **1.18×** |
| — root rollup | 29.2s | 29.6s | 1.02× |
| — private tx base | 8.2s | 10.2s | 1.24× |
| chonk client flows (11 pinned transactions) | 30.3s | 45.8s | **1.51×** |
| private tx base peak RSS | 3.4 GB | 5.1 GB (4.6 live) | 1.5× |
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

Native RSS lands at 356 MB vs bb's 312 with `MIMALLOC_PURGE_DELAY=0
MIMALLOC_ARENA_EAGER_COMMIT=0` (purging costs ~0.8s of the 4.2s wall; without it mimalloc
retains freed pages and RSS reads ~600 MB — live is 314 MB either way). The remaining
~30–40 MB over bb at the peak (the joint MegaZK+Translator phase): three tail-indexed
translator Lagrange columns bb allocates with a start window (12 MB), leading zeros in
gate-selector columns bb's structured trace skips via start indices (~10 MB per live
instance), and larger MSM scratch. All are start-window territory — the same crate-wide
`coeffs`-offset change declined above, now worth ~10% rather than a structural multiple.

Each of these is a deliberate simplicity/speed trade, consistent with the project's goals.
The next planned wins are algorithmic rather than micro-architectural — GLV over a
precomputed φ(SRS) (output-preserving), then protocol-level experiments (GKR for grand
products, small-value sumcheck) behind feature flags as upstream candidates for bb itself.
