# Own golf

bb-ref's own performance rounds (the `golf` skill): one idea per round, gated byte-exact, measured
on the bench box against master. Every idea gets a row, kept or not, so no dead end is retried
without new evidence. Golf's own submissions are classified in [golf-ledger.md](golf-ledger.md);
older measured dead ends are in [LADDER.md](LADDER.md).

Verdicts: **KEPT** (commit), **REJECTED** (built and measured, no gain), **SKIP** (not built; the
measured ceiling or estimate doesn't pay for its code).

| # | target | idea | measured | LOC | verdict |
|---|---|---|---|---|---|
| 1 | rollup | non-native arithmetic bounds on a stack 1024-bit `Uint` instead of heap `BigUint` (~40% of the serial recursion build) | corpus 0.96x vs master; merges/block roots 0.93x | +330 | KEPT 0dbf6b1 |
| 2 | rollup memory | Gemini's A_0 folded chunkwise from F and G; F, G freed before Shplonk's quotient | peak 11.86 -> 10.30 GB, time 1.00x | +30 | KEPT e28dac3 |
| 3 | chonk V8 | dedicated 4-lane square for the MSM tree's slope (bit-identical, 40 vs 66 limb products) | 0.998x (noise) | +90 | REJECTED |
| 4 | rollup | recursion constraints built on scratch threads and spliced | ceiling: 11 of 30 proving requests have >=2 constraints; perfect overlap <= 3.7% | ~1-1.5k | SKIP |
| 5 | chonk V8 | the rest of the HyperNova folding sumcheck on 4-lane SIMD (golf evaluates every relation 5-wide; the largest scope gap, 1.76 vs 1.38 s on storage_proof) | not built: a generic 4-lane path was neutral (LADDER Update 26); per-relation kernels are ~1% per few hundred lines | — | SKIP |
| 6 | chonk V8 | the ECCVM's Grumpkin key (4 MB pinned chunk: SHA-256 + decode) prepared on a helper thread while the steps accumulate instead of on the final proof's critical path (bytes read on the main thread: wasm workers cannot read files) | V8 0.974x, wasmtime 0.99x, native 1.00x vs master; V8 vs golf 1.03x -> 1.00x | +25 | KEPT 9d8b21d |
