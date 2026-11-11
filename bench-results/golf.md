# bb-ref vs golf

The tables of record (`tools/bench_tables.sh`) with golf in bb's place, plus ARM. Golf is the
three season-0 leaders (client-wasm 2eff0e, rollup-c7i 5450b4, avm-c7i 6ea0a2) merged and ported
to v6.0.0-rc.7 with bb-ref's pin patches (`golf/all7` over `golf/base7`); its proofs and corpus
responses are byte-identical to bb-ref's. Ratios are bb-ref / golf: below 1 is bb-ref ahead.
Every golf commit's status against bb-ref is in [golf-ledger.md](golf-ledger.md).

| | threads | time | memory | table |
|---|---|---|---|---|
| Chonk, native (11 flows) | 8 | **0.87×** wall, 0.90× proving | **0.90–0.99×** | [chonk-native](golf/chonk-native.txt) |
| Chonk, wasm, V8 | 8 | **0.99×** | **0.75–0.92×** | [chonk-v8](golf/chonk-v8.txt) |
| Chonk, wasm, wasmtime | 8 | **0.92×** | **0.73–0.81×** | [chonk-wasmtime](golf/chonk-wasmtime.txt) |
| Chonk, wasm, V8 wide arithmetic | 8 | **0.81×** | **0.82–0.91×** | [chonk-v8-wide](golf/chonk-v8-wide.txt) |
| Chonk, native ARM (Graviton4) | 8 | **0.94×** | | [arm-graviton](golf/arm-graviton.txt) |
| Rollup corpus (63 responses) | 16 | **0.84×** | 1.06× (11.25 vs 10.62 GB peak) | [rollup](golf/rollup.txt) |
| AVM corpus (prove, check, verify) | 16 | **0.62×** (prove 0.77×, check 0.44×) | **0.82×** (10.09 vs 12.32 GB) | [avm](golf/avm.txt) |

x86 tables: AWS c7a.4xlarge (AMD EPYC 9R14, Zen 4, 16 cores). ARM: AWS c8g.4xlarge (Graviton4,
16 vCPU). Golf's wasm is its `wasm-threads` `bb` CLI, stripped like bb's; its proving-only column
is empty (no bench-instrumented golf module). Golf's ARM build uses the pin's arm64-linux preset
(AVM off).

## Where golf leads

- **Rollup peak memory**: about 6% above golf's.
- **Chonk past ~32 threads** (Zen 5, 64–96 vCPU): golf's pool keeps its workers spinning between
  parallel regions; rayon's go to sleep and wake one after another, which costs bb-ref ~6% at 32
  threads and more beyond. A longer rayon spin reaches parity there for ~55% more CPU; not taken.
  Up to 16 threads bb-ref leads.
- **AVM proving at 96 threads** on golf's own five inputs: golf ~9% ahead (bb-ref ahead at 16 and
  32 threads, and its circuit check 2× faster throughout).
