# bb-ref vs golf

The tables of record (`tools/bench_tables.sh`) with golf in bb's place, plus ARM. Golf is the
season-0 leaders (client-wasm b517eb, rollup-c7i eeb676, avm-c7i 16c253) merged and ported to
v6.0.0-rc.7 with bb-ref's pin patches (`golf/all8b` over `golf/base7`); its proofs and corpus
responses are byte-identical to bb-ref's. Ratios are bb-ref / golf: below 1 is bb-ref ahead.
Every golf commit's status against bb-ref is in [golf-ledger.md](golf-ledger.md).

`golf/all8b` leaves out golf's scratch-thread recursion series (ledger 067: Honk recursion
constraints built on their own threads and spliced in), which rests on golf's own fixed-seed
engine; golf's rollup leader with it is faster than the build measured here.

| | threads | time | memory | table |
|---|---|---|---|---|
| Chonk, native (11 flows) | 8 | **0.93×** wall, 0.94× proving | **0.86–0.95×** | [chonk-native](golf/chonk-native.txt) |
| Chonk, wasm, V8 | 8 | 1.03× | **0.79–0.94×** | [chonk-v8](golf/chonk-v8.txt) |
| Chonk, wasm, wasmtime | 8 | **0.95×** | **0.70–0.80×** | [chonk-wasmtime](golf/chonk-wasmtime.txt) |
| Chonk, wasm, V8 wide arithmetic | 8 | **0.83×** | **0.81–0.94×** | [chonk-v8-wide](golf/chonk-v8-wide.txt) |
| Chonk, native ARM (Graviton4) | 8 | **0.95×** | **0.87–0.96×** | [arm-graviton](golf/arm-graviton.txt) |
| Rollup corpus (63 responses) | 16 | 1.01× | 1.05× (11.24 vs 10.67 GB peak) | [rollup](golf/rollup.txt) |
| AVM corpus (prove, check, verify) | 16 | **0.72×** (prove 0.96×, check 0.45×) | **0.96×** (10.40 vs 10.78 GB) | [avm](golf/avm.txt) |

x86 tables: AWS c7a.4xlarge (AMD EPYC 9R14, Zen 4, 16 cores). ARM: AWS c8g.4xlarge (Graviton4,
16 vCPU). Golf's wasm is its `wasm-threads` `bb` CLI, stripped like bb's, built from the merged
branch (its native-only rollup code compiles for wasm32 only with `-Wno-error`); its proving-only
column is empty (no bench-instrumented golf module). Golf's ARM build uses the pin's arm64-linux
preset (AVM off).

## Where golf leads

- **Chonk on V8**: ~3%, on every flow. Golf's module is built at `-O2 -fno-vectorize`, which V8
  favours: on wasmtime the same module trails bb-ref's by 5%.
- **Rollup's small recursion circuits** (merges, block roots): golf 13–16% ahead, where
  recursion constraint construction (serial in bb-ref, ~21% of the corpus) dominates; bb-ref
  leads on the large circuits, for parity overall.
- **Rollup peak memory**: about 5% above golf's.
- **Chonk past ~32 threads** (Zen 5, 64–96 vCPU): golf's pool keeps its workers spinning between
  parallel regions; rayon's go to sleep and wake one after another, which costs bb-ref ~6% at 32
  threads and more beyond. A longer rayon spin reaches parity there for ~55% more CPU; not taken.
  Up to 16 threads bb-ref leads.
