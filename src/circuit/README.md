[◄ bb-ref](../../README.md)

# circuit — the builder

Where circuits come from. A circuit here is a **table** — rows of wire indices plus selector
values, grouped into blocks by gate type — and this module is the API that fills it: variables,
copy constraints, gates, lookup tables, memory, and (for Mega) the Goblin op queue and databus.
[Tour, Act I §1–2](../../docs/tour.md#act-i--one-ultrahonk-proof) introduces the table model.

*Unfamiliar name? Every recurring term is defined in [docs/glossary.md](../../docs/glossary.md).*

Consumers: [`stdlib`](../stdlib/README.md) types hold a handle to the builder and emit gates through it;
[`honk`](../honk/README.md)'s `ProverInstance` turns the finished table into polynomials;
[`goblin`](../goblin/README.md) proves the op queue this module records. Mirrors bb
`stdlib_circuit_builders/` restricted to what the pinned flows use — one builder for both Ultra
and Mega, with the Mega extras split out rather than a class hierarchy.

| file | what it is |
|---|---|
| `builder.rs` | variables + copy constraints (union-find over `real_variable_index`), tags for the multiset checks, the gate API, finalization |
| `trace.rs` | the trace blocks: rows of wire indices + selectors, laid out sequentially per block |
| `mega.rs` | Mega-only gates: ECC op rows, databus reads, compressed Poseidon2 rounds |
| `op_queue.rs` | the Goblin ECC op queue — every deferred EC op, recorded natively (for the ECCVM) and as two width-4 rows (for Mega and the Translator) |
| `memory.rs` | ROM/RAM arrays: LogUp for single-value ROM, sorted-transcript scheme for paired ROM and RAM |
| `plookup.rs` | multi-tables that slice a key across basic tables and chain the reads with accumulators |
| `keccak_tables.rs`, `uint_tables.rs`, `secp256r1_fixed_base.rs` | the specific table families the pinned circuits look up |
| `nnf.rs` | non-native-field gates — the gate-level support `bigfield` builds its 68-bit limb arithmetic on |

## What makes this layer delicate

- **Row order is part of the VK.** Selector polynomials are committed, so *which gate lands on
  which row* — including the order finalization appends its bookkeeping gates (memory
  consistency, range lists, plookup sorts) — must match bb exactly. See
  [docs/gate-exactness.md](../../docs/gate-exactness.md).
- **Copy constraints are lazy.** `assert_equal` merges union-find classes; sigma/id polynomials
  are derived from the final classes. A variable read before its class settles is fine — a gate
  emitted with a stale *index* is not, which is why gadgets pass witness indices, not values.
- **The op queue double-books deliberately**: the native accumulator shadows the deferred ops so
  `eq_and_reset` knows the answer the ECCVM must reproduce. The two views must be appended in
  lockstep — an op recorded in one and not the other fails only at Translator time.
