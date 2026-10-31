[◄ bb-ref](../../README.md)

# avm — the AVM prover and verifier

bb's AVM2 proofs, proven over bb's trace (`prover.rs`, byte-identical to bb's: the AVM proof has no
ZK randomness) and checked natively (`verifier.rs::verify`) and as bb's
two-layer AVM recursive verifier, the public tx base rollup's AVM recursion constraint. Its inner
MegaAvm circuit (`recursive.rs`) verifies the AVM proof with the EC work deferred to the op queue;
`two_layer.rs` proves that circuit (MegaAvm Honk, then Goblin: ECCVM, TripleIPA, Translator, on one
transcript) and verifies those proofs in the rollup's Ultra circuit. All gate-exact against bb.
The simulator and trace generator are bb's (`libbb-avm-sim.a`, the `bb-avm` feature,
`src/msgpack/bb_avm.rs`); the prover, verifier, circuit check (`prover.rs::check_circuit`) and
public-input columns (`public_inputs.rs`) are bb-ref's.

*Unfamiliar name? Every recurring term is defined in [docs/glossary.md](../../docs/glossary.md).*

## Relations are data

The AVM has ~300 relations generated from PIL (bb-pilcom), ~13k lines of constraint expressions,
plus 404 lookups and permutations over ~3,200 columns. bb compiles them five times over (prover,
verifier, check-circuit, tests, in-circuit), which is most of its AVM build time. A verifier
evaluates each relation once, at one point, so bb-ref interprets them there (the prover, which
needs every row, runs them compiled to straight-line programs from the same tables):
`dev/regen_avm.py` turns the pin's bb-pilcom output into two committed tables, and
`relations.rs` evaluates them as a sumcheck `RelationSet` over any `FieldLike`. Expressions keep
bb's C++ evaluation order (aliases first, operands left to right), which in-circuit is the gate
order ([docs/gate-exactness.md](../../docs/gate-exactness.md)).

| file | what it is |
|---|---|
| `generated/layout.txt` | constants, the column layout (bb `ColumnAndShifts` order), the fixed VK |
| `generated/relations.txt` | every relation in bb's flavor order: expression trees, lookup/permutation column lists |
| `tables.rs` | parses the tables once |
| `relations.rs` | the interpreter, plus bb's log-derivative lookup/permutation body |
| `poseidon2_perm.rs` | the one relation bb hand-writes (`vm2/optimized/`) instead of generating |
| `program.rs` | the relations compiled for the prover: straight-line programs evaluated over a whole edge, each value at only as many points as its degree needs |
| `prover.rs` | the prover over bb's sparse trace (bb `AvmProver::construct_proof`) |
| `public_inputs.rs` | bb's `PublicInputs` msgpack into the verifier's columns (bb `to_columns`) |
| `verifier.rs` | the verifier, generic over native and in-circuit types |
| `recursive.rs` | bb's inner MegaAvm circuit: op-queue prefix, witnesses, fixed VK, the verifier, published outputs |
| `two_layer.rs` | the inner proofs, the outer verification of them, and the transcript-hash binding (bb `TwoLayerAvmRecursiveVerifier`) |

## What makes this layer delicate

- **The generator reads bb-pilcom's C++, not the PIL.** The C++ is what bb compiles, so its
  operation order is the specification; reproducing bb-pilcom's lowering from PIL would be a second
  place to drift. The parser rejects any construct it does not know, so a template change at a
  re-pin fails the regen loudly.
- **Re-pin:** `dev/regen_avm.py`, then `tools/regen/regen_avm.sh` and `tools/regen/regen_avm_corpus.sh`
  (both need bb's own AVM, `pin/build.sh --avm`; bb-ref's `bb-avm` build needs `--avm-lib`).
  `tests/avm.rs` then checks a real bb proof verifies, tampering is rejected, and bb-ref's inner
  circuit equals bb's dump: every polynomial, public input and the VK. `tests/public_base.rs`
  (fixture: `tools/regen/regen_public_base.sh` on a recorded PublicTxBase request) checks the whole
  rollup: VK, and with seeded randomness the proof, byte-identical to bb's.
- **The inner circuit's VK is a constant of the public base rollup.** Any gate difference here is a
  protocol change, not a performance one.
