[◄ bb-ref](../../README.md)

# avm — the AVM verifier

bb's AVM2 proofs checked without bb's AVM prover: natively (`avm/verifier.rs::verify`) and
in-circuit, as the inner MegaAvm circuit of bb's two-layer AVM recursive verifier
(`recursive.rs`), the circuit the public tx base rollup's AVM recursion constraint builds and proves.
Both are gate-exact against bb; there is no AVM prover or simulator here.

*Unfamiliar name? Every recurring term is defined in [docs/glossary.md](../../docs/glossary.md).*

## Relations are data

The AVM has ~300 relations generated from PIL (bb-pilcom), ~13k lines of constraint expressions,
plus 404 lookups and permutations over ~3,200 columns. bb compiles them five times over (prover,
verifier, check-circuit, tests, in-circuit), which is most of its AVM build time. A verifier
evaluates each relation once, at one point, so bb-ref interprets them instead:
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
| `verifier.rs` | the verifier, generic over native and in-circuit types |
| `recursive.rs` | bb's inner MegaAvm circuit: op-queue prefix, witnesses, fixed VK, the verifier, published outputs |

## What makes this layer delicate

- **The generator reads bb-pilcom's C++, not the PIL.** The C++ is what bb compiles, so its
  operation order is the specification; reproducing bb-pilcom's lowering from PIL would be a second
  place to drift. The parser rejects any construct it does not know, so a template change at a
  re-pin fails the regen loudly.
- **Re-pin:** `dev/regen_avm.py`, then `tools/regen/regen_avm.sh` (needs `pin/build.sh --avm-lib`).
  `tests/avm.rs` then checks a real bb proof verifies, tampering is rejected, and bb-ref's inner
  circuit equals bb's dump: every polynomial, public input and the VK.
- **The inner circuit's VK is a constant of the public base rollup.** Any gate difference here is a
  protocol change, not a performance one.
