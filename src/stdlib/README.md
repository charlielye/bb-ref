# stdlib — in-circuit types

The circuit-side twins of `base`'s native types: values that live inside a circuit under
construction and **emit gates as a side effect of arithmetic**. This is the layer that
makes the generic provers/verifiers in `honk`/`goblin`/`chonk` run unchanged in-circuit:
instantiate them with these types instead of native fields and the same code *builds the
recursive verifier circuit* instead of verifying.

Mirrors bb `stdlib/primitives` + `stdlib/hash`. Every public item cites its bb
counterpart; all of it is **gate-exact** — see
[docs/gate-exactness.md](../../docs/gate-exactness.md) before changing any expression here.

## The types

| type | bb counterpart | what it is |
|---|---|---|
| `FieldT` | `field_t` | a native-field value as `mul_const · witness + add_const`; arithmetic folds constants and emits at most one gate per op |
| `BoolT` | `bool_t` | a constrained bit |
| `BigField<N>` | `bigfield` | a foreign-field element as four 68-bit limbs + a prime-basis image, with per-limb *maximum-value tracking* deciding when reductions fire |
| `BigGroup` / `biggroup_secp256r1` | `element` | non-native curve points (bn254-in-bn254 for rollup recursion, secp256r1 for ECDSA) |
| `CycleGroup` | `cycle_group` | Grumpkin points over the native field (Straus MSMs, fixed-base plookup tables) |
| `GoblinField` / `GoblinElement` | `goblin_field`/`goblin_element` | two-limb commitments whose EC ops are *deferred* to the op queue instead of constrained |
| `Poseidon2 gadget`, `hash` | `stdlib/hash/poseidon2` | the transcript hash in-circuit |

## What makes this layer delicate

Gate emission order **is** program evaluation order. A `FieldT` holds an `Rc<RefCell>`
handle to the builder, so `a * b + c` emits its gates exactly where that expression
executes. Consequences:

- **Constants are free** — ops on constants fold into `add_const`/`mul_const` and emit
  nothing, until something forces materialization (`get_witness_index()` normalizes,
  emitting a gate; bb does the same, and *where* that happens is part of the contract).
- **`normalize()` is lazy** and never cached; calling it twice on a scaled value emits
  two gates. Mirror bb's call sites, not your intuition.
- **BigField reductions are bookkeeping-driven**: whether a multiply first reduces an
  operand depends on tracked maximum values, not runtime values. Wrong bounds are
  *gate-invisible* until a reduction decision flips thousands of rows later.
- **Aliasing matters**: bb's `t += t` passes one object twice, so a mid-op reduction
  fires once. Rust clones would reduce twice — use `FieldLike::dbl()` / `mul_self()`
  (which pass the same reference twice) wherever bb writes `x + x` / `x * x`.

## Deliberately absent

bb's blake2s/blake3 and AES128 gadgets are not ported: no protocol circuit uses them —
they exist in bb only because its ACIR frontend serves arbitrary Noir programs, and an app
circuit that used one fails loudly at lowering (`unsupported black box function`), never
silently. `byte_array` is the minimal slice used by SHA-256/ECDSA. When a new circuit
needs a gadget, port it then, against a micro-oracle (see the `BbRefDump.Stdlib` named
programs).
