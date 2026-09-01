# acir — Noir ingestion

The front door: Noir compiles programs to ACIR bytecode, and this module turns that bytecode into
[`circuit`](../circuit/README.md) builders — for a single Ultra circuit, or a whole private transaction's
worth of Mega circuits fed to [`chonk`](../chonk/README.md). It is bb's `dsl/acir_format` reduced to the
opcodes the protocol circuits actually use.

| file | what it is |
|---|---|
| `format.rs` | serde shapes of the ACIR `Program`/`WitnessStack` exactly as Noir serializes them (msgpack, two format markers); unlowered opcodes are skipped |
| `lower.rs` | opcode classification, then lowering in bb's fixed order: quads, ranges, Poseidon2, MSM/add, memory + databus blocks, recursion, default pairing points |
| `honk_recursion.rs` | HONK / ROLLUP_HONK / ROOT_ROLLUP_HONK recursion constraints on Ultra circuits — instantiates [`rollup`](../rollup/README.md)'s in-circuit verifier |
| `steps.rs` | `ivc-inputs.msgpack`: the per-circuit `{bytecode, witness, vk, kind}` list a Chonk proof is made from |
| `mock.rs` | write-VK mode: the mock IVC state a kernel is built against when only its VK is wanted — real shapes, arbitrary values |

## What makes this layer delicate

- **Lowering order is the circuit.** bb lowers constraint *lists* in a fixed sequence regardless
  of bytecode order; matching that order is what makes VKs bit-equal. Don't lower opcodes as
  encountered.
- **Mock proofs must be shape-perfect.** A kernel's VK is honest as long as every mock length and
  every value the verifier *branches on* (batch-merge subtable sizes) is right; everything else
  is random — drawn from the session RNG, so mock generation participates in draw-count parity
  ([base/README](../base/README.md)).
- **Unknown opcodes are skipped, not rejected**, mirroring bb: the protocol circuits are the
  scope, and a bytecode using an unported gadget fails at witness-solving distance, not here.
