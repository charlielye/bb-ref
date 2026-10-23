[◄ bb-ref](../../README.md)

# acir — Noir ingestion

The front door: Noir compiles programs to ACIR bytecode, and this module turns that bytecode into
[`circuit`](../circuit/README.md) builders — for a single Ultra circuit, or a whole private transaction's
worth of Mega circuits fed to [`chonk`](../chonk/README.md). It mirrors bb's `dsl/acir_format` across the full
ACIR black-box surface.

*Unfamiliar name? Every recurring term is defined in [docs/glossary.md](../../docs/glossary.md).*

| file | what it is |
|---|---|
| `format.rs` | serde shapes of the ACIR `Program`/`WitnessStack` exactly as Noir serializes them (msgpack, format marker 2 or 3); unconstrained calls (`BrilligCall`, `Call`) are skipped |
| `lower.rs` | opcode classification, then lowering in bb's fixed order: quads, bilinear/batched-equality, logic, ranges, the hash/ECDSA/AES gadgets, Poseidon2, MSM/add, memory + databus blocks, then recursion (HyperNova kernel logic on Mega, `honk_recursion` on Ultra) or default pairing points |
| `honk_recursion.rs` | HONK / ROLLUP_HONK / ROOT_ROLLUP_HONK recursion constraints on Ultra circuits — instantiates [`rollup`](../rollup/README.md)'s in-circuit verifier — and CHONK (the tube), via [`chonk`](../chonk/README.md)'s `chonk_verify_recursive` |
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
- **The black-box surface is complete**: every ACIR black-box function bb lowers has an arm
  here (no fallback), so any Noir program that proves under bb proves under bb-ref.
