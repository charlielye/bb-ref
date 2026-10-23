[◄ bb-ref](../README.md)

# The gate-exactness contract

bb-ref's claim is not "implements the same protocol" but "**builds the same circuits**":
for every circuit, the trace — every selector, wire index, and copy-constraint cycle at
every row — is byte-identical to barretenberg's at the pin. Verification keys are hashes
of that structure, so *any* deviation, however semantically harmless, produces a
different VK and breaks proof compatibility.

This has one consequence that surprises every reader of this codebase:

> **bb's C++ evaluation order is the specification.** Not the math — the *order of
> operations*, including its redundancies.

## What that binds, concretely

Four classes of constraint, in increasing order of "but why is the code like this":

**1. Statement order.** bb computes both temporaries before an outer operation, receives
all transcript values before deriving points, evaluates read terms before write terms.
Reordering emits the same gates in a different sequence → different trace. These carry no
code smell; they are simply the order.

**2. Deliberate redundancy (anti-CSE).** bb frequently recomputes subexpressions
per-statement where a human would hoist:

```rust
// bb recomputes (1 − first)·(1 − transition) in each of four statements — so must we.
acc[2] += (one.clone() - &first) * (one.clone() - &transition) * (dx.clone() - &dx_shift) * scaling;
acc[3] += (one.clone() - &first) * (one.clone() - &transition) * (dy.clone() - &dy_shift) * scaling;
```

Hoisting that product saves ~14 gates and **changes the VK**. Every such site carries a
comment naming the bb behavior it mirrors. If a comment says "bb recomputes per
statement", the duplication is load-bearing; common-subexpression elimination here is a
protocol change, not a cleanup.

**3. Object-aliasing semantics.** In C++, `t += t` passes the *same object* twice; if a
bigfield reduction fires mid-operation, the second operand is already reduced. A naive
Rust port (`t += &t.clone()`) reduces twice → extra gates. `FieldLike::dbl()` and
`mul_self()` exist solely to reproduce bb's aliasing (their `BigField` overrides pass one
reference twice). Use them wherever bb writes `x + x` or `x * x`; never "simplify" them
back to clones.

**4. Gate-free wiring.** Some bb operations emit *no gates* and still change the VK:
`assert_equal` on witnesses merges copy-constraint cycles (visible only in the sigma
polynomials), constants converted to *fixed witnesses* allocate wire indices, and
`get_witness_index()` on a scaled value materializes a normalization gate at that exact
point. These are the hardest divergences to find — the op streams look identical and only
the wiring differs.

Related recurring patterns: powers built by a square-and-multiply ladder vs sequential
multiplication (bb chooses per site — match each site), and maximum-value bookkeeping on
`BigField` (exact bounds arithmetic, not just bit-widths — a bound off by one non-power-
of-two term flips a reduction decision far downstream).

## Rules

1. **Never refactor an expression shape in `stdlib/`, `honk/`, `goblin/`, `chonk/`,
   `rollup/`, or `acir/` without re-running the write-VK oracles.** Green tests are the
   only permission to keep a refactor.
2. When porting new bb code, transcribe the statement structure — temporaries, order,
   redundancy — not the algebra. Cite the bb source (`/// bb \`file::function\`: …`).
3. When the oracle reports a divergence, do not guess: the op-trace tooling
   ([oracle.md](oracle.md)) pinpoints the operation. Every divergence falls into one of the
   four classes above.

## If we ever stop matching bb

Should bb-ref become the reference and the gate layout ours to define, this contract
inverts: classes 2–4 become optimization opportunities (the marked anti-CSE sites alone
are grep-able and reversible in a day; cross-relation CSE and reduction scheduling are
worth far more). That is a **VK-breaking migration** — every verification key and every
baked-in recursive verifier changes at once — so it happens deliberately and once, not
incrementally. Until then, this contract holds.
