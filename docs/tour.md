# Life of a proof

A ground-up tour of the proving system, following real objects through the codebase. Four
acts: one UltraHonk proof end to end; what changes when the verifier runs inside a circuit;
the client side (Chonk); the server side (the rollup tree). Almost no math — where a formula
appears it's because seeing one concrete instance is faster than describing it.

---

## Act I — one UltraHonk proof

### 1. A circuit is a table

Forget "arithmetic circuits" as graphs. Here a circuit is a **table**: one row per gate,
with two kinds of columns.

- **Wire columns** (`w_l, w_r, w_o, w_4`): each cell holds an index into a shared list of
  *variables* — the actual values, the witness.
- **Selector columns** (`q_m, q_l, q_r, q_o, q_4, q_c, q_arith, q_delta_range, …`):
  constants baked into the circuit that say *what constraint this row imposes*.

The workhorse row type is the arithmetic gate. With `a, b, c` the values in that row's
wires, the row demands:

```
q_m·a·b + q_l·a + q_r·b + q_o·c + q_c = 0
```

Every basic operation is this one identity with different selector constants: addition is
`q_l=1, q_r=1, q_o=−1`; multiplication is `q_m=1, q_o=−1`; a constant assignment is
`q_l=1, q_c=−k`. Richer gate types (range checks, elliptic-curve additions, Poseidon2
rounds, ROM/RAM access, non-native field arithmetic, lookups) are the same idea with their
own selectors and their own row identity — that's all a "custom gate" is. The circuit's
rows are grouped into **blocks** by gate type (`src/circuit/builder.rs`), one gate-selector
per block.

Two constraint kinds are *not* gates:

- **Copy constraints**: "this cell and that cell hold the same variable." Tracked by
  sharing variable indices (a union-find in the builder), they'll become a permutation
  argument in step 3 — no row is spent on them.
- **Lookups**: "this row's values appear in that table." Proven with a log-derivative
  argument over dedicated columns.

The builder (`src/circuit`) emits rows as a side effect of arithmetic on `stdlib` values —
write `let c = a * b` on circuit types and a multiplication row appears. Program order is
row order.

### 2. The table becomes polynomials

Pad the table to 2ⁿ rows. Each column, read top to bottom, is now a list of 2ⁿ field
values — equivalently, the evaluations of a **polynomial** over a fixed domain. This is
the whole conversion (`src/honk/prover_instance.rs`): no encoding cleverness, a column *is*
a polynomial.

Two derived column families get added:

- **sigma/id**: the copy constraints, encoded as a permutation. `id` numbers every cell;
  `sigma` maps each cell to the next cell of its copy-cycle. "All copies agree" becomes
  "the multiset of (value, position) pairs is invariant under sigma" — checkable with one
  running product (`z_perm`).
- **lookup helper columns**: read counts and log-derivative inverses.

Now split by who knows what. The **selectors, sigma/id, and tables** are the circuit's
identity — same for every proof of this circuit. The **wires and helper columns** are the
witness — different every proof. That split is the VK/proof split.

### 3. Commitments: a polynomial in 64 bytes

A **KZG commitment** turns a polynomial into a single elliptic-curve point (an MSM of the
coefficients against a trusted-setup vector, `src/base/srs.rs`). The contract, and all you
need from it:

- it's *binding* — you can't find two polynomials with the same commitment;
- given a commitment, the prover can later prove "`p(z) = v`" for any point `z` with one
  more group element, and the verifier checks it with one pairing.

The **verification key** is the commitments to the circuit-identity columns (28 points for
Ultra) plus three integers. Committing to a circuit = hashing its VK. This is why
*gate-exactness* is the compatibility bar for this whole codebase: any change to any
selector cell changes a VK.

### 4. Oink: committing to the witness, growing the challenges

The prover can't just send witness commitments and be done — several helper columns
*depend on random challenges* (the permutation product needs `beta, gamma`; memory records
need `eta`; lookups need their own). And challenges must not be choosable by the prover, so
they come from **Fiat–Shamir**: hash everything sent so far (`src/base/transcript.rs`), use
the digest as the challenge, repeat.

Oink (`src/honk/oink.rs`) is this dance: commit `w_l, w_r, w_o` → derive `eta` → build and
commit `w_4` (which embeds memory records that need `eta`) → derive `beta, gamma` → build
and commit `z_perm` and the lookup inverses → derive `alpha`. After Oink, every column is
committed and every relation parameter exists.

### 5. Sumcheck: 2ⁿ rows become one point

The claim to prove is: *every relation holds on every row*. Naively that's millions of
checks. Two reductions collapse it:

1. **Batch the relations.** Take a random `alpha` and form one combined row-identity: the
   alpha-weighted sum of all relation identities. If any single relation failed anywhere,
   the combined one fails there too (except with negligible probability over `alpha`).
2. **Batch the rows** — this is **sumcheck**. The combined identity holding on all rows is
   equivalent to a certain sum over all 2ⁿ rows being zero. The sumcheck protocol proves a
   sum over 2ⁿ points in only n rounds: each round the prover sends a small univariate
   polynomial (the sum with one variable left free), the verifier checks it's consistent
   with the previous round's claim (`S(0) + S(1) = previous`), picks a random challenge
   `uᵢ`, and the claim *folds* — the sum halves. After n rounds nothing is left but a
   claimed value of the combined identity **at one random point `u = (u₁…uₙ)`**.

That's the miracle to internalize: "the whole circuit is satisfied" has been reduced to
"these ~40 committed polynomials evaluate to these ~40 claimed values at this one random
point." The verifier's side of sumcheck is a few field ops per round
(`src/honk/sumcheck.rs`) — the 2ⁿ never appears.

### 6. Shplemini: proving the evaluations

The claimed evaluations must be checked against the *commitments* from steps 3–4. Three
sub-protocols, one job each (`src/honk/pcs.rs`):

- **Gemini** folds the n-variate opening point into a chain of univariate openings (n fold
  polynomials, opened at ±r).
- **Shplonk** batches all those opening claims — dozens of (polynomial, point, value)
  triples — into a single claim on a single combined polynomial.
- **KZG** proves that one claim with one group element; the verifier's check is one MSM
  and one pairing.

The combined pipeline is nicknamed Shplemini. Everything in it is bookkeeping — the
cryptographic content is only "KZG openings are sound."

### 7. What a proof is

The transcript, minus the challenges (the verifier re-derives those by re-hashing):
public inputs, ~8 witness commitments, n small sumcheck univariates, ~40 claimed
evaluations, ~n fold commitments and evaluations, two closing points. For Ultra ~400 field
elements, fixed-length by padding n to 25 so every proof of every circuit has the same
shape. Verification = re-hash the transcript, run the sumcheck folds, recompute the
batched-opening scalars, one MSM, one pairing (`src/honk/ultra_verifier.rs`).

---

## Act II — the verifier goes inside a circuit

Look at what the verifier does: hashing, field arithmetic, one MSM, one pairing. The first
two are cheap to express *as gates*. So build a circuit whose gates compute "verify
proof π against VK v" — and prove *that*. Now one proof attests to another. Recursion.
This is the enabling move for everything in Acts III and IV, and it has exactly
two costs worth understanding:

- **Wrong-field arithmetic.** The verifier computes over the curve's *base* field, but
  circuit values live in the *scalar* field. Simulating one field inside another
  (`stdlib::bigfield`, four 68-bit limbs per value) costs ~40 gates per multiplication —
  tolerable for field ops, ruinous for full EC arithmetic. Most of the cleverness in this
  system is about dodging exactly this cost (Act III).
- **The pairing.** No sane circuit computes a pairing. Instead every in-circuit verifier
  *defers* it: it outputs the two points its pairing check would consume, and they get
  **aggregated** — random-linear-combined with every other deferred pairing in the circuit
  — into one pair carried in the public inputs (`stdlib::PairingPoints`). Whoever verifies
  the outermost proof natively performs the one real pairing for the entire tower.

Also visible from here: why the transcript hash is Poseidon2 (designed to be cheap *as
gates*), and why `rollup_root` alone switches to Keccak (cheap on the EVM, where that one
proof is checked).

---

## Act III — the client side: Chonk

A user's phone must prove a private transaction: a chain of function calls, each a
circuit, potentially dozens of steps. Proving them all then verifying dozens of proofs
per-step with Act-II recursion would melt the phone. Chonk is IVC — incrementally
verifiable computation — built from three cost-killing ideas stacked on top of recursion.
The circuits alternate: **app** circuit, then a **kernel** that checks the previous step,
another app, another kernel, … and a final **hiding kernel**.

**1. Fold, don't verify (HyperNova, `src/honk/hypernova.rs`).** A kernel doesn't fully
verify the previous circuit's correctness — that would mean running sumcheck + Shplemini
in-circuit per step. Instead it runs only the cheap parts (Oink + sumcheck) and
*accumulates* the expensive remainder: instances are folded together with random weights
into one running accumulator. One final **decider** proof at the end discharges the
accumulator — thousands of steps, one Shplemini.

**2. Write EC ops down instead of doing them (Goblin, `src/goblin`).** Even folded,
verifiers need elliptic-curve operations — bigfield EC math at thousands of gates each.
Goblin's move: client circuits don't *perform* EC ops at all. An in-circuit "EC op" just
appends an instruction to a shared **op queue** (two trace rows). At the end of the chain,
one specialized proof — the **ECCVM** — proves every queued operation was performed
correctly. And the ECCVM runs over **Grumpkin**, a curve whose scalar field *is* bn254's
base field, so all that point arithmetic is native there. Two support proofs make the
seam sound: the **Translator** proves the bn254-side queue and the Grumpkin-side
computation describe the same operations, and **merge** proofs stitch each circuit's queue
segment into the whole. (Grumpkin commitments can't use KZG — no pairing — so the ECCVM
side closes with **IPA**, a pairing-free opening scheme whose verifier is one big MSM.
Remember that MSM; it resurfaces in Act IV.)

**3. Pass data by commitment (the databus).** Kernels consume app outputs. Routing that
data through public inputs would mean hashing megabytes in-circuit. Instead data rides in
dedicated **databus** columns, passed between circuits as commitments and equality-checked
directly (`calldata`/`return_data` in `src/circuit`).

The **hiding kernel** ends the chain: it folds the last step, verifies the accumulated
batch-merge, adds ZK masking (it's the one circuit whose proof leaves the device), and its
proof plus the decider, merge, ECCVM, Translator pieces form the **ChonkProof**
(`src/chonk`). Verifying one costs four pairings and one Grumpkin IPA — constant, whatever
the transaction did.

---

## Act IV — the server side: the rollup tree

The network aggregates many transactions into one Ethereum-verifiable proof by building a
binary tree of Act-II recursive verifiers, each an UltraHonk circuit (`src/rollup`,
`src/acir/honk_recursion.rs`):

```
tx_base (verifies a ChonkProof)         tx_base ...
        \        /
        tx_merge            parity circuits (L1→L2 messages)
            \                /
          block_root        /
              \            /
           checkpoint_root ...
                  \
              rollup_root  ── one proof, verified on Ethereum
```

`tx_base` runs the Chonk verifier in-circuit — the single biggest circuit in the system
(~1.4M rows), and the reason Acts I–III all had to be gate-exact. Each level up verifies
two child proofs and aggregates their deferred pairings. One extra thread runs up the
tree: the Grumpkin **IPA claims** from each transaction's ECCVM can't be checked cheaply
inside bn254 circuits, so — same trick as pairings — they're *accumulated* upward
(`RollupIO` carries a claim in each proof's public inputs) and the root finally verifies
the one accumulated claim in full: that in-circuit IPA MSM is 2²³ rows of the root's work.
`rollup_root` is proven with the Keccak transcript, and the Solidity contract verifies it:
one pairing on L1 stands for every private transaction in the epoch.

---

## Where to go deeper

| you want | read |
|---|---|
| the table/builder machinery | `src/circuit` (module doc) |
| relations, flavors, sumcheck, folding | `src/honk` |
| op queue, ECCVM, Translator, merge, IPA | `src/goblin` |
| the IVC driver and ChonkProof | `src/chonk` |
| in-circuit types and their gate costs | [`src/stdlib`](../src/stdlib/README.md) |
| how Noir circuits arrive | `src/acir` |
| why the code looks the way it does | [gate-exactness.md](gate-exactness.md) |
| why you should believe any of it | [oracle.md](oracle.md) |
