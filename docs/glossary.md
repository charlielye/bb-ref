[◄ bb-ref](../README.md)

# Glossary

Every recurring name in this codebase, in three sentences or so: what it is, why it exists,
where it lives. Written for an engineer, not a cryptographer. The [tour](tour.md) tells the
story in order; this is the lookup table for when a name appears without context.

---

### Barycentric extension

evaluating a polynomial at a new point directly from its values
on a small domain (0, 1, 2, …), without recovering coefficients. Sumcheck lives entirely in
this evaluation form: provers extend row pairs to the next few points, verifiers evaluate
round univariates at challenges. [`src/base/poly.rs`](../src/base/poly.rs).

### Batch merge

the once-per-IVC proof that the whole op-queue table is the concatenation
of every circuit's subtable at the right offsets, checked against a running hash the kernels
computed during accumulation. The plain [merge](#merge-proof) covers one append; batch merge
covers all of them at once. [`src/goblin/batch_merge.rs`](../src/goblin/batch_merge.rs).

### Bigfield

a foreign-field element simulated inside the circuit's native field: four
68-bit limbs plus a mod-native image, with per-limb *maximum-value tracking* deciding when
values must be renormalized. It exists because a verifier's arithmetic is over the curve's
base field, which is not the field circuit wires live in ([tour, Act II](tour.md#act-ii--the-verifier-goes-inside-a-circuit)).
~40 gates per multiplication — the cost most of Goblin exists to dodge. [`src/stdlib/bigfield.rs`](../src/stdlib/bigfield.rs).

### Biggroup

elliptic-curve points whose coordinates are [bigfields](#bigfield): full
non-native EC arithmetic in-circuit, used where it cannot be deferred (the rollup's
recursive verifiers, ECDSA). [`src/stdlib/biggroup.rs`](../src/stdlib/biggroup.rs).

### Chonk

the client-side IVC scheme: a chain of app and kernel circuits proven as one
constant-size proof, built from [HyperNova](#hypernova) folding + [Goblin](#goblin) +
the [databus](#databus). [Tour, Act III](tour.md#act-iii--the-client-side-chonk); [`src/chonk`](../src/chonk).

### ChonkProof

the five-part output of Chonk: hiding-kernel Oink, merge, ECCVM, TripleIPA
and the [joint](#joint-proof) MegaZK+Translator proof. Verifying one costs three pairings and one
Grumpkin IPA, regardless of transaction size. [`src/chonk/proof.rs`](../src/chonk/proof.rs),
[`src/chonk/verifier.rs`](../src/chonk/verifier.rs).

### Cycle group

Grumpkin points represented over the *native* field (Grumpkin's base field
is bn254's scalar field, so coordinates are plain wires — no bigfield). The cheap way to do
EC arithmetic in-circuit when the point happens to live on Grumpkin: the in-circuit ECCVM/IPA
verifiers, IPA accumulation, ACIR's `EmbeddedCurve*` opcodes. [`src/stdlib/cycle_group.rs`](../src/stdlib/cycle_group.rs).

### Databus

dedicated `calldata`/`return_data` columns for passing data between Chonk
circuits by *commitment* instead of through public inputs, with per-read LogUp consistency.
Exists so kernels can consume app outputs without hashing them in-circuit.
[`src/circuit/mega.rs`](../src/circuit/mega.rs), [tour, Act III](tour.md#act-iii--the-client-side-chonk).

### Decider

the one proof at the end of a Chonk chain that discharges the
[HyperNova](#hypernova) accumulator: a single Shplemini/KZG opening standing in for all the
per-step openings folding skipped. Verified in-circuit by the [hiding kernel](#hiding-kernel), so it
is not part of the ChonkProof. [`src/honk/decider.rs`](../src/honk/decider.rs).

### Dyadic size

every circuit is padded to 2ⁿ rows because sumcheck and the FFT-free
commitment math work over power-of-two domains; `log_circuit_size` in every VK is this n.
The padding rows are wired to zero. [`src/honk/prover_instance.rs`](../src/honk/prover_instance.rs).

### ECCVM

a special circuit over the Grumpkin curve (so over bn254's *base* field, where
bn254 point arithmetic is native) that re-executes every operation in the
[op queue](#op-queue) and proves it was computed honestly: transcript columns, precomputed
[wNAF](#wnaf) point tables, [Straus](#straus-msm) MSM rows. The engine that makes Goblin's
"write it down instead of doing it" sound. [`src/goblin/eccvm`](../src/goblin/eccvm).

### Endomorphism (GLV)

some curves (bn254, secp256k1) have a cheap map
`λ·(x,y) = (β·x, y)`, which lets a 256-bit scalar multiplication split into two 129-bit
halves (`k = k₁ − λ·k₂`) done together — half the doublings. The in-circuit secp256k1 ECDSA
leans on it heavily, as does the native bn254 MSM. [`src/stdlib/biggroup_secp256k1.rs`](../src/stdlib/biggroup_secp256k1.rs),
[`src/base/endo.rs`](../src/base/endo.rs).

### Fiat–Shamir

deriving the verifier's random challenges by hashing everything the prover
has sent so far, so an interactive protocol becomes one message. The whole proof *is* this
transcript; one element hashed in the wrong order desynchronizes every later challenge.
[`src/base/transcript.rs`](../src/base/transcript.rs), [tour, Act I §4](tour.md#act-i--one-ultrahonk-proof).

### Flavor

a named configuration of the Honk machinery: which relations are on, how many
wires/selectors exist, ZK or not, which transcript hash. The roster: **Ultra** (rollup
circuits), **UltraZK** (masked variant), **UltraKeccak(ZK)** (Keccak transcript, for the one
proof Ethereum verifies), **MegaApp**/**MegaKernel** (client circuits: Ultra + ECC-op rows +
databus + compressed Poseidon2 gates; kernels drop lookups and NNF gates), **MegaZK** (the hiding kernel), plus the bespoke
**ECCVM** and **Translator** relation sets. In bb-ref a flavor is *data* — a relation list
from which the whole wire layout is derived. [`src/honk/flavor.rs`](../src/honk/flavor.rs).

### Gate separator (pow polynomial)

sumcheck's per-row weighting by powers of a challenge,
so that a batched "sum over all rows is zero" claim actually pins *each row* to zero rather
than letting errors cancel. [`src/honk/sumcheck.rs`](../src/honk/sumcheck.rs).

### Gemini

the first stage of [Shplemini](#shplemini): reduces one *multivariate* opening
claim (the sumcheck point has n coordinates) to a chain of univariate claims via n fold
polynomials opened at ±r. [`src/honk/pcs.rs`](../src/honk/pcs.rs).

### Goblin

the deferral scheme for in-circuit EC arithmetic: Mega circuits *record* EC
operations into the [op queue](#op-queue) (two rows each) instead of computing them
(thousands of gates each); the [ECCVM](#eccvm), [Translator](#translator) and
[merge](#merge-proof) proofs later establish the recorded table was honest.
[Tour, Act III](tour.md#act-iii--the-client-side-chonk); [`src/goblin`](../src/goblin).

### Goblin element

the in-circuit point type that does the recording: a bn254 point whose
coordinates are two-limb (136 + 118 bits) goblin fields and whose "operations" just append to
the op queue, copy-constrained to the operands. The reason a kernel's
recursive verifier is cheap. [`src/stdlib/goblin.rs`](../src/stdlib/goblin.rs).

### Grand product / permutation argument

how copy constraints are enforced: wires that
must be equal are arranged into cycles by the sigma/id polynomials, and one running product
(`z_perm`) proves the multiset of (value, position) pairs is invariant under that
permutation. A corrupted copy shows up as the Permutation relation failing.
[`src/honk/oink_prover.rs`](../src/honk/oink_prover.rs), [`src/honk/relations.rs`](../src/honk/relations.rs).

### Grumpkin

the curve forming a 2-cycle with bn254: its base field is bn254's scalar
field and vice versa. Anything Grumpkin-flavored exists to put some computation in the field
where it is native — the ECCVM proves bn254 ops over Grumpkin; `cycle_group` does Grumpkin
ops over bn254. No pairing, so Grumpkin commitments open with [IPA](#ipa), never KZG.

### Hiding kernel

the final circuit of a Chonk chain: folds the last step, verifies the
[decider](#decider) and the batch merge, and adds the ZK masking — it is the one circuit whose proof leaves the device,
so it is the only Mega circuit proven with a ZK flavor. [`src/chonk/kernel.rs`](../src/chonk/kernel.rs).

### HyperNova

the folding scheme: instead of fully verifying the previous circuit, a
kernel reduces it to a *claim* (a batched evaluation of all its polynomials at the sumcheck
point) and folds claims into one running accumulator with random weights; the
[decider](#decider) opens the accumulator once at the end. Folding is why a thousand-step
chain costs one Shplemini, not a thousand. [`src/honk/hypernova.rs`](../src/honk/hypernova.rs),
[`src/honk/multilinear_batching.rs`](../src/honk/multilinear_batching.rs).

### IPA

the inner-product argument: a pairing-free polynomial opening scheme: log(n) rounds
of fold commitments, closed by one big MSM on the verifier's side. Used wherever
[Grumpkin](#grumpkin) commitments must be opened (no pairing ⇒ no KZG). Expensive to
verify — which is why the rollup [accumulates](#ipa-accumulation) instead of verifying.
[`src/goblin/ipa.rs`](../src/goblin/ipa.rs) (client), [`src/rollup/ipa.rs`](../src/rollup/ipa.rs) (rollup).

### IPA accumulation

the rollup-side trick for the expensive IPA verifications: each
rollup circuit reduces its children's IPA claims in-circuit, combines them into one, and
re-proves the combined claim natively (the 64-field IPA proof appended to every rollup proof;
the claim itself rides in [RollupIO](#rollupio)); only the root pays for a full in-circuit IPA
verification, once.
[Tour, Act IV](tour.md#act-iv--the-server-side-the-rollup-tree); [`src/rollup/ipa_recursive.rs`](../src/rollup/ipa_recursive.rs).

### Joint proof

the hiding kernel (MegaZK) and the [Translator](#translator) proven together: MegaZK is
zero-extended to the Translator's 2¹⁷ rows so one ZK sumcheck covers both relation sets and one
Shplemini/KZG opening covers all their polynomials. The last part of the [ChonkProof](#chonkproof).
[`src/chonk/batched.rs`](../src/chonk/batched.rs).

### Kernel

the alternating "checker" circuit in a Chonk chain: each kernel folds the
previous app+kernel step, checks the databus commitments against the circuits it verified,
extends the running op-queue hash the [batch merge](#batch-merge) later checks, and carries the
running state in its public inputs. Apps do user logic; kernels do protocol logic. [`src/chonk/kernel.rs`](../src/chonk/kernel.rs).

### KZG

the pairing-based commitment scheme: a polynomial becomes one curve point (an MSM
of its coefficients against the [SRS](#srs)); an opening `p(z) = v` is one more group
element, checked with one pairing. The soundness bedrock of everything on the bn254 side.
[Tour, Act I §3](tour.md#act-i--one-ultrahonk-proof); [`src/honk/pcs.rs`](../src/honk/pcs.rs).

### LogUp

the log-derivative lookup argument: instead of sorting, each looked-up value
contributes `1/(entry + challenge)` and the sum over reads must match the multiplicity-
weighted sum over the table. How lookup gates and single-value ROM are enforced (the name
behind the "lookup inverses" Oink commits to). [`src/honk/relations.rs`](../src/honk/relations.rs),
[`src/circuit/memory.rs`](../src/circuit/memory.rs).

### Masking (ZK flavors)

how a proof is made zero-knowledge: witness polynomials get
random values on a handful of reserved rows (disabled for relation purposes by the
*row-disabling polynomial*), sumcheck univariates are blinded by a masking polynomial whose
consistency [SmallSubgroupIPA](#smallsubgroupipa) proves, and commitments are masked. All
randomness draws from the session RNG — the draw-count-parity story in
[base/README](../src/base/README.md). [`src/honk/sumcheck.rs`](../src/honk/sumcheck.rs), [`src/honk/pcs.rs`](../src/honk/pcs.rs).

### Mega

the client-circuit builder variant: Ultra's gates plus ECC-op rows (the
[op queue](#op-queue)'s in-circuit image), [databus](#databus) columns, and compressed
Poseidon2 gates. Every Chonk circuit is Mega; every rollup circuit is Ultra.
[`src/circuit/mega.rs`](../src/circuit/mega.rs).

### Memory (ROM/RAM)

in-circuit arrays. Single-value ROM uses [LogUp](#logup); paired ROM
(Straus point tables) and RAM use a sorted-transcript argument: every access is a record,
records are sorted, and adjacent-row checks enforce consistency at finalization.
[`src/circuit/memory.rs`](../src/circuit/memory.rs).

### Merge proof

proves one op-queue append: the merged table `M` equals the previous
aggregate `L` plus the new subtable `R` shifted to offset `k` (`M = L + Xᵏ·R`), with a
degree check that `L` really stops before `k`. The hiding kernel's step uses the single
merge; the whole chain is covered by the [batch merge](#batch-merge). [`src/goblin/merge.rs`](../src/goblin/merge.rs).

### Montgomery ladder

a double-and-add pattern (`2P + Q` fused) that saves non-native
field multiplications in biggroup scalar multiplication; the workhorse loop of the
in-circuit MSMs and the secp256k1 ECDSA mul. [`src/stdlib/biggroup.rs`](../src/stdlib/biggroup.rs)
(`multiple_montgomery_ladder`).

### NNF gates

non-native-field gates: builder-level support (limb products, two-limb range
checks) that [bigfield](#bigfield) arithmetic compiles to, living in their own trace block.
[`src/circuit/nnf.rs`](../src/circuit/nnf.rs).

### Oink

the pre-sumcheck phase of a Honk proof: bind the VK into the transcript, read
public inputs, commit the wire polynomials, and derive the challenge-dependent helper
columns (memory records need `eta`, the grand product needs `beta, gamma`, lookups need
their inverses) in the order Fiat–Shamir forces. After Oink, everything is committed and
every relation parameter exists. [Tour, Act I §4](tour.md#act-i--one-ultrahonk-proof);
[`src/honk/oink.rs`](../src/honk/oink.rs), [`src/honk/oink_prover.rs`](../src/honk/oink_prover.rs).

### Op queue

the shared table of deferred EC operations Goblin revolves around: every
"EC op" a Mega circuit performs is recorded twice — natively (for the ECCVM to re-execute)
and as two width-4 rows (for the Mega circuit and the Translator to see).
[`src/circuit/op_queue.rs`](../src/circuit/op_queue.rs).

### Pairing points (aggregation)

no circuit computes a pairing; every in-circuit verifier
instead outputs the two points its pairing check *would* consume, random-linear-combined
with all other deferred pairings and carried in the public inputs. Whoever verifies the
outermost proof natively runs the one real pairing for the entire tower.
[`src/base/group.rs`](../src/base/group.rs) (`PairingPoints`), [tour, Act II](tour.md#act-ii--the-verifier-goes-inside-a-circuit).

### Plookup

the lookup-table machinery: a *multi-table* splits a key into slices, each
slice is read from a *basic table* (XOR/AND, sha256 sparse forms, BLAKE rotations, AES
S-box, …), and running accumulators chain the slices back into the full value. How bitwise
and byte-wise operations become affordable in an arithmetic circuit. [`src/circuit/plookup.rs`](../src/circuit/plookup.rs).

### Poseidon2

the hash used everywhere a hash runs *in-circuit* (transcripts, Merkle-ish
structures): designed to be cheap as gates, unlike Keccak, which is used only for the one
proof Ethereum verifies natively. [`src/base/poseidon2.rs`](../src/base/poseidon2.rs), [`src/stdlib/poseidon2.rs`](../src/stdlib/poseidon2.rs).

### RollupIO

the public-input convention of every rollup circuit: the aggregated
[pairing points](#pairing-points-aggregation) followed by the accumulated
[IPA claim](#ipa-accumulation), at fixed offsets the recursive verifier reads them from.
[`src/rollup/mod.rs`](../src/rollup/mod.rs).

### Shplemini

the combined opening pipeline: [Gemini](#gemini) folds the multivariate
point away, [Shplonk](#shplonk) batches all the resulting claims into one, [KZG](#kzg)
proves that one. It exists so that verifying ~40 polynomial evaluations costs one MSM and
one pairing. [Tour, Act I §6](tour.md#act-i--one-ultrahonk-proof); [`src/honk/pcs.rs`](../src/honk/pcs.rs).

### Shplonk

the batching stage of [Shplemini](#shplemini): many (polynomial, point, value)
claims become a single opening of one combined polynomial, via a random linear combination
divided by the appropriate vanishing terms. [`src/honk/pcs.rs`](../src/honk/pcs.rs).

### SmallSubgroupIPA

the consistency proof for ZK masking: the sumcheck-blinding masking
polynomial is committed, and this sub-protocol proves the blinding contributions sum to
zero over a small subgroup, so masking cannot change the proven statement. Runs inside
Shplemini for every ZK flavor. [`src/honk/pcs.rs`](../src/honk/pcs.rs).

### SRS

the "structured reference string" (also called CRS): the trusted-setup point vector
`[1]G, [τ]G, [τ²]G, …` that KZG commitments are MSM'd against (bn254, ~2²³ points for the
rollup root), plus a generator vector for Grumpkin IPA (no trust needed there). Downloaded
once to `~/.bb-crs`; a server loads it at startup. [`src/base/srs.rs`](../src/base/srs.rs).

### Straus MSM

the windowed multi-scalar-multiplication algorithm used in-circuit: per
point, a small table of multiples is precomputed (into ROM), then one shared
double-and-add pass reads table entries per scalar window. [`src/stdlib/cycle_group.rs`](../src/stdlib/cycle_group.rs),
[`src/stdlib/biggroup.rs`](../src/stdlib/biggroup.rs).

### Sumcheck

the protocol that collapses "every relation holds on every 2ⁿ rows" into one
claimed evaluation at one random point, in n rounds of small univariates (each checked by
`S(0) + S(1) = previous`). The relations are first batched into one identity with powers of
a challenge `alpha`. The heart of Honk.
[Tour, Act I §5](tour.md#act-i--one-ultrahonk-proof); [`src/honk/sumcheck.rs`](../src/honk/sumcheck.rs).

### Trace blocks

the circuit's rows grouped by gate family (arithmetic, range, elliptic,
memory, lookup, NNF, …), laid out contiguously so one selector per block suffices; block
sizes and order are part of the VK. [`src/circuit/trace.rs`](../src/circuit/trace.rs).

### Translator

the proof that ties the two sides of Goblin together: a bn254 circuit that
recomputes, in 68-bit limbs, the same batched evaluation of the op queue that the ECCVM
opened over Grumpkin. If the two values agree, the queue the circuits *recorded* and the
ops the ECCVM *executed* are the same ops. [`src/goblin/translator`](../src/goblin/translator).

### TripleIPA

one [IPA](#ipa) proof that simultaneously opens the ECCVM's three claims
(its batched multilinear, the shifted variant, and a univariate), instead of three separate
proofs. [`src/goblin/ipa.rs`](../src/goblin/ipa.rs).

### Tube (tx_base)

the rollup circuit that verifies a [ChonkProof](#chonkproof)
in-circuit, converting a client proof into a rollup-shaped Ultra proof (~1.4M rows). "Tube" and "tx_base" name the same thing in different layers.
[`src/chonk/verifier.rs`](../src/chonk/verifier.rs) (`chonk_verify_recursive`), consumed via [`src/acir/honk_recursion.rs`](../src/acir/honk_recursion.rs).

### wNAF

windowed non-adjacent form: a scalar rewritten in signed odd digits
(±1, ±3, …), so a table of odd multiples covers each window and negation is free (negate
y). The ECCVM's point tables and the secp256k1 ECDSA mul are wNAF-driven; the *staggered*
variant offsets several scalars' windows so one ladder pass serves all of them.
[`src/goblin/eccvm/trace.rs`](../src/goblin/eccvm/trace.rs), [`src/stdlib/biggroup_secp256k1.rs`](../src/stdlib/biggroup_secp256k1.rs).
