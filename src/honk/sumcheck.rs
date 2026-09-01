//! Sumcheck prover and verifier (bb `sumcheck/sumcheck.hpp`, `sumcheck_round.hpp`,
//! `polynomials/gate_separator.hpp`, `polynomials/row_disabling_polynomial.hpp`), written once over
//! a [`RelationSet`] so that Ultra/Mega flavors, the multilinear batching relation and the ECCVM share
//! it. The prover is pointwise: each entity's edge `(P[2e], P[2e+1])` is extended linearly to
//! `k = 0..D-1` and the relations are evaluated on the resulting rows with the same `accumulate` the
//! verifier uses. The committed variant (ECCVM) sends a commitment to each round univariate and its
//! values at 0 and 1 instead of the univariate itself.

use super::flavor::{FlavorDesc, Layout};
use super::relations::{RelationParams, Row};
use crate::base::field::{FieldLike, U256};
use crate::base::group::Curve;
use crate::base::poly::Polynomial;
use crate::base::rng::{random_field, Rng};
use crate::base::srs::Ck;
use crate::base::transcript::{NativeTranscript, Transcript};
use crate::base::Fr;
use crate::honk::flavor::{Ent, Rel, BUS_SPECS};
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use rayon::prelude::*;

pub use crate::base::poly::evaluate_univariate;

/// The relations a sumcheck runs over: `accumulate` adds relation `r`'s subrelation values on a row
/// of entity values (bb's `Relation::accumulate` over `AllValues`).
pub trait RelationSet<F: FieldLike> {
    fn num_relations(&self) -> usize;
    fn num_subrelations(&self, r: usize) -> usize;
    fn linearly_independent(&self, r: usize, j: usize) -> bool;
    /// Relations checked only on the sumcheck-disabled rows (bb `IsOffsetOnlyRelation`).
    fn offset_only(&self, r: usize) -> bool;
    fn accumulate(&self, r: usize, acc: &mut [F], row: &[F], p: &RelationParams<F>, scaling: &F);
    /// bb `Relation::skip`: the relation contributes nothing on the edge `(row0, row1)` (its
    /// selector, or the combination bb tests, vanishes on both rows), so the prover may skip it.
    fn skip(&self, _r: usize, _row0: &[F], _row1: &[F]) -> bool {
        false
    }
    /// bb `Flavor::skip_entire_row`: every relation vanishes on the edge `(row0, row1)`.
    fn skip_row(&self, _row0: &[F], _row1: &[F]) -> bool {
        false
    }
    /// The relation's univariate length (bb's max subrelation partial length): the prover only
    /// evaluates it at that many points and extends the accumulator afterwards.
    fn partial_length(&self, _r: usize) -> usize {
        usize::MAX
    }
    fn total_subrelations(&self) -> usize {
        (0..self.num_relations()).map(|r| self.num_subrelations(r)).sum()
    }
}

/// The relations of an Ultra/Mega flavor.
pub struct HonkRelations<'a> {
    pub flavor: &'a FlavorDesc,
    pub layout: &'a Layout,
}

impl<F: FieldLike> RelationSet<F> for HonkRelations<'_> {
    fn num_relations(&self) -> usize {
        self.flavor.relations.len()
    }
    fn num_subrelations(&self, r: usize) -> usize {
        self.flavor.relations[r].num_subrelations()
    }
    fn linearly_independent(&self, r: usize, j: usize) -> bool {
        self.flavor.relations[r].spec().lin_indep[j]
    }
    fn offset_only(&self, r: usize) -> bool {
        self.flavor.relations[r].spec().offset_only
    }
    fn accumulate(&self, r: usize, acc: &mut [F], row: &[F], p: &RelationParams<F>, scaling: &F) {
        self.flavor.relations[r].accumulate(
            acc,
            &Row {
                vals: row,
                layout: self.layout,
            },
            p,
            scaling,
        )
    }
    fn partial_length(&self, r: usize) -> usize {
        self.flavor.relations[r]
            .spec()
            .partial_lengths
            .iter()
            .copied()
            .max()
            .unwrap_or(0)
    }
    fn skip(&self, r: usize, row0: &[F], row1: &[F]) -> bool {
        let l = self.layout;
        let zero = |e: Ent| row0[l.idx(e)].is_zero() && row1[l.idx(e)].is_zero();
        match self.flavor.relations[r] {
            Rel::Permutation => {
                (row0[l.idx(Ent::z_perm)].clone() - &row0[l.shift_idx(Ent::z_perm)]).is_zero()
                    && (row1[l.idx(Ent::z_perm)].clone() - &row1[l.shift_idx(Ent::z_perm)]).is_zero()
            }
            Rel::LogDerivLookup => zero(Ent::q_lookup) && zero(Ent::lookup_read_counts),
            Rel::Arithmetic => zero(Ent::q_arith),
            Rel::DeltaRange => zero(Ent::q_delta_range),
            Rel::Elliptic => zero(Ent::q_elliptic),
            Rel::Memory => zero(Ent::q_memory),
            Rel::NonNativeField => zero(Ent::q_nnf),
            Rel::Poseidon2External => zero(Ent::q_poseidon2_external),
            Rel::Poseidon2Internal => zero(Ent::q_poseidon2_internal),
            Rel::Masking | Rel::MegaEccOpBoundary => false,
            Rel::BilinearBatchedEq => zero(Ent::q_bilinear_batched_eq),
            Rel::EccOpQueue => zero(Ent::lagrange_ecc_op),
            Rel::Bus(b) => zero(Ent::q_busread) && zero(BUS_SPECS[b].read_counts),
            Rel::Poseidon2InitialExternal => zero(Ent::q_poseidon2_external_initial),
            Rel::Poseidon2QuadInternal => zero(Ent::q_poseidon2_quad_internal),
            Rel::Poseidon2QuadInternalTerminal => zero(Ent::q_poseidon2_quad_internal_terminal),
            Rel::Poseidon2TransitionEntry => zero(Ent::q_poseidon2_transition_entry),
        }
    }
}

/// Shape of one sumcheck instance.
#[derive(Clone)]
pub struct SumcheckSpec {
    /// bb `compute_effective_round_size`: edges past the witness polynomials' extent are all-zero
    /// witness rows on which every relation vanishes, so the prover skips them (halved each round).
    pub witness_end: usize,
    /// bb `row_skip_active_prefix_end` (ECCVM): the trace rows, after which only the final edge
    /// (`lagrange_last`) can contribute.
    pub active_prefix_end: Option<usize>,
    pub virtual_log_n: usize,
    pub has_zk: bool,
    /// Rows `0..trace_offset` are excluded from the relation and handled by the row-disabling
    /// polynomial (all ZK Honk flavors and the ECCVM).
    pub row_disabling: bool,
    pub trace_offset: usize,
    /// Committed sumcheck: round univariates are committed to, not sent.
    pub committed: bool,
    /// `BATCHED_RELATION_PARTIAL_LENGTH`.
    pub batched_len: usize,
    /// Source column of every shifted entity, in order; the shifted columns follow the given
    /// polynomials in the round table and are read one row ahead of their source.
    pub shifted_sources: Vec<usize>,
    pub num_entities: usize,
}

impl SumcheckSpec {
    pub fn honk(flavor: &FlavorDesc, layout: &Layout) -> Self {
        Self {
            witness_end: usize::MAX,
            active_prefix_end: None,
            virtual_log_n: flavor.virtual_log_n,
            has_zk: flavor.has_zk,
            row_disabling: flavor.has_zk,
            trace_offset: flavor.trace_offset,
            committed: false,
            batched_len: layout.batched_len,
            num_entities: layout.num_all(),
            shifted_sources: layout.shifted.iter().map(|e| layout.idx(*e)).collect(),
        }
    }
    pub fn with_witness_end(mut self, witness_end: usize) -> Self {
        self.witness_end = witness_end;
        self
    }
}

/// `alpha, alpha^2, ..., alpha^{n}`.
pub fn alpha_powers<F: FieldLike>(alpha: &F, n: usize) -> Vec<F> {
    let mut out = Vec::with_capacity(n);
    if n > 0 {
        out.push(alpha.clone());
        for i in 1..n {
            let next = out[i - 1].clone() * alpha;
            out.push(next);
        }
    }
    out
}

/// `(1 - u) + u * beta`, the per-variable factor of pow_beta.
pub fn gate_separator_factor<F: FieldLike>(u: &F, beta: &F) -> F {
    F::one() + &(u.clone() * &(beta.clone() - &F::one()))
}

/// `1 - L(u)` where `L` is the indicator of the first `NUM_DISABLED_ROWS_IN_SUMCHECK` rows
/// (`RowDisablingPolynomial::evaluate_at_challenge`).
pub fn row_disabling_main_factor<F: FieldLike>(u: &[F]) -> F {
    let mut eval = F::one();
    for u_k in u.iter().skip(2) {
        eval *= &(F::one() - u_k);
    }
    F::one() - &eval
}

/// Evaluate the full (alpha-batched) relation at a claimed row of evaluations.
/// `scaling` is `pow_beta(u)`; `(main, offset)` are the row-disabling factors `(1-L(u), L(u))`
/// or `(1, 0)` (bb `compute_full_relation_purported_value` + `scale_and_batch_elements`).
pub fn full_relation_value<F: FieldLike>(
    rels: &impl RelationSet<F>,
    evals: &[F],
    params: &RelationParams<F>,
    scaling: &F,
    alphas: &[F],
    row_disabling_challenge: Option<&[F]>,
) -> F {
    // every relation is accumulated before any batching (bb `accumulate_relation_evaluations` then
    // `scale_and_batch_elements`), which fixes the in-circuit gate order
    let accumulated: Vec<Vec<F>> = (0..rels.num_relations())
        .map(|ri| {
            let mut acc = vec![F::zero(); rels.num_subrelations(ri)];
            rels.accumulate(ri, &mut acc, evals, params, scaling);
            acc
        })
        .collect();
    // bb computes the row-disabling factors AFTER accumulating every relation and before batching
    // (`compute_full_relation_purported_value`).
    let (main_factor, offset_factor) = match row_disabling_challenge {
        Some(challenge) => {
            let m = row_disabling_main_factor(challenge);
            let o = F::one() - &m;
            (m, o)
        }
        None => (F::one(), F::zero()),
    };
    let (main_factor, offset_factor) = (&main_factor, &offset_factor);
    let mut result = F::zero();
    let mut alpha_idx = 0;
    for (ri, acc) in accumulated.iter().enumerate() {
        let factor = if rels.offset_only(ri) {
            offset_factor
        } else {
            main_factor
        };
        for (j, e) in acc.iter().enumerate() {
            if ri == 0 && j == 0 {
                result += &(e.clone() * factor);
            } else {
                result += &(e.clone() * &alphas[alpha_idx] * factor);
                alpha_idx += 1;
            }
        }
    }
    result
}

pub struct SumcheckOutput<C: Curve> {
    pub challenge: Vec<C::Fr>,
    /// Claimed evaluations of all entities (unshifted then shifted) at `challenge`.
    pub evals: Vec<C::Fr>,
    pub verified: bool,
    /// ZK only: claimed evaluation of the Libra masking multivariate.
    pub libra_evaluation: C::Fr,
    /// Committed sumcheck only: the round univariate commitments and their values at `0`, `1`, `u_i`.
    pub round_commitments: Vec<C::G>,
    pub round_evaluations: Vec<[C::Fr; 3]>,
}

/// Verify a sumcheck proof: reads round univariates (or their commitments and values at 0, 1) and
/// the claimed evaluations from the transcript, checks each round's sum and the final relation value.
pub fn verify_sumcheck<C: Curve>(
    rels: &impl RelationSet<C::Fr>,
    spec: &SumcheckSpec,
    t: &mut Transcript<C::TF, C::Hash>,
    alphas: &[C::Fr],
    params: &RelationParams<C::Fr>,
    gate_challenges: &[C::Fr],
) -> SumcheckOutput<C> {
    type F<C> = <C as Curve>::Fr;
    assert_eq!(alphas.len(), rels.total_subrelations() - 1, "precomputed alpha powers");

    let mut target_sum = F::<C>::zero();
    let mut libra_challenge = F::<C>::zero();
    if spec.has_zk {
        let libra_total_sum: F<C> = t.receive("Libra:Sum");
        libra_challenge = t.challenge("Libra:Challenge");
        target_sum = libra_total_sum * &libra_challenge;
    }

    let mut verified = true;
    let mut challenge = Vec::with_capacity(spec.virtual_log_n);
    let mut partial_evaluation_result = F::<C>::one();
    let mut round_commitments = Vec::new();
    let mut round_evaluations: Vec<[F<C>; 3]> = Vec::new();
    for round in 0..spec.virtual_log_n {
        if spec.committed {
            round_commitments.push(t.receive(&format!("Sumcheck:univariate_comm_{round}")));
            let e0: F<C> = t.receive(&format!("Sumcheck:univariate_{round}_eval_0"));
            let e1: F<C> = t.receive(&format!("Sumcheck:univariate_{round}_eval_1"));
            round_evaluations.push([e0, e1, F::<C>::zero()]);
            let u: F<C> = t.challenge(&format!("Sumcheck:u_{round}"));
            let factor = gate_separator_factor(&u, &gate_challenges[round]);
            partial_evaluation_result *= &factor;
            challenge.push(u);
        } else {
            let univariate: Vec<F<C>> = t.receive_vec(&format!("Sumcheck:univariate_{round}"), spec.batched_len);
            let u: F<C> = t.challenge(&format!("Sumcheck:u_{round}"));
            let round_sum = univariate[0].clone() + &univariate[1];
            if round_sum.value() != target_sum.value() {
                verified = false;
            }
            target_sum.assert_equal(&round_sum);
            target_sum = evaluate_univariate(&univariate, &u);
            partial_evaluation_result *= &gate_separator_factor(&u, &gate_challenges[round]);
            challenge.push(u);
        }
    }

    let evals: Vec<F<C>> = t.receive_vec("Sumcheck:evaluations", spec.num_entities);

    let mut full_value = full_relation_value(
        rels,
        &evals,
        params,
        &partial_evaluation_result,
        &alphas,
        spec.row_disabling.then_some(challenge.as_slice()),
    );

    let mut libra_evaluation = F::<C>::zero();
    if spec.has_zk {
        libra_evaluation = t.receive("Libra:claimed_evaluation");
        full_value += &(libra_evaluation.clone() * &libra_challenge);
    }

    if spec.committed {
        // Only the first round's sum is checked here; the chain S_i(u_i) = S_{i+1}(0) + S_{i+1}(1) and
        // S_{d-1}(u_{d-1}) = full relation value are enforced through the univariate opening claims.
        let first_sum = round_evaluations[0][0].clone() + &round_evaluations[0][1];
        // bb Grumpkin recursive `perform_final_verification`: reduce all three before the equality.
        first_sum.self_reduce();
        target_sum.self_reduce();
        full_value.self_reduce();
        if first_sum.value() != target_sum.value() {
            verified = false;
        }
        first_sum.assert_equal(&target_sum);
        let d = round_evaluations.len();
        for i in 1..d {
            round_evaluations[i - 1][2] = round_evaluations[i][0].clone() + &round_evaluations[i][1];
        }
        round_evaluations[d - 1][2] = full_value.clone();
    } else {
        if full_value.value() != target_sum.value() {
            verified = false;
        }
        full_value.assert_equal(&target_sum);
    }

    SumcheckOutput {
        challenge,
        evals,
        verified,
        libra_evaluation,
        round_commitments,
        round_evaluations,
    }
}

// ---------------------------------------------------------------------------------------------
// Prover
// ---------------------------------------------------------------------------------------------

/// Libra masking data for ZK sumcheck (bb `ZKSumcheckData`).
pub struct ZkData<C: Curve> {
    pub constant_term: C::Fr,
    /// One random univariate (monomial coefficients) per round, scaled as bb does.
    pub libra_univariates: Vec<Polynomial<C::Fr>>,
    pub libra_concatenated_lagrange: Vec<C::Fr>,
    pub libra_concatenated_monomial: Polynomial<C::Fr>,
    pub interpolation_domain: Vec<C::Fr>,
    pub libra_scaling_factor: C::Fr,
    pub libra_challenge: C::Fr,
    pub libra_running_sum: C::Fr,
    pub libra_evaluations: Vec<C::Fr>,
    pub num_rounds: usize,
}

/// Monomial coefficients of the polynomial with the given values on the subgroup `{g^i}`.
pub fn interpolate_on_subgroup<F: FieldLike + Copy>(evals: &[F], g: &F) -> Polynomial<F> {
    let n = evals.len();
    let g_inv = g.invert();
    let n_inv = F::from_u64(n as u64).invert();
    let mut coeffs = Vec::with_capacity(n);
    for j in 0..n {
        let w = g_inv.pow_u64(j as u64);
        let mut acc = F::zero();
        let mut wi = F::one();
        for e in evals {
            acc += *e * wi;
            wi *= w;
        }
        coeffs.push(acc * n_inv);
    }
    Polynomial::from_coeffs(coeffs)
}

/// The subgroup `{1, g, g^2, ...}` of size `C::SUBGROUP_SIZE`.
pub fn subgroup_domain<C: Curve>() -> Vec<C::Fr>
where
    C::Fr: Copy,
{
    let g = C::Fr::constant(C::subgroup_generator());
    let mut domain = vec![C::Fr::one(); C::SUBGROUP_SIZE];
    for i in 1..C::SUBGROUP_SIZE {
        domain[i] = domain[i - 1] * g;
    }
    domain
}

impl<C: Curve> ZkData<C>
where
    C::Fr: PrimeField<BigInt = U256>,
    C::G: AffineRepr<ScalarField = C::Fr>,
{
    pub fn new(
        num_rounds: usize,
        t: &mut crate::base::transcript::Transcript<C::TF, C::Hash>,
        ck: &Ck<C::G>,
        rng: &mut dyn Rng,
    ) -> Self {
        type F<C> = <C as Curve>::Fr;
        let subgroup_size = C::SUBGROUP_SIZE;
        let libra_len = C::LIBRA_UNIVARIATES_LENGTH;
        let constant_term: F<C> = random_field(rng);
        let libra_univariates: Vec<Polynomial<F<C>>> = (0..num_rounds)
            .map(|_| Polynomial::from_coeffs((0..libra_len).map(|_| random_field(rng)).collect()))
            .collect();
        let g = F::<C>::constant(C::subgroup_generator());
        let interpolation_domain = subgroup_domain::<C>();
        // concatenated Libra polynomial in the Lagrange basis over H, then monomial + masking
        assert!(num_rounds * libra_len + 1 < subgroup_size);
        let mut lagrange = vec![F::<C>::zero(); subgroup_size];
        lagrange[0] = constant_term;
        for (r, u) in libra_univariates.iter().enumerate() {
            for (i, c) in u.coeffs.iter().enumerate() {
                lagrange[1 + r * libra_len + i] = *c;
            }
        }
        let mut monomial = interpolate_on_subgroup(&lagrange, &g);
        monomial.coeffs.resize(subgroup_size + 2, F::<C>::zero());
        let masking: [F<C>; 2] = [random_field(rng), random_field(rng)];
        for (i, m) in masking.iter().enumerate() {
            monomial.coeffs[i] -= m;
            monomial.coeffs[subgroup_size + i] += m;
        }
        t.send("Libra:concatenation_commitment", &ck.commit(&monomial));

        // total sum over the hypercube: 2^{d-1} sum_i (g_i(0) + g_i(1)) + 2^d * constant
        let two = F::<C>::from_u64(2);
        let mut total_sum = F::<C>::zero();
        let mut scaling_factor = two.invert();
        for u in &libra_univariates {
            total_sum += u.coeffs[0] + u.evaluate(&F::<C>::one());
            scaling_factor *= two;
        }
        total_sum *= scaling_factor;
        total_sum += constant_term * F::<C>::from_u64(1u64 << num_rounds);
        t.send("Libra:Sum", &total_sum);
        let libra_challenge: F<C> = t.challenge("Libra:Challenge");
        let mut running_sum = total_sum * libra_challenge;

        // setup_auxiliary_data
        scaling_factor *= libra_challenge;
        let mut libra_univariates = libra_univariates;
        for u in libra_univariates.iter_mut() {
            for c in u.coeffs.iter_mut() {
                *c *= scaling_factor;
            }
        }
        running_sum += -libra_univariates[0].coeffs[0] - libra_univariates[0].evaluate(&F::<C>::one());
        running_sum *= two.invert();

        Self {
            constant_term,
            libra_univariates,
            libra_concatenated_lagrange: lagrange,
            libra_concatenated_monomial: monomial,
            interpolation_domain,
            libra_scaling_factor: scaling_factor,
            libra_challenge,
            libra_running_sum: running_sum,
            libra_evaluations: Vec::new(),
            num_rounds,
        }
    }
}

impl<C: Curve> ZkData<C>
where
    C::Fr: Copy,
{
    /// Values of the Libra round univariate at `k = 0..len-1`.
    pub fn round_univariate(&self, round: usize, len: usize) -> Vec<C::Fr> {
        (0..len)
            .map(|k| self.libra_univariates[round].evaluate(&C::Fr::from_u64(k as u64)) + self.libra_running_sum)
            .collect()
    }

    /// bb `update_zk_sumcheck_data`.
    pub fn update(&mut self, u: &C::Fr, round: usize) {
        let half = C::Fr::from_u64(2).invert();
        if round < self.num_rounds - 1 {
            for p in self.libra_univariates.iter_mut() {
                for c in p.coeffs.iter_mut() {
                    *c *= half;
                }
            }
            let eval = self.libra_univariates[round].evaluate(u);
            let next = &self.libra_univariates[round + 1];
            self.libra_running_sum += -next.coeffs[0] - next.evaluate(&C::Fr::one());
            self.libra_running_sum *= half;
            self.libra_running_sum += eval;
            self.libra_scaling_factor *= half;
            self.libra_evaluations.push(eval * self.libra_scaling_factor.invert());
        } else {
            let eval = self.libra_univariates[round].evaluate(u) * self.libra_scaling_factor.invert();
            self.libra_evaluations.push(eval);
        }
    }

    /// `constant + sum_i g_i(u_i)`: the claimed evaluation of the Libra multivariate.
    pub fn claimed_evaluation(&self) -> C::Fr {
        self.libra_evaluations.iter().fold(self.constant_term, |a, e| a + *e)
    }
}

/// Linear univariate given by its values at 0 and 1, evaluated at `k`.
fn linear_at<F: FieldLike + Copy>(v0: &F, v1: &F, k: usize) -> F {
    *v0 + F::from_u64(k as u64) * (*v1 - *v0)
}

/// Relation accumulators, point-major per relation: subrelation `j` of relation `ri` at point `k`
/// lives at `offsets[ri] + k * ns[ri] + j`, so a relation adds point `k` of all its subrelations
/// into one contiguous slice.
struct Accumulators<F> {
    data: Vec<F>,
    offsets: Vec<usize>,
    ns: Vec<usize>,
}

impl<F: FieldLike + Copy> Accumulators<F> {
    fn new(rels: &impl RelationSet<F>, d: usize) -> Self {
        let ns: Vec<usize> = (0..rels.num_relations()).map(|r| rels.num_subrelations(r)).collect();
        let mut offsets = Vec::with_capacity(ns.len());
        let mut total = 0;
        for n in &ns {
            offsets.push(total);
            total += n * d;
        }
        Self { data: vec![F::zero(); total], offsets, ns }
    }
    fn point(&mut self, ri: usize, k: usize) -> &mut [F] {
        let start = self.offsets[ri] + k * self.ns[ri];
        &mut self.data[start..start + self.ns[ri]]
    }
    fn at(&self, ri: usize, j: usize, k: usize) -> F {
        self.data[self.offsets[ri] + k * self.ns[ri] + j]
    }
    fn add(mut self, other: Self) -> Self {
        for (x, y) in self.data.iter_mut().zip(other.data) {
            *x += y;
        }
        self
    }
}

/// `prod_{bits j of e} betas[round + 1 + j]` for every edge `e` of the round (bb `beta_products`):
/// one multiplication per entry.
fn gate_separator_products<F: FieldLike + Copy>(betas: &[F], round: usize, num_edges: usize) -> Vec<F> {
    let mut p = vec![F::one(); num_edges.max(1)];
    let mut j = 0;
    while (1 << j) < num_edges {
        let b = betas[round + 1 + j];
        let (lo, hi) = p.split_at_mut(1 << j);
        for (x, y) in hi.iter_mut().zip(lo.iter()) {
            *x = *y * b;
        }
        j += 1;
    }
    p
}

/// `BBREF_TIMING_RELATIONS=1`: nanoseconds and active edges per relation of the current round
/// (meaningful single-threaded), printed for round 0 of every sumcheck.
static RELATION_STATS: std::sync::Mutex<Vec<(u128, u64)>> = std::sync::Mutex::new(Vec::new());
static EXTENSION_NS: std::sync::Mutex<u128> = std::sync::Mutex::new(0);
pub fn relation_stats_enabled() -> bool {
    std::env::var_os("BBREF_TIMING_RELATIONS").is_some()
}
fn print_relation_stats<F: FieldLike>(rels: &impl RelationSet<F>, num_edges: usize) {
    let mut stats = RELATION_STATS.lock().unwrap();
    let ext = std::mem::take(&mut *EXTENSION_NS.lock().unwrap());
    eprintln!(
        "[relations] {} edges, row extension {:.0} ms",
        num_edges,
        ext as f64 / 1e6
    );
    for (r, (ns, edges)) in stats.iter().enumerate() {
        eprintln!(
            "[relations]   rel {r:2}: {:8.1} ms over {:7} active edges ({:.1} us/edge, partial length {})",
            *ns as f64 / 1e6,
            edges,
            *ns as f64 / 1e3 / (*edges).max(1) as f64,
            rels.partial_length(r).min(64)
        );
    }
    stats.clear();
}

/// Per-thread scratch for `accumulate_edge`.
struct Scratch<F> {
    row0: Vec<F>,
    row1: Vec<F>,
    /// `row1 - row0`: the edge univariate is stepped by repeated addition (bb `extend_edges`).
    delta: Vec<F>,
    row: Vec<F>,
    active: Vec<bool>,
    /// Points evaluated per relation: `min(partial_length, d)`.
    len: Vec<usize>,
    /// Columns read by the edge's active relations: the only ones stepped.
    cols: Vec<usize>,
    mark: Vec<bool>,
}

impl<F: FieldLike + Copy> Scratch<F> {
    fn new(rels: &impl RelationSet<F>, num_columns: usize, d: usize) -> Self {
        Self {
            row0: vec![F::zero(); num_columns],
            row1: vec![F::zero(); num_columns],
            delta: vec![F::zero(); num_columns],
            row: vec![F::zero(); num_columns],
            active: vec![false; rels.num_relations()],
            len: (0..rels.num_relations())
                .map(|r| rels.partial_length(r).min(d))
                .collect(),
            cols: Vec::with_capacity(num_columns),
            mark: vec![false; num_columns],
        }
    }
}

/// The columns each relation reads, found by re-randomizing one column at a time: a body that
/// depends on a column changes value with overwhelming probability (Schwartz-Zippel), so the
/// edge extension can skip the others (bb `LazyExtendedEdges`).
fn used_columns<F: FieldLike + Copy>(
    rels: &impl RelationSet<F>,
    num_columns: usize,
    params: &RelationParams<F>,
) -> Vec<Vec<usize>> {
    let mut rng = ark_std::test_rng();
    let mut draw = || F::constant(<F::Native as ark_ff::UniformRand>::rand(&mut rng));
    let row: Vec<F> = (0..num_columns).map(|_| draw()).collect();
    let alt: Vec<F> = (0..num_columns).map(|_| draw()).collect();
    let scaling = draw();
    let eval = |r: usize, row: &[F]| {
        let mut acc = vec![F::zero(); rels.num_subrelations(r)];
        rels.accumulate(r, &mut acc, row, params, &scaling);
        acc
    };
    (0..rels.num_relations())
        .map(|r| {
            let base = eval(r, &row);
            let mut probe = row.clone();
            (0..num_columns)
                .filter(|&j| {
                    probe[j] = alt[j];
                    let changed = eval(r, &probe).iter().zip(&base).any(|(a, b)| !(*a - b).is_zero());
                    probe[j] = row[j];
                    changed
                })
                .collect()
        })
        .collect()
}

/// Lagrange weights extending a univariate known at `0..len` to the points `len..d`:
/// `weights[len][k - len][i] = prod_{j != i} (k - j) / (i - j)` (bb `BarycentricData`), one
/// batched inversion for all of them.
pub struct ExtensionWeights<F> {
    weights: Vec<Vec<Vec<F>>>,
}

impl<F: FieldLike + Copy> ExtensionWeights<F> {
    pub fn new(lengths: impl Iterator<Item = usize>, d: usize) -> Self {
        let mut weights = vec![vec![]; d + 1];
        for len in lengths.filter(|l| *l < d) {
            if !weights[len].is_empty() {
                continue;
            }
            let mut inverse: Vec<F> = (0..len)
                .map(|i| {
                    let mut den = F::one();
                    for j in (0..len).filter(|j| *j != i) {
                        den *= &(F::from_u64(i as u64) - &F::from_u64(j as u64));
                    }
                    den
                })
                .collect();
            for x in inverse.iter_mut() {
                *x = x.invert();
            }
            weights[len] = (len..d)
                .map(|k| {
                    (0..len)
                        .map(|i| {
                            let mut num = F::one();
                            for j in (0..len).filter(|j| *j != i) {
                                num *= &(F::from_u64(k as u64) - &F::from_u64(j as u64));
                            }
                            num * inverse[i]
                        })
                        .collect()
                })
                .collect();
        }
        Self { weights }
    }
    /// The accumulator of subrelation `j` of relation `ri` at point `k`: stored for `k` below the
    /// relation's partial length, extended beyond it.
    fn accumulator_at(
        &self,
        rels: &impl RelationSet<F>,
        acc: &Accumulators<F>,
        ri: usize,
        j: usize,
        k: usize,
        d: usize,
    ) -> F {
        let len = rels.partial_length(ri).min(d);
        if k < len {
            acc.at(ri, j, k)
        } else {
            let mut v = F::zero();
            for (i, w) in self.weights[len][k - len].iter().enumerate() {
                v += &(*w * acc.at(ri, j, i));
            }
            v
        }
    }
}

/// The accumulators over a range of edges, split across threads (exact arithmetic: any split
/// gives the same sums).
fn accumulate_edges<F: FieldLike + Copy + Send + Sync>(
    rels: &(impl RelationSet<F> + Sync),
    used: &[Vec<usize>],
    table: &[Column<F>],
    edges: std::ops::Range<usize>,
    params: &RelationParams<F>,
    pows: &[F],
    d: usize,
) -> Accumulators<F>
where
    RelationParams<F>: Sync,
{
    // A few chunks per thread, each with its own accumulators and scratch.
    let chunk = (edges.len() / (4 * rayon::current_num_threads())).max(16);
    let starts: Vec<usize> = edges.clone().step_by(chunk).collect();
    starts
        .into_par_iter()
        .map(|start| {
            let mut acc = Accumulators::new(rels, d);
            let mut scratch = Scratch::new(rels, table.len(), d);
            for e in start..(start + chunk).min(edges.end) {
                accumulate_edge(rels, used, table, e, params, &pows[e], &mut acc, &mut scratch);
            }
            acc
        })
        .reduce(|| Accumulators::new(rels, d), Accumulators::add)
}

/// Add the contributions of the edge `(table[·][2e], table[·][2e+1])` at every `k`, skipping the
/// relations that vanish on it.
fn accumulate_edge<F: FieldLike + Copy>(
    rels: &impl RelationSet<F>,
    used: &[Vec<usize>],
    table: &[Column<F>],
    e: usize,
    params: &RelationParams<F>,
    scaling: &F,
    acc: &mut Accumulators<F>,
    s: &mut Scratch<F>,
) {
    for j in 0..table.len() {
        s.row0[j] = column_value(table, j, 2 * e);
        s.row1[j] = column_value(table, j, 2 * e + 1);
    }
    if rels.skip_row(&s.row0, &s.row1) {
        return;
    }
    let mut num_points = 0;
    s.cols.clear();
    for ri in 0..rels.num_relations() {
        s.active[ri] = !rels.skip(ri, &s.row0, &s.row1);
        if s.active[ri] {
            num_points = num_points.max(s.len[ri]);
            for &j in &used[ri] {
                if !s.mark[j] {
                    s.mark[j] = true;
                    s.cols.push(j);
                }
            }
        }
    }
    for &j in &s.cols {
        s.mark[j] = false;
        s.delta[j] = s.row1[j] - s.row0[j];
    }
    let stats = relation_stats_enabled();
    let mut ext_ns = 0u128;
    let mut rel_ns = vec![0u128; if stats { rels.num_relations() } else { 0 }];
    for k in 0..num_points {
        let t0 = stats.then(std::time::Instant::now);
        for &j in &s.cols {
            if k == 0 {
                s.row[j] = s.row0[j];
            } else {
                s.row[j] += s.delta[j];
            }
        }
        if let Some(t0) = t0 {
            ext_ns += t0.elapsed().as_nanos();
        }
        for ri in 0..rels.num_relations() {
            if !s.active[ri] || k >= s.len[ri] {
                continue;
            }
            let t0 = stats.then(std::time::Instant::now);
            rels.accumulate(ri, acc.point(ri, k), &s.row, params, scaling);
            if let Some(t0) = t0 {
                rel_ns[ri] += t0.elapsed().as_nanos();
            }
        }
    }
    if stats {
        let mut st = RELATION_STATS.lock().unwrap();
        st.resize(rels.num_relations(), (0, 0));
        for ri in 0..rels.num_relations() {
            st[ri].0 += rel_ns[ri];
            st[ri].1 += s.active[ri] as u64;
        }
        *EXTENSION_NS.lock().unwrap() += ext_ns;
    }
}

/// bb `batch_over_relations`: `S(k) = sum_r Λ_r(k) sum_j α_{r,j} acc_{r,j}(k) [lin. indep.: · (1 + k(β - 1)) · c]`.
fn batch_over_relations<F: FieldLike + Copy>(
    rels: &impl RelationSet<F>,
    ext: &ExtensionWeights<F>,
    acc: &Accumulators<F>,
    alphas: &[F],
    beta: &F,
    partial_eval: &F,
    row_disabling: Option<(F, F)>,
    d: usize,
) -> Vec<F> {
    let mut result = vec![F::zero(); d];
    for k in 0..d {
        let pow_factor = linear_at(&F::one(), beta, k) * *partial_eval;
        let (main, offset) = match row_disabling {
            Some((l0, l1)) => {
                let l = linear_at(&l0, &l1, k);
                (F::one() - l, l)
            }
            None => (F::one(), F::zero()),
        };
        let mut alpha_idx = 0;
        for ri in 0..rels.num_relations() {
            let mut per_relation = F::zero();
            for j in 0..rels.num_subrelations(ri) {
                let alpha = if ri == 0 && j == 0 { F::one() } else { alphas[alpha_idx] };
                if !(ri == 0 && j == 0) {
                    alpha_idx += 1;
                }
                let mut term = ext.accumulator_at(rels, acc, ri, j, k, d) * alpha;
                if rels.linearly_independent(ri, j) {
                    term *= pow_factor;
                }
                per_relation += term;
            }
            result[k] += per_relation * if rels.offset_only(ri) { offset } else { main };
        }
    }
    result
}

/// `pow_beta` factor of edge pair `e` in `round`: product of `betas[round+1+j]` over the set bits `j` of `e`.

/// Per-round prover state for one relation set (bb `SumcheckProverRound` +
/// `PartiallyEvaluatedMultivariates`): the table being folded and the row-disabling bookkeeping.
/// A column of the round table: the prover's polynomial itself until the first fold (trimmed to
/// its last non-zero coefficient, bb `end_index`), the shift of another column (read one row
/// ahead), or the folded values once a round has been evaluated.
pub enum Column<'a, F> {
    Borrowed(&'a [F]),
    ShiftOf(usize),
    Own(Vec<F>),
}

fn column_len<F>(table: &[Column<F>], j: usize) -> usize {
    match &table[j] {
        Column::Borrowed(s) => s.len(),
        Column::Own(v) => v.len(),
        Column::ShiftOf(k) => column_len(table, *k).saturating_sub(1),
    }
}

/// Value of column `j` at row `i` (zero past the column's end).
fn column_value<F: FieldLike + Copy>(table: &[Column<F>], j: usize, i: usize) -> F {
    match &table[j] {
        Column::Borrowed(s) => s.get(i).copied().unwrap_or_else(F::zero),
        Column::Own(v) => v.get(i).copied().unwrap_or_else(F::zero),
        Column::ShiftOf(k) => column_value(table, *k, i + 1),
    }
}

/// Rounds past `log_n` are virtual (zero-extension) rounds.
pub struct RoundProver<'a, F> {
    table: Vec<Column<'a, F>>,
    log_n: usize,
    row_disabling: bool,
    excluded_head: usize,
    rd0: F,
    rd1: F,
    round: usize,
    /// Rows past this are all-zero witness rows (bb witness `end_index`), halved each round.
    witness_end: usize,
    active_prefix_end: Option<usize>,
    ext: ExtensionWeights<F>,
    /// Columns read by each relation (`used_columns`), found on the first round.
    used: Vec<Vec<usize>>,
}

impl<'a, F: FieldLike + Copy + Send + Sync> RoundProver<'a, F>
where
    RelationParams<F>: Sync,
{
    /// The table is `polys` followed by the shifts of `polys[shifted_sources[..]]`. `witness_end`:
    /// rows from there on are all-zero witness rows (bb witness `end_index`; the full size disables
    /// row skipping). `active_prefix_end`: the ECCVM's trace rows, beyond which only the last edge
    /// is evaluated (bb `row_skip_active_prefix_end`).
    pub fn new(
        polys: &'a [Polynomial<F>],
        shifted_sources: &[usize],
        row_disabling: bool,
        trace_offset: usize,
        witness_end: usize,
        active_prefix_end: Option<usize>,
    ) -> Self {
        let n = polys[0].len();
        let trim = |p: &'a Polynomial<F>| {
            let end = p.coeffs.iter().rposition(|c| !c.is_zero()).map_or(0, |i| i + 1);
            Column::Borrowed(&p.coeffs[..end])
        };
        let table = polys.iter().map(trim).chain(shifted_sources.iter().map(|s| Column::ShiftOf(*s))).collect();
        Self {
            table,
            log_n: n.trailing_zeros() as usize,
            row_disabling,
            excluded_head: if row_disabling { trace_offset } else { 0 },
            rd0: F::one(),
            rd1: F::one(),
            round: 0,
            witness_end: witness_end.min(n),
            active_prefix_end,
            ext: ExtensionWeights { weights: vec![] },
            used: vec![],
        }
    }
    /// Extension weights for this relation set and univariate length (built once, on the first round).
    fn ensure_weights(&mut self, rels: &impl RelationSet<F>, params: &RelationParams<F>, d: usize) {
        if self.ext.weights.is_empty() {
            self.ext = ExtensionWeights::new((0..rels.num_relations()).map(|r| rels.partial_length(r)), d);
            self.used = used_columns(rels, self.table.len(), params);
        }
    }

    /// bb `compute_edge_ranges`: the edges to evaluate this round, after the disabled head.
    fn edge_ranges(&self, round_size: usize) -> Vec<std::ops::Range<usize>> {
        let head = self.excluded_head / 2;
        let effective = round_size.min(self.witness_end + self.witness_end % 2) / 2;
        let mut ranges = vec![];
        match self.active_prefix_end {
            Some(prefix) if prefix < round_size => {
                let prefix_end = ((prefix + prefix % 2) / 2).min(effective).max(head);
                ranges.push(head..prefix_end);
                if effective > prefix_end && effective >= head + 1 {
                    ranges.push(effective - 1..effective);
                }
            }
            _ => ranges.push(head..effective),
        }
        ranges
    }
    pub fn log_n(&self) -> usize {
        self.log_n
    }
    /// Current value of column `i` (its evaluation once all real rounds are done).
    pub fn current(&self, i: usize) -> F {
        column_value(&self.table, i, 0)
    }
    pub fn evals(&self) -> Vec<F> {
        (0..self.table.len()).map(|i| self.current(i)).collect()
    }

    /// The round univariate of the relations (bb `compute_univariate` + `compute_offset_area_contribution`,
    /// or `compute_virtual_contribution` for a virtual round), without any Libra term.
    pub fn univariate(
        &mut self,
        rels: &(impl RelationSet<F> + Sync),
        params: &RelationParams<F>,
        betas: &[F],
        partial_eval: &F,
        alphas: &[F],
        d: usize,
    ) -> Vec<F> {
        self.ensure_weights(rels, params, d);
        let round = self.round;
        if round < self.log_n {
            let round_size = 1 << (self.log_n - round);
            if round == 0 && relation_stats_enabled() {
                RELATION_STATS.lock().unwrap().clear();
                *EXTENSION_NS.lock().unwrap() = 0;
            }
            let pows = gate_separator_products(betas, round, round_size / 2);
            let acc = self
                .edge_ranges(round_size)
                .into_iter()
                .map(|edges| accumulate_edges(rels, &self.used, &self.table, edges, params, &pows, d))
                .reduce(Accumulators::add)
                .unwrap_or_else(|| Accumulators::new(rels, d));
            if round == 0 && relation_stats_enabled() {
                print_relation_stats(rels, round_size / 2);
            }
            let mut univariate =
                batch_over_relations(rels, &self.ext, &acc, alphas, &betas[round], partial_eval, None, d);
            if self.row_disabling {
                let head =
                    accumulate_edges(rels, &self.used, &self.table, 0..self.excluded_head / 2, params, &pows, d);
                let head_uni = batch_over_relations(
                    rels,
                    &self.ext,
                    &head,
                    alphas,
                    &betas[round],
                    partial_eval,
                    Some((self.rd0, self.rd1)),
                    d,
                );
                for (k, v) in head_uni.into_iter().enumerate() {
                    univariate[k] += v;
                }
            }
            univariate
        } else {
            // virtual round: the table has one row and the edge is (P(u), 0)
            let mut acc = Accumulators::new(rels, d);
            let edge_table: Vec<Column<F>> = (0..self.table.len())
                .map(|i| Column::Own(vec![self.current(i), F::zero()]))
                .collect();
            accumulate_edge(
                rels,
                &self.used,
                &edge_table,
                0,
                params,
                &F::one(),
                &mut acc,
                &mut Scratch::new(rels, edge_table.len(), d),
            );
            let rd = if self.row_disabling {
                Some((self.rd0, self.rd1))
            } else {
                None
            };
            batch_over_relations(rels, &self.ext, &acc, alphas, &betas[round], partial_eval, rd, d)
        }
    }

    /// bb `partially_evaluate` / `fold_for_zero_extension` plus the row-disabling updates.
    pub fn partially_evaluate(&mut self, u: &F) {
        let round = self.round;
        if round < self.log_n {
            // The folded table is half the size and owned (bb `PartiallyEvaluatedMultivariates`).
            let table = &self.table;
            let folded: Vec<Column<F>> = (0..table.len())
                .into_par_iter()
                .map(|j| {
                    let half = column_len(table, j).div_ceil(2);
                    Column::Own(
                        (0..half)
                            .map(|k| {
                                let a = column_value(table, j, 2 * k);
                                a + *u * (column_value(table, j, 2 * k + 1) - a)
                            })
                            .collect(),
                    )
                })
                .collect();
            self.table = folded;
        } else {
            for j in 0..self.table.len() {
                let v = column_value(&self.table, j, 0) * (F::one() - *u);
                self.table[j] = Column::Own(vec![v]);
            }
        }
        self.witness_end = self.witness_end.div_ceil(2);
        self.active_prefix_end = self.active_prefix_end.map(|p| p.div_ceil(2));
        if round == 1 {
            self.rd1 = F::zero();
        }
        if round >= 2 {
            self.rd0 *= F::one() - *u;
        }
        if self.row_disabling {
            self.excluded_head = 2;
        }
        self.round += 1;
    }
}

/// Committed-sumcheck bookkeeping (bb `RoundUnivariateHandler<Flavor, true>`).
pub struct CommittedRounds<C: Curve> {
    pub univariates: Vec<Polynomial<C::Fr>>,
    pub commitments: Vec<C::G>,
    pub evaluations: Vec<[C::Fr; 3]>,
}

impl<C: Curve> CommittedRounds<C>
where
    C::Fr: Copy,
    C::G: AffineRepr<ScalarField = C::Fr>,
{
    pub fn new() -> Self {
        Self {
            univariates: Vec::new(),
            commitments: Vec::new(),
            evaluations: Vec::new(),
        }
    }
    /// Commit to the round univariate and send its values at 0 and 1.
    pub fn process(&mut self, round: usize, univariate: &[C::Fr], ck: &Ck<C::G>, t: &mut crate::base::transcript::Transcript<C::TF, C::Hash>) {
        let domain: Vec<C::Fr> = (0..univariate.len()).map(|k| C::Fr::from_u64(k as u64)).collect();
        let monomial = Polynomial::interpolate(&domain, univariate);
        let commitment = ck.commit(&monomial);
        t.send(&format!("Sumcheck:univariate_comm_{round}"), &commitment);
        self.commitments.push(commitment);
        self.univariates.push(monomial);
        t.send(&format!("Sumcheck:univariate_{round}_eval_0"), &univariate[0]);
        t.send(&format!("Sumcheck:univariate_{round}_eval_1"), &univariate[1]);
        self.evaluations.push([univariate[0], univariate[1], C::Fr::zero()]);
        if round > 0 {
            self.evaluations[round - 1][2] = univariate[0] + univariate[1];
        }
    }
    pub fn finalize(&mut self, last_univariate: &[C::Fr], last_challenge: &C::Fr) {
        let last = self.evaluations.len() - 1;
        self.evaluations[last][2] = evaluate_univariate(last_univariate, last_challenge);
    }
}

impl<C: Curve> Default for CommittedRounds<C>
where
    C::Fr: Copy,
    C::G: AffineRepr<ScalarField = C::Fr>,
{
    fn default() -> Self {
        Self::new()
    }
}

pub struct SumcheckProverOutput<C: Curve> {
    pub challenge: Vec<C::Fr>,
    pub evals: Vec<C::Fr>,
    pub libra_evaluation: C::Fr,
    /// Committed sumcheck only: round univariates in monomial form, their commitments, and their
    /// values at `0`, `1`, `u_i`.
    pub round_univariates: Vec<Polynomial<C::Fr>>,
    pub round_commitments: Vec<C::G>,
    pub round_evaluations: Vec<[C::Fr; 3]>,
}

/// bb `SumcheckProver::prove` (plain, ZK and committed variants). `ck` is required for the
/// committed variant (to commit to the round univariates).
pub fn prove_sumcheck<C: Curve>(
    rels: &(impl RelationSet<C::Fr> + Sync),
    spec: &SumcheckSpec,
    polys: &[Polynomial<C::Fr>],
    t: &mut crate::base::transcript::Transcript<C::TF, C::Hash>,
    alpha: &C::Fr,
    betas: &[C::Fr],
    params: &RelationParams<C::Fr>,
    mut zk: Option<&mut ZkData<C>>,
    ck: Option<&Ck<C::G>>,
) -> SumcheckProverOutput<C>
where
    C::Fr: Copy,
    C::G: AffineRepr<ScalarField = C::Fr>,
    C::Fr: Copy + Send + Sync,
    RelationParams<C::Fr>: Sync,
{
    type F<C> = <C as Curve>::Fr;
    let d = spec.batched_len;
    let alphas = alpha_powers(alpha, rels.total_subrelations() - 1);
    let mut state = RoundProver::new(
        polys,
        &spec.shifted_sources,
        spec.row_disabling,
        spec.trace_offset,
        spec.witness_end,
        spec.active_prefix_end,
    );
    let mut committed = CommittedRounds::<C>::new();
    let mut challenge = Vec::with_capacity(spec.virtual_log_n);
    let mut partial_eval = F::<C>::one();
    let mut last_univariate = Vec::new();
    for round in 0..spec.virtual_log_n {
        let round_start = relation_stats_enabled().then(std::time::Instant::now);
        let mut univariate = state.univariate(rels, params, betas, &partial_eval, &alphas, d);
        if let Some(zk) = zk.as_deref_mut() {
            for (k, v) in zk.round_univariate(round, d).into_iter().enumerate() {
                univariate[k] += v;
            }
        }
        if spec.committed {
            committed.process(
                round,
                &univariate,
                ck.expect("committed sumcheck needs a commitment key"),
                t,
            );
        } else {
            t.send_vec(&format!("Sumcheck:univariate_{round}"), &univariate);
        }
        let u: F<C> = t.challenge(&format!("Sumcheck:u_{round}"));
        state.partially_evaluate(&u);
        if let Some(t0) = round_start {
            eprintln!("[round {round}] {:.1} ms", t0.elapsed().as_secs_f64() * 1e3);
        }
        if let Some(zk) = zk.as_deref_mut() {
            zk.update(&u, round);
        }
        partial_eval *= gate_separator_factor(&u, &betas[round]);
        challenge.push(u);
        last_univariate = univariate;
    }
    if spec.committed {
        committed.finalize(&last_univariate, challenge.last().unwrap());
    }
    let evals = state.evals();
    t.send_vec("Sumcheck:evaluations", &evals);
    let mut libra_evaluation = F::<C>::zero();
    if let Some(zk) = zk {
        libra_evaluation = zk.claimed_evaluation();
        t.send("Libra:claimed_evaluation", &libra_evaluation);
    }
    SumcheckProverOutput {
        challenge,
        evals,
        libra_evaluation,
        round_univariates: committed.univariates,
        round_commitments: committed.commitments,
        round_evaluations: committed.evaluations,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::transcript::NativeTranscript;
    use crate::base::{Bn254, Fr};

    /// One relation, one subrelation: `w0 · w1 == 0` on every row. The relation itself has degree 2
    /// (partial length 3); the batched univariate carries one more point for the linear
    /// gate-separator factor, exactly like bb's `BATCHED_RELATION_PARTIAL_LENGTH`.
    struct ProductVanishes;
    impl RelationSet<Fr> for ProductVanishes {
        fn num_relations(&self) -> usize {
            1
        }
        fn num_subrelations(&self, _r: usize) -> usize {
            1
        }
        fn linearly_independent(&self, _r: usize, _j: usize) -> bool {
            true
        }
        fn offset_only(&self, _r: usize) -> bool {
            false
        }
        fn accumulate(&self, _r: usize, acc: &mut [Fr], row: &[Fr], _p: &RelationParams<Fr>, scaling: &Fr) {
            acc[0] += row[0] * row[1] * scaling;
        }
        fn partial_length(&self, _r: usize) -> usize {
            3
        }
    }

    fn spec(log_n: usize) -> SumcheckSpec {
        SumcheckSpec {
            witness_end: 1 << log_n,
            active_prefix_end: None,
            virtual_log_n: log_n,
            has_zk: false,
            row_disabling: false,
            trace_offset: 0,
            committed: false,
            batched_len: 4,
            shifted_sources: vec![],
            num_entities: 2,
        }
    }

    fn run(w0: Vec<u64>, w1: Vec<u64>) -> (SumcheckOutput<Bn254>, Vec<Fr>, Vec<Fr>) {
        let log_n = w0.len().trailing_zeros() as usize;
        let polys =
            [w0, w1].map(|w| Polynomial::from_coeffs(w.into_iter().map(Fr::from).collect()));
        let params = RelationParams::default();
        let alpha = Fr::from(0u64); // one subrelation: no batching challenge is consumed
        let betas: Vec<Fr> = (0..log_n).map(|i| Fr::from(3 + i as u64)).collect();

        let mut pt = NativeTranscript::new();
        let out = prove_sumcheck::<Bn254>(
            &ProductVanishes,
            &spec(log_n),
            &polys,
            &mut pt,
            &alpha,
            &betas,
            &params,
            None,
            None,
        );
        let proof = pt.export_proof();

        let mut vt = NativeTranscript::from_proof(&proof);
        let v = verify_sumcheck::<Bn254>(&ProductVanishes, &spec(log_n), &mut vt, &[], &params, &betas);
        (v, out.challenge, out.evals)
    }

    /// A satisfying trace round-trips: the verifier accepts and lands on the prover's challenge
    /// point and claimed evaluations.
    #[test]
    fn round_trip_on_satisfying_trace() {
        let (v, p_challenge, p_evals) = run(vec![0, 5, 0, 7], vec![3, 0, 9, 0]);
        assert!(v.verified);
        assert_eq!(v.challenge, p_challenge);
        assert_eq!(v.evals, p_evals);
    }

    /// One violating row (w0·w1 ≠ 0) makes the honestly-computed proof claim a nonzero sum, which
    /// the first round check (u(0) + u(1) == target) rejects.
    #[test]
    fn violating_row_rejected_at_first_round() {
        let (v, _, _) = run(vec![0, 5, 2, 7], vec![3, 0, 9, 0]);
        assert!(!v.verified);
    }
}
