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
use ark_ec::AffineRepr;
use ark_ff::PrimeField;

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
        self.flavor.relations[r].accumulate(acc, &Row { vals: row, layout: self.layout }, p, scaling)
    }
}

/// Shape of one sumcheck instance.
#[derive(Clone, Copy)]
pub struct SumcheckSpec {
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
    pub num_entities: usize,
}

impl SumcheckSpec {
    pub fn honk(flavor: &FlavorDesc, layout: &Layout) -> Self {
        Self {
            virtual_log_n: flavor.virtual_log_n,
            has_zk: flavor.has_zk,
            row_disabling: flavor.has_zk,
            trace_offset: flavor.trace_offset,
            committed: false,
            batched_len: layout.batched_len,
            num_entities: layout.num_all(),
        }
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
pub fn full_relation_value<F: FieldLike>(rels: &impl RelationSet<F>, evals: &[F], params: &RelationParams<F>, scaling: &F, alphas: &[F], main_factor: &F, offset_factor: &F) -> F {
    // every relation is accumulated before any batching (bb `accumulate_relation_evaluations` then
    // `scale_and_batch_elements`), which fixes the in-circuit gate order
    let accumulated: Vec<Vec<F>> = (0..rels.num_relations())
        .map(|ri| {
            let mut acc = vec![F::zero(); rels.num_subrelations(ri)];
            rels.accumulate(ri, &mut acc, evals, params, scaling);
            crate::circuit::builder::trace_phase(&format!("relation {ri} accumulated"));
            acc
        })
        .collect();
    let mut result = F::zero();
    let mut alpha_idx = 0;
    for (ri, acc) in accumulated.iter().enumerate() {
        let factor = if rels.offset_only(ri) { offset_factor } else { main_factor };
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
    alpha: &C::Fr,
    params: &RelationParams<C::Fr>,
    gate_challenges: &[C::Fr],
) -> SumcheckOutput<C> {
    type F<C> = <C as Curve>::Fr;
    let alphas = alpha_powers(alpha, rels.total_subrelations() - 1);

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
            partial_evaluation_result *= &gate_separator_factor(&u, &gate_challenges[round]);
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

    crate::circuit::builder::trace_phase("sumcheck: rounds done");
    let evals: Vec<F<C>> = t.receive_vec("Sumcheck:evaluations", spec.num_entities);

    let (main_factor, offset_factor) = if spec.row_disabling {
        let m = row_disabling_main_factor(&challenge);
        let o = F::<C>::one() - &m;
        (m, o)
    } else {
        (F::<C>::one(), F::<C>::zero())
    };
    crate::circuit::builder::trace_phase("sumcheck: row disabling factors");
    let mut full_value = full_relation_value(rels, &evals, params, &partial_evaluation_result, &alphas, &main_factor, &offset_factor);
    crate::circuit::builder::trace_phase("sumcheck: full relation value");

    let mut libra_evaluation = F::<C>::zero();
    if spec.has_zk {
        libra_evaluation = t.receive("Libra:claimed_evaluation");
        full_value += &(libra_evaluation.clone() * &libra_challenge);
    }

    if spec.committed {
        // Only the first round's sum is checked here; the chain S_i(u_i) = S_{i+1}(0) + S_{i+1}(1) and
        // S_{d-1}(u_{d-1}) = full relation value are enforced through the univariate opening claims.
        let first_sum = round_evaluations[0][0].clone() + &round_evaluations[0][1];
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

impl<C: Curve<TF = Fr>> ZkData<C>
where
    C::Fr: PrimeField<BigInt = U256>,
    C::G: AffineRepr<ScalarField = C::Fr>,
{
    pub fn new(num_rounds: usize, t: &mut NativeTranscript, ck: &Ck<C::G>, rng: &mut dyn Rng) -> Self {
        type F<C> = <C as Curve>::Fr;
        let subgroup_size = C::SUBGROUP_SIZE;
        let libra_len = C::LIBRA_UNIVARIATES_LENGTH;
        let constant_term: F<C> = random_field(rng);
        let libra_univariates: Vec<Polynomial<F<C>>> = (0..num_rounds).map(|_| Polynomial::from_coeffs((0..libra_len).map(|_| random_field(rng)).collect())).collect();
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
        (0..len).map(|k| self.libra_univariates[round].evaluate(&C::Fr::from_u64(k as u64)) + self.libra_running_sum).collect()
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

/// Accumulators `acc[relation][subrelation][k]` for `k = 0..D-1`.
type Accumulators<F> = Vec<Vec<Vec<F>>>;

fn new_accumulators<F: FieldLike>(rels: &impl RelationSet<F>, d: usize) -> Accumulators<F> {
    (0..rels.num_relations()).map(|r| vec![vec![F::zero(); d]; rels.num_subrelations(r)]).collect()
}

/// Add the contributions of the edge `(table[·][2e], table[·][2e+1])` at every `k`.
fn accumulate_edge<F: FieldLike + Copy>(rels: &impl RelationSet<F>, table: &[Vec<F>], e: usize, params: &RelationParams<F>, scaling: &F, acc: &mut Accumulators<F>, d: usize) {
    let mut row = vec![F::zero(); table.len()];
    for k in 0..d {
        for (j, col) in table.iter().enumerate() {
            let a = col.get(2 * e).copied().unwrap_or(F::zero());
            let b = col.get(2 * e + 1).copied().unwrap_or(F::zero());
            row[j] = linear_at(&a, &b, k);
        }
        for ri in 0..rels.num_relations() {
            let mut sub = vec![F::zero(); rels.num_subrelations(ri)];
            rels.accumulate(ri, &mut sub, &row, params, scaling);
            for (j, v) in sub.into_iter().enumerate() {
                acc[ri][j][k] += v;
            }
        }
    }
}

/// bb `batch_over_relations`: `S(k) = sum_r Λ_r(k) sum_j α_{r,j} acc_{r,j}(k) [lin. indep.: · (1 + k(β - 1)) · c]`.
fn batch_over_relations<F: FieldLike + Copy>(rels: &impl RelationSet<F>, acc: &Accumulators<F>, alphas: &[F], beta: &F, partial_eval: &F, row_disabling: Option<(F, F)>, d: usize) -> Vec<F> {
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
                let mut term = acc[ri][j][k] * alpha;
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
fn pow_tail<F: FieldLike + Copy>(betas: &[F], round: usize, e: usize) -> F {
    let mut f = F::one();
    let mut bits = e;
    let mut j = 0;
    while bits != 0 {
        if bits & 1 == 1 {
            f *= betas[round + 1 + j];
        }
        bits >>= 1;
        j += 1;
    }
    f
}

/// Per-round prover state for one relation set (bb `SumcheckProverRound` +
/// `PartiallyEvaluatedMultivariates`): the table being folded and the row-disabling bookkeeping.
/// Rounds past `log_n` are virtual (zero-extension) rounds.
pub struct RoundProver<F> {
    table: Vec<Vec<F>>,
    log_n: usize,
    row_disabling: bool,
    excluded_head: usize,
    rd0: F,
    rd1: F,
    round: usize,
}

impl<F: FieldLike + Copy> RoundProver<F> {
    pub fn new(polys: &[Polynomial<F>], row_disabling: bool, trace_offset: usize) -> Self {
        let n = polys[0].len();
        Self {
            table: polys.iter().map(|p| p.coeffs.clone()).collect(),
            log_n: n.trailing_zeros() as usize,
            row_disabling,
            excluded_head: if row_disabling { trace_offset } else { 0 },
            rd0: F::one(),
            rd1: F::one(),
            round: 0,
        }
    }
    pub fn log_n(&self) -> usize {
        self.log_n
    }
    /// Current value of column `i` (its evaluation once all real rounds are done).
    pub fn current(&self, i: usize) -> F {
        self.table[i][0]
    }
    pub fn evals(&self) -> Vec<F> {
        self.table.iter().map(|c| c[0]).collect()
    }

    /// The round univariate of the relations (bb `compute_univariate` + `compute_offset_area_contribution`,
    /// or `compute_virtual_contribution` for a virtual round), without any Libra term.
    pub fn univariate(&self, rels: &impl RelationSet<F>, params: &RelationParams<F>, betas: &[F], partial_eval: &F, alphas: &[F], d: usize) -> Vec<F> {
        let round = self.round;
        if round < self.log_n {
            let round_size = 1 << (self.log_n - round);
            let mut acc = new_accumulators(rels, d);
            for e in self.excluded_head / 2..round_size / 2 {
                accumulate_edge(rels, &self.table, e, params, &pow_tail(betas, round, e), &mut acc, d);
            }
            let mut univariate = batch_over_relations(rels, &acc, alphas, &betas[round], partial_eval, None, d);
            if self.row_disabling {
                let mut head = new_accumulators(rels, d);
                for e in 0..self.excluded_head / 2 {
                    accumulate_edge(rels, &self.table, e, params, &pow_tail(betas, round, e), &mut head, d);
                }
                let head_uni = batch_over_relations(rels, &head, alphas, &betas[round], partial_eval, Some((self.rd0, self.rd1)), d);
                for (k, v) in head_uni.into_iter().enumerate() {
                    univariate[k] += v;
                }
            }
            univariate
        } else {
            // virtual round: the table has one row and the edge is (P(u), 0)
            let mut acc = new_accumulators(rels, d);
            let edge_table: Vec<Vec<F>> = self.table.iter().map(|c| vec![c[0], F::zero()]).collect();
            accumulate_edge(rels, &edge_table, 0, params, &F::one(), &mut acc, d);
            let rd = if self.row_disabling { Some((self.rd0, self.rd1)) } else { None };
            batch_over_relations(rels, &acc, alphas, &betas[round], partial_eval, rd, d)
        }
    }

    /// bb `partially_evaluate` / `fold_for_zero_extension` plus the row-disabling updates.
    pub fn partially_evaluate(&mut self, u: &F) {
        let round = self.round;
        if round < self.log_n {
            for col in self.table.iter_mut() {
                let half = col.len() / 2;
                for k in 0..half {
                    col[k] = col[2 * k] + *u * (col[2 * k + 1] - col[2 * k]);
                }
                col.truncate(half);
            }
        } else {
            for col in self.table.iter_mut() {
                col[0] *= F::one() - *u;
            }
        }
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

impl<C: Curve<TF = Fr>> CommittedRounds<C>
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
    pub fn process(&mut self, round: usize, univariate: &[C::Fr], ck: &Ck<C::G>, t: &mut NativeTranscript) {
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

impl<C: Curve<TF = Fr>> Default for CommittedRounds<C>
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
pub fn prove_sumcheck<C: Curve<TF = Fr>>(
    rels: &impl RelationSet<C::Fr>,
    spec: &SumcheckSpec,
    polys: &[Polynomial<C::Fr>],
    t: &mut NativeTranscript,
    alpha: &C::Fr,
    betas: &[C::Fr],
    params: &RelationParams<C::Fr>,
    mut zk: Option<&mut ZkData<C>>,
    ck: Option<&Ck<C::G>>,
) -> SumcheckProverOutput<C>
where
    C::Fr: Copy,
    C::G: AffineRepr<ScalarField = C::Fr>,
{
    type F<C> = <C as Curve>::Fr;
    let d = spec.batched_len;
    let alphas = alpha_powers(alpha, rels.total_subrelations() - 1);
    let mut state = RoundProver::new(polys, spec.row_disabling, spec.trace_offset);
    let mut committed = CommittedRounds::<C>::new();
    let mut challenge = Vec::with_capacity(spec.virtual_log_n);
    let mut partial_eval = F::<C>::one();
    let mut last_univariate = Vec::new();
    for round in 0..spec.virtual_log_n {
        let mut univariate = state.univariate(rels, params, betas, &partial_eval, &alphas, d);
        if let Some(zk) = zk.as_deref_mut() {
            for (k, v) in zk.round_univariate(round, d).into_iter().enumerate() {
                univariate[k] += v;
            }
        }
        if spec.committed {
            committed.process(round, &univariate, ck.expect("committed sumcheck needs a commitment key"), t);
        } else {
            t.send_vec(&format!("Sumcheck:univariate_{round}"), &univariate);
        }
        let u: F<C> = t.challenge(&format!("Sumcheck:u_{round}"));
        state.partially_evaluate(&u);
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
