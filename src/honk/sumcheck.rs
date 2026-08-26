//! Sumcheck verifier (bb `sumcheck/sumcheck.hpp`, `sumcheck_round.hpp`, `polynomials/gate_separator.hpp`,
//! `polynomials/row_disabling_polynomial.hpp`, `polynomials/univariate.hpp::evaluate`).

use super::flavor::{FlavorDesc, Layout};
use super::relations::{RelationParams, Row};
use crate::base::field::FieldLike;
use crate::base::group::Curve;
use crate::base::transcript::Transcript;

pub use crate::base::poly::evaluate_univariate;

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

/// Evaluate the full (alpha-batched) Honk relation at a claimed row of evaluations.
/// `scaling` is `pow_beta(u)`; `(main, offset)` are the row-disabling factors `(1-L(u), L(u))` for
/// ZK flavors and `(1, 0)` otherwise (bb `compute_full_relation_purported_value` + `scale_and_batch_elements`).
pub fn full_relation_value<F: FieldLike>(
    flavor: &FlavorDesc,
    layout: &Layout,
    evals: &[F],
    params: &RelationParams<F>,
    scaling: &F,
    alphas: &[F],
    main_factor: &F,
    offset_factor: &F,
) -> F {
    let row = Row { vals: evals, layout };
    let mut result = F::zero();
    let mut alpha_idx = 0;
    for (ri, rel) in flavor.relations.iter().enumerate() {
        let spec = rel.spec();
        let mut acc = vec![F::zero(); spec.partial_lengths.len()];
        rel.accumulate(&mut acc, &row, params, scaling);
        let factor = if spec.offset_only { offset_factor } else { main_factor };
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

pub struct SumcheckOutput<F> {
    pub challenge: Vec<F>,
    /// Claimed evaluations of all entities (unshifted then shifted) at `challenge`.
    pub evals: Vec<F>,
    pub verified: bool,
    /// ZK only: claimed evaluation of the Libra masking multivariate.
    pub libra_evaluation: F,
}

/// Verify the sumcheck proof (non-committed variant). Reads round univariates and evaluations from
/// the transcript, checks each round's sum, and checks the final relation evaluation.
pub fn verify_sumcheck<C: Curve>(
    flavor: &FlavorDesc,
    layout: &Layout,
    t: &mut Transcript<C::TF, C::Hash>,
    alpha: &C::Fr,
    params: &RelationParams<C::Fr>,
    gate_challenges: &[C::Fr],
) -> SumcheckOutput<C::Fr> {
    type F<C> = <C as Curve>::Fr;
    let virtual_log_n = flavor.virtual_log_n;
    let alphas = alpha_powers(alpha, layout.num_subrelations - 1);

    let mut target_sum = F::<C>::zero();
    let mut libra_challenge = F::<C>::zero();
    if flavor.has_zk {
        let libra_total_sum: F<C> = t.receive("Libra:Sum");
        libra_challenge = t.challenge("Libra:Challenge");
        target_sum = libra_total_sum * &libra_challenge;
    }

    let mut verified = true;
    let mut challenge = Vec::with_capacity(virtual_log_n);
    let mut partial_evaluation_result = F::<C>::one();
    for round in 0..virtual_log_n {
        let univariate: Vec<F<C>> = t.receive_vec(&format!("Sumcheck:univariate_{round}"), layout.batched_len);
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

    let evals: Vec<F<C>> = t.receive_vec("Sumcheck:evaluations", layout.num_all());

    let (main_factor, offset_factor) = if flavor.has_zk {
        let m = row_disabling_main_factor(&challenge);
        let o = F::<C>::one() - &m;
        (m, o)
    } else {
        (F::<C>::one(), F::<C>::zero())
    };
    let mut full_value = full_relation_value(flavor, layout, &evals, params, &partial_evaluation_result, &alphas, &main_factor, &offset_factor);

    let mut libra_evaluation = F::<C>::zero();
    if flavor.has_zk {
        libra_evaluation = t.receive("Libra:claimed_evaluation");
        full_value += &(libra_evaluation.clone() * &libra_challenge);
    }

    if full_value.value() != target_sum.value() {
        verified = false;
    }
    full_value.assert_equal(&target_sum);

    SumcheckOutput { challenge, evals, verified, libra_evaluation }
}

// ---------------------------------------------------------------------------------------------
// Prover (bb `SumcheckProver` / `SumcheckProverRound`), written pointwise: each entity's edge
// `(P[2e], P[2e+1])` is extended linearly to `k = 0..D-1` and the relations are evaluated on the
// resulting rows with the same `Rel::accumulate` the verifier uses.
// ---------------------------------------------------------------------------------------------

use crate::base::poly::{extend_univariate, Poly};
use crate::base::rng::Rng;
use crate::base::transcript::NativeTranscript;
use crate::base::{Bn254, CommitmentKey, Fr};

/// Libra masking data for ZK sumcheck (bb `ZKSumcheckData`).
pub struct ZkData {
    pub constant_term: Fr,
    /// One random univariate (monomial coefficients) per round, scaled as bb does.
    pub libra_univariates: Vec<Poly>,
    pub libra_concatenated_lagrange: Vec<Fr>,
    pub libra_concatenated_monomial: Poly,
    pub interpolation_domain: Vec<Fr>,
    pub libra_scaling_factor: Fr,
    pub libra_challenge: Fr,
    pub libra_running_sum: Fr,
    pub libra_evaluations: Vec<Fr>,
    pub num_rounds: usize,
}

/// Monomial coefficients of the polynomial with the given values on the subgroup `{g^i}`.
pub fn interpolate_on_subgroup(evals: &[Fr], g: &Fr) -> Poly {
    let n = evals.len();
    let g_inv = g.invert();
    let n_inv = Fr::from(n as u64).invert();
    let mut coeffs = Vec::with_capacity(n);
    for j in 0..n {
        let w = g_inv.pow_u64(j as u64);
        let mut acc = Fr::zero();
        let mut wi = Fr::one();
        for e in evals {
            acc += *e * wi;
            wi *= w;
        }
        coeffs.push(acc * n_inv);
    }
    Poly::from_coeffs(coeffs)
}

impl ZkData {
    pub fn new(num_rounds: usize, t: &mut NativeTranscript, ck: &CommitmentKey, rng: &mut dyn Rng) -> Self {
        use crate::base::group::Curve;
        let subgroup_size = Bn254::SUBGROUP_SIZE;
        let libra_len = Bn254::LIBRA_UNIVARIATES_LENGTH;
        let constant_term = rng.fr();
        let libra_univariates: Vec<Poly> = (0..num_rounds).map(|_| Poly::from_coeffs((0..libra_len).map(|_| rng.fr()).collect())).collect();
        let g = Bn254::subgroup_generator();
        let mut interpolation_domain = vec![Fr::one(); subgroup_size];
        for i in 1..subgroup_size {
            interpolation_domain[i] = interpolation_domain[i - 1] * g;
        }
        // concatenated Libra polynomial in the Lagrange basis over H, then monomial + masking
        assert!(num_rounds * libra_len + 1 < subgroup_size);
        let mut lagrange = vec![Fr::zero(); subgroup_size];
        lagrange[0] = constant_term;
        for (r, u) in libra_univariates.iter().enumerate() {
            for (i, c) in u.coeffs.iter().enumerate() {
                lagrange[1 + r * libra_len + i] = *c;
            }
        }
        let mut monomial = interpolate_on_subgroup(&lagrange, &g);
        monomial.coeffs.resize(subgroup_size + 2, Fr::zero());
        let masking = [rng.fr(), rng.fr()];
        for (i, m) in masking.iter().enumerate() {
            monomial.coeffs[i] -= m;
            monomial.coeffs[subgroup_size + i] += m;
        }
        t.send("Libra:concatenation_commitment", &ck.commit(&monomial));

        // total sum over the hypercube: 2^{d-1} sum_i (g_i(0) + g_i(1)) + 2^d * constant
        let mut total_sum = Fr::zero();
        let mut scaling_factor = Fr::from(2u64).invert();
        for u in &libra_univariates {
            total_sum += u.coeffs[0] + u.evaluate(&Fr::one());
            scaling_factor *= Fr::from(2u64);
        }
        total_sum *= scaling_factor;
        total_sum += constant_term * Fr::from(1u64 << num_rounds);
        t.send("Libra:Sum", &total_sum);
        let libra_challenge: Fr = t.challenge("Libra:Challenge");
        let mut running_sum = total_sum * libra_challenge;

        // setup_auxiliary_data
        scaling_factor *= libra_challenge;
        let mut libra_univariates = libra_univariates;
        for u in libra_univariates.iter_mut() {
            for c in u.coeffs.iter_mut() {
                *c *= scaling_factor;
            }
        }
        running_sum += -libra_univariates[0].coeffs[0] - libra_univariates[0].evaluate(&Fr::one());
        running_sum *= Fr::from(2u64).invert();

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

    /// Values of the Libra round univariate at `k = 0..len-1`.
    pub fn round_univariate(&self, round: usize, len: usize) -> Vec<Fr> {
        (0..len).map(|k| self.libra_univariates[round].evaluate(&Fr::from(k as u64)) + self.libra_running_sum).collect()
    }

    /// bb `update_zk_sumcheck_data`.
    pub fn update(&mut self, u: &Fr, round: usize) {
        let half = Fr::from(2u64).invert();
        if round < self.num_rounds - 1 {
            for p in self.libra_univariates.iter_mut() {
                for c in p.coeffs.iter_mut() {
                    *c *= half;
                }
            }
            let eval = self.libra_univariates[round].evaluate(u);
            let next = &self.libra_univariates[round + 1];
            self.libra_running_sum += -next.coeffs[0] - next.evaluate(&Fr::one());
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
    pub fn claimed_evaluation(&self) -> Fr {
        self.libra_evaluations.iter().fold(self.constant_term, |a, e| a + e)
    }
}

/// Linear univariate given by its values at 0 and 1, evaluated at `k`.
fn linear_at(v0: &Fr, v1: &Fr, k: usize) -> Fr {
    *v0 + Fr::from(k as u64) * (*v1 - *v0)
}

/// Accumulators `acc[relation][subrelation][k]` for `k = 0..D-1`.
type Accumulators = Vec<Vec<Vec<Fr>>>;

fn new_accumulators(flavor: &FlavorDesc, d: usize) -> Accumulators {
    flavor.relations.iter().map(|r| vec![vec![Fr::zero(); d]; r.num_subrelations()]).collect()
}

/// Add the contributions of the edge `(table[·][2e], table[·][2e+1])` at every `k`.
fn accumulate_edge(flavor: &FlavorDesc, layout: &Layout, table: &[Vec<Fr>], e: usize, params: &RelationParams<Fr>, scaling: &Fr, acc: &mut Accumulators) {
    let d = acc[0].first().map_or(0, |v| v.len()).max(acc.iter().flat_map(|a| a.iter().map(|v| v.len())).max().unwrap_or(0));
    let mut row = vec![Fr::zero(); table.len()];
    for k in 0..d {
        for (j, col) in table.iter().enumerate() {
            let a = col.get(2 * e).copied().unwrap_or(Fr::zero());
            let b = col.get(2 * e + 1).copied().unwrap_or(Fr::zero());
            row[j] = linear_at(&a, &b, k);
        }
        let r = Row { vals: &row, layout };
        for (ri, rel) in flavor.relations.iter().enumerate() {
            let mut sub = vec![Fr::zero(); rel.num_subrelations()];
            rel.accumulate(&mut sub, &r, params, scaling);
            for (j, v) in sub.into_iter().enumerate() {
                acc[ri][j][k] += v;
            }
        }
    }
}

/// bb `batch_over_relations`: `S(k) = sum_r Λ_r(k) sum_j α_{r,j} acc_{r,j}(k) [lin. indep.: · (1 + k(β - 1)) · c]`.
fn batch_over_relations(flavor: &FlavorDesc, acc: &Accumulators, alphas: &[Fr], beta: &Fr, partial_eval: &Fr, row_disabling: Option<(Fr, Fr)>, d: usize) -> Vec<Fr> {
    let mut result = vec![Fr::zero(); d];
    for k in 0..d {
        let pow_factor = linear_at(&Fr::one(), beta, k) * partial_eval;
        let (main, offset) = match row_disabling {
            Some((l0, l1)) => {
                let l = linear_at(&l0, &l1, k);
                (Fr::one() - l, l)
            }
            None => (Fr::one(), Fr::zero()),
        };
        let mut alpha_idx = 0;
        for (ri, rel) in flavor.relations.iter().enumerate() {
            let spec = rel.spec();
            let mut per_relation = Fr::zero();
            for j in 0..spec.partial_lengths.len() {
                let alpha = if ri == 0 && j == 0 { Fr::one() } else { alphas[alpha_idx] };
                if !(ri == 0 && j == 0) {
                    alpha_idx += 1;
                }
                let mut term = acc[ri][j][k] * alpha;
                if spec.lin_indep[j] {
                    term *= pow_factor;
                }
                per_relation += term;
            }
            result[k] += per_relation * if spec.offset_only { offset } else { main };
        }
    }
    result
}

/// `pow_beta` factor of edge pair `e` in `round`: product of `betas[round+1+j]` over the set bits `j` of `e`.
fn pow_tail(betas: &[Fr], round: usize, e: usize) -> Fr {
    let mut f = Fr::one();
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

pub struct SumcheckProverOutput {
    pub challenge: Vec<Fr>,
    pub evals: Vec<Fr>,
    pub libra_evaluation: Fr,
}

/// bb `SumcheckProver::prove` (both the plain and the ZK variant, selected by `zk`).
pub fn prove_sumcheck(
    flavor: &FlavorDesc,
    layout: &Layout,
    polys: &[Poly],
    t: &mut NativeTranscript,
    alpha: &Fr,
    betas: &[Fr],
    params: &RelationParams<Fr>,
    mut zk: Option<&mut ZkData>,
) -> SumcheckProverOutput {
    let n = polys[0].len();
    let log_n = n.trailing_zeros() as usize;
    let virtual_log_n = flavor.virtual_log_n;
    let d = layout.batched_len;
    let alphas = alpha_powers(alpha, layout.num_subrelations - 1);
    let has_zk = zk.is_some();

    let mut table: Vec<Vec<Fr>> = polys.iter().map(|p| p.coeffs.clone()).collect();
    let mut challenge = Vec::with_capacity(virtual_log_n);
    let mut partial_eval = Fr::one();
    // RowDisablingPolynomial: values of L^{(i)} at 0 and 1
    let (mut rd0, mut rd1) = (Fr::one(), Fr::one());
    let mut excluded_head = if has_zk { flavor.trace_offset } else { 0 };

    for round in 0..log_n {
        let round_size = n >> round;
        let mut acc = new_accumulators(flavor, d);
        for e in excluded_head / 2..round_size / 2 {
            accumulate_edge(flavor, layout, &table, e, params, &pow_tail(betas, round, e), &mut acc);
        }
        let mut univariate = batch_over_relations(flavor, &acc, &alphas, &betas[round], &partial_eval, None, d);
        if let Some(zk) = zk.as_deref_mut() {
            for (k, v) in zk.round_univariate(round, d).into_iter().enumerate() {
                univariate[k] += v;
            }
            // head rows, scaled by the row-disabling factors
            let mut head = new_accumulators(flavor, d);
            for e in 0..excluded_head / 2 {
                accumulate_edge(flavor, layout, &table, e, params, &pow_tail(betas, round, e), &mut head);
            }
            let head_uni = batch_over_relations(flavor, &head, &alphas, &betas[round], &partial_eval, Some((rd0, rd1)), d);
            for (k, v) in head_uni.into_iter().enumerate() {
                univariate[k] += v;
            }
        }
        t.send_vec(&format!("Sumcheck:univariate_{round}"), &univariate);
        let u: Fr = t.challenge(&format!("Sumcheck:u_{round}"));
        // partially evaluate
        for col in table.iter_mut() {
            let half = col.len() / 2;
            for k in 0..half {
                col[k] = col[2 * k] + u * (col[2 * k + 1] - col[2 * k]);
            }
            col.truncate(half);
        }
        if let Some(zk) = zk.as_deref_mut() {
            zk.update(&u, round);
        }
        if round == 1 {
            rd1 = Fr::zero();
        }
        if round >= 2 {
            rd0 *= Fr::one() - u;
        }
        partial_eval *= gate_separator_factor(&u, &betas[round]);
        challenge.push(u);
        if has_zk {
            excluded_head = 2;
        }
    }

    // virtual (zero-extension) rounds: the table has one row; the edge is (P(u), 0)
    for round in log_n..virtual_log_n {
        let mut acc = new_accumulators(flavor, d);
        let edge_table: Vec<Vec<Fr>> = table.iter().map(|c| vec![c[0], Fr::zero()]).collect();
        accumulate_edge(flavor, layout, &edge_table, 0, params, &Fr::one(), &mut acc);
        let rd = if has_zk { Some((rd0, rd1)) } else { None };
        let mut univariate = batch_over_relations(flavor, &acc, &alphas, &betas[round], &partial_eval, rd, d);
        if let Some(zk) = zk.as_deref_mut() {
            for (k, v) in zk.round_univariate(round, d).into_iter().enumerate() {
                univariate[k] += v;
            }
        }
        t.send_vec(&format!("Sumcheck:univariate_{round}"), &univariate);
        let u: Fr = t.challenge(&format!("Sumcheck:u_{round}"));
        for col in table.iter_mut() {
            col[0] *= Fr::one() - u;
        }
        if let Some(zk) = zk.as_deref_mut() {
            zk.update(&u, round);
        }
        if round == 1 {
            rd1 = Fr::zero();
        }
        if round >= 2 {
            rd0 *= Fr::one() - u;
        }
        partial_eval *= gate_separator_factor(&u, &betas[round]);
        challenge.push(u);
    }

    let evals: Vec<Fr> = table.iter().map(|c| c[0]).collect();
    t.send_vec("Sumcheck:evaluations", &evals);
    let mut libra_evaluation = Fr::zero();
    if let Some(zk) = zk {
        libra_evaluation = zk.claimed_evaluation();
        t.send("Libra:claimed_evaluation", &libra_evaluation);
    }
    let _ = extend_univariate; // (barycentric extension is not needed by the pointwise prover)
    SumcheckProverOutput { challenge, evals, libra_evaluation }
}
