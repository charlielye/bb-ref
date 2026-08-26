//! Sumcheck verifier (bb `sumcheck/sumcheck.hpp`, `sumcheck_round.hpp`, `polynomials/gate_separator.hpp`,
//! `polynomials/row_disabling_polynomial.hpp`, `polynomials/univariate.hpp::evaluate`).

use super::flavor::{FlavorDesc, Layout};
use super::relations::{RelationParams, Row};
use crate::base::field::FieldLike;
use crate::base::group::Curve;
use crate::base::transcript::Transcript;

/// Barycentric evaluation of a univariate given by its values on `{0, 1, ..., n-1}`.
pub fn evaluate_univariate<F: FieldLike>(vals: &[F], u: &F) -> F {
    let n = vals.len();
    let mut full_numerator = F::one();
    for i in 0..n {
        full_numerator *= &(u.clone() - &F::from_u64(i as u64));
    }
    let mut result = F::zero();
    for (i, v) in vals.iter().enumerate() {
        // d_i = prod_{j != i} (i - j)
        let mut denom = F::one();
        for j in 0..n {
            if j != i {
                denom *= &(F::from_u64(i as u64) - &F::from_u64(j as u64));
            }
        }
        denom *= &(u.clone() - &F::from_u64(i as u64));
        result += &(v.clone() * &denom.invert());
    }
    result * &full_numerator
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
