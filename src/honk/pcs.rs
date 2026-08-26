//! Polynomial commitment verification: Shplemini (Gemini + Shplonk batched into one MSM),
//! SmallSubgroupIPA consistency for ZK, and the final KZG reduction to pairing points.
//! Sources: `commitment_schemes/shplonk/shplemini.hpp`, `gemini/gemini.hpp`, `shplonk/shplonk.hpp`,
//! `claim_batcher.hpp`, `small_subgroup_ipa/*`, `kzg/kzg.hpp`.

use crate::base::field::FieldLike;
use crate::base::group::{Curve, GroupLike, PairingPoints};
use crate::base::transcript::Transcript;

pub const NUM_SMALL_IPA_COMMITMENTS: usize = 3;
pub const NUM_SMALL_IPA_OPENING_CLAIMS: usize = 5;
/// (commitment index, evaluation point kind, transmitted, label suffix) for the 5 small-IPA claims.
const SMALL_IPA_CLAIMS: [(usize, EvalPoint, bool, &str); NUM_SMALL_IPA_OPENING_CLAIMS] = [
    (0, EvalPoint::Challenge, true, "concatenation_eval"),
    (1, EvalPoint::ChallengeShifted, true, "shifted_grand_sum_eval"),
    (1, EvalPoint::Challenge, true, "grand_sum_eval"),
    (1, EvalPoint::One, false, "grand_sum_at_one_eval"),
    (2, EvalPoint::Challenge, true, "quotient_eval"),
];
#[derive(Clone, Copy)]
enum EvalPoint {
    Challenge,
    ChallengeShifted,
    One,
}

/// Commitments to be opened at the sumcheck challenge with their claimed evaluations.
pub struct ClaimBatcher<C: Curve> {
    pub unshifted_comms: Vec<C::G>,
    pub unshifted_evals: Vec<C::Fr>,
    /// Commitments of the to-be-shifted polynomials, and claimed evaluations of their shifts.
    pub shifted_comms: Vec<C::G>,
    pub shifted_evals: Vec<C::Fr>,
}

/// `(commitments, scalars, z)` such that the KZG check is on `sum scalars_i * commitments_i` at `z`.
pub struct BatchOpeningClaim<C: Curve> {
    pub commitments: Vec<C::G>,
    pub scalars: Vec<C::Fr>,
    pub evaluation_point: C::Fr,
}

pub struct ShpleminiOutput<C: Curve> {
    pub claim: BatchOpeningClaim<C>,
    /// ZK only: the Libra evaluation consistency check.
    pub consistency_checked: bool,
}

fn powers<F: FieldLike>(base: &F, n: usize) -> Vec<F> {
    let mut out = Vec::with_capacity(n);
    if n > 0 {
        out.push(F::one());
        for i in 1..n {
            let next = out[i - 1].clone() * base;
            out.push(next);
        }
    }
    out
}

/// bb `ShpleminiVerifier_::compute_batch_opening_claim` (non-committed-sumcheck variant).
pub fn shplemini_verify<C: Curve>(
    has_zk: bool,
    has_gemini_masking: bool,
    batcher: &ClaimBatcher<C>,
    multivariate_challenge: &[C::Fr],
    g1_identity: &C::G,
    t: &mut Transcript<C::TF, C::Hash>,
    // (original, duplicate) index pairs into `[unshifted..., shifted...]` sharing one commitment.
    repeated: &[(usize, usize)],
    libra_commitments: &[C::G],
    libra_univariate_evaluation: &C::Fr,
) -> ShpleminiOutput<C> {
    type F<C> = <C as Curve>::Fr;
    let virtual_log_n = multivariate_challenge.len();
    assert!(virtual_log_n > 0);

    let rho: F<C> = t.challenge("rho");
    let fold_commitments: Vec<C::G> = (1..virtual_log_n).map(|i| t.receive(&format!("Gemini:FOLD_{i}"))).collect();
    let gemini_r: F<C> = t.challenge("Gemini:r");
    let gemini_neg_evals: Vec<F<C>> = (1..=virtual_log_n).map(|i| t.receive(&format!("Gemini:a_{i}"))).collect();
    // r, r^2, r^4, ...
    let mut r_powers = Vec::with_capacity(virtual_log_n);
    r_powers.push(gemini_r.clone());
    for j in 1..virtual_log_n {
        let sq = r_powers[j - 1].sqr();
        r_powers.push(sq);
    }

    let mut libra_evaluations = [F::<C>::zero(), F::<C>::zero(), F::<C>::zero(), F::<C>::zero(), F::<C>::zero()];
    if has_zk {
        for (i, (_, _, transmitted, suffix)) in SMALL_IPA_CLAIMS.iter().enumerate() {
            if *transmitted {
                libra_evaluations[i] = t.receive(&format!("Libra:{suffix}"));
            }
        }
    }

    let nu: F<C> = t.challenge("Shplonk:nu");
    let num_nu_powers = 2 * virtual_log_n + if has_zk { NUM_SMALL_IPA_OPENING_CLAIMS } else { 0 };
    let nu_powers = powers(&nu, num_nu_powers);
    let q_commitment: C::G = t.receive("Shplonk:Q");
    let z: F<C> = t.challenge("Shplonk:z");

    let mut commitments = vec![q_commitment];
    let mut scalars = vec![F::<C>::one()];
    let mut constant_term_accumulator = F::<C>::zero();

    // 1/(z - r^{2^j}), 1/(z + r^{2^j})
    let mut inverse_vanishing_evals = Vec::with_capacity(2 * virtual_log_n);
    for rp in &r_powers {
        inverse_vanishing_evals.push((z.clone() - rp).invert());
        inverse_vanishing_evals.push((z.clone() + rp).invert());
    }

    // ClaimBatcher::compute_scalars_for_each_batch
    let unshifted_scalar = inverse_vanishing_evals[0].clone() + &(nu.clone() * &inverse_vanishing_evals[1]);
    let shifted_scalar = gemini_r.invert() * &(inverse_vanishing_evals[0].clone() - &(nu.clone() * &inverse_vanishing_evals[1]));

    // ClaimBatcher::update_batch_mul_inputs_and_batched_evaluation
    let mut batched_evaluation = F::<C>::zero();
    let num_powers = batcher.unshifted_comms.len() + batcher.shifted_comms.len();
    let mut rho_power = F::<C>::one();
    let mut power_idx = 0;
    let mut aggregate = |comms: &[C::G], evals: &[F<C>], batch_scalar: &F<C>, commitments: &mut Vec<C::G>, scalars: &mut Vec<F<C>>| {
        for (c, e) in comms.iter().zip(evals) {
            commitments.push(c.clone());
            scalars.push(-batch_scalar.clone() * &rho_power);
            batched_evaluation += &(e.clone() * &rho_power);
            power_idx += 1;
            if power_idx < num_powers {
                rho_power *= &rho;
            }
        }
    };
    aggregate(&batcher.unshifted_comms, &batcher.unshifted_evals, &unshifted_scalar, &mut commitments, &mut scalars);
    aggregate(&batcher.shifted_comms, &batcher.shifted_evals, &shifted_scalar, &mut commitments, &mut scalars);

    // GeminiVerifier::compute_fold_pos_evaluations
    let mut fold_pos_evals = Vec::with_capacity(virtual_log_n);
    let mut eval_pos_prev = batched_evaluation;
    for l in (1..=virtual_log_n).rev() {
        let rp = &r_powers[l - 1];
        let u = &multivariate_challenge[l - 1];
        let eval_neg = &gemini_neg_evals[l - 1];
        let one_minus_u = F::<C>::one() - u;
        let mut eval_pos = (rp.clone() * &eval_pos_prev * &F::<C>::from_u64(2)) - &(eval_neg.clone() * &(rp.clone() * &one_minus_u - u));
        eval_pos *= &(rp.clone() * &one_minus_u + u).invert();
        eval_pos_prev = eval_pos.clone();
        fold_pos_evals.push(eval_pos);
    }
    fold_pos_evals.reverse();

    // batch_gemini_claims_received_from_prover
    for j in 1..virtual_log_n {
        let pos = 2 * j;
        let neg = 2 * j + 1;
        let scaling_factor_pos = nu_powers[pos].clone() * &inverse_vanishing_evals[pos];
        let scaling_factor_neg = nu_powers[neg].clone() * &inverse_vanishing_evals[neg];
        constant_term_accumulator += &(scaling_factor_neg.clone() * &gemini_neg_evals[j] + &(scaling_factor_pos.clone() * &fold_pos_evals[j]));
        scalars.push(-(scaling_factor_neg + &scaling_factor_pos));
        commitments.push(fold_commitments[j - 1].clone());
    }
    constant_term_accumulator += &(fold_pos_evals[0].clone() * &inverse_vanishing_evals[0]);
    constant_term_accumulator += &(gemini_neg_evals[0].clone() * &nu * &inverse_vanishing_evals[1]);

    // remove_repeated_commitments: fold each duplicate's scalar into its original, then drop the
    // duplicates (highest index first). Indices are into [unshifted..., shifted...]; +1 for Shplonk:Q.
    let mut to_erase: Vec<usize> = Vec::new();
    for (original, duplicate) in repeated {
        let (o, d) = (original + 1, duplicate + 1);
        let dup = scalars[d].clone();
        scalars[o] += &dup;
        to_erase.push(d);
    }
    to_erase.sort_unstable();
    for d in to_erase.into_iter().rev() {
        scalars.remove(d);
        commitments.remove(d);
    }
    let _ = has_gemini_masking; // the masking commitment is part of `unshifted`; nothing extra to do

    let mut consistency_checked = true;
    if has_zk {
        // batch_small_ipa_opening_claims
        for c in libra_commitments {
            commitments.push(c.clone());
        }
        let g = F::<C>::constant(C::subgroup_generator());
        let inv_z_minus_r = (z.clone() - &gemini_r).invert();
        let inv_z_minus_gr = (z.clone() - &(g.clone() * &gemini_r)).invert();
        let inv_z_minus_one = (z.clone() - &F::<C>::one()).invert();
        let mut grouped = [F::<C>::zero(), F::<C>::zero(), F::<C>::zero()];
        for (idx, (comm_idx, point, _, _)) in SMALL_IPA_CLAIMS.iter().enumerate() {
            let denom = match point {
                EvalPoint::Challenge => &inv_z_minus_r,
                EvalPoint::ChallengeShifted => &inv_z_minus_gr,
                EvalPoint::One => &inv_z_minus_one,
            };
            let scaling_factor = denom.clone() * &nu_powers[2 * virtual_log_n + idx];
            grouped[*comm_idx] -= &scaling_factor;
            constant_term_accumulator += &(scaling_factor * &libra_evaluations[idx]);
        }
        scalars.extend(grouped);

        consistency_checked = check_libra_evaluations_consistency::<C>(&libra_evaluations, &gemini_r, multivariate_challenge, libra_univariate_evaluation);
    }

    commitments.push(g1_identity.clone());
    scalars.push(constant_term_accumulator);
    ShpleminiOutput { claim: BatchOpeningClaim { commitments, scalars, evaluation_point: z }, consistency_checked }
}

/// bb `SmallSubgroupIPAVerifier::check_libra_evaluations_consistency`.
pub fn check_libra_evaluations_consistency<C: Curve>(
    evals: &[C::Fr; NUM_SMALL_IPA_OPENING_CLAIMS],
    r: &C::Fr,
    multivariate_challenge: &[C::Fr],
    inner_product_claim: &C::Fr,
) -> bool {
    type F<C> = <C as Curve>::Fr;
    let n = C::SUBGROUP_SIZE;
    let vanishing_poly_eval = r.pow_u64(n as u64) - &F::<C>::one();
    assert!(!vanishing_poly_eval.is_zero(), "SmallSubgroupIPA: evaluation challenge is in the small subgroup");

    // challenge polynomial in the Lagrange basis over H: (1, u_0, u_0^2, ..., 1, u_{d-1}, ...)
    let libra_len = C::LIBRA_UNIVARIATES_LENGTH;
    assert!(libra_len * multivariate_challenge.len() + 1 < n);
    let mut coeffs = vec![F::<C>::zero(); n];
    coeffs[0] = F::<C>::one();
    for (round, u) in multivariate_challenge.iter().enumerate() {
        let start = 1 + libra_len * round;
        coeffs[start] = F::<C>::one();
        for idx in start + 1..start + libra_len {
            coeffs[idx] = coeffs[idx - 1].clone() * u;
        }
    }

    // compute_batched_barycentric_evaluations: F(r), L_1(r), L_{|H|}(r)
    let g_inv = F::<C>::constant(C::subgroup_generator_inverse());
    let mut denominators = Vec::with_capacity(n);
    let mut running_power = F::<C>::one();
    for _ in 0..n {
        denominators.push((running_power.clone() * r - &F::<C>::one()).invert());
        running_power *= &g_inv;
    }
    let numerator = vanishing_poly_eval.clone() * &F::<C>::from_u64(n as u64).invert();
    let mut challenge_poly = F::<C>::zero();
    for (c, d) in coeffs.iter().zip(&denominators) {
        challenge_poly += &(c.clone() * d);
    }
    let challenge_poly = challenge_poly * &numerator;
    let lagrange_first = denominators[0].clone() * &numerator;
    let lagrange_last = denominators[n - 1].clone() * &numerator;

    let concatenated_at_r = &evals[0];
    let grand_sum_shifted_eval = &evals[1];
    let grand_sum_eval = &evals[2];
    let quotient_eval = &evals[4];
    let mut diff = lagrange_first * grand_sum_eval;
    diff += &((r.clone() - &g_inv) * &(grand_sum_shifted_eval.clone() - grand_sum_eval - &(concatenated_at_r.clone() * &challenge_poly)));
    diff += &(lagrange_last * &(grand_sum_eval.clone() - inner_product_claim) - &(vanishing_poly_eval * quotient_eval));
    let ok = diff.is_zero();
    diff.assert_equal(&F::<C>::zero());
    ok
}

/// bb `KZG::reduce_verify_batch_opening_claim`: `P0 = C + z*[W]`, `P1 = -[W]`.
pub fn kzg_reduce_verify_batch_opening_claim<C: Curve>(
    mut claim: BatchOpeningClaim<C>,
    t: &mut Transcript<C::TF, C::Hash>,
    expected_final_msm_size: usize,
) -> PairingPoints<C> {
    let w: C::G = t.receive("KZG:W");
    claim.commitments.push(w.clone());
    claim.scalars.push(claim.evaluation_point.clone());
    assert_eq!(claim.commitments.len(), expected_final_msm_size, "unexpected final MSM size");
    let p0 = C::G::batch_mul(&claim.commitments, &claim.scalars);
    PairingPoints { p0, p1: w.neg() }
}
