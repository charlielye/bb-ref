//! Polynomial commitment verification: Shplemini (Gemini + Shplonk batched into one MSM),
//! SmallSubgroupIPA consistency for ZK, and the final KZG reduction to pairing points.
//! Sources: `commitment_schemes/shplonk/shplemini.hpp`, `gemini/gemini.hpp`, `shplonk/shplonk.hpp`,
//! `claim_batcher.hpp`, `small_subgroup_ipa/*`, `kzg/kzg.hpp`.

use crate::base::field::{FieldLike, U256};
use crate::base::group::{Curve, GroupLike, PairingPoints};
use crate::base::poly::Polynomial;
use crate::base::rng::random_field;
use crate::base::srs::Ck;
use crate::base::transcript::Transcript;
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use rayon::prelude::*;

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

/// Which of the three witness commitments the `i`-th small-IPA claim opens.
pub fn small_ipa_commitment_index(i: usize) -> usize {
    SMALL_IPA_CLAIMS[i].0
}

/// The five small-IPA evaluation points for challenge `r`: `r`, `g r`, `r`, `1`, `r`.
fn small_ipa_points<C: Curve>(r: &C::Fr) -> [C::Fr; NUM_SMALL_IPA_OPENING_CLAIMS] {
    let g = C::Fr::constant(C::subgroup_generator());
    std::array::from_fn(|i| match SMALL_IPA_CLAIMS[i].1 {
        EvalPoint::Challenge => r.clone(),
        EvalPoint::ChallengeShifted => r.clone() * &g,
        EvalPoint::One => C::Fr::one(),
    })
}

/// bb `make_small_ipa_verifier_opening_claims`: receive the transmitted evaluations under
/// `<prefix><suffix>` and pair them with the witness commitments.
pub fn small_ipa_verifier_claims<C: Curve>(
    commitments: &[C::G; NUM_SMALL_IPA_COMMITMENTS],
    r: &C::Fr,
    prefix: &str,
    t: &mut Transcript<C::TF, C::Hash>,
) -> Vec<VerifierOpeningClaim<C>> {
    let points = small_ipa_points::<C>(r);
    SMALL_IPA_CLAIMS
        .iter()
        .enumerate()
        .map(|(i, (comm_idx, _, transmitted, suffix))| {
            let evaluation = if *transmitted {
                t.receive(&format!("{prefix}{suffix}"))
            } else {
                C::Fr::zero()
            };
            VerifierOpeningClaim {
                commitment: commitments[*comm_idx].clone(),
                challenge: points[i].clone(),
                evaluation,
            }
        })
        .collect()
}

/// bb `SmallSubgroupIPAVerifier::check_consistency`: the grand-sum identity at `r`, with the
/// challenge polynomial given by its Lagrange coefficients over the subgroup.
pub fn small_ipa_check_consistency<C: Curve>(
    evals: &[C::Fr],
    r: &C::Fr,
    challenge_coeffs: &[C::Fr],
    inner_product_claim: &C::Fr,
) -> bool {
    type F<C> = <C as Curve>::Fr;
    let n = C::SUBGROUP_SIZE;
    let vanishing_poly_eval = r.pow_u64(n as u64) - &F::<C>::one();
    assert!(
        !vanishing_poly_eval.is_zero(),
        "SmallSubgroupIPA: evaluation challenge is in the small subgroup"
    );
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
    for (c, d) in challenge_coeffs.iter().zip(&denominators) {
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
    diff += &((r.clone() - &g_inv)
        * &(grand_sum_shifted_eval.clone() - grand_sum_eval - &(concatenated_at_r.clone() * &challenge_poly)));
    diff += &(lagrange_last * &(grand_sum_eval.clone() - inner_product_claim) - &(vanishing_poly_eval * quotient_eval));
    let ok = diff.is_zero();
    diff.assert_equal(&F::<C>::zero());
    ok
}

/// bb `compute_challenge_polynomial_coeffs`: `(1, 1, u_0, ..., u_0^{L-1}, 1, u_1, ...)` over the subgroup.
pub fn libra_challenge_coeffs<C: Curve>(multivariate_challenge: &[C::Fr]) -> Vec<C::Fr> {
    let n = C::SUBGROUP_SIZE;
    let libra_len = C::LIBRA_UNIVARIATES_LENGTH;
    assert!(libra_len * multivariate_challenge.len() + 1 < n);
    let mut coeffs = vec![C::Fr::zero(); n];
    coeffs[0] = C::Fr::one();
    for (round, u) in multivariate_challenge.iter().enumerate() {
        let start = 1 + libra_len * round;
        coeffs[start] = C::Fr::one();
        for idx in start + 1..start + libra_len {
            coeffs[idx] = coeffs[idx - 1].clone() * u;
        }
    }
    coeffs
}

/// bb `compute_eccvm_challenge_coeffs`: `(v^i x^j)` for `i < num_polys`, `j < coeffs_per_poly`.
pub fn eccvm_challenge_coeffs<C: Curve>(x: &C::Fr, v: &C::Fr, num_polys: usize, coeffs_per_poly: usize) -> Vec<C::Fr> {
    let n = C::SUBGROUP_SIZE;
    assert!(num_polys * coeffs_per_poly < n);
    let mut coeffs = vec![C::Fr::zero(); n];
    let mut v_power = C::Fr::one();
    for poly_idx in 0..num_polys {
        let start = coeffs_per_poly * poly_idx;
        coeffs[start] = v_power.clone();
        for idx in start + 1..start + coeffs_per_poly {
            coeffs[idx] = coeffs[idx - 1].clone() * x;
        }
        v_power *= v;
    }
    coeffs
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
    // Committed sumcheck only: the round univariate commitments and their values at 0, 1, u_i.
    sumcheck_round_commitments: &[C::G],
    sumcheck_round_evaluations: &[[C::Fr; 3]],
) -> ShpleminiOutput<C> {
    type F<C> = <C as Curve>::Fr;
    let virtual_log_n = multivariate_challenge.len();
    assert!(virtual_log_n > 0);
    let committed_sumcheck = !sumcheck_round_evaluations.is_empty();
    assert!(
        !committed_sumcheck || has_zk,
        "committed sumcheck requires ZK for the nu power indexing"
    );

    crate::circuit::builder::trace_phase("shplemini: start");
    let rho: F<C> = t.challenge("rho");
    let fold_commitments: Vec<C::G> = (1..virtual_log_n)
        .map(|i| t.receive(&format!("Gemini:FOLD_{i}")))
        .collect();
    let gemini_r: F<C> = t.challenge("Gemini:r");
    let gemini_neg_evals: Vec<F<C>> = (1..=virtual_log_n)
        .map(|i| t.receive(&format!("Gemini:a_{i}")))
        .collect();
    // r, r^2, r^4, ...
    let mut r_powers = Vec::with_capacity(virtual_log_n);
    r_powers.push(gemini_r.clone());
    for j in 1..virtual_log_n {
        let sq = r_powers[j - 1].sqr();
        r_powers.push(sq);
    }

    let mut libra_evaluations = [
        F::<C>::zero(),
        F::<C>::zero(),
        F::<C>::zero(),
        F::<C>::zero(),
        F::<C>::zero(),
    ];
    if has_zk {
        for (i, (_, _, transmitted, suffix)) in SMALL_IPA_CLAIMS.iter().enumerate() {
            if *transmitted {
                libra_evaluations[i] = t.receive(&format!("Libra:{suffix}"));
            }
        }
    }

    let nu: F<C> = t.challenge("Shplonk:nu");
    let num_nu_powers = 2 * virtual_log_n
        + if has_zk { NUM_SMALL_IPA_OPENING_CLAIMS } else { 0 }
        + if committed_sumcheck { 3 * virtual_log_n } else { 0 };
    let nu_powers = powers(&nu, num_nu_powers);
    let q_commitment: C::G = t.receive("Shplonk:Q");
    let z: F<C> = t.challenge("Shplonk:z");

    crate::circuit::builder::trace_phase("shplemini: challenges received");
    let mut commitments = vec![q_commitment];
    let mut scalars = vec![F::<C>::one()];
    let mut constant_term_accumulator = F::<C>::zero();

    // 1/(z - r^{2^j}), 1/(z + r^{2^j}): every denominator first, then the inversions
    // (bb `compute_inverted_gemini_denominators`)
    let mut inverse_vanishing_evals = Vec::with_capacity(2 * virtual_log_n);
    for rp in &r_powers {
        inverse_vanishing_evals.push(z.clone() - rp);
        inverse_vanishing_evals.push(z.clone() + rp);
    }
    for d in inverse_vanishing_evals.iter_mut() {
        *d = d.invert();
    }

    // ClaimBatcher::compute_scalars_for_each_batch
    let unshifted_scalar = inverse_vanishing_evals[0].clone() + &(nu.clone() * &inverse_vanishing_evals[1]);
    let shifted_scalar =
        gemini_r.invert() * &(inverse_vanishing_evals[0].clone() - &(nu.clone() * &inverse_vanishing_evals[1]));

    // ClaimBatcher::update_batch_mul_inputs_and_batched_evaluation
    let mut batched_evaluation = F::<C>::zero();
    let num_powers = batcher.unshifted_comms.len() + batcher.shifted_comms.len();
    let mut rho_power = F::<C>::one();
    let mut power_idx = 0;
    let mut aggregate =
        |comms: &[C::G], evals: &[F<C>], batch_scalar: &F<C>, commitments: &mut Vec<C::G>, scalars: &mut Vec<F<C>>| {
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
    aggregate(
        &batcher.unshifted_comms,
        &batcher.unshifted_evals,
        &unshifted_scalar,
        &mut commitments,
        &mut scalars,
    );
    aggregate(
        &batcher.shifted_comms,
        &batcher.shifted_evals,
        &shifted_scalar,
        &mut commitments,
        &mut scalars,
    );

    crate::circuit::builder::trace_phase("shplemini: batched claims");
    // GeminiVerifier::compute_fold_pos_evaluations
    let mut fold_pos_evals = Vec::with_capacity(virtual_log_n);
    let mut eval_pos_prev = batched_evaluation;
    for l in (1..=virtual_log_n).rev() {
        let rp = &r_powers[l - 1];
        let u = &multivariate_challenge[l - 1];
        let eval_neg = &gemini_neg_evals[l - 1];
        let one_minus_u = F::<C>::one() - u;
        let mut eval_pos = (rp.clone() * &eval_pos_prev * &F::<C>::from_u64(2))
            - &(eval_neg.clone() * &(rp.clone() * &one_minus_u - u));
        eval_pos *= &(rp.clone() * &one_minus_u + u).invert();
        eval_pos_prev = eval_pos.clone();
        fold_pos_evals.push(eval_pos);
    }
    fold_pos_evals.reverse();

    crate::circuit::builder::trace_phase("shplemini: fold pos evals");
    // batch_gemini_claims_received_from_prover
    for j in 1..virtual_log_n {
        let pos = 2 * j;
        let neg = 2 * j + 1;
        let scaling_factor_pos = nu_powers[pos].clone() * &inverse_vanishing_evals[pos];
        let scaling_factor_neg = nu_powers[neg].clone() * &inverse_vanishing_evals[neg];
        constant_term_accumulator +=
            &(scaling_factor_neg.clone() * &gemini_neg_evals[j] + &(scaling_factor_pos.clone() * &fold_pos_evals[j]));
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
        let inv_z_minus_r = F::<C>::one().div(&(z.clone() - &gemini_r));
        let inv_z_minus_gr = F::<C>::one().div(&(z.clone() - &(g.clone() * &gemini_r)));
        let inv_z_minus_one = F::<C>::one().div(&(z.clone() - &F::<C>::one()));
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

        consistency_checked = check_libra_evaluations_consistency::<C>(
            &libra_evaluations,
            &gemini_r,
            multivariate_challenge,
            libra_univariate_evaluation,
        );
    }

    if committed_sumcheck {
        // batch_sumcheck_round_claims: each round univariate is opened at 0, 1 and u_i.
        let inv_z = F::<C>::one().div(&z);
        let inv_z_minus_one = F::<C>::one().div(&(z.clone() - &F::<C>::one()));
        let mut power = 2 * virtual_log_n + NUM_SMALL_IPA_OPENING_CLAIMS;
        for (i, (comm, evals)) in sumcheck_round_commitments
            .iter()
            .zip(sumcheck_round_evaluations)
            .enumerate()
        {
            commitments.push(comm.clone());
            let inv_z_minus_u = F::<C>::one().div(&(z.clone() - &multivariate_challenge[i]));
            let mut batched_scalar = F::<C>::zero();
            for (denominator, eval) in [
                (&inv_z, &evals[0]),
                (&inv_z_minus_one, &evals[1]),
                (&inv_z_minus_u, &evals[2]),
            ] {
                let scaling_factor = denominator.clone() * &nu_powers[power];
                power += 1;
                batched_scalar -= &scaling_factor;
                constant_term_accumulator += &(scaling_factor * eval);
            }
            scalars.push(batched_scalar);
        }
    }

    crate::circuit::builder::trace_phase("shplemini: done");
    commitments.push(g1_identity.clone());
    scalars.push(constant_term_accumulator);
    ShpleminiOutput {
        claim: BatchOpeningClaim {
            commitments,
            scalars,
            evaluation_point: z,
        },
        consistency_checked,
    }
}

/// bb `SmallSubgroupIPAVerifier::check_libra_evaluations_consistency`.
pub fn check_libra_evaluations_consistency<C: Curve>(
    evals: &[C::Fr; NUM_SMALL_IPA_OPENING_CLAIMS],
    r: &C::Fr,
    multivariate_challenge: &[C::Fr],
    inner_product_claim: &C::Fr,
) -> bool {
    small_ipa_check_consistency::<C>(
        evals,
        r,
        &libra_challenge_coeffs::<C>(multivariate_challenge),
        inner_product_claim,
    )
}

/// bb `KZG::reduce_verify_batch_opening_claim`: `P0 = C + z*[W]`, `P1 = -[W]`.
/// An opening claim `f(x) = v` on a commitment, as seen by the verifier.
pub struct VerifierOpeningClaim<C: Curve> {
    pub commitment: C::G,
    pub challenge: C::Fr,
    pub evaluation: C::Fr,
}

/// bb `ShplonkVerifier_::reduce_verification_no_finalize` + `export_batch_opening_claim`: the batched
/// claim `[Q] - sum_i nu^i/(z - x_i) [f_i] + (sum_i nu^i v_i/(z - x_i)) [1]` opened at `z` with value 0.
pub fn shplonk_verify<C: Curve>(
    claims: &[VerifierOpeningClaim<C>],
    g1_identity: C::G,
    t: &mut Transcript<C::TF, C::Hash>,
) -> BatchOpeningClaim<C> {
    assert!(claims.len() > 1, "Shplonk with one claim; open it directly");
    let nu: C::Fr = t.challenge("Shplonk:nu");
    let q: C::G = t.receive("Shplonk:Q");
    let z: C::Fr = t.challenge("Shplonk:z");
    shplonk_batch_claim(claims, q, &nu, &z, g1_identity)
}

/// The MSM behind bb `ShplonkVerifier_::compute_partially_evaluated_quotient_claim`.
pub fn shplonk_batch_claim<C: Curve>(
    claims: &[VerifierOpeningClaim<C>],
    q: C::G,
    nu: &C::Fr,
    z: &C::Fr,
    g1_identity: C::G,
) -> BatchOpeningClaim<C> {
    let nu_pows = powers(nu, claims.len());
    // bb `ShplonkVerifier_::initialize` fixes a zero "evaluation" witness in-circuit (unused natively)
    if let Some(ctx) = nu.ctx() {
        let _evaluation = C::Fr::fixed_witness(&ctx, <C::Fr as FieldLike>::Native::from(0u64));
    }
    let mut commitments = vec![q];
    let mut scalars = vec![C::Fr::one()];
    let mut identity_scalar = C::Fr::zero();
    // bb `accumulate_claims`: every inverse first, then the batching
    let inverse_vanishing_evals: Vec<C::Fr> = claims.iter().map(|c| (z.clone() - &c.challenge).invert()).collect();
    for ((c, nu_pow), inv) in claims.iter().zip(&nu_pows).zip(&inverse_vanishing_evals) {
        let factor = nu_pow.clone() * inv;
        commitments.push(c.commitment.clone());
        scalars.push(C::Fr::zero() - &factor);
        identity_scalar += factor * &c.evaluation;
    }
    commitments.push(g1_identity);
    scalars.push(identity_scalar);
    BatchOpeningClaim {
        commitments,
        scalars,
        evaluation_point: z.clone(),
    }
}

pub fn kzg_reduce_verify_batch_opening_claim<C: Curve>(
    mut claim: BatchOpeningClaim<C>,
    t: &mut Transcript<C::TF, C::Hash>,
    expected_final_msm_size: usize,
) -> PairingPoints<C> {
    crate::circuit::builder::trace_phase("kzg: start");
    let w: C::G = t.receive("KZG:W");
    claim.commitments.push(w.clone());
    claim.scalars.push(claim.evaluation_point.clone());
    assert_eq!(
        claim.commitments.len(),
        expected_final_msm_size,
        "unexpected final MSM size"
    );
    let p0 = C::G::batch_mul(&claim.commitments, &claim.scalars);
    PairingPoints { p0, p1: w.neg() }
}

// ---------------------------------------------------------------------------------------------
// Provers (bb `gemini_impl.hpp`, `shplonk.hpp`, `kzg.hpp`, `small_subgroup_ipa.cpp`).
// ---------------------------------------------------------------------------------------------

use crate::base::poly::Poly;
use crate::base::rng::Rng;
use crate::base::transcript::NativeTranscript;
use crate::base::{Bn254, CommitmentKey, Fr};
use crate::honk::sumcheck::{interpolate_on_subgroup, subgroup_domain, ZkData};

/// A polynomial with a claimed evaluation (bb `ProverOpeningClaim`).
pub struct ProverClaim<F: FieldLike = Fr> {
    pub poly: Polynomial<F>,
    pub challenge: F,
    pub evaluation: F,
    /// Gemini fold polynomials are additionally opened at `-challenge` (the positive point).
    pub gemini_fold: bool,
}

/// The three SmallSubgroupIPA witness polynomials `[G, A, Q]` (bb `get_witness_polynomials`).
pub struct LibraPolys<F: FieldLike = Fr>(pub [Polynomial<F>; NUM_SMALL_IPA_COMMITMENTS]);

/// bb `make_small_ipa_prover_opening_claims`: send the transmitted evaluations under
/// `<prefix><suffix>` and return the five claims.
pub fn small_ipa_prover_claims<C: Curve<TF = Fr>>(
    polys: &LibraPolys<C::Fr>,
    r: &C::Fr,
    prefix: &str,
    t: &mut NativeTranscript,
) -> Vec<ProverClaim<C::Fr>>
where
    C::Fr: Copy,
{
    let points = small_ipa_points::<C>(r);
    SMALL_IPA_CLAIMS
        .iter()
        .enumerate()
        .map(|(i, (comm_idx, _, transmitted, suffix))| {
            let evaluation = if *transmitted {
                let e = polys.0[*comm_idx].evaluate(&points[i]);
                t.send(&format!("{prefix}{suffix}"), &e);
                e
            } else {
                C::Fr::zero()
            };
            ProverClaim {
                poly: polys.0[*comm_idx].clone(),
                challenge: points[i],
                evaluation,
                gemini_fold: false,
            }
        })
        .collect()
}

/// Output of the Shplonk prover: the partially evaluated quotient claim `(G, z, 0)` plus what the
/// verifier needs to rebuild its side of it (bb `ShplonkProver_::PartiallyEvaluatedQuotient`).
pub struct ShplonkProverOutput<C: Curve> {
    pub claim: ProverClaim<C::Fr>,
    pub quotient_commitment: C::G,
    pub nu: C::Fr,
    pub z: C::Fr,
}

/// bb `ShpleminiProver_::prove`: Gemini folds + (ZK) Libra claims + Shplonk batching. Returns the
/// final opening claim `(G, z, 0)` to be opened with KZG.
pub fn shplemini_prove(
    unshifted: &[&Poly],
    to_be_shifted: &[&Poly],
    u: &[Fr],
    ck: &CommitmentKey,
    t: &mut NativeTranscript,
    libra: Option<&LibraPolys>,
    sumcheck_round_claims: &[ProverClaim],
) -> ProverClaim {
    use crate::base::group::Curve;
    let virtual_log_n = u.len();
    // Shorter polynomials (a smaller circuit batched with a larger one) are zero-extended.
    let n = unshifted.iter().chain(to_be_shifted).map(|p| p.len()).max().unwrap();
    let log_n = n.trailing_zeros() as usize;

    // --- Gemini ---
    let rho: Fr = t.challenge("rho");
    // A_0 = F + G/X with F = sum rho^i f_i, G = sum rho^{k+j} g_j
    let mut batched_unshifted = Poly::zero(n);
    let mut batched_to_be_shifted = Poly::zero(n);
    let mut scalar = Fr::one();
    let mut unshifted_terms = Vec::with_capacity(unshifted.len());
    let mut shifted_terms = Vec::with_capacity(to_be_shifted.len());
    for f in unshifted {
        unshifted_terms.push((*f, scalar));
        scalar *= rho;
    }
    for g in to_be_shifted {
        shifted_terms.push((*g, scalar));
        scalar *= rho;
    }
    batched_unshifted.add_scaled_batch(&unshifted_terms);
    batched_to_be_shifted.add_scaled_batch(&shifted_terms);
    let mut a_0 = batched_unshifted.clone();
    a_0.add_scaled(&batched_to_be_shifted.shifted(), &Fr::one());
    crate::base::timing::phase("    shplemini: batching");

    // folds A_{l+1}[j] = A_l[2j] + u_l (A_l[2j+1] - A_l[2j]), l = 0..log_n-2
    let mut folds: Vec<Poly> = Vec::with_capacity(virtual_log_n - 1);
    let mut current = a_0.coeffs.clone();
    for l in 0..log_n - 1 {
        let half = current.len() / 2;
        let next: Vec<Fr> = (0..half)
            .into_par_iter()
            .map(|j| current[2 * j] + u[l] * (current[2 * j + 1] - current[2 * j]))
            .collect();
        folds.push(Poly::from_coeffs(next.clone()));
        current = next;
    }
    // constant folds for the virtual rounds
    if log_n < virtual_log_n {
        let last = &folds[folds.len() - 1];
        let final_eval = last.coeffs[0] + u[log_n - 1] * (last.coeffs[1] - last.coeffs[0]);
        folds.push(Poly::from_coeffs(vec![final_eval]));
        let mut tail = Fr::one();
        for k in log_n..virtual_log_n - 1 {
            tail *= Fr::one() - u[k];
            folds.push(Poly::from_coeffs(vec![final_eval * tail]));
        }
    }
    crate::base::timing::phase("    shplemini: folds");
    let fold_comms: Vec<_> = folds.par_iter().map(|f| ck.commit(f)).collect();
    crate::base::timing::phase("    shplemini: fold commits");
    for (l, c) in fold_comms.iter().enumerate() {
        t.send(&format!("Gemini:FOLD_{}", l + 1), c);
    }
    let r: Fr = t.challenge("Gemini:r");
    if libra.is_some() {
        assert!(
            r.pow_u64(Bn254::SUBGROUP_SIZE as u64) != Fr::one(),
            "Gemini evaluation challenge is in the small subgroup"
        );
    }
    // A_0_pos = F + G/r, A_0_neg = F - G/r
    let r_inv = r.invert();
    let mut a_0_pos = batched_unshifted.clone();
    a_0_pos.add_scaled(&batched_to_be_shifted, &r_inv);
    let mut a_0_neg = batched_unshifted;
    a_0_neg.add_scaled(&batched_to_be_shifted, &(-r_inv));

    let mut claims = Vec::with_capacity(virtual_log_n + 1);
    let a_0_pos_eval = a_0_pos.evaluate(&r);
    claims.push(ProverClaim {
        poly: a_0_pos,
        challenge: r,
        evaluation: a_0_pos_eval,
        gemini_fold: false,
    });
    let a_0_neg_eval = a_0_neg.evaluate(&(-r));
    claims.push(ProverClaim {
        poly: a_0_neg,
        challenge: -r,
        evaluation: a_0_neg_eval,
        gemini_fold: false,
    });
    let mut r_pow = r;
    for f in folds {
        r_pow = r_pow.sqr();
        let evaluation = f.evaluate(&(-r_pow));
        claims.push(ProverClaim {
            poly: f,
            challenge: -r_pow,
            evaluation,
            gemini_fold: true,
        });
    }
    for (l, c) in claims.iter().enumerate().skip(1) {
        t.send(&format!("Gemini:a_{l}"), &c.evaluation);
    }

    // --- Libra opening claims (ZK) ---
    let libra_claims = libra.map_or(Vec::new(), |polys| {
        small_ipa_prover_claims::<Bn254>(polys, &r, "Libra:", t)
    });

    // --- Shplonk ---
    shplonk_prove::<Bn254>(virtual_log_n, &claims, &libra_claims, sumcheck_round_claims, ck, t).claim
}

/// bb `ShpleminiProver_::compute_sumcheck_round_claims`: each committed round univariate opened at
/// `0`, `1` and `u_i`.
pub fn sumcheck_round_claims(univariates: &[Poly], evaluations: &[[Fr; 3]], u: &[Fr]) -> Vec<ProverClaim> {
    let mut claims = Vec::with_capacity(3 * univariates.len());
    for (i, poly) in univariates.iter().enumerate() {
        for (k, point) in [Fr::from(0u64), Fr::from(1u64), u[i]].into_iter().enumerate() {
            claims.push(ProverClaim {
                poly: poly.clone(),
                challenge: point,
                evaluation: evaluations[i][k],
                gemini_fold: false,
            });
        }
    }
    claims
}

/// `q += scale * (p - v) / (X - x)` with `x` a root of `p - v` (bb `factor_roots`), fused with
/// the accumulation: `q_{n-2} = p_{n-1}`, `q_{i-1} = p_i + x q_i`.
fn accumulate_quotient<F: FieldLike + Copy>(q: &mut [F], p: &[F], x: F, v: F, scale: F) {
    let mut carry = F::zero();
    for i in (1..p.len()).rev() {
        carry = p[i] + x * carry;
        q[i - 1] += scale * carry;
    }
    assert!((p[0] - v + x * carry).is_zero(), "accumulate_quotient: not a root");
}

/// bb `ShplonkProver_::prove`: batched quotient `Q`, then `G = Q - Q_z` opened at `z` with value 0.
/// `virtual_log_n` only matters when `libra_claims` is non-empty.
pub fn shplonk_prove<C: Curve<TF = Fr>>(
    virtual_log_n: usize,
    claims: &[ProverClaim<C::Fr>],
    libra_claims: &[ProverClaim<C::Fr>],
    sumcheck_claims: &[ProverClaim<C::Fr>],
    ck: &Ck<C::G>,
    t: &mut NativeTranscript,
) -> ShplonkProverOutput<C>
where
    C::Fr: Copy + Send + Sync,
    C::G: AffineRepr<ScalarField = C::Fr>,
{
    type F<C> = <C as Curve>::Fr;
    let nu: F<C> = t.challenge("Shplonk:nu");
    let fold_pos_evals: Vec<F<C>> = claims
        .iter()
        .filter(|c| c.gemini_fold)
        .map(|c| c.poly.evaluate(&(-c.challenge)))
        .collect();
    let max_size = claims
        .iter()
        .chain(libra_claims)
        .chain(sumcheck_claims)
        .map(|c| c.poly.len())
        .max()
        .unwrap();

    // Q = sum_j nu^j (f_j - v_j) / (X - x_j)
    // Every opening `(poly, x, v, nu^i)` in bb's batching order: a Gemini fold contributes its
    // positive and negative openings back to back; Libra and committed-sumcheck claims start at
    // nu^{2 * virtual_log_n}.
    let mut openings: Vec<(&Polynomial<F<C>>, F<C>, F<C>, F<C>)> = Vec::new();
    let mut current_nu = F::<C>::one();
    let mut fold_idx = 0;
    for c in claims {
        if c.gemini_fold {
            openings.push((&c.poly, -c.challenge, fold_pos_evals[fold_idx], current_nu));
            fold_idx += 1;
            current_nu *= nu;
        }
        openings.push((&c.poly, c.challenge, c.evaluation, current_nu));
        current_nu *= nu;
    }
    if !libra_claims.is_empty() || !sumcheck_claims.is_empty() {
        current_nu = nu.pow_u64(2 * virtual_log_n as u64);
        for c in libra_claims.iter().chain(sumcheck_claims) {
            openings.push((&c.poly, c.challenge, c.evaluation, current_nu));
            current_nu *= nu;
        }
    }
    // Longest openings first so the parallel folds below balance.
    openings.sort_by_key(|o| std::cmp::Reverse(o.0.len()));
    // Q = sum_i nu^i (p_i(X) - v_i) / (X - x_i): each quotient at its own length, openings in
    // parallel, then one row-parallel sum.
    let quotients: Vec<Polynomial<F<C>>> = openings
        .par_iter()
        .map(|(poly, x, v, scale)| {
            let mut q = Polynomial::zero(poly.len());
            accumulate_quotient(&mut q.coeffs, &poly.coeffs, *x, *v, *scale);
            q
        })
        .collect();
    let mut q = Polynomial::<F<C>>::zero(max_size);
    q.add_scaled_batch(&quotients.iter().map(|p| (p, F::<C>::one())).collect::<Vec<_>>());
    crate::base::timing::phase("    shplonk: quotient");
    let quotient_commitment = ck.commit(&q);
    crate::base::timing::phase("    shplonk: Q commit");
    t.send("Shplonk:Q", &quotient_commitment);
    let z: F<C> = t.challenge("Shplonk:z");

    // G = Q - sum_i nu^i / (z - x_i) (p_i(X) - v_i)
    let mut g = q;
    let scalars: Vec<F<C>> = openings.iter().map(|(_, x, _, scale)| *scale * (z - x).invert()).collect();
    g.add_scaled_batch(&openings.iter().zip(&scalars).map(|((poly, ..), s)| (*poly, -*s)).collect::<Vec<_>>());
    for ((_, _, v, _), s) in openings.iter().zip(&scalars) {
        g.coeffs[0] += *s * v;
    }
    crate::base::timing::phase("    shplonk: batched G");
    ShplonkProverOutput {
        claim: ProverClaim {
            poly: g,
            challenge: z,
            evaluation: F::<C>::zero(),
            gemini_fold: false,
        },
        quotient_commitment,
        nu,
        z,
    }
}

/// bb `KZG::compute_opening_proof`: commit to `(p - v) / (X - r)` and send it as `KZG:W`.
pub fn kzg_open(claim: ProverClaim, ck: &CommitmentKey, t: &mut NativeTranscript) {
    let mut quotient = claim.poly;
    quotient.coeffs[0] -= claim.evaluation;
    quotient.factor_root(&claim.challenge);
    crate::base::timing::phase("    kzg: quotient");
    t.send("KZG:W", &ck.commit(&quotient));
    crate::base::timing::phase("    kzg: W commit");
}

/// bb `SmallSubgroupIPAProver` for the Libra data: computes and commits to the grand-sum
/// polynomial `A` and the identity quotient `Q`, returning `[G, A, Q]`.
pub fn small_subgroup_ipa_prove<C: Curve<TF = Fr>>(
    zk: &ZkData<C>,
    u: &[C::Fr],
    claimed_inner_product: &C::Fr,
    ck: &Ck<C::G>,
    t: &mut NativeTranscript,
    rng: &mut dyn Rng,
) -> LibraPolys<C::Fr>
where
    C::Fr: PrimeField<BigInt = U256>,
    C::G: AffineRepr<ScalarField = C::Fr>,
{
    let challenge_lagrange = libra_challenge_coeffs::<C>(u);
    small_subgroup_ipa_prove_core::<C>(
        &zk.libra_concatenated_monomial,
        &zk.libra_concatenated_lagrange,
        &challenge_lagrange,
        claimed_inner_product,
        "Libra:",
        ck,
        t,
        rng,
    )
}

/// The SmallSubgroupIPA prover proper (bb `SmallSubgroupIPAProver::prove`) for a concatenated
/// witness `G` (monomial form, masked) with Lagrange values `g` over the subgroup and a challenge
/// polynomial `F` given by its Lagrange values: proves `Σ_i g_i F_i = claimed_inner_product`.
pub fn small_subgroup_ipa_prove_core<C: Curve<TF = Fr>>(
    g_poly: &Polynomial<C::Fr>,
    g_lagrange: &[C::Fr],
    f_lagrange: &[C::Fr],
    claimed_inner_product: &C::Fr,
    prefix: &str,
    ck: &Ck<C::G>,
    t: &mut NativeTranscript,
    rng: &mut dyn Rng,
) -> LibraPolys<C::Fr>
where
    C::Fr: PrimeField<BigInt = U256>,
    C::G: AffineRepr<ScalarField = C::Fr>,
{
    type F<C> = <C as Curve>::Fr;
    let n = C::SUBGROUP_SIZE;
    let g = F::<C>::constant(C::subgroup_generator());
    let domain = subgroup_domain::<C>();
    let f_monomial = interpolate_on_subgroup(f_lagrange, &g);

    // grand sum A: A_0 = 0, A_i = A_{i-1} + F_{i-1} G_{i-1}; masked by Z_H(X) R(X), deg R = 2
    let mut a_lagrange = vec![F::<C>::zero(); n];
    for i in 1..n {
        a_lagrange[i] = a_lagrange[i - 1] + f_lagrange[i - 1] * g_lagrange[i - 1];
    }
    let mut a = interpolate_on_subgroup(&a_lagrange, &g);
    a.coeffs.resize(n + 3, F::<C>::zero());
    let masking: [F<C>; 3] = [random_field(rng), random_field(rng), random_field(rng)];
    for (i, m) in masking.iter().enumerate() {
        a.coeffs[i] -= m;
        a.coeffs[n + i] += m;
    }
    t.send(&format!("{prefix}grand_sum_commitment"), &ck.commit(&a));

    // identity C = L_1 A + (X - g^{-1})(A(gX) - A - F G) + L_{|H|}(A - s), then Q = C / Z_H
    let masked_g_len = n + 2;
    let masked_a_len = n + 3;
    let identity_len = masked_g_len + n;
    let mut c = vec![F::<C>::zero(); identity_len];
    let shifted_a: Vec<F<C>> = (0..masked_a_len).map(|i| a.coeffs[i] * domain[i % n]).collect();
    let mut e_first = vec![F::<C>::zero(); n];
    e_first[0] = F::<C>::one();
    let l_first = interpolate_on_subgroup(&e_first, &g);
    let mut e_last = vec![F::<C>::zero(); n];
    e_last[n - 1] = F::<C>::one();
    let l_last = interpolate_on_subgroup(&e_last, &g);
    for i in 0..masked_g_len {
        for j in 0..n {
            c[i + j] -= g_poly.coeffs[i] * f_monomial.coeffs[j];
        }
    }
    for i in 0..masked_a_len {
        c[i] += shifted_a[i] - a.coeffs[i];
    }
    for i in (1..identity_len).rev() {
        c[i] = c[i - 1];
    }
    c[0] = F::<C>::zero();
    let g_inv = domain[n - 1];
    for i in 0..identity_len - 1 {
        c[i] = c[i] - c[i + 1] * g_inv;
    }
    for i in 0..masked_a_len {
        for j in 0..n {
            c[i + j] += a.coeffs[i] * (l_first.coeffs[j] + l_last.coeffs[j]);
        }
    }
    for j in 0..n {
        c[j] -= l_last.coeffs[j] * *claimed_inner_product;
    }
    let mut quotient = vec![F::<C>::zero(); identity_len - n];
    let mut remainder = c;
    for i in (n..identity_len).rev() {
        quotient[i - n] = remainder[i];
        remainder[i - n] = remainder[i - n] + remainder[i];
    }
    let q = Polynomial::from_coeffs(quotient);
    t.send(&format!("{prefix}quotient_commitment"), &ck.commit(&q));
    LibraPolys([g_poly.clone(), a, q])
}
