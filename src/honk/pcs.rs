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

// ---------------------------------------------------------------------------------------------
// Provers (bb `gemini_impl.hpp`, `shplonk.hpp`, `kzg.hpp`, `small_subgroup_ipa.cpp`).
// ---------------------------------------------------------------------------------------------

use crate::base::poly::Poly;
use crate::base::rng::Rng;
use crate::base::transcript::NativeTranscript;
use crate::base::{Bn254, CommitmentKey, Fr};
use crate::honk::sumcheck::{interpolate_on_subgroup, ZkData};

/// A polynomial with a claimed evaluation (bb `ProverOpeningClaim`).
pub struct ProverClaim {
    pub poly: Poly,
    pub challenge: Fr,
    pub evaluation: Fr,
    /// Gemini fold polynomials are additionally opened at `-challenge` (the positive point).
    pub gemini_fold: bool,
}

/// The three SmallSubgroupIPA witness polynomials `[G, A, Q]` (bb `get_witness_polynomials`).
pub struct LibraPolys(pub [Poly; NUM_SMALL_IPA_COMMITMENTS]);

/// bb `ShpleminiProver_::prove`: Gemini folds + (ZK) Libra claims + Shplonk batching. Returns the
/// final opening claim `(G, z, 0)` to be opened with KZG.
pub fn shplemini_prove(
    unshifted: &[&Poly],
    to_be_shifted: &[&Poly],
    u: &[Fr],
    ck: &CommitmentKey,
    t: &mut NativeTranscript,
    libra: Option<&LibraPolys>,
) -> ProverClaim {
    use crate::base::group::Curve;
    let virtual_log_n = u.len();
    let n = unshifted[0].len();
    let log_n = n.trailing_zeros() as usize;

    // --- Gemini ---
    let rho: Fr = t.challenge("rho");
    // A_0 = F + G/X with F = sum rho^i f_i, G = sum rho^{k+j} g_j
    let mut batched_unshifted = Poly::zero(n);
    let mut batched_to_be_shifted = Poly::zero(n);
    let mut scalar = Fr::one();
    for f in unshifted {
        batched_unshifted.add_scaled(f, &scalar);
        scalar *= rho;
    }
    for g in to_be_shifted {
        batched_to_be_shifted.add_scaled(g, &scalar);
        scalar *= rho;
    }
    let mut a_0 = batched_unshifted.clone();
    a_0.add_scaled(&batched_to_be_shifted.shifted(), &Fr::one());

    // folds A_{l+1}[j] = A_l[2j] + u_l (A_l[2j+1] - A_l[2j]), l = 0..log_n-2
    let mut folds: Vec<Poly> = Vec::with_capacity(virtual_log_n - 1);
    let mut current = a_0.coeffs.clone();
    for l in 0..log_n - 1 {
        let half = current.len() / 2;
        let next: Vec<Fr> = (0..half).map(|j| current[2 * j] + u[l] * (current[2 * j + 1] - current[2 * j])).collect();
        folds.push(Poly::from_coeffs(next.clone()));
        current = next;
    }
    // constant folds for the virtual rounds
    let last = &folds[folds.len() - 1];
    let final_eval = last.coeffs[0] + u[log_n - 1] * (last.coeffs[1] - last.coeffs[0]);
    folds.push(Poly::from_coeffs(vec![final_eval]));
    let mut tail = Fr::one();
    for k in log_n..virtual_log_n - 1 {
        tail *= Fr::one() - u[k];
        folds.push(Poly::from_coeffs(vec![final_eval * tail]));
    }
    for (l, f) in folds.iter().enumerate() {
        t.send(&format!("Gemini:FOLD_{}", l + 1), &ck.commit(f));
    }
    let r: Fr = t.challenge("Gemini:r");
    if libra.is_some() {
        assert!(r.pow_u64(Bn254::SUBGROUP_SIZE as u64) != Fr::one(), "Gemini evaluation challenge is in the small subgroup");
    }
    // A_0_pos = F + G/r, A_0_neg = F - G/r
    let r_inv = r.invert();
    let mut a_0_pos = batched_unshifted.clone();
    a_0_pos.add_scaled(&batched_to_be_shifted, &r_inv);
    let mut a_0_neg = batched_unshifted;
    a_0_neg.add_scaled(&batched_to_be_shifted, &(-r_inv));

    let mut claims = Vec::with_capacity(virtual_log_n + 1);
    let a_0_pos_eval = a_0_pos.evaluate(&r);
    claims.push(ProverClaim { poly: a_0_pos, challenge: r, evaluation: a_0_pos_eval, gemini_fold: false });
    let a_0_neg_eval = a_0_neg.evaluate(&(-r));
    claims.push(ProverClaim { poly: a_0_neg, challenge: -r, evaluation: a_0_neg_eval, gemini_fold: false });
    let mut r_pow = r;
    for f in folds {
        r_pow = r_pow.sqr();
        let evaluation = f.evaluate(&(-r_pow));
        claims.push(ProverClaim { poly: f, challenge: -r_pow, evaluation, gemini_fold: true });
    }
    for (l, c) in claims.iter().enumerate().skip(1) {
        t.send(&format!("Gemini:a_{l}"), &c.evaluation);
    }

    // --- Libra opening claims (ZK) ---
    let mut libra_claims = Vec::new();
    if let Some(LibraPolys(polys)) = libra {
        let g = Bn254::subgroup_generator();
        for (comm_idx, point_kind, transmitted, suffix) in SMALL_IPA_CLAIMS {
            let point = match point_kind {
                EvalPoint::Challenge => r,
                EvalPoint::ChallengeShifted => r * g,
                EvalPoint::One => Fr::one(),
            };
            let evaluation = if transmitted {
                let e = polys[comm_idx].evaluate(&point);
                t.send(&format!("Libra:{suffix}"), &e);
                e
            } else {
                Fr::zero()
            };
            libra_claims.push(ProverClaim { poly: polys[comm_idx].clone(), challenge: point, evaluation, gemini_fold: false });
        }
    }

    // --- Shplonk ---
    shplonk_prove(virtual_log_n, &claims, &libra_claims, ck, t)
}

/// bb `ShplonkProver_::prove`: batched quotient `Q`, then `G = Q - Q_z` opened at `z` with value 0.
fn shplonk_prove(virtual_log_n: usize, claims: &[ProverClaim], libra_claims: &[ProverClaim], ck: &CommitmentKey, t: &mut NativeTranscript) -> ProverClaim {
    let nu: Fr = t.challenge("Shplonk:nu");
    let fold_pos_evals: Vec<Fr> = claims.iter().filter(|c| c.gemini_fold).map(|c| c.poly.evaluate(&(-c.challenge))).collect();
    let max_size = claims.iter().chain(libra_claims).map(|c| c.poly.len()).max().unwrap();

    // Q = sum_j nu^j (f_j - v_j) / (X - x_j)
    let mut q = Poly::zero(max_size);
    let mut current_nu = Fr::one();
    let mut fold_idx = 0;
    let add_quotient = |q: &mut Poly, poly: &Poly, x: &Fr, v: &Fr, scale: &Fr| {
        let mut tmp = poly.clone();
        tmp.coeffs.resize(max_size, Fr::zero());
        tmp.coeffs[0] -= v;
        tmp.factor_root(x);
        q.add_scaled(&tmp, scale);
    };
    for c in claims {
        if c.gemini_fold {
            add_quotient(&mut q, &c.poly, &(-c.challenge), &fold_pos_evals[fold_idx], &current_nu);
            fold_idx += 1;
            current_nu *= nu;
        }
        add_quotient(&mut q, &c.poly, &c.challenge, &c.evaluation, &current_nu);
        current_nu *= nu;
    }
    if !libra_claims.is_empty() {
        current_nu = nu.pow_u64(2 * virtual_log_n as u64);
        for c in libra_claims {
            add_quotient(&mut q, &c.poly, &c.challenge, &c.evaluation, &current_nu);
            current_nu *= nu;
        }
    }
    t.send("Shplonk:Q", &ck.commit(&q));
    let z: Fr = t.challenge("Shplonk:z");

    // G = Q - sum_j nu^j (f_j - v_j) / (z - x_j)
    let mut g = q;
    let mut current_nu = Fr::one();
    let mut fold_idx = 0;
    let subtract = |g: &mut Poly, poly: &Poly, x: &Fr, v: &Fr, scale: &Fr| {
        let s = *scale * (z - x).invert();
        g.add_scaled(poly, &(-s));
        g.coeffs[0] += s * v;
    };
    for c in claims {
        if c.gemini_fold {
            subtract(&mut g, &c.poly, &(-c.challenge), &fold_pos_evals[fold_idx], &current_nu);
            fold_idx += 1;
            current_nu *= nu;
        }
        subtract(&mut g, &c.poly, &c.challenge, &c.evaluation, &current_nu);
        current_nu *= nu;
    }
    if !libra_claims.is_empty() {
        current_nu = nu.pow_u64(2 * virtual_log_n as u64);
        for c in libra_claims {
            subtract(&mut g, &c.poly, &c.challenge, &c.evaluation, &current_nu);
            current_nu *= nu;
        }
    }
    ProverClaim { poly: g, challenge: z, evaluation: Fr::zero(), gemini_fold: false }
}

/// bb `KZG::compute_opening_proof`: commit to `(p - v) / (X - r)` and send it as `KZG:W`.
pub fn kzg_open(claim: ProverClaim, ck: &CommitmentKey, t: &mut NativeTranscript) {
    let mut quotient = claim.poly;
    quotient.coeffs[0] -= claim.evaluation;
    quotient.factor_root(&claim.challenge);
    t.send("KZG:W", &ck.commit(&quotient));
}

/// bb `SmallSubgroupIPAProver` for the Libra data: computes and commits to the grand-sum
/// polynomial `A` and the identity quotient `Q`, returning `[G, A, Q]`.
pub fn small_subgroup_ipa_prove(zk: &ZkData, u: &[Fr], claimed_inner_product: &Fr, ck: &CommitmentKey, t: &mut NativeTranscript, rng: &mut dyn Rng) -> LibraPolys {
    use crate::base::group::Curve;
    let n = Bn254::SUBGROUP_SIZE;
    let libra_len = Bn254::LIBRA_UNIVARIATES_LENGTH;
    let g = Bn254::subgroup_generator();
    let domain = &zk.interpolation_domain;

    // challenge polynomial F: (1, 1, u_0, ..., u_0^{L-1}, 1, u_1, ...) in the Lagrange basis over H
    let mut f_lagrange = vec![Fr::zero(); n];
    f_lagrange[0] = Fr::one();
    for (round, u_i) in u.iter().enumerate() {
        let start = 1 + libra_len * round;
        f_lagrange[start] = Fr::one();
        for idx in start + 1..start + libra_len {
            f_lagrange[idx] = f_lagrange[idx - 1] * u_i;
        }
    }
    let f_monomial = interpolate_on_subgroup(&f_lagrange, &g);
    let g_poly = &zk.libra_concatenated_monomial; // G, length n + 2
    let g_lagrange = &zk.libra_concatenated_lagrange;

    // grand sum A: A_0 = 0, A_i = A_{i-1} + F_{i-1} G_{i-1}; masked by Z_H(X) R(X), deg R = 2
    let mut a_lagrange = vec![Fr::zero(); n];
    for i in 1..n {
        a_lagrange[i] = a_lagrange[i - 1] + f_lagrange[i - 1] * g_lagrange[i - 1];
    }
    let mut a = interpolate_on_subgroup(&a_lagrange, &g);
    a.coeffs.resize(n + 3, Fr::zero());
    let masking = [rng.fr(), rng.fr(), rng.fr()];
    for (i, m) in masking.iter().enumerate() {
        a.coeffs[i] -= m;
        a.coeffs[n + i] += m;
    }
    t.send("Libra:grand_sum_commitment", &ck.commit(&a));

    // identity C = L_1 A + (X - g^{-1})(A(gX) - A - F G) + L_{|H|}(A - s), then Q = C / Z_H
    let masked_g_len = n + 2;
    let masked_a_len = n + 3;
    let identity_len = masked_g_len + n;
    let mut c = vec![Fr::zero(); identity_len];
    let shifted_a: Vec<Fr> = (0..masked_a_len).map(|i| a.coeffs[i] * domain[i % n]).collect();
    let l_first = interpolate_on_subgroup(&std::iter::once(Fr::one()).chain(std::iter::repeat(Fr::zero()).take(n - 1)).collect::<Vec<_>>(), &g);
    let mut e_last = vec![Fr::zero(); n];
    e_last[n - 1] = Fr::one();
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
    c[0] = Fr::zero();
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
        c[j] -= l_last.coeffs[j] * claimed_inner_product;
    }
    let mut quotient = vec![Fr::zero(); identity_len - n];
    let mut remainder = c;
    for i in (n..identity_len).rev() {
        quotient[i - n] = remainder[i];
        remainder[i - n] = remainder[i - n] + remainder[i];
    }
    let q = Poly::from_coeffs(quotient);
    t.send("Libra:quotient_commitment", &ck.commit(&q));
    LibraPolys([g_poly.clone(), a, q])
}
