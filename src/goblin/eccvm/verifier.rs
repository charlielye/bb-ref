//! The ECCVM verifier (bb `eccvm/eccvm_verifier.cpp`): reduces the proof on the (shared) transcript
//! to one TripleIPA claim, which the caller discharges with the IPA proof. One generic body runs
//! natively (`Grumpkin`) and in-circuit (`StdUltraGrumpkin`), like bb's single template.

use super::check::eccvm_relation_params;
use super::prover::{sumcheck_spec, NUM_TRANSLATION_EVALUATIONS, TRANSLATION_LABELS};
use super::relations::EccvmRelations;
use super::trace::TRANSLATION_ENTITIES;
use super::*;
use crate::base::codec::ChallengeField;
use crate::base::field::FieldLike;
use crate::base::group::{Curve, GroupLike};
use crate::base::transcript::Transcript;
use crate::base::Grumpkin;
use crate::goblin::ipa::{rho_powers, TripleIpaClaim, TripleIpaClaims};
use crate::honk::pcs::{
    check_libra_evaluations_consistency, eccvm_challenge_coeffs, shplonk_verify, small_ipa_check_consistency,
    small_ipa_verifier_claims, VerifierOpeningClaim,
};
use crate::honk::sumcheck::verify_sumcheck;

pub struct EccvmVerifierOutput<C: Curve = Grumpkin> {
    /// Sumcheck, Libra and translation consistency checks passed.
    pub ok: bool,
    pub triple_ipa_claim: TripleIpaClaim<C>,
    pub evaluation_challenge_x: C::Fr,
    pub batching_challenge_v: C::Fr,
    /// The batched translation evaluation with the masking term removed, divided by `x^{TRACE_OFFSET+1}`.
    pub accumulated_result: C::Fr,
}

/// bb `ECCVMVerifier_::reduce_to_triple_ipa_claim`; the proof must already be loaded into `t`.
pub fn eccvm_verify<C: Curve>(
    ctx: &<C::Fr as FieldLike>::Ctx,
    t: &mut Transcript<C::TF, C::Hash>,
) -> EccvmVerifierOutput<C>
where
    C::Fr: FieldLike<Native = Fq>,
    C::TF: ChallengeField + FieldLike<Native = crate::base::Fr, Ctx = <C::Fr as FieldLike>::Ctx>,
    C::G: GroupLike<C::Fr, Native = GrumpkinAffine>,
{
    // bb `FixedStdlibVKAndHash_(builder, native_vk)`: the hash and the four fixed commitments
    // become witnesses (in this order), then all are pinned with fix gates; natively plain values.
    let vk_hash_wit = <C::TF as FieldLike>::from_witness(ctx, fixed_vk_hash());
    let mut vk_comms: Vec<C::G> = fixed_vk().into_iter().map(|p| C::G::from_witness(ctx, p)).collect();
    vk_hash_wit.fix();
    for c in &mut vk_comms {
        c.fix_witness();
    }
    t.add_to_hash_buffer("vk_hash", &vk_hash_wit);
    let mut commitments: Vec<C::G> = vec![C::G::constant(ctx, GrumpkinAffine::identity()); FIRST_SHIFTED];
    commitments[0] = t.receive("Gemini:masking_poly_comm");
    for (k, p) in vk_comms.into_iter().enumerate() {
        commitments[1 + k] = p;
    }
    for e in NUM_PRECOMPUTED + 1..FIRST_SHIFTED - 2 {
        commitments[e] = t.receive(&label(ent(e)));
    }
    let mut bg: Vec<C::Fr> = t.challenges(&["beta", "gamma"]);
    let gamma = bg.pop().unwrap();
    let beta = bg.pop().unwrap();
    let params = eccvm_relation_params(beta, gamma);
    for e in [Ent::lookup_inverses, Ent::z_perm] {
        commitments[e as usize] = t.receive(&label(e));
    }
    let alpha: C::Fr = t.challenge("Sumcheck:alpha");
    // bb constructs `SumcheckVerifier` — computing the subrelation separators — BEFORE drawing
    // the gate challenges here, unlike Ultra/HyperNova where the challenges come first.
    let alphas = crate::honk::sumcheck::alpha_powers(
        &alpha,
        crate::honk::sumcheck::RelationSet::<C::Fr>::total_subrelations(&EccvmRelations) - 1,
    );
    let gate_challenges: Vec<C::Fr> = t.dyadic_powers("Sumcheck:gate_challenge", CONST_ECCVM_LOG_N);
    let libra_concatenation: C::G = t.receive("Libra:concatenation_commitment");
    let sc = verify_sumcheck::<C>(&EccvmRelations, &sumcheck_spec(), t, &alphas, &params, &gate_challenges);
    let libra_grand_sum: C::G = t.receive("Libra:grand_sum_commitment");
    let libra_quotient: C::G = t.receive("Libra:quotient_commitment");
    let libra_commitments = [libra_concatenation, libra_grand_sum, libra_quotient];

    let mut claims: Vec<VerifierOpeningClaim<C>> = Vec::new();
    let libra_r: C::Fr = t.challenge("Libra:small_ipa_evaluation_challenge");
    let libra_claims = small_ipa_verifier_claims::<C>(&libra_commitments, &libra_r, "Libra:", t);
    let libra_evals: [C::Fr; 5] = std::array::from_fn(|i| libra_claims[i].evaluation.clone());
    let libra_ok =
        check_libra_evaluations_consistency::<C>(&libra_evals, &libra_r, &sc.challenge, &sc.libra_evaluation);
    claims.extend(libra_claims);

    // Translation
    let translation_masking: C::G = t.receive("Translation:concatenated_masking_term_commitment");
    let x: C::Fr = t.challenge("Translation:evaluation_challenge_x");
    let translation_evaluations: Vec<C::Fr> = TRANSLATION_LABELS.iter().map(|l| t.receive(l)).collect();
    let v: C::Fr = t.challenge("Translation:batching_challenge_v");
    let masking_term_eval: C::Fr = t.receive("Translation:masking_term_eval");
    let translation_grand_sum: C::G = t.receive("Translation:grand_sum_commitment");
    let translation_quotient: C::G = t.receive("Translation:quotient_commitment");
    let translation_commitments = [translation_masking, translation_grand_sum, translation_quotient];
    let translation_r: C::Fr = t.challenge("Translation:small_ipa_evaluation_challenge");
    let translation_claims =
        small_ipa_verifier_claims::<C>(&translation_commitments, &translation_r, "Translation:", t);
    let translation_evals: Vec<C::Fr> = translation_claims.iter().map(|c| c.evaluation.clone()).collect();
    let translation_vanishing = translation_r.pow_u64(C::SUBGROUP_SIZE as u64) - &C::Fr::one();
    let translation_ok = small_ipa_check_consistency::<C>(
        &translation_evals,
        &translation_r,
        &eccvm_challenge_coeffs::<C>(&x, &v, NUM_TRANSLATION_EVALUATIONS, TRACE_OFFSET),
        &masking_term_eval,
        translation_vanishing,
    );
    claims.extend(translation_claims);
    let v_powers = rho_powers(&v, NUM_TRANSLATION_EVALUATIONS, 0);
    // bb `batch_evaluations`: one chunk-16 mult_madd, not a per-term sum.
    let batched_evaluation = crate::goblin::ipa::batch_evaluations(&translation_evaluations, &v_powers);
    let translation_column_commitments: Vec<C::G> =
        TRANSLATION_ENTITIES.iter().map(|e| commitments[*e as usize].clone()).collect();
    claims.push(VerifierOpeningClaim {
        commitment: C::G::batch_mul(&translation_column_commitments, &v_powers),
        challenge: x.clone(),
        evaluation: batched_evaluation.clone(),
    });

    // Sumcheck round univariates at 0, 1, u_i
    for (i, comm) in sc.round_commitments.iter().enumerate() {
        for (point, eval) in [
            (C::Fr::zero(), sc.round_evaluations[i][0].clone()),
            (C::Fr::one(), sc.round_evaluations[i][1].clone()),
            (sc.challenge[i].clone(), sc.round_evaluations[i][2].clone()),
        ] {
            claims.push(VerifierOpeningClaim {
                commitment: comm.clone(),
                challenge: point,
                evaluation: eval,
            });
        }
    }
    let mask_commitment: C::G = t.receive("TripleIPA:pow_mask_commitment");
    let mask_challenge: C::Fr = t.challenge("TripleIPA:pow_mask_challenge");
    let mask_evaluation: C::Fr = t.receive("TripleIPA:pow_mask_evaluation");
    claims.push(VerifierOpeningClaim {
        commitment: mask_commitment,
        challenge: mask_challenge,
        evaluation: mask_evaluation,
    });

    // The Shplonk quotient's base point is the SRS first point, NOT the Grumpkin generator
    // (bb VerifierCommitmentKey::get_g1_identity; a circuit constant in the recursive verifier).
    let g1_identity = C::G::constant(ctx, crate::base::GrumpkinKey::new(1).points[0]);
    let batch = shplonk_verify::<C>(&claims, g1_identity, t);
    let univariate_commitment = C::G::batch_mul(&batch.commitments, &batch.scalars);

    let rho: C::Fr = t.challenge("TripleIPA:rho");
    let triple_ipa_claim = TripleIpaClaims::<C> {
        unshifted_commitments: commitments.clone(),
        unshifted_evaluations: sc.evals[..FIRST_SHIFTED].to_vec(),
        unshifted_rho_powers: rho_powers(&rho, FIRST_SHIFTED, 0),
        shifted_commitments: TO_BE_SHIFTED.iter().map(|e| commitments[*e as usize].clone()).collect(),
        shifted_source_evaluations: TO_BE_SHIFTED.iter().map(|e| sc.evals[*e as usize].clone()).collect(),
        shifted_evaluations: sc.evals[FIRST_SHIFTED..].to_vec(),
        shifted_rho_powers: rho_powers(&rho, NUM_SHIFTED, FIRST_SHIFTED),
        multilinear_challenge: sc.challenge.clone(),
        univariate_commitment,
        univariate_challenge: batch.evaluation_point,
        univariate_evaluation: batch.evaluation,
    }
    .batch();

    // bb `compute_accumulated_result` recomputes the batched evaluation from scratch (it does not
    // reuse the claim batching): v^2 = v*v (aliased), v^3, v^4, then the left-associated sum
    // minus the masking evaluation, divided by x^{1 + TRACE_OFFSET}.
    let v_squared = v.mul_self();
    let v_cubed = v_squared.clone() * &v;
    let v_fourth = v_cubed.clone() * &v;
    let batched_eval_minus_masking = translation_evaluations[0].clone()
        + &(v.clone() * &translation_evaluations[1])
        + &(v_squared * &translation_evaluations[2])
        + &(v_cubed * &translation_evaluations[3])
        + &(v_fourth * &translation_evaluations[4])
        - &masking_term_eval;
    let mut x_power = x.clone();
    for _ in 0..TRACE_OFFSET {
        x_power *= &x;
    }
    let accumulated_result = batched_eval_minus_masking.div(&x_power);
    EccvmVerifierOutput {
        ok: sc.verified && libra_ok && translation_ok,
        triple_ipa_claim,
        evaluation_challenge_x: x,
        batching_challenge_v: v,
        accumulated_result,
    }
}
