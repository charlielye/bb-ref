//! The ECCVM verifier (bb `eccvm/eccvm_verifier.cpp`): reduces the proof on the (shared) transcript
//! to one TripleIPA claim, which the caller discharges with the IPA proof.

use super::check::eccvm_relation_params;
use super::prover::{sumcheck_spec, NUM_TRANSLATION_EVALUATIONS, TRANSLATION_LABELS};
use super::relations::EccvmRelations;
use super::trace::TRANSLATION_ENTITIES;
use super::*;
use crate::base::field::FieldLike;
use crate::base::{Grumpkin, GrumpkinKey, NativeTranscript};
use crate::goblin::ipa::{rho_powers, TripleIpaClaim, TripleIpaClaims};
use crate::honk::pcs::{check_libra_evaluations_consistency, eccvm_challenge_coeffs, shplonk_verify, small_ipa_check_consistency, small_ipa_verifier_claims, VerifierOpeningClaim};
use crate::honk::sumcheck::verify_sumcheck;
use ark_ec::{CurveGroup, VariableBaseMSM};

pub struct EccvmVerifierOutput {
    /// Sumcheck, Libra and translation consistency checks passed.
    pub ok: bool,
    pub triple_ipa_claim: TripleIpaClaim,
    pub evaluation_challenge_x: Fq,
    pub batching_challenge_v: Fq,
    /// The batched translation evaluation with the masking term removed, divided by `x^{TRACE_OFFSET+1}`.
    pub accumulated_result: Fq,
}

fn msm(points: &[GrumpkinAffine], scalars: &[Fq]) -> GrumpkinAffine {
    ark_grumpkin::Projective::msm_unchecked(points, scalars).into_affine()
}

/// bb `ECCVMVerifier_::reduce_to_triple_ipa_claim`; the proof must already be loaded into `t`.
pub fn eccvm_verify(t: &mut NativeTranscript) -> EccvmVerifierOutput {
    t.add_to_hash_buffer("vk_hash", &fixed_vk_hash());
    let mut commitments: Vec<GrumpkinAffine> = vec![GrumpkinAffine::identity(); FIRST_SHIFTED];
    commitments[0] = t.receive("Gemini:masking_poly_comm");
    commitments[1..=NUM_PRECOMPUTED].copy_from_slice(&fixed_vk());
    for e in NUM_PRECOMPUTED + 1..FIRST_SHIFTED - 2 {
        commitments[e] = t.receive(&label(ent(e)));
    }
    let [beta, gamma]: [Fq; 2] = t.challenges(&["beta", "gamma"]).try_into().unwrap();
    let params = eccvm_relation_params(beta, gamma);
    for e in [Ent::lookup_inverses, Ent::z_perm] {
        commitments[e as usize] = t.receive(&label(e));
    }
    let alpha: Fq = t.challenge("Sumcheck:alpha");
    let gate_challenges: Vec<Fq> = t.dyadic_powers("Sumcheck:gate_challenge", CONST_ECCVM_LOG_N);
    let mut libra_commitments = [GrumpkinAffine::identity(); 3];
    libra_commitments[0] = t.receive("Libra:concatenation_commitment");
    let sc = verify_sumcheck::<Grumpkin>(&EccvmRelations, &sumcheck_spec(), t, &alpha, &params, &gate_challenges);
    libra_commitments[1] = t.receive("Libra:grand_sum_commitment");
    libra_commitments[2] = t.receive("Libra:quotient_commitment");

    let mut claims: Vec<VerifierOpeningClaim<Grumpkin>> = Vec::new();
    let libra_r: Fq = t.challenge("Libra:small_ipa_evaluation_challenge");
    let libra_claims = small_ipa_verifier_claims::<Grumpkin>(&libra_commitments, &libra_r, "Libra:", t);
    let libra_evals: [Fq; 5] = std::array::from_fn(|i| libra_claims[i].evaluation);
    let libra_ok = check_libra_evaluations_consistency::<Grumpkin>(&libra_evals, &libra_r, &sc.challenge, &sc.libra_evaluation);
    claims.extend(libra_claims);

    // Translation
    let mut translation_commitments = [GrumpkinAffine::identity(); 3];
    translation_commitments[0] = t.receive("Translation:concatenated_masking_term_commitment");
    let x: Fq = t.challenge("Translation:evaluation_challenge_x");
    let translation_evaluations: Vec<Fq> = TRANSLATION_LABELS.iter().map(|l| t.receive(l)).collect();
    let v: Fq = t.challenge("Translation:batching_challenge_v");
    let masking_term_eval: Fq = t.receive("Translation:masking_term_eval");
    translation_commitments[1] = t.receive("Translation:grand_sum_commitment");
    translation_commitments[2] = t.receive("Translation:quotient_commitment");
    let translation_r: Fq = t.challenge("Translation:small_ipa_evaluation_challenge");
    let translation_claims = small_ipa_verifier_claims::<Grumpkin>(&translation_commitments, &translation_r, "Translation:", t);
    let translation_evals: Vec<Fq> = translation_claims.iter().map(|c| c.evaluation).collect();
    let translation_ok = small_ipa_check_consistency::<Grumpkin>(&translation_evals, &translation_r, &eccvm_challenge_coeffs::<Grumpkin>(&x, &v, NUM_TRANSLATION_EVALUATIONS, TRACE_OFFSET), &masking_term_eval);
    claims.extend(translation_claims);
    let v_powers = rho_powers(&v, NUM_TRANSLATION_EVALUATIONS, 0);
    let batched_evaluation: Fq = translation_evaluations.iter().zip(&v_powers).map(|(a, b)| *a * b).sum();
    let translation_column_commitments: Vec<GrumpkinAffine> = TRANSLATION_ENTITIES.iter().map(|e| commitments[*e as usize]).collect();
    claims.push(VerifierOpeningClaim { commitment: msm(&translation_column_commitments, &v_powers), challenge: x, evaluation: batched_evaluation });

    // Sumcheck round univariates at 0, 1, u_i
    for (i, comm) in sc.round_commitments.iter().enumerate() {
        for (point, eval) in [(Fq::from(0u64), sc.round_evaluations[i][0]), (Fq::from(1u64), sc.round_evaluations[i][1]), (sc.challenge[i], sc.round_evaluations[i][2])] {
            claims.push(VerifierOpeningClaim { commitment: *comm, challenge: point, evaluation: eval });
        }
    }
    let mask_commitment: GrumpkinAffine = t.receive("TripleIPA:pow_mask_commitment");
    let mask_challenge: Fq = t.challenge("TripleIPA:pow_mask_challenge");
    let mask_evaluation: Fq = t.receive("TripleIPA:pow_mask_evaluation");
    claims.push(VerifierOpeningClaim { commitment: mask_commitment, challenge: mask_challenge, evaluation: mask_evaluation });

    let g1_identity = GrumpkinKey::new(1).points[0];
    let batch = shplonk_verify::<Grumpkin>(&claims, g1_identity, t);
    let univariate_commitment = msm(&batch.commitments, &batch.scalars);

    let rho: Fq = t.challenge("TripleIPA:rho");
    let triple_ipa_claim = TripleIpaClaims {
        unshifted_commitments: commitments.clone(),
        unshifted_evaluations: sc.evals[..FIRST_SHIFTED].to_vec(),
        unshifted_rho_powers: rho_powers(&rho, FIRST_SHIFTED, 0),
        shifted_commitments: TO_BE_SHIFTED.iter().map(|e| commitments[*e as usize]).collect(),
        shifted_source_evaluations: TO_BE_SHIFTED.iter().map(|e| sc.evals[*e as usize]).collect(),
        shifted_evaluations: sc.evals[FIRST_SHIFTED..].to_vec(),
        shifted_rho_powers: rho_powers(&rho, NUM_SHIFTED, FIRST_SHIFTED),
        multilinear_challenge: sc.challenge.clone(),
        univariate_commitment,
        univariate_challenge: batch.evaluation_point,
        univariate_evaluation: Fq::from(0u64),
    }
    .batch();

    let x_power = x.pow_u64(TRACE_OFFSET as u64 + 1);
    let accumulated_result = (batched_evaluation - masking_term_eval) * x_power.invert();
    EccvmVerifierOutput { ok: sc.verified && libra_ok && translation_ok, triple_ipa_claim, evaluation_challenge_x: x, batching_challenge_v: v, accumulated_result }
}
