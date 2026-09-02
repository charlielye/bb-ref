//! The ECCVM prover (bb `eccvm/eccvm_prover.cpp`): commits to the trace over Grumpkin, runs the
//! committed ZK sumcheck, then opens everything — the Libra and translation masking terms, the
//! per-round sumcheck univariates and a masking polynomial — with one Shplonk batch whose final
//! claim is proven together with the multilinear claims by a TripleIPA on its own transcript.

use super::check::eccvm_relation_params;
use super::relations::EccvmRelations;
use super::trace::TRANSLATION_ENTITIES;
use super::*;
use crate::base::field::FieldLike;
use crate::base::group::Curve;
use crate::base::poly::Polynomial;
use crate::base::rng::{random_field, Rng};
use crate::base::{Grumpkin, GrumpkinKey, NativeTranscript};
use crate::circuit::op_queue::EccOpQueue;
use crate::goblin::ipa::{rho_powers, triple_ipa_prove, TripleIpaClaims, TripleIpaInput};
use crate::honk::pcs::{
    eccvm_challenge_coeffs, shplonk_batch_claim, shplonk_prove, small_ipa_prover_claims, small_subgroup_ipa_prove,
    small_subgroup_ipa_prove_core, LibraPolys, ProverClaim, VerifierOpeningClaim,
};
use crate::honk::sumcheck::{interpolate_on_subgroup, prove_sumcheck, subgroup_domain, SumcheckSpec, ZkData};
use ark_ec::{CurveGroup, VariableBaseMSM};
use rayon::prelude::*;

pub const NUM_TRANSLATION_EVALUATIONS: usize = 5;
pub const TRANSLATION_LABELS: [&str; NUM_TRANSLATION_EVALUATIONS] = [
    "Translation:op",
    "Translation:Px",
    "Translation:Py",
    "Translation:z1",
    "Translation:z2",
];
const POW_MASK_SIZE: usize = 8;

pub fn sumcheck_spec() -> SumcheckSpec {
    SumcheckSpec {
        witness_end: usize::MAX,
        active_prefix_end: None,
        virtual_log_n: CONST_ECCVM_LOG_N,
        has_zk: true,
        row_disabling: true,
        trace_offset: TRACE_OFFSET,
        committed: true,
        batched_len: 24,
        num_entities: NUM_ALL_ENTITIES,
        shifted_sources: vec![],
    }
}

/// What the Translator needs from the ECCVM prover, plus the TripleIPA proof.
pub struct EccvmProverOutput {
    pub ipa_proof: Vec<Fr>,
    pub evaluation_challenge_x: Fq,
    pub batching_challenge_v: Fq,
}

/// The witnesses in the order bb's proving key allocates (and masks) them: transcript, precompute
/// and MSM wires, lookup read counts, the to-be-shifted wires by group, the accumulators, `z_perm`,
/// `lookup_inverses` (bb `ECCVMFlavor::ProverPolynomials` constructor).
const MASKING_ORDER: [usize; 88] = [
    5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 50, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
    64, // transcript wires
    17, 18, 19, 20, 21, 22, 23, 24, 25, // precompute wires
    26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49,
    65, // msm wires
    51, 52, // lookup read counts
    66, 67, 85, // shifted transcript wires
    68, 69, 70, 71, 72, 73, 84, 86, 87, // shifted precompute wires
    74, 75, 76, 77, 78, 79, 80, 81, 82, 83, // shifted msm wires
    88, 89, 90, // accumulators
    91, 92, // z_perm, lookup_inverses
];

impl EccvmPolys {
    /// bb `Polynomial::add_masking`: random values on the sumcheck-disabled rows 1..3 of every witness,
    /// drawn in bb's allocation order.
    pub fn add_masking(&mut self, rng: &mut dyn Rng) {
        for e in MASKING_ORDER {
            for r in 1..TRACE_OFFSET {
                self.cols[e].coeffs[r] = random_field(rng);
            }
        }
    }
}

fn msm(points: &[GrumpkinAffine], scalars: &[Fq]) -> GrumpkinAffine {
    crate::base::msm::msm(points, scalars).into_affine()
}

/// bb `ECCVMProver::construct_proof` on `t`; the TripleIPA proof is returned separately.
pub fn eccvm_prove(q: &EccOpQueue, ck: &GrumpkinKey, t: &mut NativeTranscript, rng: &mut dyn Rng) -> EccvmProverOutput {
    let mut polys = EccvmPolys::from_op_queue(q);
    crate::base::timing::phase(&format!(
        "  eccvm: trace polys ({} of {} rows)",
        polys.num_rows,
        polys.size()
    ));
    polys.add_masking(rng);
    let n = FIXED_SIZE;

    t.add_to_hash_buffer("vk_hash", &fixed_vk_hash());
    polys.cols[Ent::gemini_masking_poly as usize] =
        Polynomial::from_coeffs((0..n).map(|_| random_field(rng)).collect());
    let mut commitments: Vec<GrumpkinAffine> = vec![GrumpkinAffine::identity(); FIRST_SHIFTED];
    commitments[0] = ck.commit(polys.col(Ent::gemini_masking_poly));
    t.send("Gemini:masking_poly_comm", &commitments[0]);
    commitments[1..=NUM_PRECOMPUTED].copy_from_slice(&fixed_vk());
    let witness_range = NUM_PRECOMPUTED + 1..FIRST_SHIFTED - 2;
    let witness_polys: Vec<_> = witness_range.clone().map(|e| &polys.cols[e]).collect();
    let comms: Vec<GrumpkinAffine> = ck.batch_commit(&witness_polys);
    for (e, c) in witness_range.zip(comms) {
        commitments[e] = c;
        t.send(&label(ent(e)), &commitments[e]);
    }

    let [beta, gamma]: [Fq; 2] = t.challenges(&["beta", "gamma"]).try_into().unwrap();
    let params = eccvm_relation_params(beta, gamma);
    polys.compute_derived(&params);
    for e in [Ent::lookup_inverses, Ent::z_perm] {
        commitments[e as usize] = ck.commit(polys.col(e));
        t.send(&label(e), &commitments[e as usize]);
    }

    let alpha: Fq = t.challenge("Sumcheck:alpha");
    let gate_challenges: Vec<Fq> = t.dyadic_powers("Sumcheck:gate_challenge", CONST_ECCVM_LOG_N);
    let mut zk = ZkData::<Grumpkin>::new(CONST_ECCVM_LOG_N, t, ck, rng);
    crate::base::timing::phase("  eccvm: oink commits + derived polys");
    let mut spec = sumcheck_spec();
    spec.active_prefix_end = Some(polys.num_rows);
    let sc = prove_sumcheck::<Grumpkin>(
        &EccvmRelations,
        &spec,
        &polys.cols,
        t,
        &alpha,
        &gate_challenges,
        &params,
        Some(&mut zk),
        Some(ck),
    );
    crate::base::timing::phase("  eccvm: sumcheck");

    // Every univariate opening claim, paired with the commitment the verifier holds for it.
    let mut claims: Vec<ProverClaim<Fq>> = Vec::new();
    let mut claim_commitments: Vec<GrumpkinAffine> = Vec::new();
    let add_small_ipa_claims = |polys: &LibraPolys<Fq>,
                                r: &Fq,
                                prefix: &str,
                                t: &mut NativeTranscript,
                                claims: &mut Vec<ProverClaim<Fq>>,
                                comms: &mut Vec<GrumpkinAffine>| {
        let witness_commitments: [GrumpkinAffine; 3] = std::array::from_fn(|i| ck.commit(&polys.0[i]));
        for (i, claim) in small_ipa_prover_claims::<Grumpkin>(polys, r, prefix, t)
            .into_iter()
            .enumerate()
        {
            comms.push(witness_commitments[crate::honk::pcs::small_ipa_commitment_index(i)]);
            claims.push(claim);
        }
    };

    // Libra
    let libra_polys = small_subgroup_ipa_prove::<Grumpkin>(&zk, &sc.challenge, &sc.libra_evaluation, ck, t, rng);
    let libra_r: Fq = t.challenge("Libra:small_ipa_evaluation_challenge");
    add_small_ipa_claims(&libra_polys, &libra_r, "Libra:", t, &mut claims, &mut claim_commitments);

    // Translation: the first TRACE_OFFSET rows of the five translation columns, concatenated over the subgroup.
    let g = Fq::constant(Grumpkin::subgroup_generator());
    let subgroup_size = Grumpkin::SUBGROUP_SIZE;
    let mut concatenated_lagrange = vec![Fq::from(0u64); subgroup_size];
    for (p, e) in TRANSLATION_ENTITIES.iter().enumerate() {
        for idx in 0..TRACE_OFFSET {
            concatenated_lagrange[p * TRACE_OFFSET + idx] = polys.col(*e).coeffs[idx];
        }
    }
    let mut concatenated = interpolate_on_subgroup(&concatenated_lagrange, &g);
    concatenated.coeffs.resize(subgroup_size + 2, Fq::from(0u64));
    let masking: [Fq; 2] = [random_field(rng), random_field(rng)];
    for (i, m) in masking.iter().enumerate() {
        concatenated.coeffs[i] -= m;
        concatenated.coeffs[subgroup_size + i] += m;
    }
    t.send(
        "Translation:concatenated_masking_term_commitment",
        &ck.commit(&concatenated),
    );
    let x: Fq = t.challenge("Translation:evaluation_challenge_x");
    let translation_evaluations: Vec<Fq> = TRANSLATION_ENTITIES
        .iter()
        .zip(TRANSLATION_LABELS)
        .map(|(e, l)| {
            let v = polys.col(*e).evaluate(&x);
            t.send(l, &v);
            v
        })
        .collect();
    let v: Fq = t.challenge("Translation:batching_challenge_v");
    let f_lagrange = eccvm_challenge_coeffs::<Grumpkin>(&x, &v, NUM_TRANSLATION_EVALUATIONS, TRACE_OFFSET);
    let claimed_inner_product: Fq = concatenated_lagrange.iter().zip(&f_lagrange).map(|(a, b)| *a * b).sum();
    t.send("Translation:masking_term_eval", &claimed_inner_product);
    let translation_polys = small_subgroup_ipa_prove_core::<Grumpkin>(
        &concatenated,
        &concatenated_lagrange,
        &f_lagrange,
        &claimed_inner_product,
        "Translation:",
        ck,
        t,
        rng,
    );
    let translation_r: Fq = t.challenge("Translation:small_ipa_evaluation_challenge");
    add_small_ipa_claims(
        &translation_polys,
        &translation_r,
        "Translation:",
        t,
        &mut claims,
        &mut claim_commitments,
    );
    let v_powers = rho_powers(&v, NUM_TRANSLATION_EVALUATIONS, 0);
    let mut batched_translation = Polynomial::zero(n);
    for (e, s) in TRANSLATION_ENTITIES.iter().zip(&v_powers) {
        batched_translation.add_scaled(polys.col(*e), s);
    }
    let batched_evaluation = translation_evaluations.iter().zip(&v_powers).map(|(a, b)| *a * b).sum();
    claims.push(ProverClaim {
        poly: batched_translation,
        challenge: x,
        evaluation: batched_evaluation,
        gemini_fold: false,
    });
    let translation_commitments: Vec<GrumpkinAffine> =
        TRANSLATION_ENTITIES.iter().map(|e| commitments[*e as usize]).collect();
    claim_commitments.push(msm(&translation_commitments, &v_powers));

    // Sumcheck round univariates at 0, 1, u_i
    for (i, poly) in sc.round_univariates.iter().enumerate() {
        for (point, eval) in [
            (Fq::from(0u64), sc.round_evaluations[i][0]),
            (Fq::from(1u64), sc.round_evaluations[i][1]),
            (sc.challenge[i], sc.round_evaluations[i][2]),
        ] {
            claims.push(ProverClaim {
                poly: poly.clone(),
                challenge: point,
                evaluation: eval,
                gemini_fold: false,
            });
            claim_commitments.push(sc.round_commitments[i]);
        }
    }

    // Masking polynomial for the powers tensor of the TripleIPA
    let mask = Polynomial::from_coeffs((0..POW_MASK_SIZE).map(|_| random_field(rng)).collect());
    let mask_commitment = ck.commit(&mask);
    t.send("TripleIPA:pow_mask_commitment", &mask_commitment);
    let mask_challenge: Fq = t.challenge("TripleIPA:pow_mask_challenge");
    let mask_evaluation = mask.evaluate(&mask_challenge);
    t.send("TripleIPA:pow_mask_evaluation", &mask_evaluation);
    claims.push(ProverClaim {
        poly: mask,
        challenge: mask_challenge,
        evaluation: mask_evaluation,
        gemini_fold: false,
    });
    claim_commitments.push(mask_commitment);

    // Shplonk over all univariate claims; the verifier's view of the batched claim is its commitment.
    let verifier_claims: Vec<VerifierOpeningClaim<Grumpkin>> = claims
        .iter()
        .zip(&claim_commitments)
        .map(|(c, comm)| VerifierOpeningClaim {
            commitment: *comm,
            challenge: c.challenge,
            evaluation: c.evaluation,
        })
        .collect();
    let shplonk = shplonk_prove::<Grumpkin>(0, &claims, &[], &[], ck, t);
    let batch = shplonk_batch_claim::<Grumpkin>(
        &verifier_claims,
        shplonk.quotient_commitment,
        &shplonk.nu,
        &shplonk.z,
        ck.points[0],
    );
    let univariate_commitment = msm(&batch.commitments, &batch.scalars);

    // TripleIPA on its own transcript
    let rho: Fq = t.challenge("TripleIPA:rho");
    let input = TripleIpaInput {
        claims: TripleIpaClaims {
            unshifted_commitments: commitments.clone(),
            unshifted_evaluations: sc.evals[..FIRST_SHIFTED].to_vec(),
            unshifted_rho_powers: rho_powers(&rho, FIRST_SHIFTED, 0),
            shifted_commitments: TO_BE_SHIFTED.iter().map(|e| commitments[*e as usize]).collect(),
            shifted_source_evaluations: TO_BE_SHIFTED.iter().map(|e| sc.evals[*e as usize]).collect(),
            shifted_evaluations: sc.evals[FIRST_SHIFTED..].to_vec(),
            shifted_rho_powers: rho_powers(&rho, NUM_SHIFTED, FIRST_SHIFTED),
            multilinear_challenge: sc.challenge.clone(),
            univariate_commitment,
            univariate_challenge: shplonk.z,
            univariate_evaluation: Fq::from(0u64),
        },
        unshifted_polys: polys.cols[..FIRST_SHIFTED].to_vec(),
        shifted_polys: TO_BE_SHIFTED.iter().map(|e| polys.col(*e).clone()).collect(),
        univariate_poly: shplonk.claim.poly,
    };
    let mut ipa_transcript = NativeTranscript::new();
    crate::base::timing::phase("  eccvm: shplemini + translation claims");
    triple_ipa_prove(ck, &input, &mut ipa_transcript);
    crate::base::timing::phase("  eccvm: triple ipa");
    let _ = subgroup_domain::<Grumpkin>;
    EccvmProverOutput {
        ipa_proof: ipa_transcript.export_proof(),
        evaluation_challenge_x: x,
        batching_challenge_v: v,
    }
}
