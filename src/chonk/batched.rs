//! The joint MegaZK (hiding kernel) + Translator proof (bb `chonk/batched_honk_translator/`): one
//! committed ZK sumcheck of `CONST_TRANSLATOR_LOG_N` rounds over both circuits' relations, then one
//! Shplemini/KZG opening of all their polynomials. The MegaZK polynomials are zero-extended from
//! `2^16` to `2^17` variables.

use rayon::prelude::*;
use crate::base::codec::Transcriptable;
use crate::base::field::FieldLike;
use crate::base::group::{GroupLike, PairingPoints};
use crate::base::poly::Poly;
use crate::base::rng::Rng;
use crate::base::vk::Vk;
use crate::base::{Bn254, CommitmentKey, Fq, Fr, G1Affine, NativeTranscript};
use crate::goblin::translator::builder::{split_fq_into_limbs, ACCUMULATORS_BINARY_LIMBS_0};
use crate::goblin::translator::check::translator_relation_params;
use crate::goblin::translator::relations::TranslatorRelations;
use crate::goblin::translator::{
    complete_evaluations, fixed_vk, fixed_vk_hash, minicircuit_entities, Ent as TEnt, TranslatorPolys, CIRCUIT_SIZE, CONST_TRANSLATOR_LOG_N, FIRST_WIRE, FULL_CIRCUIT_ENTITIES, LOG_MINI_CIRCUIT_SIZE,
    NUM_MINICIRCUIT_EVALUATIONS, NUM_OP_QUEUE_WIRES, PCS_SHIFTED, PCS_TO_BE_SHIFTED, PCS_UNSHIFTED, RESULT_ROW,
};
use crate::honk::flavor::MEGA_ZK;
use crate::honk::oink::OinkOutput;
use crate::honk::oink_prover::build_gemini_masking_poly;
use crate::honk::pcs::{kzg_open, kzg_reduce_verify_batch_opening_claim, shplemini_prove, shplemini_verify, small_subgroup_ipa_prove, sumcheck_round_claims, ClaimBatcher};
use crate::honk::prover_instance::ProverInstance;
use crate::honk::relations::RelationParams;
use crate::honk::sumcheck::{
    alpha_powers, evaluate_univariate, full_relation_value, gate_separator_factor, row_disabling_main_factor, CommittedRounds, HonkRelations, RelationSet, RoundProver, ZkData,
};

pub const JOINT_LOG_N: usize = CONST_TRANSLATOR_LOG_N;

const CONCATENATED_LABELS: [&str; 5] = [
    "CONCATENATED_RANGE_CONSTRAINTS_0",
    "CONCATENATED_RANGE_CONSTRAINTS_1",
    "CONCATENATED_RANGE_CONSTRAINTS_2",
    "CONCATENATED_RANGE_CONSTRAINTS_3",
    "CONCATENATED_NON_RANGE",
];
const ORDERED_LABELS: [&str; 5] = [
    "ORDERED_RANGE_CONSTRAINTS_0",
    "ORDERED_RANGE_CONSTRAINTS_1",
    "ORDERED_RANGE_CONSTRAINTS_2",
    "ORDERED_RANGE_CONSTRAINTS_3",
    "ORDERED_RANGE_CONSTRAINTS_4",
];

/// The translator's part of the joint proof before sumcheck (bb `TranslatorProver::execute_preamble_round`,
/// `execute_wire_and_sorted_constraints_commitments_round`, `execute_grand_product_computation_round`).
/// Fills in the Gemini masking polynomial, `z_perm` and the shifts.
pub fn translator_oink_prove(polys: &mut TranslatorPolys, v: &Fq, x: &Fq, ck: &CommitmentKey, t: &mut NativeTranscript, rng: &mut dyn Rng) -> RelationParams<Fr> {
    t.add_to_hash_buffer("vk_hash", &fixed_vk_hash());
    let result_limbs: [Fr; 4] = std::array::from_fn(|i| polys.cols[FIRST_WIRE + ACCUMULATORS_BINARY_LIMBS_0 + i].coeffs[RESULT_ROW]);
    polys.cols[TEnt::gemini_masking_poly as usize] = build_gemini_masking_poly(CONST_TRANSLATOR_LOG_N, CIRCUIT_SIZE, CIRCUIT_SIZE, rng);
    t.send("Gemini:masking_poly_comm", &ck.commit(polys.col(TEnt::gemini_masking_poly)));
    let cols: Vec<usize> = (0..CONCATENATED_LABELS.len())
        .map(|g| TEnt::concatenated_range_constraints_0 as usize + g)
        .chain((0..ORDERED_LABELS.len()).map(|k| TEnt::ordered_range_constraints_0 as usize + k))
        .collect();
    let comms: Vec<_> = cols.par_iter().map(|c| ck.commit(&polys.cols[*c])).collect();
    for (label, c) in CONCATENATED_LABELS.iter().chain(ORDERED_LABELS.iter()).zip(&comms) {
        t.send(label, c);
    }
    let beta: Fr = t.challenge("beta");
    let gamma: Fr = t.challenge("gamma");
    let params = translator_relation_params(v, x, result_limbs, beta, gamma);
    polys.compute_grand_product(&params);
    t.send("Z_PERM", &ck.commit(polys.col(TEnt::z_perm)));
    params
}

/// bb `BatchedHonkTranslatorProver::prove`: the translator Oink, the joint sumcheck and the joint PCS.
/// The MegaZK Oink (`prove_oink` with `emit_alpha = false`) must already have run on `t`.
pub fn joint_prove(mega: &ProverInstance, mega_params: &RelationParams<Fr>, trans: &mut TranslatorPolys, v: &Fq, x: &Fq, ck: &CommitmentKey, t: &mut NativeTranscript, rng: &mut dyn Rng) {
    let trans_params = translator_oink_prove(trans, v, x, ck, t, rng);
    crate::base::timing::phase("  joint: translator oink");
    let layout = &mega.layout;
    let mega_rels = HonkRelations { flavor: &MEGA_ZK, layout };
    let trans_rels = TranslatorRelations;

    // --- joint sumcheck ---
    let alpha: Fr = t.challenge("Sumcheck:alpha");
    let betas: Vec<Fr> = t.dyadic_powers("Sumcheck:gate_challenge", JOINT_LOG_N);
    let alpha_kh = alpha.pow_u64(RelationSet::<Fr>::total_subrelations(&mega_rels) as u64);
    let mega_alphas = alpha_powers(&alpha, RelationSet::<Fr>::total_subrelations(&mega_rels) - 1);
    let trans_alphas = alpha_powers(&alpha, RelationSet::<Fr>::total_subrelations(&trans_rels) - 1);
    let mut zk = ZkData::<Bn254>::new(JOINT_LOG_N, t, ck, rng);
    let d = layout.batched_len;
    let mut mega_state = RoundProver::new(&mega.all_polys(), true, MEGA_ZK.trace_offset, mega.max_end_index, None);
    let mut trans_state = RoundProver::new(&trans.cols, false, 0, usize::MAX, None);
    let mut committed = CommittedRounds::<Bn254>::new();
    let mut partial_eval = Fr::one();
    let mut challenge = Vec::with_capacity(JOINT_LOG_N);
    let mut univariate = Vec::new();
    for round in 0..JOINT_LOG_N {
        let t0 = std::time::Instant::now();
        univariate = mega_state.univariate(&mega_rels, mega_params, &betas, &partial_eval, &mega_alphas, d);
        let t1 = std::time::Instant::now();
        let u_t = trans_state.univariate(&trans_rels, &trans_params, &betas, &partial_eval, &trans_alphas, d);
        if crate::honk::sumcheck::relation_stats_enabled() {
            eprintln!("[joint round {round}] mega {:.1} ms, translator {:.1} ms", (t1 - t0).as_secs_f64() * 1e3, t1.elapsed().as_secs_f64() * 1e3);
        }
        let libra = zk.round_univariate(round, d);
        for k in 0..d {
            univariate[k] += u_t[k] * alpha_kh + libra[k];
        }
        committed.process(round, &univariate, ck, t);
        let u: Fr = t.challenge(&format!("Sumcheck:u_{round}"));
        let t2 = std::time::Instant::now();
        mega_state.partially_evaluate(&u);
        let t3 = std::time::Instant::now();
        trans_state.partially_evaluate(&u);
        if crate::honk::sumcheck::relation_stats_enabled() {
            eprintln!("[joint round {round}] fold mega {:.1} ms, translator {:.1} ms", (t3 - t2).as_secs_f64() * 1e3, t3.elapsed().as_secs_f64() * 1e3);
        }
        if round == LOG_MINI_CIRCUIT_SIZE - 1 {
            let mini: Vec<Fr> = minicircuit_entities().map(|e| trans_state.current(e)).collect();
            t.send_vec("Sumcheck:minicircuit_evaluations", &mini);
        }
        zk.update(&u, round);
        partial_eval *= gate_separator_factor(&u, &betas[round]);
        challenge.push(u);
    }
    committed.finalize(&univariate, challenge.last().unwrap());
    t.send_vec("Sumcheck:evaluations", &mega_state.evals());
    let trans_full: Vec<Fr> = FULL_CIRCUIT_ENTITIES.iter().map(|e| trans_state.current(*e)).collect();
    t.send_vec("Sumcheck:evaluations_translator", &trans_full);
    let libra_evaluation = zk.claimed_evaluation();
    t.send("Libra:claimed_evaluation", &libra_evaluation);

    // --- joint PCS ---
    let libra = small_subgroup_ipa_prove::<Bn254>(&zk, &challenge, &libra_evaluation, ck, t, rng);
    let unshifted: Vec<&Poly> = PCS_UNSHIFTED.iter().map(|e| &trans.cols[*e]).chain(mega.polys.iter()).collect();
    let to_be_shifted: Vec<&Poly> = layout.shifted.iter().map(|e| mega.poly(*e)).chain(PCS_TO_BE_SHIFTED.iter().map(|e| &trans.cols[*e])).collect();
    let round_claims = sumcheck_round_claims(&committed.univariates, &committed.evaluations, &challenge);
    crate::base::timing::phase("  joint: sumcheck");
    let claim = shplemini_prove(&unshifted, &to_be_shifted, &challenge, ck, t, Some(&libra), &round_claims);
    kzg_open(claim, ck, t);
    crate::base::timing::phase("  joint: shplemini + kzg");
}

/// What the joint verifier needs besides the proofs: the ECCVM's translation challenges and result,
/// and the merged op-queue table commitments (from the merge protocol).
pub struct JointVerifierInputs {
    pub evaluation_input_x: Fq,
    pub batching_challenge_v: Fq,
    pub accumulated_result: Fq,
    pub op_queue_wire_commitments: [G1Affine; NUM_OP_QUEUE_WIRES],
}

pub struct JointVerification {
    pub pairing_points: PairingPoints<Bn254>,
    /// Sumcheck and Libra consistency checks.
    pub verified: bool,
}

/// bb `BatchedHonkTranslatorVerifier_::verify`. `mega_oink` is the output of `verify_oink` with
/// `emit_alpha = false` on the same transcript `t`; `joint_proof` is loaded here.
pub fn joint_verify(mega_vk: &Vk<Bn254>, mega_oink: &OinkOutput<Bn254>, joint_proof: &[Fr], inputs: &JointVerifierInputs, t: &mut NativeTranscript) -> JointVerification {
    t.load_proof(joint_proof);
    let layout = MEGA_ZK.layout();
    let mega_rels = HonkRelations { flavor: &MEGA_ZK, layout: &layout };
    let trans_rels = TranslatorRelations;
    let _ = mega_vk;

    // --- translator oink (bb `TranslatorVerifier_::receive_pre_sumcheck`) ---
    t.add_to_hash_buffer("vk_hash", &fixed_vk_hash());
    let masking: G1Affine = t.receive("Gemini:masking_poly_comm");
    let concatenated: Vec<G1Affine> = CONCATENATED_LABELS.iter().map(|l| t.receive(l)).collect();
    let ordered: Vec<G1Affine> = ORDERED_LABELS.iter().map(|l| t.receive(l)).collect();
    let beta: Fr = t.challenge("beta");
    let gamma: Fr = t.challenge("gamma");
    let trans_params = translator_relation_params(&inputs.batching_challenge_v, &inputs.evaluation_input_x, split_fq_into_limbs(&inputs.accumulated_result), beta, gamma);
    let z_perm: G1Affine = t.receive("Z_PERM");
    let opq = &inputs.op_queue_wire_commitments;
    // bb `get_pcs_unshifted` / `get_pcs_to_be_shifted` in commitment form
    let trans_unshifted: Vec<G1Affine> = [masking, fixed_vk(), opq[0], opq[1], opq[2], opq[3]]
        .into_iter()
        .chain(ordered.iter().copied())
        .chain([z_perm])
        .chain(concatenated.iter().copied())
        .collect();
    let trans_to_be_shifted: Vec<G1Affine> = [opq[1], opq[2], opq[3]]
        .into_iter()
        .chain(ordered.iter().copied())
        .chain([z_perm])
        .chain(concatenated.iter().copied())
        .collect();

    // --- joint sumcheck ---
    let alpha: Fr = t.challenge("Sumcheck:alpha");
    let alpha_kh = alpha.pow_u64(RelationSet::<Fr>::total_subrelations(&mega_rels) as u64);
    let mega_alphas = alpha_powers(&alpha, RelationSet::<Fr>::total_subrelations(&mega_rels) - 1);
    let trans_alphas = alpha_powers(&alpha, RelationSet::<Fr>::total_subrelations(&trans_rels) - 1);
    let gate_challenges: Vec<Fr> = t.dyadic_powers("Sumcheck:gate_challenge", JOINT_LOG_N);
    let mut libra_commitments: Vec<G1Affine> = vec![t.receive("Libra:concatenation_commitment")];
    let libra_total_sum: Fr = t.receive("Libra:Sum");
    let libra_challenge: Fr = t.challenge("Libra:Challenge");
    let target_sum = libra_total_sum * libra_challenge;
    let mut challenge = Vec::with_capacity(JOINT_LOG_N);
    let mut partial_eval = Fr::one();
    let mut round_commitments = Vec::with_capacity(JOINT_LOG_N);
    let mut round_evaluations: Vec<[Fr; 3]> = Vec::with_capacity(JOINT_LOG_N);
    let mut minicircuit = Vec::new();
    for round in 0..JOINT_LOG_N {
        round_commitments.push(t.receive::<G1Affine>(&format!("Sumcheck:univariate_comm_{round}")));
        let e0: Fr = t.receive(&format!("Sumcheck:univariate_{round}_eval_0"));
        let e1: Fr = t.receive(&format!("Sumcheck:univariate_{round}_eval_1"));
        round_evaluations.push([e0, e1, Fr::zero()]);
        let u: Fr = t.challenge(&format!("Sumcheck:u_{round}"));
        partial_eval *= gate_separator_factor(&u, &gate_challenges[round]);
        challenge.push(u);
        if round == LOG_MINI_CIRCUIT_SIZE - 1 {
            minicircuit = t.receive_vec("Sumcheck:minicircuit_evaluations", NUM_MINICIRCUIT_EVALUATIONS);
        }
    }
    let mega_evals: Vec<Fr> = t.receive_vec("Sumcheck:evaluations", layout.num_all());
    let trans_full: Vec<Fr> = t.receive_vec("Sumcheck:evaluations_translator", FULL_CIRCUIT_ENTITIES.len());
    let (trans_evals, concat_shift_evals) = complete_evaluations(&trans_full, &minicircuit, &challenge);

    let main_factor = row_disabling_main_factor(&challenge);
    let offset_factor = Fr::one() - main_factor;
    let frv_mega = full_relation_value(&mega_rels, &mega_evals, &mega_oink.params, &partial_eval, &mega_alphas, &main_factor, &offset_factor);
    let frv_trans = full_relation_value(&trans_rels, &trans_evals, &trans_params, &partial_eval, &trans_alphas, &Fr::one(), &Fr::zero());
    let mut full_value = frv_mega + alpha_kh * frv_trans;
    let libra_evaluation: Fr = t.receive("Libra:claimed_evaluation");
    libra_commitments.push(t.receive("Libra:grand_sum_commitment"));
    libra_commitments.push(t.receive("Libra:quotient_commitment"));
    full_value += libra_evaluation * libra_challenge;
    // committed sumcheck: the first sum is checked here, the chain and the last value through the openings
    let sumcheck_verified = round_evaluations[0][0] + round_evaluations[0][1] == target_sum;
    for i in 1..JOINT_LOG_N {
        round_evaluations[i - 1][2] = round_evaluations[i][0] + round_evaluations[i][1];
    }
    round_evaluations[JOINT_LOG_N - 1][2] = full_value;
    let _ = evaluate_univariate::<Fr>;

    // --- joint PCS ---
    let n_mega_unshifted = layout.num_unshifted();
    let trans_shifted_evals = PCS_SHIFTED.iter().map(|e| trans_evals[*e]).chain(concat_shift_evals);
    let batcher = ClaimBatcher::<Bn254> {
        unshifted_comms: trans_unshifted.iter().copied().chain(mega_oink.commitments.iter().copied()).collect(),
        unshifted_evals: PCS_UNSHIFTED.iter().map(|e| trans_evals[*e]).chain(mega_evals[..n_mega_unshifted].iter().copied()).collect(),
        shifted_comms: layout.shifted.iter().map(|e| mega_oink.commitments[layout.idx(*e)]).chain(trans_to_be_shifted).collect(),
        shifted_evals: mega_evals[n_mega_unshifted..].iter().copied().chain(trans_shifted_evals).collect(),
    };
    // bb `REPEATED_COMMITMENTS`: indices into [unshifted..., shifted...]
    let n_unshifted = batcher.unshifted_comms.len();
    let n_mega_shifted = layout.shifted.len();
    let mut repeated: Vec<(usize, usize)> = (0..PCS_TO_BE_SHIFTED.len()).map(|j| (2 + 1 + j, n_unshifted + n_mega_shifted + j)).collect();
    repeated.extend(layout.shifted.iter().enumerate().map(|(j, e)| (PCS_UNSHIFTED.len() + layout.idx(*e), n_unshifted + j)));
    let shplemini = shplemini_verify::<Bn254>(
        true,
        true,
        &batcher,
        &challenge,
        &G1Affine::one(&()),
        t,
        &repeated,
        &libra_commitments,
        &libra_evaluation,
        &round_commitments,
        &round_evaluations,
    );
    let msm_size = shplemini.claim.commitments.len() + 1;
    let pairing_points = kzg_reduce_verify_batch_opening_claim::<Bn254>(shplemini.claim, t, msm_size);
    JointVerification {
        pairing_points,
        verified: sumcheck_verified && shplemini.consistency_checked,
    }
}

/// The number of fields in the MegaZK Oink proof beyond the public inputs
/// (bb `ProofLength::Oink<MegaZKFlavor>::LENGTH_WITHOUT_PUB_INPUTS`).
pub fn mega_zk_oink_length_without_public_inputs() -> usize {
    let layout = MEGA_ZK.layout();
    (layout.num_witness + layout.num_masking) * <G1Affine as Transcriptable<Fr>>::num_fields()
}
