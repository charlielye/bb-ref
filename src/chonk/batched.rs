//! The joint MegaZK (hiding kernel) + Translator proof (bb `chonk/batched_honk_translator/`): one
//! committed ZK sumcheck of `CONST_TRANSLATOR_LOG_N` rounds over both circuits' relations, then one
//! Shplemini/KZG opening of all their polynomials. The MegaZK polynomials are zero-extended from
//! `2^16` to `2^17` variables.

use crate::base::codec::Transcriptable;
use crate::base::field::FieldLike;
use crate::base::field::{from_u256, u256};
use crate::base::group::{Curve, GroupLike, PairingPoints};
use crate::base::poly::Poly;
use crate::base::rng::Rng;
use crate::base::transcript::Transcript;
use crate::base::vk::Vk;
use crate::base::{Bn254, CommitmentKey, Fq, Fr, G1Affine, NativeTranscript};
use crate::goblin::translator::builder::{split_fq_into_limbs, ACCUMULATORS_BINARY_LIMBS_0};
use crate::goblin::translator::check::translator_relation_params;
use crate::goblin::translator::relations::TranslatorRelations;
use crate::goblin::translator::{
    complete_evaluations, fixed_vk, fixed_vk_hash, minicircuit_entities, Ent as TEnt, TranslatorPolys, CIRCUIT_SIZE,
    CONST_TRANSLATOR_LOG_N, FIRST_WIRE, FULL_CIRCUIT_ENTITIES, LOG_MINI_CIRCUIT_SIZE, NUM_MINICIRCUIT_EVALUATIONS,
    NUM_OP_QUEUE_WIRES, PCS_SHIFTED, PCS_TO_BE_SHIFTED, PCS_UNSHIFTED, RESULT_ROW,
};
use crate::honk::flavor::MEGA_ZK;
use crate::honk::oink::OinkOutput;
use crate::honk::oink_prover::build_gemini_masking_poly;
use crate::honk::pcs::{
    kzg_open, kzg_reduce_verify_batch_opening_claim, shplemini_prove, shplemini_verify, small_subgroup_ipa_prove,
    sumcheck_round_claims, ClaimBatcher,
};
use crate::honk::prover_instance::ProverInstance;
use crate::honk::relations::RelationParams;
use crate::honk::sumcheck::{
    alpha_powers, evaluate_univariate, full_relation_value, gate_separator_factor, CommittedRounds, HonkRelations,
    RelationSet, RoundProver, ZkData,
};
use rayon::prelude::*;

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
pub fn translator_oink_prove(
    polys: &mut TranslatorPolys,
    v: &Fq,
    x: &Fq,
    ck: &CommitmentKey,
    t: &mut NativeTranscript,
    rng: &mut dyn Rng,
) -> RelationParams<Fr> {
    t.add_to_hash_buffer("vk_hash", &fixed_vk_hash());
    let result_limbs: [Fr; 4] =
        std::array::from_fn(|i| polys.cols[FIRST_WIRE + ACCUMULATORS_BINARY_LIMBS_0 + i].coeffs[RESULT_ROW]);
    polys.cols[TEnt::gemini_masking_poly as usize] =
        build_gemini_masking_poly(CONST_TRANSLATOR_LOG_N, CIRCUIT_SIZE, CIRCUIT_SIZE, rng);
    t.send(
        "Gemini:masking_poly_comm",
        &ck.commit(polys.col(TEnt::gemini_masking_poly)),
    );
    let cols: Vec<usize> = (0..CONCATENATED_LABELS.len())
        .map(|g| TEnt::concatenated_range_constraints_0 as usize + g)
        .chain((0..ORDERED_LABELS.len()).map(|k| TEnt::ordered_range_constraints_0 as usize + k))
        .collect();
    let col_polys: Vec<_> = cols.iter().map(|c| &polys.cols[*c]).collect();
    let comms: Vec<_> = ck.batch_commit(&col_polys);
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
pub fn joint_prove(
    mega: &ProverInstance,
    mega_params: &RelationParams<Fr>,
    trans: &mut TranslatorPolys,
    v: &Fq,
    x: &Fq,
    ck: &CommitmentKey,
    t: &mut NativeTranscript,
    rng: &mut dyn Rng,
) {
    let trans_params = translator_oink_prove(trans, v, x, ck, t, rng);
    crate::base::timing::phase("  joint: translator oink");
    let layout = &mega.layout;
    let mega_rels = HonkRelations {
        flavor: &MEGA_ZK,
        layout,
    };
    let trans_rels = TranslatorRelations;

    // --- joint sumcheck ---
    let alpha: Fr = t.challenge("Sumcheck:alpha");
    let betas: Vec<Fr> = t.dyadic_powers("Sumcheck:gate_challenge", JOINT_LOG_N);
    let alpha_kh = {
        let mut p = Fr::one();
        for _ in 0..RelationSet::<Fr>::total_subrelations(&mega_rels) {
            p *= alpha;
        }
        p
    };
    let mega_alphas = alpha_powers(&alpha, RelationSet::<Fr>::total_subrelations(&mega_rels) - 1);
    let trans_alphas = alpha_powers(&alpha, RelationSet::<Fr>::total_subrelations(&trans_rels) - 1);
    let mut zk = ZkData::<Bn254>::new(JOINT_LOG_N, t, ck, rng);
    let d = layout.batched_len;
    let mega_shifted: Vec<usize> = layout.shifted.iter().map(|e| layout.idx(*e)).collect();
    let mut mega_state = RoundProver::new(
        mega.dyadic_size,
        &mega.polys,
        &mega_shifted,
        true,
        MEGA_ZK.trace_offset,
        mega.max_end_index,
        None,
    );
    // Shift entities (the 104.. tail, in source order) are read as views one row ahead of their
    // sources instead of materialized copies.
    let trans_shift_sources: Vec<usize> = (13..=98).collect();
    let mut trans_state = RoundProver::new(
        CIRCUIT_SIZE,
        &trans.cols[..crate::goblin::translator::FIRST_SHIFTED],
        &trans_shift_sources,
        false,
        0,
        usize::MAX,
        None,
    );
    let mut committed = CommittedRounds::<Bn254>::new();
    let mut partial_eval = Fr::one();
    let mut challenge = Vec::with_capacity(JOINT_LOG_N);
    let mut univariate = Vec::new();
    for round in 0..JOINT_LOG_N {
        let t0 = std::time::Instant::now();
        univariate = mega_state.univariate(&mega_rels, mega_params, &betas, &partial_eval, &mega_alphas, d);
        let t1 = std::time::Instant::now();
        let u_t = trans_state.univariate(&trans_rels, &trans_params, &betas, &partial_eval, &trans_alphas, d);
        if std::env::var_os("BBREF_TIMING").is_some() {
            eprintln!(
                "[joint round {round}] mega {:.1} ms, translator {:.1} ms",
                (t1 - t0).as_secs_f64() * 1e3,
                t1.elapsed().as_secs_f64() * 1e3
            );
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
        if std::env::var_os("BBREF_TIMING").is_some() {
            eprintln!(
                "[joint round {round}] fold mega {:.1} ms, translator {:.1} ms",
                (t3 - t2).as_secs_f64() * 1e3,
                t3.elapsed().as_secs_f64() * 1e3
            );
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
    let unshifted: Vec<&Poly> = PCS_UNSHIFTED
        .iter()
        .map(|e| &trans.cols[*e])
        .chain(mega.polys.iter())
        .collect();
    let to_be_shifted: Vec<&Poly> = layout
        .shifted
        .iter()
        .map(|e| mega.poly(*e))
        .chain(PCS_TO_BE_SHIFTED.iter().map(|e| &trans.cols[*e]))
        .collect();
    let round_claims = sumcheck_round_claims(&committed.univariates, &committed.evaluations, &challenge);
    crate::base::timing::phase("  joint: sumcheck");
    let claim = shplemini_prove::<crate::base::Bn254>(
        CIRCUIT_SIZE,
        &unshifted,
        &to_be_shifted,
        &challenge,
        ck,
        t,
        Some(&libra),
        &round_claims,
    );
    kzg_open::<crate::base::Bn254>(claim, ck, t);
    crate::base::timing::phase("  joint: shplemini + kzg");
}

/// What the joint verifier needs besides the proofs: the ECCVM's translation challenges and result,
/// and the merged op-queue table commitments (from the merge protocol).
/// bb `TransFlavor::BF`: how the translator's Grumpkin-scalar inputs (x, v, accumulated result)
/// yield their limb representations — native slicing for `fq`, direct limb extraction for the
/// in-circuit bigfield (bb `put_translation_data_in_relation_parameters_impl`, both overloads).
pub trait TranslatorBf<TF: crate::base::field::FieldLike>: Clone {
    fn five_limbs(&self) -> [TF; 5];
    fn four_limbs(&self) -> [TF; 4];
    fn mul(&self, other: &Self) -> Self;
}

impl TranslatorBf<Fr> for Fq {
    fn five_limbs(&self) -> [Fr; 5] {
        let l = split_fq_into_limbs(self);
        [l[0], l[1], l[2], l[3], from_u256::<Fr>(u256(self))]
    }
    fn four_limbs(&self) -> [Fr; 4] {
        split_fq_into_limbs(self)
    }
    fn mul(&self, other: &Self) -> Self {
        *self * other
    }
}

impl TranslatorBf<crate::stdlib::FieldT> for crate::stdlib::bigfield::BigField<Fq> {
    fn five_limbs(&self) -> [crate::stdlib::FieldT; 5] {
        std::array::from_fn(|i| {
            if i < 4 {
                self.limb_element(i)
            } else {
                self.get_prime_basis_limb()
            }
        })
    }
    fn four_limbs(&self) -> [crate::stdlib::FieldT; 4] {
        std::array::from_fn(|i| self.limb_element(i))
    }
    fn mul(&self, other: &Self) -> Self {
        crate::stdlib::bigfield::BigField::mul(self, other)
    }
}

/// bb `put_translation_data_in_relation_parameters` + beta/gamma: the v powers are computed with
/// four multiplications (the last unused), matching bb's loop.
fn translator_params_bf<TF, B>(v: &B, x: &B, accumulated_result: &B) -> RelationParams<TF>
where
    TF: crate::base::field::FieldLike,
    B: TranslatorBf<TF>,
{
    let mut params = RelationParams {
        evaluation_input_x: x.five_limbs(),
        ..Default::default()
    };
    let mut v_power = v.clone();
    for i in 0..4 {
        params.batching_challenge_v[i] = v_power.five_limbs();
        v_power = v_power.mul(v);
    }
    params.accumulated_result = accumulated_result.four_limbs();
    params
}

pub struct JointVerification<C: Curve = Bn254> {
    pub pairing_points: PairingPoints<C>,
    /// Sumcheck and Libra consistency checks.
    pub verified: bool,
}

/// bb `BatchedHonkTranslatorVerifier_::verify`. `mega_oink` is the output of `verify_oink` with
/// `emit_alpha = false` on the same transcript `t`; `joint_proof` is loaded here.
pub fn joint_verify<C: Curve, B: TranslatorBf<C::Fr>>(
    ctx: &<C::Fr as FieldLike>::Ctx,
    mega_vk: &Vk<C>,
    mega_oink: &OinkOutput<C>,
    joint_proof: &[C::TF],
    evaluation_input_x: &B,
    batching_challenge_v: &B,
    accumulated_result: &B,
    op_queue_wire_commitments: &[C::G; NUM_OP_QUEUE_WIRES],
    t: &mut Transcript<C::TF, C::Hash>,
) -> JointVerification<C>
where
    C::Fr: FieldLike<Native = Fr>,
    C::TF: crate::base::codec::ChallengeField + FieldLike<Native = Fr, Ctx = <C::Fr as FieldLike>::Ctx>,
    C::G: crate::base::group::GroupLike<C::Fr, Native = G1Affine>,
{
    t.load_proof(joint_proof);
    let layout = MEGA_ZK.layout();
    let mega_rels = HonkRelations {
        flavor: &MEGA_ZK,
        layout: &layout,
    };
    let trans_rels = TranslatorRelations;
    let _ = mega_vk;

    // --- translator oink (bb `TranslatorVerifier_::receive_pre_sumcheck`) ---
    // bb `FixedVKAndHash` in the recursive verifier: the hash and the single fixed commitment
    // become witnesses pinned by fix gates (`FixedStdlibVKAndHash_`); natively plain values.
    let vk_hash_wit = <C::TF as FieldLike>::from_witness(ctx, fixed_vk_hash());
    let mut trans_vk_comm = C::G::from_witness(ctx, fixed_vk());
    vk_hash_wit.fix();
    trans_vk_comm.fix_witness();
    t.add_to_hash_buffer("vk_hash", &vk_hash_wit);
    // bb `receive_pre_sumcheck` computes the translation-data relation parameters right after the
    // vk hash, before any commitment is received; beta/gamma are filled in after their challenges.
    let mut trans_params =
        translator_params_bf::<C::Fr, B>(batching_challenge_v, evaluation_input_x, accumulated_result);
    let masking: C::G = t.receive("Gemini:masking_poly_comm");
    let concatenated: Vec<C::G> = CONCATENATED_LABELS.iter().map(|l| t.receive(l)).collect();
    let ordered: Vec<C::G> = ORDERED_LABELS.iter().map(|l| t.receive(l)).collect();
    let beta: C::Fr = t.challenge("beta");
    let gamma: C::Fr = t.challenge("gamma");
    trans_params.beta = beta;
    trans_params.gamma = gamma;
    let z_perm: C::G = t.receive("Z_PERM");
    let opq = op_queue_wire_commitments;
    // bb `get_pcs_unshifted` / `get_pcs_to_be_shifted` in commitment form
    let trans_unshifted: Vec<C::G> = [
        masking.clone(),
        trans_vk_comm,
        opq[0].clone(),
        opq[1].clone(),
        opq[2].clone(),
        opq[3].clone(),
    ]
    .into_iter()
    .chain(ordered.iter().cloned())
    .chain([z_perm.clone()])
    .chain(concatenated.iter().cloned())
    .collect();
    let trans_to_be_shifted: Vec<C::G> = [opq[1].clone(), opq[2].clone(), opq[3].clone()]
        .into_iter()
        .chain(ordered.iter().cloned())
        .chain([z_perm])
        .chain(concatenated.iter().cloned())
        .collect();

    // --- joint sumcheck ---
    let alpha: C::Fr = t.challenge("Sumcheck:alpha");
    // bb computes alpha^{K_H} by K_H sequential multiplications from FF(1), not a pow gadget.
    let alpha_kh = {
        let mut p = C::Fr::one();
        for _ in 0..RelationSet::<C::Fr>::total_subrelations(&mega_rels) {
            p = p * &alpha;
        }
        p
    };
    let mega_alphas = alpha_powers(&alpha, RelationSet::<C::Fr>::total_subrelations(&mega_rels) - 1);
    let trans_alphas = alpha_powers(&alpha, RelationSet::<C::Fr>::total_subrelations(&trans_rels) - 1);
    let gate_challenges: Vec<C::Fr> = t.dyadic_powers("Sumcheck:gate_challenge", JOINT_LOG_N);
    let mut libra_commitments: Vec<C::G> = vec![t.receive("Libra:concatenation_commitment")];
    let libra_total_sum: C::Fr = t.receive("Libra:Sum");
    let libra_challenge: C::Fr = t.challenge("Libra:Challenge");
    let target_sum = libra_total_sum * &libra_challenge;
    let mut challenge = Vec::with_capacity(JOINT_LOG_N);
    let mut partial_eval = C::Fr::one();
    let mut round_commitments = Vec::with_capacity(JOINT_LOG_N);
    let mut round_evaluations: Vec<[C::Fr; 3]> = Vec::with_capacity(JOINT_LOG_N);
    let mut minicircuit = Vec::new();
    for round in 0..JOINT_LOG_N {
        round_commitments.push(t.receive::<C::G>(&format!("Sumcheck:univariate_comm_{round}")));
        let e0: C::Fr = t.receive(&format!("Sumcheck:univariate_{round}_eval_0"));
        let e1: C::Fr = t.receive(&format!("Sumcheck:univariate_{round}_eval_1"));
        round_evaluations.push([e0, e1, C::Fr::zero()]);
        let u: C::Fr = t.challenge(&format!("Sumcheck:u_{round}"));
        partial_eval *= gate_separator_factor(&u, &gate_challenges[round]);
        challenge.push(u);
        if round == LOG_MINI_CIRCUIT_SIZE - 1 {
            minicircuit = t.receive_vec("Sumcheck:minicircuit_evaluations", NUM_MINICIRCUIT_EVALUATIONS);
        }
    }
    let mega_evals: Vec<C::Fr> = t.receive_vec("Sumcheck:evaluations", layout.num_all());
    let trans_full: Vec<C::Fr> = t.receive_vec("Sumcheck:evaluations_translator", FULL_CIRCUIT_ENTITIES.len());
    let trans_evals = complete_evaluations(&trans_full, &minicircuit, &challenge);

    // bb builds a fresh `GateSeparatorPolynomial(gate_challenges, joint_challenge)` for the FRV
    // calls, recomputing the partial evaluation from scratch after the receives (the incremental
    // one from the rounds is discarded).
    let mut final_partial_eval = C::Fr::one();
    for (round, u) in challenge.iter().enumerate() {
        final_partial_eval *= gate_separator_factor(u, &gate_challenges[round]);
    }

    let frv_mega = full_relation_value(
        &mega_rels,
        &mega_evals,
        &mega_oink.params,
        &final_partial_eval,
        &mega_alphas,
        Some(challenge.as_slice()),
    );
    let frv_trans = full_relation_value(
        &trans_rels,
        &trans_evals,
        &trans_params,
        &final_partial_eval,
        &trans_alphas,
        None,
    );
    let mut full_value = frv_mega + &(alpha_kh * &frv_trans);
    let libra_evaluation: C::Fr = t.receive("Libra:claimed_evaluation");
    libra_commitments.push(t.receive("Libra:grand_sum_commitment"));
    libra_commitments.push(t.receive("Libra:quotient_commitment"));
    full_value += libra_evaluation.clone() * &libra_challenge;
    // committed sumcheck: the first sum is checked here, the chain and the last value through the openings
    let first_round_sum = round_evaluations[0][0].clone() + &round_evaluations[0][1];
    let sumcheck_verified = first_round_sum.value() == target_sum.value();
    // bb `perform_final_verification`: `first_sumcheck_round_evaluations_sum.assert_equal(target_total_sum)`
    // (in-circuit copy-constraint, no gates).
    first_round_sum.assert_equal(&target_sum);
    for i in 1..JOINT_LOG_N {
        let chained = round_evaluations[i][0].clone() + &round_evaluations[i][1];
        round_evaluations[i - 1][2] = chained;
    }
    round_evaluations[JOINT_LOG_N - 1][2] = full_value;
    let _ = evaluate_univariate::<Fr>;

    // --- joint PCS ---
    let concat_shift_evals = crate::goblin::translator::concat_shift_evaluations(&trans_evals, &challenge);
    let n_mega_unshifted = layout.num_unshifted();
    let trans_shifted_evals = PCS_SHIFTED
        .iter()
        .map(|e| trans_evals[*e].clone())
        .chain(concat_shift_evals);
    let batcher = ClaimBatcher::<C> {
        unshifted_comms: trans_unshifted
            .iter()
            .cloned()
            .chain(mega_oink.commitments.iter().cloned())
            .collect(),
        unshifted_evals: PCS_UNSHIFTED
            .iter()
            .map(|e| trans_evals[*e].clone())
            .chain(mega_evals[..n_mega_unshifted].iter().cloned())
            .collect(),
        shifted_comms: layout
            .shifted
            .iter()
            .map(|e| mega_oink.commitments[layout.idx(*e)].clone())
            .chain(trans_to_be_shifted)
            .collect(),
        shifted_evals: mega_evals[n_mega_unshifted..]
            .iter()
            .cloned()
            .chain(trans_shifted_evals)
            .collect(),
    };
    // bb `REPEATED_COMMITMENTS`: indices into [unshifted..., shifted...]
    let n_unshifted = batcher.unshifted_comms.len();
    let n_mega_shifted = layout.shifted.len();
    let mut repeated: Vec<(usize, usize)> = (0..PCS_TO_BE_SHIFTED.len())
        .map(|j| (2 + 1 + j, n_unshifted + n_mega_shifted + j))
        .collect();
    repeated.extend(
        layout
            .shifted
            .iter()
            .enumerate()
            .map(|(j, e)| (PCS_UNSHIFTED.len() + layout.idx(*e), n_unshifted + j)),
    );
    let shplemini = shplemini_verify::<C>(
        true,
        true,
        &batcher,
        &challenge,
        &C::G::one(ctx),
        t,
        &repeated,
        &libra_commitments,
        &libra_evaluation,
        &round_commitments,
        &round_evaluations,
    );
    let msm_size = shplemini.claim.commitments.len() + 1;
    let pairing_points = kzg_reduce_verify_batch_opening_claim::<C>(shplemini.claim, t, msm_size);
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
