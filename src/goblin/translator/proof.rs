//! The Translator proof on its own (bb `translator_prover.cpp`, `translator_verifier.cpp`), as Goblin
//! proves it for the AVM: the pre-sumcheck commitments, a ZK sumcheck of `CONST_TRANSLATOR_LOG_N`
//! rounds (mini-circuit evaluations sent mid-way), then Shplemini/KZG. The pre-sumcheck round and
//! the translation-data parameters are shared with the joint MegaZK+Translator proof
//! ([`crate::chonk::batched`]).

use super::builder::{split_fq_into_limbs, ACCUMULATORS_BINARY_LIMBS_0};
use super::check::translator_relation_params;
use super::relations::TranslatorRelations;
use super::{
    fixed_vk, fixed_vk_hash, minicircuit_entities, Ent as TEnt, TranslatorPolys, CIRCUIT_SIZE, CONST_TRANSLATOR_LOG_N,
    FIRST_SHIFTED, FIRST_WIRE, FULL_CIRCUIT_ENTITIES, LOG_MINI_CIRCUIT_SIZE, NUM_OP_QUEUE_WIRES, PCS_SHIFTED,
    PCS_TO_BE_SHIFTED, PCS_UNSHIFTED, RESULT_ROW,
};
use crate::base::field::{from_u256, u256, FieldLike};
use crate::base::group::{Curve, GroupLike, PairingPoints};
use crate::base::poly::Poly;
use crate::base::rng::Rng;
use crate::base::transcript::Transcript;
use crate::base::{Bn254, CommitmentKey, Fq, Fr, G1Affine, NativeTranscript};
use crate::honk::oink_prover::build_gemini_masking_poly;
use crate::honk::pcs::{
    kzg_open, kzg_reduce_verify_batch_opening_claim, shplemini_prove, shplemini_verify, small_subgroup_ipa_prove,
    ClaimBatcher,
};
use crate::honk::relations::RelationParams;
use crate::honk::sumcheck::{alpha_powers, gate_separator_factor, verify_sumcheck, RelationSet, RoundProver, SumcheckSpec, ZkData};

pub const CONCATENATED_LABELS: [&str; 5] = [
    "CONCATENATED_RANGE_CONSTRAINTS_0",
    "CONCATENATED_RANGE_CONSTRAINTS_1",
    "CONCATENATED_RANGE_CONSTRAINTS_2",
    "CONCATENATED_RANGE_CONSTRAINTS_3",
    "CONCATENATED_NON_RANGE",
];
pub const ORDERED_LABELS: [&str; 5] = [
    "ORDERED_RANGE_CONSTRAINTS_0",
    "ORDERED_RANGE_CONSTRAINTS_1",
    "ORDERED_RANGE_CONSTRAINTS_2",
    "ORDERED_RANGE_CONSTRAINTS_3",
    "ORDERED_RANGE_CONSTRAINTS_4",
];

/// bb `TranslatorProver::execute_preamble_round`, `execute_wire_and_sorted_constraints_commitments_round`,
/// `execute_grand_product_computation_round`. Fills in the Gemini masking polynomial, `z_perm` and the shifts.
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
    t.send("Gemini:masking_poly_comm", &ck.commit(polys.col(TEnt::gemini_masking_poly)));
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

/// bb `TranslatorProver::construct_proof` on the shared transcript (Goblin's, after the ECCVM).
pub fn translator_prove(polys: &mut TranslatorPolys, v: &Fq, x: &Fq, ck: &CommitmentKey, t: &mut NativeTranscript, rng: &mut dyn Rng) {
    let params = translator_oink_prove(polys, v, x, ck, t, rng);
    let rels = TranslatorRelations;
    let alpha: Fr = t.challenge("Sumcheck:alpha");
    let betas: Vec<Fr> = t.dyadic_powers("Sumcheck:gate_challenge", CONST_TRANSLATOR_LOG_N);
    let alphas = alpha_powers(&alpha, RelationSet::<Fr>::total_subrelations(&rels) - 1);
    let mut zk = ZkData::<Bn254>::new(CONST_TRANSLATOR_LOG_N, t, ck, rng);
    let d = Bn254::LIBRA_UNIVARIATES_LENGTH;
    let shift_sources: Vec<usize> = (13..=98).collect();
    let mut state = RoundProver::new(CIRCUIT_SIZE, &polys.cols[..FIRST_SHIFTED], &shift_sources, false, 0, usize::MAX, None);
    let mut partial_eval = Fr::one();
    let mut challenge = Vec::with_capacity(CONST_TRANSLATOR_LOG_N);
    for round in 0..CONST_TRANSLATOR_LOG_N {
        let mut univariate = state.univariate(&rels, &params, &betas, &partial_eval, &alphas, d);
        let libra = zk.round_univariate(round, d);
        for k in 0..d {
            univariate[k] += libra[k];
        }
        t.send_vec(&format!("Sumcheck:univariate_{round}"), &univariate);
        let u: Fr = t.challenge(&format!("Sumcheck:u_{round}"));
        state.partially_evaluate(&u);
        if round == LOG_MINI_CIRCUIT_SIZE - 1 {
            let mini: Vec<Fr> = minicircuit_entities().map(|e| state.current(e)).collect();
            t.send_vec("Sumcheck:minicircuit_evaluations", &mini);
        }
        zk.update(&u, round);
        partial_eval *= gate_separator_factor(&u, &betas[round]);
        challenge.push(u);
    }
    let full: Vec<Fr> = FULL_CIRCUIT_ENTITIES.iter().map(|e| state.current(*e)).collect();
    t.send_vec("Sumcheck:evaluations", &full);
    let libra_evaluation = zk.claimed_evaluation();
    t.send("Libra:claimed_evaluation", &libra_evaluation);
    drop(state);

    let libra = small_subgroup_ipa_prove::<Bn254>(&zk, &challenge, &libra_evaluation, ck, t, rng);
    let unshifted: Vec<&Poly> = PCS_UNSHIFTED.iter().map(|e| &polys.cols[*e]).collect();
    let to_be_shifted: Vec<&Poly> = PCS_TO_BE_SHIFTED.iter().map(|e| &polys.cols[*e]).collect();
    let claim = shplemini_prove::<Bn254>(CIRCUIT_SIZE, &unshifted, &to_be_shifted, &challenge, ck, t, Some(&libra), &[]);
    kzg_open::<Bn254>(claim, ck, t);
}

/// bb `TransFlavor::BF`: how the translator's Grumpkin-scalar inputs (x, v, accumulated result)
/// yield their limb representations — native slicing for `fq`, direct limb extraction for the
/// in-circuit bigfield (bb `put_translation_data_in_relation_parameters_impl`, both overloads).
pub trait TranslatorBf<TF: FieldLike>: Clone {
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
        std::array::from_fn(|i| if i < 4 { self.limb_element(i) } else { self.get_prime_basis_limb() })
    }
    fn four_limbs(&self) -> [crate::stdlib::FieldT; 4] {
        std::array::from_fn(|i| self.limb_element(i))
    }
    fn mul(&self, other: &Self) -> Self {
        crate::stdlib::bigfield::BigField::mul(self, other)
    }
}

/// bb `put_translation_data_in_relation_parameters`: the v powers are computed with four
/// multiplications (the last unused), matching bb's loop.
fn translator_params_bf<TF: FieldLike, B: TranslatorBf<TF>>(v: &B, x: &B, accumulated_result: &B) -> RelationParams<TF> {
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

/// The verifier's view after bb `TranslatorVerifier_::receive_pre_sumcheck`.
pub struct PreSumcheck<C: Curve> {
    pub params: RelationParams<C::Fr>,
    /// bb `get_pcs_unshifted` / `get_pcs_to_be_shifted` in commitment form.
    pub unshifted: Vec<C::G>,
    pub to_be_shifted: Vec<C::G>,
}

/// bb `TranslatorVerifier_::receive_pre_sumcheck`, after its constructor fixed the VK. In-circuit
/// (`FixedStdlibVKAndHash`) the hash and the single fixed commitment become witnesses pinned by fix
/// gates; natively plain values.
pub fn receive_pre_sumcheck<C: Curve, B: TranslatorBf<C::Fr>>(
    ctx: &<C::Fr as FieldLike>::Ctx,
    evaluation_input_x: &B,
    batching_challenge_v: &B,
    accumulated_result: &B,
    op_queue_wire_commitments: &[C::G; NUM_OP_QUEUE_WIRES],
    t: &mut Transcript<C::TF, C::Hash>,
) -> PreSumcheck<C>
where
    C::TF: FieldLike<Native = Fr, Ctx = <C::Fr as FieldLike>::Ctx>,
    C::G: GroupLike<C::Fr, Native = G1Affine>,
{
    let vk_hash_wit = <C::TF as FieldLike>::from_witness(ctx, fixed_vk_hash());
    let mut vk_comm = C::G::from_witness(ctx, fixed_vk());
    vk_hash_wit.fix();
    vk_comm.fix_witness();
    t.add_to_hash_buffer("vk_hash", &vk_hash_wit);
    // bb computes the translation-data relation parameters right after the vk hash, before any
    // commitment is received; beta/gamma are filled in after their challenges.
    let mut params = translator_params_bf::<C::Fr, B>(batching_challenge_v, evaluation_input_x, accumulated_result);
    let masking: C::G = t.receive("Gemini:masking_poly_comm");
    let concatenated: Vec<C::G> = CONCATENATED_LABELS.iter().map(|l| t.receive(l)).collect();
    let ordered: Vec<C::G> = ORDERED_LABELS.iter().map(|l| t.receive(l)).collect();
    params.beta = t.challenge("beta");
    params.gamma = t.challenge("gamma");
    let z_perm: C::G = t.receive("Z_PERM");
    let opq = op_queue_wire_commitments;
    let unshifted = [masking, vk_comm, opq[0].clone(), opq[1].clone(), opq[2].clone(), opq[3].clone()]
        .into_iter()
        .chain(ordered.iter().cloned())
        .chain([z_perm.clone()])
        .chain(concatenated.iter().cloned())
        .collect();
    let to_be_shifted = [opq[1].clone(), opq[2].clone(), opq[3].clone()]
        .into_iter()
        .chain(ordered.iter().cloned())
        .chain([z_perm])
        .chain(concatenated.iter().cloned())
        .collect();
    PreSumcheck {
        params,
        unshifted,
        to_be_shifted,
    }
}

pub struct TranslatorReduction<C: Curve> {
    pub pairing_points: PairingPoints<C>,
    /// Sumcheck and Libra consistency checks.
    pub verified: bool,
}

/// bb `TranslatorVerifier_::reduce_to_pairing_check`: `proof` is loaded onto the shared transcript.
pub fn translator_verify<C: Curve, B: TranslatorBf<C::Fr>>(
    ctx: &<C::Fr as FieldLike>::Ctx,
    proof: &[C::TF],
    evaluation_input_x: &B,
    batching_challenge_v: &B,
    accumulated_result: &B,
    op_queue_wire_commitments: &[C::G; NUM_OP_QUEUE_WIRES],
    t: &mut Transcript<C::TF, C::Hash>,
) -> TranslatorReduction<C>
where
    C::Fr: FieldLike<Native = Fr>,
    C::TF: crate::base::codec::ChallengeField + FieldLike<Native = Fr, Ctx = <C::Fr as FieldLike>::Ctx>,
    C::G: GroupLike<C::Fr, Native = G1Affine>,
{
    t.load_proof(proof);
    let pre = receive_pre_sumcheck::<C, B>(
        ctx,
        evaluation_input_x,
        batching_challenge_v,
        accumulated_result,
        op_queue_wire_commitments,
        t,
    );
    let rels = TranslatorRelations;
    let alpha: C::Fr = t.challenge("Sumcheck:alpha");
    let alphas = alpha_powers(&alpha, RelationSet::<C::Fr>::total_subrelations(&rels) - 1);
    let gate_challenges: Vec<C::Fr> = t.dyadic_powers("Sumcheck:gate_challenge", CONST_TRANSLATOR_LOG_N);
    let mut libra_commitments: Vec<C::G> = vec![t.receive("Libra:concatenation_commitment")];
    let spec = SumcheckSpec {
        witness_end: usize::MAX,
        active_prefix_end: None,
        virtual_log_n: CONST_TRANSLATOR_LOG_N,
        has_zk: true,
        row_disabling: false,
        trace_offset: 0,
        committed: false,
        batched_len: Bn254::LIBRA_UNIVARIATES_LENGTH,
        shifted_sources: Vec::new(),
        num_entities: 0,
        translator: true,
    };
    let sc = verify_sumcheck::<C>(&rels, &spec, t, &alphas, &pre.params, &gate_challenges);
    libra_commitments.push(t.receive("Libra:grand_sum_commitment"));
    libra_commitments.push(t.receive("Libra:quotient_commitment"));

    let concat_shift_evals = super::concat_shift_evaluations(&sc.evals, &sc.challenge);
    let batcher = ClaimBatcher::<C> {
        unshifted_comms: pre.unshifted,
        unshifted_evals: PCS_UNSHIFTED.iter().map(|e| sc.evals[*e].clone()).collect(),
        shifted_comms: pre.to_be_shifted,
        shifted_evals: PCS_SHIFTED.iter().map(|e| sc.evals[*e].clone()).chain(concat_shift_evals).collect(),
    };
    // bb `TranslatorFlavor::REPEATED_COMMITMENTS`: every to-be-shifted commitment is also unshifted,
    // the op-queue wires from position 3 of the unshifted list.
    let n_unshifted = batcher.unshifted_comms.len();
    let repeated: Vec<(usize, usize)> = (0..PCS_TO_BE_SHIFTED.len()).map(|j| (2 + 1 + j, n_unshifted + j)).collect();
    let shplemini = shplemini_verify::<C>(
        true,
        true,
        &batcher,
        &sc.challenge,
        &C::G::one(ctx),
        t,
        &repeated,
        &libra_commitments,
        &sc.libra_evaluation,
        &[],
        &[],
    );
    let msm_size = shplemini.claim.commitments.len() + 1;
    let pairing_points = kzg_reduce_verify_batch_opening_claim::<C>(shplemini.claim, t, msm_size);
    TranslatorReduction {
        pairing_points,
        verified: sc.verified && shplemini.consistency_checked,
    }
}
