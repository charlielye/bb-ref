//! bb `honk_recursion_constraint.cpp` + `recursion_constraint_output.cpp`: ACIR lowering of
//! HONK / ROLLUP_HONK / ROOT_ROLLUP_HONK recursive verification on Ultra circuits, with bb's
//! write-VK mock proofs and VKs (`mock_verifier_inputs.cpp`).

use crate::base::codec::Transcriptable;
use crate::base::group::PairingPoints;
use crate::base::rng::global_field;
use crate::base::{Fq, Fr, GrumpkinAffine, GrumpkinKey};
use crate::circuit::Builder;
use crate::honk::ULTRA;
use crate::rollup::ipa::{IPA_PROOF_LENGTH, LOG_POLY_LENGTH, POLY_LENGTH};
use crate::rollup::ipa_recursive::{
    accumulate, create_random_valid_ipa_claim_and_proof, prove_accumulator_claim, reduce_verify_ct, IpaClaimCt,
    StdlibTranscript,
};
use crate::rollup::{
    aggregate_pair, set_rollup_io_public, set_ultra_pairing_points_public, verify_recursive_ultra,
    verify_recursive_ultra_rollup, vk_from_fields,
};
use crate::stdlib::curve::StdUltraBn254;
use crate::stdlib::{Ctx, FieldT};
use ark_ec::AffineRepr;
use std::cell::RefCell;
use std::rc::Rc;

pub const HONK: u32 = 0;
pub const AVM: u32 = 3;
pub const ROLLUP_HONK: u32 = 4;
pub const ROOT_ROLLUP_HONK: u32 = 5;
pub const HONK_ZK: u32 = 6;
pub const CHONK: u32 = 8;

/// bb `RecursionConstraint` (Honk subset): witness indices of the key, proof, ACIR-level public
/// inputs and key hash of a proof recursively verified on an Ultra circuit.
pub struct HonkRecursionConstraint {
    pub key: Vec<u32>,
    pub key_hash: u32,
    pub proof: Vec<u32>,
    pub public_inputs: Vec<u32>,
    pub proof_type: u32,
}

fn has_ipa(proof_type: u32) -> bool {
    proof_type == ROLLUP_HONK || proof_type == ROOT_ROLLUP_HONK
}

/// bb `create_mock_honk_vk`: VK metadata for a `1 << VIRTUAL_LOG_N` circuit, every commitment the
/// bn254 generator.
fn mock_vk_fields(acir_public_inputs: usize, ipa: bool) -> Vec<Fr> {
    let io_size = if ipa {
        crate::rollup::ROLLUP_PUBLIC_INPUTS_SIZE
    } else {
        8
    };
    let mut fields = vec![
        Fr::from(ULTRA.virtual_log_n as u64),
        Fr::from((acir_public_inputs + io_size) as u64),
        Fr::from(1u64), // NUM_ZERO_ROWS
    ];
    let one = <crate::base::G1Affine as Transcriptable<Fr>>::to_fields(&crate::base::G1Affine::generator());
    for _ in 0..ULTRA.layout().num_precomputed {
        fields.extend_from_slice(&one);
    }
    fields
}

/// bb `create_mock_honk_proof`: mock Oink (public inputs + generator commitments), mock decider
/// (random sumcheck/PCS fields, generator commitments), and for RollupIO a mock IPA tail.
fn mock_proof_fields(acir_public_inputs: usize, ipa: bool) -> Vec<Fr> {
    let lay = ULTRA.layout();
    let num_witness_comms = lay.num_unshifted() - lay.num_precomputed;
    let num_all = lay.num_unshifted() + lay.num_shifted();
    let one = <crate::base::G1Affine as Transcriptable<Fr>>::to_fields(&crate::base::G1Affine::generator());
    let mut fields = Vec::new();
    // Oink: ACIR public inputs (random), the IO public inputs from a scratch `add_default`, and
    // the witness commitments.
    for _ in 0..acir_public_inputs {
        fields.push(global_field::<Fr>());
    }
    if ipa {
        // bb runs `RollupIO::add_default` on a scratch builder and copies its public input values:
        // eight zeros then the random claim (challenge, evaluation, commitment halves).
        let scratch = Rc::new(RefCell::new(Builder::new()));
        let (claim, _ipa_proof) = create_random_valid_ipa_claim_and_proof(&scratch);
        fields.extend(std::iter::repeat(Fr::from(0u64)).take(8));
        let v = claim.value();
        fields.extend(<Fq as Transcriptable<Fr>>::to_fields(&v.challenge));
        fields.extend(<Fq as Transcriptable<Fr>>::to_fields(&v.evaluation));
        fields.extend(<GrumpkinAffine as Transcriptable<Fr>>::to_fields(&v.commitment));
    } else {
        fields.extend(std::iter::repeat(Fr::from(0u64)).take(8));
    }
    for _ in 0..num_witness_comms {
        fields.extend_from_slice(&one);
    }
    // Decider: sumcheck univariates and evaluations, Gemini fold commitments and evaluations,
    // Shplonk and KZG commitments.
    let log_n = ULTRA.virtual_log_n;
    for _ in 0..log_n * 8 + num_all {
        fields.push(global_field::<Fr>());
    }
    for _ in 0..log_n - 1 {
        fields.extend_from_slice(&one);
    }
    for _ in 0..log_n {
        fields.push(global_field::<Fr>());
    }
    fields.extend_from_slice(&one);
    fields.extend_from_slice(&one);
    if ipa {
        let g = <GrumpkinAffine as Transcriptable<Fr>>::to_fields(&GrumpkinAffine::generator());
        for _ in 0..2 * LOG_POLY_LENGTH + 1 {
            fields.extend_from_slice(&g);
        }
        let a0: Fq = global_field();
        fields.extend(<Fq as Transcriptable<Fr>>::to_fields(&a0));
        debug_assert_eq!(2 * (2 * LOG_POLY_LENGTH + 1) + 2, IPA_PROOF_LENGTH);
    }
    fields
}

/// bb `create_recursion_constraints` (Ultra) + `HonkRecursionConstraintsOutput::finalize`: verify
/// each constraint, aggregate the pairing points, accumulate any nested IPA claims, and publish
/// the circuit's IO.
/// bb `construct_arbitrary_valid_honk_proof_and_vk`, draw-ledger only. In real (non-write-VK) mode
/// bb unconditionally builds and proves a scratch one-gate circuit per honk-family constraint; its
/// proof/vk are only ever used for witness-predicate substitution, which never triggers on the
/// protocol circuits (predicates are constant). Only the randomness matters for byte parity: three
/// gate values, one value per ACIR public input, then `RollupIO::add_default`'s random IPA claim.
/// Instance construction and non-ZK proving draw nothing (M2/B0), so the scratch prove is skipped.
fn arbitrary_valid_proof_draws(ctx_template: &Ctx, acir_public_inputs: usize, ipa: bool) {
    let _ = ctx_template;
    for _ in 0..3 + acir_public_inputs {
        let _: Fr = global_field();
    }
    if ipa {
        let scratch = std::rc::Rc::new(std::cell::RefCell::new(crate::circuit::Builder::new()));
        let _ = crate::rollup::add_default_rollup_io(&scratch);
    }
}

pub fn process_honk_recursion_constraints(
    ctx: &Ctx,
    constraints: &[HonkRecursionConstraint],
    chonk_constraints: &[HonkRecursionConstraint],
    is_write_vk: bool,
    has_ipa_claim: bool,
) {
    let mut points: Option<PairingPoints<StdUltraBn254>> = None;
    let mut nested: Vec<(IpaClaimCt, Vec<FieldT>)> = Vec::new();
    let mut openings: Vec<crate::chonk::verifier::DeferredTripleIpaOpening> = Vec::new();
    let mut is_root_rollup = false;
    for c in constraints {
        assert!(
            matches!(c.proof_type, HONK | ROLLUP_HONK | ROOT_ROLLUP_HONK),
            "unsupported honk recursion proof type {}",
            c.proof_type
        );
        is_root_rollup |= c.proof_type == ROOT_ROLLUP_HONK;
        if !is_write_vk {
            arbitrary_valid_proof_draws(ctx, c.public_inputs.len(), has_ipa(c.proof_type));
        }
        if is_write_vk {
            let ipa = has_ipa(c.proof_type);
            let mut b = ctx.borrow_mut();
            for (&idx, v) in c.key.iter().zip(mock_vk_fields(c.public_inputs.len(), ipa)) {
                b.set_variable(idx, v);
            }
            let proof_values = mock_proof_fields(c.public_inputs.len(), ipa);
            let indices = c.public_inputs.iter().chain(&c.proof);
            for (&idx, v) in indices.zip(proof_values) {
                b.set_variable(idx, v);
            }
        }
        let vk_fields: Vec<FieldT> = c.key.iter().map(|&i| FieldT::from_witness_index(ctx, i)).collect();
        let vk_hash = FieldT::from_witness_index(ctx, c.key_hash);
        let proof: Vec<FieldT> = c
            .public_inputs
            .iter()
            .chain(&c.proof)
            .map(|&i| FieldT::from_witness_index(ctx, i))
            .collect();
        let vk = vk_from_fields(&vk_fields);
        crate::base::timing::phase("      rec: setup");
        let constraint_points = match c.proof_type {
            HONK => verify_recursive_ultra(&ULTRA, ctx, &vk, &vk_hash, &proof).points_accumulator,
            _ => {
                let out = verify_recursive_ultra_rollup(&ULTRA, ctx, &vk, &vk_hash, &proof);
                nested.push((out.ipa_claim, out.ipa_proof));
                out.points_accumulator
            }
        };
        crate::base::timing::phase("      rec: verify_recursive");
        points = Some(match points {
            None => constraint_points,
            Some(acc) => aggregate_pair(acc, constraint_points),
        });
        crate::base::timing::phase("      rec: aggregate");
    }

    for c in chonk_constraints {
        assert_eq!(c.proof_type, CHONK);
        if is_write_vk {
            let mut b = ctx.borrow_mut();
            for (&idx, v) in c.key.iter().zip(mock_mega_zk_vk_fields(c.public_inputs.len())) {
                b.set_variable(idx, v);
            }
            let proof_values = mock_chonk_proof_fields(c.public_inputs.len());
            let indices = c.public_inputs.iter().chain(&c.proof);
            for (&idx, v) in indices.zip(proof_values) {
                b.set_variable(idx, v);
            }
        }
        let vk_fields: Vec<FieldT> = c.key.iter().map(|&i| FieldT::from_witness_index(ctx, i)).collect();
        let vk_hash = FieldT::from_witness_index(ctx, c.key_hash);
        let proof: Vec<FieldT> = c
            .public_inputs
            .iter()
            .chain(&c.proof)
            .map(|&i| FieldT::from_witness_index(ctx, i))
            .collect();
        let vk = vk_from_fields(&vk_fields);
        let out = crate::chonk::verifier::chonk_verify_recursive(ctx, &vk, &vk_hash, &proof);
        if !out.all_checks_passed && !is_write_vk {
            ctx.borrow_mut().failure("Chonk recursion verification failed");
        }
        openings.push(out.triple_ipa_opening);
        points = Some(match points {
            None => out.pairing_points,
            Some(acc) => aggregate_pair(acc, out.pairing_points),
        });
    }

    if has_ipa_claim {
        crate::base::timing::phase("      rec: pre-ipa");
        let ck = GrumpkinKey::new(POLY_LENGTH);
        crate::base::timing::phase("      rec: grumpkin key");
        let mut accumulators: Vec<_> = nested
            .into_iter()
            .map(|(claim, proof)| {
                let mut t = StdlibTranscript::from_proof(&proof);
                reduce_verify_ct(ctx, &claim, &mut t)
            })
            .collect();
        for opening in openings {
            let mut t = StdlibTranscript::from_proof(&opening.proof);
            let acc = crate::goblin::ipa::triple_ipa_reduce_to_accumulator::<crate::stdlib::curve::StdUltraGrumpkin>(
                ctx,
                &opening.claim,
                &mut t,
            );
            accumulators.push(crate::rollup::ipa_recursive::IpaAccumulatorCt {
                u_challenges_inv: acc.u_challenges_inv,
                comm: acc.claimed_commitment,
            });
        }
        let (claim, ipa_proof) = match accumulators.len() {
            2 => {
                let a2 = accumulators.pop().unwrap();
                let a1 = accumulators.pop().unwrap();
                accumulate(&ck, a1, a2)
            }
            1 => prove_accumulator_claim(&ck, accumulators.pop().unwrap()),
            0 => create_random_valid_ipa_claim_and_proof(ctx),
            n => panic!("too many nested IPA accumulators: {n}"),
        };
        crate::base::timing::phase("      rec: ipa claim+proof");
        ctx.borrow_mut().ipa_proof = ipa_proof;
        match points {
            Some(pp) => {
                set_rollup_io_public(&pp, &claim);
            }
            None => {
                crate::stdlib::io::set_default_pairing_points_public(ctx);
                claim.set_public();
            }
        }
    } else if is_root_rollup {
        assert!(openings.is_empty(), "unreachable: root rollup with chonk openings");
        // bb `perform_full_IPA_verification`: accumulate the two nested claims, then fully verify
        // the accumulated claim in-circuit (DefaultIO; no IPA proof rides on the circuit).
        let ck = GrumpkinKey::new(POLY_LENGTH);
        let mut accumulators: Vec<_> = nested
            .into_iter()
            .map(|(claim, proof)| {
                let mut t = StdlibTranscript::from_proof(&proof);
                reduce_verify_ct(ctx, &claim, &mut t)
            })
            .collect();
        assert_eq!(accumulators.len(), 2, "root rollup must accumulate two IPA proofs");
        let a2 = accumulators.pop().unwrap();
        let a1 = accumulators.pop().unwrap();
        let (claim, ipa_proof) = accumulate(&ck, a1, a2);
        let proof_fields: Vec<FieldT> = ipa_proof.iter().map(|f| FieldT::from_witness(ctx, *f)).collect();
        let mut t = StdlibTranscript::from_proof(&proof_fields);
        crate::rollup::ipa_recursive::full_verify_ct(ctx, &claim, &mut t);
        match points {
            Some(pp) => {
                set_ultra_pairing_points_public(&pp);
            }
            None => super::lower::add_default_pairing_points(&mut ctx.borrow_mut()),
        }
    } else {
        assert!(nested.is_empty(), "IPA claims present without --ipa_accumulation");
        match points {
            Some(pp) => {
                set_ultra_pairing_points_public(&pp);
            }
            None => super::lower::add_default_pairing_points(&mut ctx.borrow_mut()),
        }
    }
    ctx.borrow_mut().finalize_public_inputs();
}

/// bb `create_mock_honk_vk<MegaZKFlavor, HidingKernelIO>`.
fn mock_mega_zk_vk_fields(acir_public_inputs: usize) -> Vec<Fr> {
    use crate::honk::flavor::MEGA_ZK;
    let one = <crate::base::G1Affine as Transcriptable<Fr>>::to_fields(&crate::base::G1Affine::generator());
    let mut fields = vec![
        Fr::from(MEGA_ZK.virtual_log_n as u64),
        Fr::from((acir_public_inputs + crate::chonk::verifier::HIDING_KERNEL_PUBLIC_INPUTS_SIZE) as u64),
        Fr::from(1u64),
    ];
    for _ in 0..MEGA_ZK.layout().num_precomputed {
        fields.extend_from_slice(&one);
    }
    fields
}

/// bb `create_mock_chonk_proof`: mock MegaZK Oink, merge, ECCVM, TripleIPA and joint proofs, each
/// section length asserted against the real proof layout.
fn mock_chonk_proof_fields(acir_public_inputs: usize) -> Vec<Fr> {
    use crate::base::GrumpkinAffine;
    use crate::chonk::proof::{ECCVM_PROOF_LENGTH, JOINT_PROOF_LENGTH, TRIPLE_IPA_PROOF_LENGTH};
    use crate::goblin::eccvm::{CONST_ECCVM_LOG_N, NUM_ALL_ENTITIES as ECCVM_ALL, NUM_WITNESS as ECCVM_WITNESS};
    use crate::goblin::merge::MERGE_PROOF_SIZE;
    use crate::goblin::translator::{
        CONST_TRANSLATOR_LOG_N, FULL_CIRCUIT_ENTITIES, LOG_MINI_CIRCUIT_SIZE, NUM_MINICIRCUIT_EVALUATIONS,
    };
    use crate::honk::flavor::MEGA_ZK;
    let bn_one = <crate::base::G1Affine as Transcriptable<Fr>>::to_fields(&crate::base::G1Affine::generator());
    let gr_one = <GrumpkinAffine as Transcriptable<Fr>>::to_fields(&GrumpkinAffine::generator());
    let mut fields = Vec::new();

    // --- MegaZK Oink: ACIR public inputs, the HidingKernelIO defaults, witness commitments ---
    for _ in 0..acir_public_inputs {
        fields.push(global_field::<Fr>());
    }
    fields.extend(std::iter::repeat(Fr::from(0u64)).take(8));
    let default_comm =
        <crate::base::G1Affine as Transcriptable<Fr>>::to_fields(&crate::stdlib::io::default_ecc_commitment());
    for _ in 0..5 {
        fields.extend_from_slice(&default_comm);
    }
    let mega_lay = MEGA_ZK.layout();
    for _ in 0..mega_lay.num_witness + mega_lay.num_masking {
        fields.extend_from_slice(&bn_one);
    }

    // --- Merge ---
    let start = fields.len();
    for _ in 0..5 {
        fields.extend_from_slice(&bn_one);
    }
    for _ in 0..13 {
        fields.push(global_field::<Fr>());
    }
    fields.extend_from_slice(&bn_one);
    fields.extend_from_slice(&bn_one);
    assert_eq!(fields.len() - start, MERGE_PROOF_SIZE);

    // --- ECCVM (Grumpkin commitments, fq field elements as limb pairs) ---
    let start = fields.len();
    let fq_random = |fields: &mut Vec<Fr>, n: usize| {
        for _ in 0..n {
            let v: Fq = global_field();
            fields.extend(<Fq as Transcriptable<Fr>>::to_fields(&v));
        }
    };
    for _ in 0..ECCVM_WITNESS + 1 {
        fields.extend_from_slice(&gr_one);
    }
    fq_random(&mut fields, 1); // Libra sum
    for _ in 0..CONST_ECCVM_LOG_N {
        fields.extend_from_slice(&gr_one);
        fq_random(&mut fields, 2);
    }
    fq_random(&mut fields, ECCVM_ALL);
    fq_random(&mut fields, 1); // Libra evaluation
    fields.extend_from_slice(&gr_one);
    fields.extend_from_slice(&gr_one);
    fq_random(&mut fields, 5); // small-IPA transcript evals
    fields.extend_from_slice(&gr_one); // translation masking commitment
    fq_random(&mut fields, 6); // op, Px, Py, z1, z2, masking-term eval
    fields.extend_from_slice(&gr_one); // translation grand sum commitment
    fields.extend_from_slice(&gr_one); // translation quotient commitment
    fq_random(&mut fields, 4); // concatenation, grand-sum-shift, grand-sum, quotient evals
    fields.extend_from_slice(&gr_one); // TripleIPA pow-tensor masking commitment
    fq_random(&mut fields, 1); // pow-tensor masking evaluation
    fields.extend_from_slice(&gr_one); // Shplonk Q
    assert_eq!(fields.len() - start, ECCVM_PROOF_LENGTH, "mock eccvm proof length");

    // --- TripleIPA ---
    let start = fields.len();
    fq_random(&mut fields, 3);
    for _ in 0..2 * CONST_ECCVM_LOG_N + 1 {
        fields.extend_from_slice(&gr_one);
    }
    fq_random(&mut fields, 1);
    assert_eq!(fields.len() - start, TRIPLE_IPA_PROOF_LENGTH, "mock triple ipa length");

    // --- Joint (Translator Oink + committed sumcheck + PCS) ---
    let start = fields.len();
    for _ in 0..1 + 10 + 1 + 1 {
        fields.extend_from_slice(&bn_one);
    }
    fields.push(global_field::<Fr>()); // Libra sum
    for round in 0..CONST_TRANSLATOR_LOG_N {
        if round == LOG_MINI_CIRCUIT_SIZE {
            for _ in 0..NUM_MINICIRCUIT_EVALUATIONS {
                fields.push(global_field::<Fr>());
            }
        }
        fields.extend_from_slice(&bn_one);
        fields.push(global_field::<Fr>());
        fields.push(global_field::<Fr>());
    }
    for _ in 0..mega_lay.num_all() + FULL_CIRCUIT_ENTITIES.len() + 1 {
        fields.push(global_field::<Fr>());
    }
    fields.extend_from_slice(&bn_one);
    fields.extend_from_slice(&bn_one);
    // PCS: gemini folds, gemini evals, small-IPA evals (ZK), Shplonk Q, KZG W
    for _ in 0..CONST_TRANSLATOR_LOG_N - 1 {
        fields.extend_from_slice(&bn_one);
    }
    for _ in 0..CONST_TRANSLATOR_LOG_N + 4 {
        fields.push(global_field::<Fr>());
    }
    fields.extend_from_slice(&bn_one);
    fields.extend_from_slice(&bn_one);
    assert_eq!(fields.len() - start, JOINT_PROOF_LENGTH, "mock joint proof length");
    fields
}
