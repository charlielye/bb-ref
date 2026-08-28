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
    let io_size = if ipa { crate::rollup::ROLLUP_PUBLIC_INPUTS_SIZE } else { 8 };
    let mut fields = vec![
        Fr::from(ULTRA.virtual_log_n as u64),
        Fr::from((acir_public_inputs + io_size) as u64),
        Fr::from(1u64), // NUM_ZERO_ROWS
    ];
    let one = <ark_bn254::G1Affine as Transcriptable<Fr>>::to_fields(&ark_bn254::G1Affine::generator());
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
    let one = <ark_bn254::G1Affine as Transcriptable<Fr>>::to_fields(&ark_bn254::G1Affine::generator());
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
pub fn process_honk_recursion_constraints(
    ctx: &Ctx,
    constraints: &[HonkRecursionConstraint],
    is_write_vk: bool,
    has_ipa_claim: bool,
) {
    let mut points: Option<PairingPoints<StdUltraBn254>> = None;
    let mut nested: Vec<(IpaClaimCt, Vec<FieldT>)> = Vec::new();
    let mut is_root_rollup = false;
    for c in constraints {
        assert!(
            matches!(c.proof_type, HONK | ROLLUP_HONK | ROOT_ROLLUP_HONK),
            "unsupported honk recursion proof type {}",
            c.proof_type
        );
        is_root_rollup |= c.proof_type == ROOT_ROLLUP_HONK;
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
        let constraint_points = match c.proof_type {
            HONK => verify_recursive_ultra(&ULTRA, ctx, &vk, &vk_hash, &proof).points_accumulator,
            _ => {
                let out = verify_recursive_ultra_rollup(&ULTRA, ctx, &vk, &vk_hash, &proof);
                nested.push((out.ipa_claim, out.ipa_proof));
                out.points_accumulator
            }
        };
        points = Some(match points {
            None => constraint_points,
            Some(acc) => aggregate_pair(acc, constraint_points),
        });
    }

    if has_ipa_claim {
        let ck = GrumpkinKey::new(POLY_LENGTH);
        let mut accumulators: Vec<_> = nested
            .into_iter()
            .map(|(claim, proof)| {
                let mut t = StdlibTranscript::from_proof(&proof);
                reduce_verify_ct(ctx, &claim, &mut t)
            })
            .collect();
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
        unimplemented!("root rollup full IPA verification (fixed_batch_mul) not yet ported");
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
