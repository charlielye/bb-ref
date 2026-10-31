//! bb `ChonkVerifier<false>`: native verification of a Chonk proof against the hiding kernel's VK.

use super::batched::{joint_verify, mega_zk_oink_length_without_public_inputs};
use super::proof::{ChonkProof, ECCVM_PROOF_LENGTH, JOINT_PROOF_LENGTH, TRIPLE_IPA_PROOF_LENGTH};
use crate::base::codec::Transcriptable;
use crate::base::group::Curve;
use crate::base::group::{G2Points, PairingPoints};
use crate::base::vk::Vk;
use crate::base::{Bn254, G1Affine, GrumpkinKey, NativeTranscript};
use crate::goblin::eccvm::verifier::eccvm_verify;
use crate::goblin::ipa::triple_ipa_verify;
use crate::goblin::ipa::TripleIpaClaim;
use crate::goblin::merge::{merge_verify, MergeInputs, MERGE_PROOF_SIZE};
use crate::honk::flavor::{Ent, MEGA_ZK};
use crate::honk::oink::verify_oink;
use crate::honk::ultra_verifier::default_io_pairing_points;
use crate::stdlib::curve::{StdUltraBn254, StdUltraGrumpkin};
use crate::stdlib::{Ctx, FieldT};

/// bb `HidingKernelIO::PUBLIC_INPUTS_SIZE`: pairing points, the kernel return data commitment and
/// the four merged op-queue table commitments.
pub const HIDING_KERNEL_PUBLIC_INPUTS_SIZE: usize = 8 + 4 + 4 * 4;

/// bb `HidingKernelIO::reconstruct_from_public` (the trailing public inputs).
pub struct HidingKernelIo<C: Curve = Bn254> {
    pub pairing_points: PairingPoints<C>,
    pub kernel_return_data: C::G,
    pub ecc_op_tables: [C::G; 4],
}

impl<C: Curve> HidingKernelIo<C> {
    pub fn from_public_inputs(public_inputs: &[C::Fr]) -> Self {
        assert!(
            public_inputs.len() >= HIDING_KERNEL_PUBLIC_INPUTS_SIZE,
            "public inputs too small for HidingKernelIO"
        );
        let tail = &public_inputs[public_inputs.len() - HIDING_KERNEL_PUBLIC_INPUTS_SIZE..];
        let fields: Vec<C::TF> = tail.iter().flat_map(|f| f.to_fields()).collect();
        let point = |i: usize| <C::G as Transcriptable<C::TF>>::from_fields(&fields[i..i + 4]);
        Self {
            pairing_points: default_io_pairing_points::<C>(&tail[..8]),
            kernel_return_data: point(8),
            ecc_op_tables: std::array::from_fn(|k| point(12 + 4 * k)),
        }
    }
}


/// bb `ChonkVerifier<false>::verify`: the hiding kernel Oink, its IO consistency, the merge, the
/// ECCVM, the joint MegaZK + Translator proof, and finally the TripleIPA accumulator.
pub fn chonk_verify(hiding_vk: &Vk<Bn254>, proof: &ChonkProof, g2: &G2Points, grumpkin: &GrumpkinKey) -> bool {
    let layout = MEGA_ZK.layout();
    let overhead = mega_zk_oink_length_without_public_inputs();
    // bb `ChonkProof::has_valid_structure`.
    if proof.hiding_oink_proof.len() < overhead
        || proof.merge_proof.len() != MERGE_PROOF_SIZE
        || proof.eccvm_proof.len() != ECCVM_PROOF_LENGTH
        || proof.ipa_proof.len() != TRIPLE_IPA_PROOF_LENGTH
        || proof.joint_proof.len() != JOINT_PROOF_LENGTH
    {
        return false;
    }
    let num_public_inputs = proof.hiding_oink_proof.len() - overhead;
    let mut t = NativeTranscript::from_proof(&proof.hiding_oink_proof);
    let oink = verify_oink::<Bn254>(
        &MEGA_ZK,
        &layout,
        hiding_vk,
        &hiding_vk.hash(),
        &mut t,
        num_public_inputs,
        false,
    );
    let io = HidingKernelIo::from_public_inputs(&oink.public_inputs);
    if !io.pairing_points.check(g2) {
        eprintln!("chonk_verify: PI pairing check failed");
        return false;
    }
    if oink.commitments[layout.idx(Ent::kernel_calldata)] != io.kernel_return_data {
        return false;
    }
    let ecc_op_wires: [G1Affine; 4] = std::array::from_fn(|k| {
        oink.commitments[layout.idx(
            [
                Ent::ecc_op_wire_1,
                Ent::ecc_op_wire_2,
                Ent::ecc_op_wire_3,
                Ent::ecc_op_wire_4,
            ][k],
        )]
    });

    t.load_proof(&proof.merge_proof);
    let merge = merge_verify::<Bn254>(
        &MergeInputs {
            t_commitments: ecc_op_wires,
            t_prev_commitments: io.ecc_op_tables,
        },
        &mut t,
        &(),
    );
    if !merge.ok || !merge.pairing_points.check(g2) {
        eprintln!("chonk_verify: merge failed ok={}", merge.ok);
        return false;
    }

    t.load_proof(&proof.eccvm_proof);
    let eccvm = eccvm_verify::<crate::base::Grumpkin>(&(), &mut t);
    if !eccvm.ok {
        eprintln!("chonk_verify: eccvm failed");
        return false;
    }

    let joint = joint_verify::<Bn254, crate::base::Fq>(
        &(),
        hiding_vk,
        &oink,
        &proof.joint_proof,
        &eccvm.evaluation_challenge_x,
        &eccvm.batching_challenge_v,
        &eccvm.accumulated_result,
        &merge.merged_commitments,
        &mut t,
    );
    if !joint.verified || !joint.pairing_points.check(g2) {
        eprintln!("chonk_verify: joint failed verified={}", joint.verified);
        return false;
    }
    t.enforce_proof_fully_consumed("ChonkVerifier");

    let mut ipa_transcript = NativeTranscript::from_proof(&proof.ipa_proof);
    let ok = triple_ipa_verify(grumpkin, &eccvm.triple_ipa_claim, &mut ipa_transcript);
    ipa_transcript.enforce_proof_fully_consumed("TripleIPA");
    if !ok {
        eprintln!("chonk_verify: triple ipa failed");
    }
    ok
}

/// bb `ChonkVerifier<true>::Output`'s deferred TripleIPA data: the in-circuit claim plus the
/// (witness) IPA proof fields, reduced to an accumulator during the outer circuit's finalize.
pub struct DeferredTripleIpaOpening {
    pub claim: TripleIpaClaim<StdUltraGrumpkin>,
    pub proof: Vec<FieldT>,
}

pub struct ChonkRecursiveOutput {
    pub pairing_points: crate::base::group::PairingPoints<StdUltraBn254>,
    pub triple_ipa_opening: DeferredTripleIpaOpening,
    /// Native-value consistency of every reduction (the circuit enforces them; this mirrors bb's bool).
    pub all_checks_passed: bool,
}

/// bb `ChonkVerifier<true>::verify`: the whole Chonk verification in-circuit on an Ultra builder —
/// MegaZK Oink, databus consistency, merge, ECCVM (over in-circuit Grumpkin), the joint
/// MegaZK+Translator proof, and the aggregation of all three pairing-point pairs. The TripleIPA
/// opening is deferred to the caller.
pub fn chonk_verify_recursive(
    ctx: &Ctx,
    hiding_vk: &Vk<StdUltraBn254>,
    vk_hash: &FieldT,
    proof_fields: &[FieldT],
) -> ChonkRecursiveOutput {
    use super::proof::{ECCVM_PROOF_LENGTH, JOINT_PROOF_LENGTH, TRIPLE_IPA_PROOF_LENGTH};
    use crate::goblin::merge::MergeInputs;
    let fixed =
        crate::goblin::merge::MERGE_PROOF_SIZE + ECCVM_PROOF_LENGTH + TRIPLE_IPA_PROOF_LENGTH + JOINT_PROOF_LENGTH;
    assert!(
        proof_fields.len() >= fixed,
        "Chonk proof too short: {}",
        proof_fields.len()
    );
    let mut rest = proof_fields;
    let mut take = |n: usize| {
        let (head, tail) = rest.split_at(n);
        rest = tail;
        head
    };
    let hiding_oink = take(proof_fields.len() - fixed);
    let merge_fields = take(crate::goblin::merge::MERGE_PROOF_SIZE);
    let eccvm_fields = take(ECCVM_PROOF_LENGTH);
    let ipa_fields = take(TRIPLE_IPA_PROOF_LENGTH);
    let joint_fields = take(JOINT_PROOF_LENGTH);

    let layout = MEGA_ZK.layout();
    let num_public_inputs = hiding_oink.len() - mega_zk_oink_length_without_public_inputs();
    let mut t = crate::rollup::ipa_recursive::StdlibTranscript::from_proof(hiding_oink);
    let oink = verify_oink::<StdUltraBn254>(&MEGA_ZK, &layout, hiding_vk, vk_hash, &mut t, num_public_inputs, false);
    let io = HidingKernelIo::<StdUltraBn254>::from_public_inputs(&oink.public_inputs);

    // Databus consistency: the hiding kernel's return data is its own calldata commitment.
    let kernel_calldata = oink.commitments[layout.idx(Ent::kernel_calldata)].clone();
    let databus_ok = io.kernel_return_data.get_value() == kernel_calldata.get_value();
    io.kernel_return_data.incomplete_assert_equal(&kernel_calldata);

    let ecc_op_wires = std::array::from_fn(|k| {
        oink.commitments[layout.idx(
            [
                Ent::ecc_op_wire_1,
                Ent::ecc_op_wire_2,
                Ent::ecc_op_wire_3,
                Ent::ecc_op_wire_4,
            ][k],
        )]
        .clone()
    });
    t.load_proof(merge_fields);
    let merge = crate::goblin::merge::merge_verify::<StdUltraBn254>(
        &MergeInputs {
            t_commitments: ecc_op_wires,
            t_prev_commitments: io.ecc_op_tables.clone(),
        },
        &mut t,
        ctx,
    );

    t.load_proof(eccvm_fields);
    let eccvm = eccvm_verify::<StdUltraGrumpkin>(ctx, &mut t);

    let joint = joint_verify::<StdUltraBn254, crate::stdlib::bigfield::BigField<crate::base::Fq>>(
        ctx,
        hiding_vk,
        &oink,
        joint_fields,
        &eccvm.evaluation_challenge_x,
        &eccvm.batching_challenge_v,
        &eccvm.accumulated_result,
        &merge.merged_commitments,
        &mut t,
    );

    let pairing_points =
        crate::rollup::aggregate_multiple(vec![io.pairing_points, merge.pairing_points, joint.pairing_points]);
    ChonkRecursiveOutput {
        pairing_points,
        triple_ipa_opening: DeferredTripleIpaOpening {
            claim: eccvm.triple_ipa_claim,
            proof: ipa_fields.to_vec(),
        },
        all_checks_passed: databus_ok && merge.ok && eccvm.ok && joint.verified,
    }
}
