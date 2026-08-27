//! bb `ChonkVerifier<false>`: native verification of a Chonk proof against the hiding kernel's VK.

use super::batched::{joint_verify, mega_zk_oink_length_without_public_inputs, JointVerifierInputs};
use super::proof::ChonkProof;
use crate::base::codec::Transcriptable;
use crate::base::group::{G2Points, PairingPoints};
use crate::base::vk::Vk;
use crate::base::{Bn254, Fr, G1Affine, GrumpkinKey, NativeTranscript};
use crate::goblin::eccvm::verifier::eccvm_verify;
use crate::goblin::ipa::triple_ipa_verify;
use crate::goblin::merge::{merge_verify, MergeInputs};
use crate::honk::flavor::{Ent, MEGA_ZK};
use crate::honk::oink::verify_oink;
use crate::honk::ultra_verifier::default_io_pairing_points;

/// bb `HidingKernelIO::PUBLIC_INPUTS_SIZE`: pairing points, the kernel return data commitment and
/// the four merged op-queue table commitments.
pub const HIDING_KERNEL_PUBLIC_INPUTS_SIZE: usize = 8 + 4 + 4 * 4;

/// bb `HidingKernelIO::reconstruct_from_public` (the trailing public inputs).
pub struct HidingKernelIo {
    pub pairing_points: PairingPoints<Bn254>,
    pub kernel_return_data: G1Affine,
    pub ecc_op_tables: [G1Affine; 4],
}

impl HidingKernelIo {
    pub fn from_public_inputs(public_inputs: &[Fr]) -> Self {
        assert!(public_inputs.len() >= HIDING_KERNEL_PUBLIC_INPUTS_SIZE, "public inputs too small for HidingKernelIO");
        let tail = &public_inputs[public_inputs.len() - HIDING_KERNEL_PUBLIC_INPUTS_SIZE..];
        let point = |i: usize| <G1Affine as Transcriptable<Fr>>::from_fields(&tail[i..i + 4]);
        Self {
            pairing_points: default_io_pairing_points::<Bn254>(&tail[..8]),
            kernel_return_data: point(8),
            ecc_op_tables: std::array::from_fn(|k| point(12 + 4 * k)),
        }
    }
    pub fn to_public_inputs(&self) -> Vec<Fr> {
        let mut out = self.pairing_points.to_fields();
        out.extend(self.kernel_return_data.to_fields());
        for c in &self.ecc_op_tables {
            out.extend(c.to_fields());
        }
        out
    }
}

/// bb `ChonkVerifier<false>::verify`: the hiding kernel Oink, its IO consistency, the merge, the
/// ECCVM, the joint MegaZK + Translator proof, and finally the TripleIPA accumulator.
pub fn chonk_verify(hiding_vk: &Vk<Bn254>, proof: &ChonkProof, g2: &G2Points, grumpkin: &GrumpkinKey) -> bool {
    let layout = MEGA_ZK.layout();
    let overhead = mega_zk_oink_length_without_public_inputs();
    if proof.hiding_oink_proof.len() < overhead {
        return false;
    }
    let num_public_inputs = proof.hiding_oink_proof.len() - overhead;
    let mut t = NativeTranscript::from_proof(&proof.hiding_oink_proof);
    let oink = verify_oink::<Bn254>(&MEGA_ZK, &layout, hiding_vk, &hiding_vk.hash(), &mut t, num_public_inputs, false);
    let io = HidingKernelIo::from_public_inputs(&oink.public_inputs);
    if !io.pairing_points.check(g2) {
        return false;
    }
    if oink.commitments[layout.idx(Ent::kernel_calldata)] != io.kernel_return_data {
        return false;
    }
    let ecc_op_wires: [G1Affine; 4] = std::array::from_fn(|k| oink.commitments[layout.idx([Ent::ecc_op_wire_1, Ent::ecc_op_wire_2, Ent::ecc_op_wire_3, Ent::ecc_op_wire_4][k])]);

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
        return false;
    }

    t.load_proof(&proof.eccvm_proof);
    let eccvm = eccvm_verify(&mut t);
    if !eccvm.ok {
        return false;
    }

    let inputs = JointVerifierInputs {
        evaluation_input_x: eccvm.evaluation_challenge_x,
        batching_challenge_v: eccvm.batching_challenge_v,
        accumulated_result: eccvm.accumulated_result,
        op_queue_wire_commitments: merge.merged_commitments,
    };
    let joint = joint_verify(hiding_vk, &oink, &proof.joint_proof, &inputs, &mut t);
    if !joint.verified || !joint.pairing_points.check(g2) {
        return false;
    }

    triple_ipa_verify(grumpkin, &eccvm.triple_ipa_claim, &mut NativeTranscript::from_proof(&proof.ipa_proof))
}
