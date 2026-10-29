//! The inner layer of bb's two-layer AVM recursive verifier (bb
//! `vm2/constraining/recursion/two_layer_avm_recursive_verifier.hpp`): a MegaAvm circuit verifying
//! an AVM proof, its EC operations deferred to the op queue. Its public inputs are the final
//! transcript state (binding the outer circuit to the same proof and public inputs) and the
//! pairing points.

use super::tables::layout;
use super::verifier::reduce_to_pairing_check;
use crate::base::field::Fr;
use crate::base::group::GroupLike;
use crate::base::rng::GlobalProxy;
use crate::base::Fq;
use crate::circuit::op_queue::EccOpQueue;
use crate::circuit::Builder;
use crate::stdlib::curve::StdBn254;
use crate::stdlib::field::{Ctx, FieldT};
use crate::stdlib::goblin::GoblinElement;
use crate::stdlib::io::{proof_to_witnesses, set_pairing_points_public};
use std::cell::RefCell;
use std::rc::Rc;

/// bb `TwoLayerAvmRecursiveVerifier::construct_inner_recursive_verification_circuit`, on a fresh
/// Mega builder set up as bb's `GoblinAvm` constructor leaves it.
pub fn inner_circuit(proof: &[Fr], public_inputs: &[Vec<Fr>]) -> Builder {
    let ctx: Ctx = Rc::new(RefCell::new(Builder::new_mega(EccOpQueue::shared())));
    {
        // bb `GoblinAvm::GoblinAvm`: the Translator's shiftability no-op, three random ops, and an
        // eq-and-reset hiding op at (0, 0) (the AVM needs no ZK).
        let mut b = ctx.borrow_mut();
        b.queue_ecc_no_op();
        for _ in 0..3 {
            b.queue_ecc_random_op(&mut GlobalProxy);
        }
        b.queue_ecc_hiding_op(Fq::from(0u64), Fq::from(0u64));
    }
    {
        let stdlib_proof = proof_to_witnesses(&ctx, proof);
        let stdlib_public_inputs: Vec<Vec<FieldT>> =
            public_inputs.iter().map(|column| proof_to_witnesses(&ctx, column)).collect();

        // bb `FixedStdlibVKAndHash_`: the hash, then every commitment, as witnesses; then all fixed.
        let l = layout();
        let vk_hash = FieldT::from_witness(&ctx, l.vk_hash);
        let vk: Vec<GoblinElement> = l.vk.iter().map(|p| GoblinElement::from_witness(&ctx, *p)).collect();
        vk_hash.fix_witness();
        for c in &vk {
            c.fix_witness();
        }

        let mut r = reduce_to_pairing_check::<StdBn254>(&stdlib_proof, &stdlib_public_inputs, &vk, &vk_hash, &ctx)
            .unwrap_or_else(|e| panic!("AvmRecursiveVerifier::verify_proof: {e}"));
        let transcript_hash: FieldT = r.transcript.challenge("final_transcript_state");

        // bb `GoblinAvmIO::set_public`
        transcript_hash.set_public();
        set_pairing_points_public(&r.pairing_points);
        ctx.borrow_mut().finalize_public_inputs();
    }
    Rc::try_unwrap(ctx).ok().expect("builder still shared").into_inner()
}
