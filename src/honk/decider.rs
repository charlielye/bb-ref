//! HyperNova decider (bb `hypernova/hypernova_decider_{prover,verifier}.cpp`): open the final
//! accumulator's two commitments at its challenge with Shplemini + KZG.

use super::hypernova::{ProverClaim, VerifierClaim};
use super::pcs::{kzg_open, kzg_reduce_verify_batch_opening_claim, shplemini_prove, shplemini_verify, ClaimBatcher};
use crate::base::field::FieldLike;
use crate::base::group::{Curve, GroupLike, PairingPoints};
use crate::base::transcript::Transcript;
use crate::base::{CommitmentKey, NativeTranscript};

pub fn decider_prove(acc: &ProverClaim, ck: &CommitmentKey, t: &mut NativeTranscript) {
    let claim = shplemini_prove::<crate::base::Bn254>(
        &[&acc.non_shifted_polynomial],
        &[&acc.shifted_polynomial],
        &acc.challenge,
        &ck,
        t,
        None,
        &[],
    );
    kzg_open::<crate::base::Bn254>(claim, &ck, t);
}

pub fn decider_verify<C: Curve>(
    acc: &VerifierClaim<C>,
    t: &mut Transcript<C::TF, C::Hash>,
    ctx: &<C::Fr as FieldLike>::Ctx,
) -> PairingPoints<C> {
    let batcher = ClaimBatcher {
        unshifted_comms: vec![acc.non_shifted_commitment.clone()],
        unshifted_evals: vec![acc.non_shifted_evaluation.clone()],
        shifted_comms: vec![acc.shifted_commitment.clone()],
        shifted_evals: vec![acc.shifted_evaluation.clone()],
    };
    let out = shplemini_verify::<C>(
        false,
        false,
        &batcher,
        &acc.challenge,
        &C::G::one(ctx),
        t,
        &[],
        &[],
        &C::Fr::zero(),
        &[],
        &[],
    );
    let msm_size = out.claim.commitments.len() + 1;
    kzg_reduce_verify_batch_opening_claim::<C>(out.claim, t, msm_size)
}
