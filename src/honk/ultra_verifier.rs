//! UltraHonk verifier (bb `ultra_honk/ultra_verifier.cpp` with `DefaultIO`).

use super::flavor::{FlavorDesc, Layout};
use super::oink::verify_oink;
use super::pcs::{kzg_reduce_verify_batch_opening_claim, shplemini_verify, ClaimBatcher, NUM_SMALL_IPA_COMMITMENTS};
use super::sumcheck::{verify_sumcheck, HonkRelations, SumcheckSpec};
use crate::base::codec::Transcriptable;
use crate::base::field::FieldLike;
use crate::base::group::{Bn254, Curve, G2Points, GroupLike, PairingPoints};
use crate::base::transcript::Transcript;
use crate::base::vk::Vk;
use ark_ec::AffineRepr;

/// Proof length excluding public inputs (bb `honk/proof_length.hpp::Honk::LENGTH_WITHOUT_PUB_INPUTS`).
pub fn proof_length_without_public_inputs<C: Curve>(flavor: &FlavorDesc, layout: &Layout) -> usize {
    let comm = C::G::num_fields();
    let scalar = C::Fr::num_fields();
    let log_n = flavor.virtual_log_n;
    let oink = (layout.num_witness + layout.num_masking) * comm;
    let mut sumcheck = log_n * layout.batched_len * scalar + layout.num_all() * scalar;
    let mut shplemini = (log_n - 1) * comm + log_n * scalar + 2 * comm;
    if flavor.has_zk {
        sumcheck += 3 * comm + 2 * scalar;
        shplemini += 4 * scalar; // transmitted small-IPA evaluations
    }
    oink + sumcheck + shplemini
}

pub fn final_pcs_msm_size(flavor: &FlavorDesc, layout: &Layout) -> usize {
    layout.num_unshifted() + flavor.virtual_log_n + 2 + if flavor.has_zk { NUM_SMALL_IPA_COMMITMENTS } else { 0 }
}

/// The result of running the verifier up to (but not including) the pairing checks.
pub struct Reduction<C: Curve> {
    pub public_inputs: Vec<C::Fr>,
    /// Pairing points produced by the PCS.
    pub pcs_pairing_points: PairingPoints<C>,
    /// Sumcheck and (ZK) Libra consistency checks.
    pub succeeded: bool,
}

/// bb `UltraVerifier_::reduce_to_pairing_check`. `proof` = public inputs followed by the Honk proof.
pub fn reduce_to_pairing_check<C: Curve>(flavor: &FlavorDesc, vk: &Vk<C>, proof: &[C::TF], ctx: &<C::Fr as FieldLike>::Ctx) -> Reduction<C> {
    let layout = flavor.layout();
    let overhead = proof_length_without_public_inputs::<C>(flavor, &layout);
    assert!(proof.len() >= overhead, "proof too short: {} < {overhead}", proof.len());
    let num_public_inputs = proof.len() - overhead;
    let log_n = flavor.virtual_log_n;

    let mut t = Transcript::<C::TF, C::Hash>::from_proof(proof);
    let oink = verify_oink::<C>(flavor, &layout, vk, &mut t, num_public_inputs);
    let gate_challenges: Vec<C::Fr> = t.dyadic_powers("Sumcheck:gate_challenge", log_n);

    let mut libra_commitments: Vec<C::G> = Vec::new();
    if flavor.has_zk {
        libra_commitments.push(t.receive("Libra:concatenation_commitment"));
    }
    let sc = verify_sumcheck::<C>(&HonkRelations { flavor, layout: &layout }, &SumcheckSpec::honk(flavor, &layout), &mut t, &oink.alpha, &oink.params, &gate_challenges);
    if flavor.has_zk {
        libra_commitments.push(t.receive("Libra:grand_sum_commitment"));
        libra_commitments.push(t.receive("Libra:quotient_commitment"));
    }

    let n_unshifted = layout.num_unshifted();
    let batcher = ClaimBatcher::<C> {
        unshifted_comms: oink.commitments.clone(),
        unshifted_evals: sc.evals[..n_unshifted].to_vec(),
        shifted_comms: layout.shifted.iter().map(|e| oink.commitments[layout.idx(*e)].clone()).collect(),
        shifted_evals: sc.evals[n_unshifted..].to_vec(),
    };
    let repeated: Vec<(usize, usize)> = layout.shifted.iter().enumerate().map(|(j, e)| (layout.idx(*e), n_unshifted + j)).collect();
    let one = C::G::one(ctx);
    let shplemini = shplemini_verify::<C>(
        flavor.has_zk,
        flavor.has_gemini_masking,
        &batcher,
        &sc.challenge,
        &one,
        &mut t,
        &repeated,
        &libra_commitments,
        &sc.libra_evaluation,
    );
    let pcs_pairing_points = kzg_reduce_verify_batch_opening_claim::<C>(shplemini.claim, &mut t, final_pcs_msm_size(flavor, &layout));
    Reduction { public_inputs: oink.public_inputs, pcs_pairing_points, succeeded: sc.verified && shplemini.consistency_checked }
}

/// The pairing-point accumulator carried in the last 8 public inputs (bb `DefaultIO`).
pub fn default_io_pairing_points<C: Curve>(public_inputs: &[C::Fr]) -> PairingPoints<C>
where
    C::Fr: Transcriptable<C::TF>,
{
    let n = PairingPoints::<C>::num_fields();
    assert!(public_inputs.len() >= n, "public inputs too small for DefaultIO");
    let fields: Vec<C::TF> = public_inputs[public_inputs.len() - n..].iter().flat_map(|f| f.to_fields()).collect();
    PairingPoints::from_fields(&fields)
}

/// Native UltraHonk verification. `public_inputs` are the user public inputs; `proof` is bb's proof
/// (which starts with the pairing-point public inputs).
pub fn verify_ultra(flavor: &FlavorDesc, vk: &Vk<Bn254>, public_inputs: &[crate::base::Fr], proof: &[crate::base::Fr], g2: &G2Points) -> bool {
    let full: Vec<_> = [public_inputs, proof].concat();
    let r = reduce_to_pairing_check::<Bn254>(flavor, vk, &full, &());
    if !r.succeeded {
        return false;
    }
    let pi_points = default_io_pairing_points::<Bn254>(&r.public_inputs);
    // A default (all-infinity) accumulator carries no claim. Otherwise, both pairing claims must hold;
    // bb aggregates them with a random separator, which is equivalent and unobservable.
    let pi_ok = (AffineRepr::is_zero(&pi_points.p0) && AffineRepr::is_zero(&pi_points.p1)) || pi_points.check(g2);
    pi_ok && r.pcs_pairing_points.check(g2)
}
