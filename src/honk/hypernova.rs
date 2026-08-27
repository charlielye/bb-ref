//! HyperNova folding (bb `hypernova/hypernova_prover.hpp`, `hypernova_verifier.cpp`): each incoming
//! circuit is reduced to a *claim* — a batched evaluation of all its polynomials at the sumcheck
//! point — and a kernel's group of claims is batched into one accumulator by the multilinear
//! batching sumcheck. Opening the accumulator is deferred to the decider.

use super::flavor::FlavorDesc;
use super::multilinear_batching::{mlb_prove, mlb_verify};
use super::oink::{verify_oink, OinkOutput};
use super::oink_prover::prove_oink;
use super::prover_instance::ProverInstance;
use super::sumcheck::{prove_sumcheck, verify_sumcheck, HonkRelations, SumcheckSpec};
use crate::base::codec::{ChallengeField, Transcriptable};
use crate::base::field::FieldLike;
use crate::base::group::{Curve, GroupLike};
use crate::base::poseidon2::Hasher;
use crate::base::transcript::Transcript;
use crate::base::{Bn254, CommitmentKey, Fr, G1Affine, NativeTranscript, Poly, Rng, Vk};

/// The prover's accumulator: batched polynomials with their claimed evaluations and commitments
/// (bb `MultilinearBatchingProverClaim`). `shifted_polynomial` is the pre-shift form.
#[derive(Clone)]
pub struct ProverClaim {
    pub challenge: Vec<Fr>,
    pub non_shifted_evaluation: Fr,
    pub shifted_evaluation: Fr,
    pub non_shifted_polynomial: Poly,
    pub shifted_polynomial: Poly,
    pub non_shifted_commitment: G1Affine,
    pub shifted_commitment: G1Affine,
    pub dyadic_size: usize,
}

/// The verifier's accumulator (bb `MultilinearBatchingVerifierClaim`).
#[derive(Clone)]
pub struct VerifierClaim<C: Curve> {
    pub challenge: Vec<C::Fr>,
    pub non_shifted_evaluation: C::Fr,
    pub shifted_evaluation: C::Fr,
    pub non_shifted_commitment: C::G,
    pub shifted_commitment: C::G,
}

impl<C: Curve> VerifierClaim<C> {
    /// bb `hash_with_origin_tagging`: Poseidon2 over the challenge, the two evaluations and the two
    /// commitments (the kernel's `output_hn_accum_hash`).
    pub fn hash(&self) -> C::TF {
        let mut fields: Vec<C::TF> = self.challenge.iter().flat_map(Transcriptable::to_fields).collect();
        fields.extend(self.non_shifted_evaluation.to_fields());
        fields.extend(self.shifted_evaluation.to_fields());
        fields.extend(self.non_shifted_commitment.to_fields());
        fields.extend(self.shifted_commitment.to_fields());
        C::Hash::hash(&fields)
    }
    /// bb `stdlib_from_native`: every component as a fresh witness, in declaration order.
    pub fn from_native<N: Curve>(ctx: &<C::Fr as FieldLike>::Ctx, native: &VerifierClaim<N>) -> Self
    where
        C::Fr: FieldLike<Native = <N::Fr as FieldLike>::Native>,
        C::G: GroupLike<C::Fr, Native = <N::G as GroupLike<N::Fr>>::Native>,
    {
        Self {
            challenge: native.challenge.iter().map(|c| C::Fr::from_witness(ctx, c.value())).collect(),
            non_shifted_evaluation: C::Fr::from_witness(ctx, native.non_shifted_evaluation.value()),
            shifted_evaluation: C::Fr::from_witness(ctx, native.shifted_evaluation.value()),
            non_shifted_commitment: C::G::from_witness(ctx, native.non_shifted_commitment.value()),
            shifted_commitment: C::G::from_witness(ctx, native.shifted_commitment.value()),
        }
    }
}

impl ProverClaim {
    pub fn to_verifier_claim(&self) -> VerifierClaim<Bn254> {
        VerifierClaim {
            challenge: self.challenge.clone(),
            non_shifted_evaluation: self.non_shifted_evaluation,
            shifted_evaluation: self.shifted_evaluation,
            non_shifted_commitment: self.non_shifted_commitment,
            shifted_commitment: self.shifted_commitment,
        }
    }
}

impl<C: Curve> std::fmt::Debug for VerifierClaim<C>
where
    C::Fr: std::fmt::Debug,
    C::G: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifierClaim")
            .field("challenge", &self.challenge)
            .field("non_shifted_evaluation", &self.non_shifted_evaluation)
            .field("shifted_evaluation", &self.shifted_evaluation)
            .field("non_shifted_commitment", &self.non_shifted_commitment)
            .field("shifted_commitment", &self.shifted_commitment)
            .finish()
    }
}

impl<C: Curve> PartialEq for VerifierClaim<C>
where
    C::Fr: PartialEq,
    C::G: PartialEq,
{
    fn eq(&self, o: &Self) -> bool {
        self.challenge == o.challenge
            && self.non_shifted_evaluation == o.non_shifted_evaluation
            && self.shifted_evaluation == o.shifted_evaluation
            && self.non_shifted_commitment == o.non_shifted_commitment
            && self.shifted_commitment == o.shifted_commitment
    }
}

/// bb `get_hypernova_batching_challenges`: `n - 1` short challenges with an implicit leading 1.
pub fn batching_challenges<C: Curve>(t: &mut Transcript<C::TF, C::Hash>, num_unshifted: usize, num_shifted: usize) -> (Vec<C::Fr>, Vec<C::Fr>)
where
    C::TF: ChallengeField,
{
    let labels = |prefix: &str, n: usize| (0..n - 1).map(|i| format!("{prefix}_{i}")).collect::<Vec<_>>();
    let draw = |t: &mut Transcript<C::TF, C::Hash>, labels: Vec<String>| {
        let refs: Vec<&str> = labels.iter().map(String::as_str).collect();
        let mut v: Vec<C::Fr> = t.short_challenges(&refs);
        v.insert(0, C::Fr::one());
        v
    };
    let unshifted = draw(t, labels("unshifted_challenge", num_unshifted));
    let shifted = draw(t, labels("shifted_challenge", num_shifted));
    (unshifted, shifted)
}

/// Proof length of Oink + sumcheck for a non-ZK flavor, excluding the public inputs.
pub fn instance_proof_length_without_pis<C: Curve>(flavor: &FlavorDesc) -> usize {
    assert!(!flavor.has_zk, "only non-ZK flavors are folded");
    let layout = flavor.layout();
    let g = <C::G as Transcriptable<C::TF>>::num_fields();
    (layout.num_witness + layout.num_masking) * g + flavor.virtual_log_n * layout.batched_len + layout.num_all()
}

/// Oink + sumcheck on an instance, then batch its polynomials into one claim
/// (bb `HypernovaFoldingProver::instance_to_accumulator`).
pub fn instance_to_accumulator(inst: &mut ProverInstance, vk: &Vk<Bn254>, ck: &CommitmentKey, t: &mut NativeTranscript, rng: &mut dyn Rng) -> ProverClaim {
    let flavor = inst.flavor;
    let oink = prove_oink(inst, vk, ck, t, rng, true);
    crate::base::timing::phase("  fold: oink");
    let betas: Vec<Fr> = t.dyadic_powers("HypernovaFoldingProver:gate_challenge", flavor.virtual_log_n);
    let polys = inst.all_polys();
    let sc = prove_sumcheck::<Bn254>(
        &HonkRelations { flavor, layout: &inst.layout },
        &SumcheckSpec::honk(flavor, &inst.layout),
        &polys,
        t,
        &oink.alpha,
        &betas,
        &oink.params,
        None,
        None,
    );
    crate::base::timing::phase("  fold: sumcheck");

    let layout = &inst.layout;
    let (uc, sh) = batching_challenges::<Bn254>(t, layout.num_unshifted(), layout.num_shifted());
    let mut non_shifted_polynomial = Poly::zero(inst.dyadic_size);
    let mut shifted_polynomial = Poly::zero(inst.dyadic_size);
    let mut non_shifted_evaluation = Fr::zero();
    let mut shifted_evaluation = Fr::zero();
    for (i, c) in uc.iter().enumerate() {
        non_shifted_polynomial.add_scaled(&inst.polys[i], c);
        non_shifted_evaluation += sc.evals[i] * c;
    }
    for (j, c) in sh.iter().enumerate() {
        shifted_polynomial.add_scaled(inst.poly(layout.shifted[j]), c);
        shifted_evaluation += sc.evals[layout.num_unshifted() + j] * c;
    }
    // Batching the commitments equals committing to the batched polynomials.
    ProverClaim {
        challenge: sc.challenge,
        non_shifted_evaluation,
        shifted_evaluation,
        non_shifted_commitment: ck.commit(&non_shifted_polynomial),
        shifted_commitment: ck.commit(&shifted_polynomial),
        non_shifted_polynomial,
        shifted_polynomial,
        dyadic_size: inst.dyadic_size,
    }
}

/// The verifier's side of `instance_to_accumulator` on a proof already loaded into `t`. Returns the
/// Oink output too (public inputs and witness commitments feed the kernel's IO checks).
pub fn verify_instance_to_accumulator<C: Curve>(
    flavor: &FlavorDesc,
    vk: &Vk<C>,
    vk_hash: &C::TF,
    num_public_inputs: usize,
    t: &mut Transcript<C::TF, C::Hash>,
) -> (bool, VerifierClaim<C>, OinkOutput<C>)
where
    C::TF: ChallengeField,
{
    let layout = flavor.layout();
    let oink = verify_oink::<C>(flavor, &layout, vk, vk_hash, t, num_public_inputs, true);
    let betas: Vec<C::Fr> = t.dyadic_powers("HypernovaFoldingProver:gate_challenge", flavor.virtual_log_n);
    let sc = verify_sumcheck::<C>(&HonkRelations { flavor, layout: &layout }, &SumcheckSpec::honk(flavor, &layout), t, &oink.alpha, &oink.params, &betas);
    crate::circuit::builder::trace_phase("hypernova: sumcheck verified");
    let (uc, sh) = batching_challenges::<C>(t, layout.num_unshifted(), layout.num_shifted());
    crate::circuit::builder::trace_phase("hypernova: batching challenges");
    let mut non_shifted_evaluation = C::Fr::zero();
    let mut shifted_evaluation = C::Fr::zero();
    for (i, c) in uc.iter().enumerate() {
        non_shifted_evaluation += &(sc.evals[i].clone() * c);
    }
    for (j, c) in sh.iter().enumerate() {
        shifted_evaluation += &(sc.evals[layout.num_unshifted() + j].clone() * c);
    }
    crate::circuit::builder::trace_phase("hypernova: batched evaluations");
    let to_be_shifted: Vec<C::G> = layout.shifted.iter().map(|e| oink.commitments[layout.idx(*e)].clone()).collect();
    let claim = VerifierClaim {
        challenge: sc.challenge,
        non_shifted_evaluation,
        shifted_evaluation,
        non_shifted_commitment: C::G::batch_mul(&oink.commitments, &uc),
        shifted_commitment: C::G::batch_mul(&to_be_shifted, &sh),
    };
    crate::circuit::builder::trace_phase("hypernova: batched commitments");
    (sc.verified, claim, oink)
}

/// Stateful driver for one folding group (bb `HypernovaFoldingProver`): accumulate each instance,
/// then batch the group (plus the previous accumulator, if any) into one claim.
pub struct FoldingProver {
    pub transcript: NativeTranscript,
    cached: Vec<ProverClaim>,
}

impl FoldingProver {
    pub fn new() -> Self {
        Self {
            transcript: NativeTranscript::new(),
            cached: vec![],
        }
    }
    /// Returns the instance's proof slice (Oink + sumcheck).
    pub fn accumulate_instance(&mut self, inst: &mut ProverInstance, vk: &Vk<Bn254>, ck: &CommitmentKey, rng: &mut dyn Rng) -> Vec<Fr> {
        let claim = instance_to_accumulator(inst, vk, ck, &mut self.transcript, rng);
        self.cached.push(claim);
        self.transcript.export_proof()
    }
    /// The batching proof (empty for a single claim) and the new accumulator.
    pub fn finalize(&mut self, previous: Option<ProverClaim>) -> (Vec<Fr>, ProverClaim) {
        let mut claims: Vec<ProverClaim> = previous.into_iter().collect();
        claims.append(&mut self.cached);
        assert!(!claims.is_empty(), "nothing to fold");
        if claims.len() == 1 {
            return (vec![], claims.pop().unwrap());
        }
        let claim = mlb_prove(claims, &mut self.transcript);
        (self.transcript.export_proof(), claim)
    }
}

impl Default for FoldingProver {
    fn default() -> Self {
        Self::new()
    }
}

/// bb `HypernovaFoldingVerifier`.
pub struct FoldingVerifier<C: Curve> {
    pub transcript: Transcript<C::TF, C::Hash>,
    cached: Vec<VerifierClaim<C>>,
}

impl<C: Curve> FoldingVerifier<C>
where
    C::TF: ChallengeField,
{
    pub fn new() -> Self {
        Self {
            transcript: Transcript::new(),
            cached: vec![],
        }
    }
    pub fn accumulate_instance(&mut self, flavor: &FlavorDesc, vk: &Vk<C>, vk_hash: &C::TF, proof: &[C::TF]) -> (bool, OinkOutput<C>) {
        let num_public_inputs = proof.len() - instance_proof_length_without_pis::<C>(flavor);
        self.transcript.load_proof(proof);
        let (verified, claim, oink) = verify_instance_to_accumulator::<C>(flavor, vk, vk_hash, num_public_inputs, &mut self.transcript);
        self.cached.push(claim);
        (verified, oink)
    }
    pub fn finalize(&mut self, batching_proof: &[C::TF], previous: Option<VerifierClaim<C>>) -> (bool, VerifierClaim<C>) {
        let mut claims: Vec<VerifierClaim<C>> = previous.into_iter().collect();
        claims.append(&mut self.cached);
        assert!(!claims.is_empty(), "nothing to fold");
        if claims.len() == 1 {
            return (true, claims.pop().unwrap());
        }
        self.transcript.load_proof(batching_proof);
        mlb_verify::<C>(&claims, &mut self.transcript)
    }
}

impl<C: Curve> Default for FoldingVerifier<C>
where
    C::TF: ChallengeField,
{
    fn default() -> Self {
        Self::new()
    }
}
