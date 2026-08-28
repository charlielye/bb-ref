//! UltraHonk prover (bb `ultra_honk/ultra_prover.cpp`).

use super::oink_prover::prove_oink_as;
use super::pcs::{kzg_open, shplemini_prove, small_subgroup_ipa_prove};
use super::prover_instance::ProverInstance;
use super::sumcheck::{prove_sumcheck, HonkRelations, SumcheckSpec, ZkData};
use crate::base::group::Curve;
use crate::base::rng::Rng;
use crate::base::transcript::Transcript;
use crate::base::vk::Vk;
use crate::base::{Bn254, CommitmentKey, Fr, G1Affine};

/// Produce the full proof (public inputs first, then the Honk proof).
pub fn prove_ultra(inst: &mut ProverInstance, vk: &Vk<Bn254>, rng: &mut dyn Rng) -> Vec<Fr> {
    prove_ultra_as::<Bn254>(inst, vk, rng)
}

/// Generic over the transcript codec/hash: `Bn254` natively, `KeccakBn254` for the Keccak flavors.
pub fn prove_ultra_as<C>(inst: &mut ProverInstance, vk: &Vk<C>, rng: &mut dyn Rng) -> Vec<C::TF>
where
    C: Curve<Fr = Fr, G = G1Affine>,
    Fr: crate::base::codec::Transcriptable<C::TF> + crate::base::codec::FromChallenge<C::TF>,
    G1Affine: crate::base::codec::Transcriptable<C::TF>,
{
    // bb `UltraProver_::generate_gate_challenges`: unpadded flavors use the actual dyadic log.
    let mut flavor_local = *inst.flavor;
    if !flavor_local.use_padding {
        flavor_local.virtual_log_n = inst.log_n();
    }
    let flavor = &flavor_local;
    let mut key_size = inst.max_end_index;
    if flavor.has_zk {
        key_size = key_size.max(2 * Bn254::SUBGROUP_SIZE);
    }
    let ck = CommitmentKey::new(key_size);
    let mut t = Transcript::<C::TF, C::Hash>::new();

    let oink = prove_oink_as::<C>(inst, vk, &ck, &mut t, rng, true);
    let betas: Vec<Fr> = t.dyadic_powers("Sumcheck:gate_challenge", flavor.virtual_log_n);

    let mut zk = flavor
        .has_zk
        .then(|| ZkData::<C>::new(flavor.virtual_log_n, &mut t, &ck, rng));
    let rels = HonkRelations {
        flavor,
        layout: &inst.layout,
    };
    let sc = prove_sumcheck::<C>(
        &rels,
        &SumcheckSpec::honk(flavor, &inst.layout).with_witness_end(inst.max_end_index),
        &inst.polys,
        &mut t,
        &oink.alpha,
        &betas,
        &oink.params,
        zk.as_mut(),
        None,
    );

    let layout = &inst.layout;
    let unshifted: Vec<&_> = inst.polys.iter().collect();
    let to_be_shifted: Vec<&_> = layout.shifted.iter().map(|e| inst.poly(*e)).collect();
    let libra = zk
        .as_ref()
        .map(|z| small_subgroup_ipa_prove::<C>(z, &sc.challenge, &sc.libra_evaluation, &ck, &mut t, rng));
    let claim = shplemini_prove::<C>(
        &unshifted,
        &to_be_shifted,
        &sc.challenge,
        &ck,
        &mut t,
        libra.as_ref(),
        &[],
    );
    kzg_open::<C>(claim, &ck, &mut t);
    let mut proof = t.export_proof();
    // bb `UltraProver_::construct_proof`: a RollupIO circuit's IPA proof rides after the Honk proof.
    for f in &inst.ipa_proof {
        proof.extend(crate::base::codec::Transcriptable::<C::TF>::to_fields(f));
    }
    proof
}
