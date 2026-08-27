//! UltraHonk prover (bb `ultra_honk/ultra_prover.cpp`).

use super::oink_prover::prove_oink;
use super::pcs::{kzg_open, shplemini_prove, small_subgroup_ipa_prove};
use super::prover_instance::ProverInstance;
use super::sumcheck::{prove_sumcheck, HonkRelations, SumcheckSpec, ZkData};
use crate::base::group::Curve;
use crate::base::rng::Rng;
use crate::base::transcript::NativeTranscript;
use crate::base::vk::Vk;
use crate::base::{Bn254, CommitmentKey, Fr};

/// Produce the full proof (public inputs first, then the Honk proof).
pub fn prove_ultra(inst: &mut ProverInstance, vk: &Vk<Bn254>, rng: &mut dyn Rng) -> Vec<Fr> {
    let flavor = inst.flavor;
    let mut key_size = inst.max_end_index;
    if flavor.has_zk {
        key_size = key_size.max(2 * Bn254::SUBGROUP_SIZE);
    }
    let ck = CommitmentKey::new(key_size);
    let mut t = NativeTranscript::new();

    let oink = prove_oink(inst, vk, &ck, &mut t, rng, true);
    let betas: Vec<Fr> = t.dyadic_powers("Sumcheck:gate_challenge", flavor.virtual_log_n);

    let mut zk = flavor
        .has_zk
        .then(|| ZkData::<Bn254>::new(flavor.virtual_log_n, &mut t, &ck, rng));
    let rels = HonkRelations {
        flavor,
        layout: &inst.layout,
    };
    let sc = prove_sumcheck::<Bn254>(
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
        .map(|z| small_subgroup_ipa_prove::<Bn254>(z, &sc.challenge, &sc.libra_evaluation, &ck, &mut t, rng));
    let claim = shplemini_prove(
        &unshifted,
        &to_be_shifted,
        &sc.challenge,
        &ck,
        &mut t,
        libra.as_ref(),
        &[],
    );
    kzg_open(claim, &ck, &mut t);
    t.export_proof()
}
