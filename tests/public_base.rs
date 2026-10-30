//! The public tx base rollup (recursively verifying an AVM proof through bb's two-layer AVM
//! verifier) against bb, from a real proving request (`tools/regen/regen_public_base.sh`): the VK is
//! byte-identical, and with bb's RNG seeded (single-threaded) so is the proof.
mod common;

use bb_ref::acir::{decode_program, decode_witness};
use bb_ref::base::io::decode_fields;
use bb_ref::base::rng::{set_global, DebugRng, GlobalProxy};
use bb_ref::base::CommitmentKey;
use bb_ref::honk::prover_instance::ProverInstance;
use bb_ref::honk::ultra_prover::prove_ultra;
use bb_ref::honk::ULTRA;

fn instance(witness: bool) -> Option<ProverInstance> {
    let dir = common::fixture_dir("instance/public_tx_base");
    if !dir.join("proof").exists() {
        eprintln!("skipping: no public_tx_base fixture");
        return None;
    }
    let circuit = decode_program(&std::fs::read(dir.join("program.json")).unwrap());
    let witness = witness.then(|| decode_witness(&std::fs::read(dir.join("witness.gz")).unwrap(), &mut GlobalProxy));
    let mut builder = bb_ref::acir::lower::build_circuit_opts(&circuit, witness.as_deref(), true);
    if witness.is_some() {
        assert!(builder.failed.is_none(), "circuit not satisfied: {:?}", builder.failed);
    }
    Some(ProverInstance::from_builder(&ULTRA, &mut builder, &mut GlobalProxy))
}

/// One test, so the write-VK build cannot draw from the global RNG while the seeded proof runs.
#[test]
fn public_base_matches_bb() {
    if !common::in_tier("public_base", true) {
        return;
    }
    let Some(inst) = instance(false) else { return };
    let dir = common::fixture_dir("instance/public_tx_base");
    let vk = inst.compute_vk(&CommitmentKey::new(inst.max_end_index));
    assert_eq!(vk.to_bytes(), std::fs::read(dir.join("vk")).unwrap(), "write-VK mode VK");
    drop(inst);

    set_global(Box::new(DebugRng::new(7)));
    let mut inst = instance(true).unwrap();
    let ck = CommitmentKey::new(inst.max_end_index);
    let vk = inst.compute_vk(&ck);
    assert_eq!(vk.to_bytes(), std::fs::read(dir.join("vk")).unwrap(), "VK");
    let proof = prove_ultra(&mut inst, &vk, &mut GlobalProxy);
    let bb_public_inputs = decode_fields(&std::fs::read(dir.join("public_inputs")).unwrap());
    let bb_proof = decode_fields(&std::fs::read(dir.join("proof")).unwrap());
    let n = bb_public_inputs.len();
    assert_eq!(&proof[..n], &bb_public_inputs[..], "public inputs");
    assert_eq!(proof.len() - n, bb_proof.len(), "proof length");
    if let Some(k) = (0..bb_proof.len()).find(|k| proof[n + k] != bb_proof[*k]) {
        panic!("proof field {k} differs");
    }
}
