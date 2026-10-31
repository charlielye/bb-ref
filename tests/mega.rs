//! Mega circuits (op queue, databus, bilinear gates, compressed Poseidon2) match bb —
//! `bb write_vk --scheme chonk --circuit_kind app` for every acir_tests program in the supported
//! subset.
mod common;
use bb_ref::acir::{build_circuit_mega, decode_program};
use bb_ref::base::{CommitmentKey, OsRng};
use bb_ref::honk::prover_instance::ProverInstance;
use bb_ref::honk::MEGA_APP;
use sha2::{Digest, Sha256};

fn mega_app_instance(prog: &str) -> ProverInstance {
    let dir = common::acir_tests().join(prog).join("target");
    let circuit = decode_program(&std::fs::read(dir.join("program.json")).expect("program.json"));
    let mut builder = build_circuit_mega(&circuit, None, None, &mut OsRng);
    ProverInstance::from_builder(&MEGA_APP, &mut builder, &mut OsRng)
}

/// sha256 of every MegaApp VK bb writes for the acir_tests subset.
#[test]
fn mega_app_vk_sweep() {
    let dir = common::fixture_dir("vk_sha256_mega_app");
    let mut entries: Vec<_> = std::fs::read_dir(&dir)
        .expect("vk_sha256_mega_app fixtures")
        .map(|e| e.unwrap().path())
        .collect();
    entries.sort();
    let mut failures = vec![];
    for path in &entries {
        let prog = path.file_name().unwrap().to_str().unwrap();
        let expected = std::fs::read_to_string(path).unwrap().trim().to_string();
        let inst = mega_app_instance(prog);
        let ck = CommitmentKey::new(inst.max_end_index);
        let got = hex::encode(Sha256::digest(inst.compute_vk(&ck).to_bytes()));
        if got != expected {
            failures.push(prog.to_string());
        }
    }
    assert!(!entries.is_empty());
    assert!(
        failures.is_empty(),
        "MegaApp VK mismatch for {} of {} programs: {failures:?}",
        failures.len(),
        entries.len()
    );
}
