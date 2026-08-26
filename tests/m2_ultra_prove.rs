//! M2 exit: proving from bb's dumped proving instance reproduces bb's proof byte-for-byte (non-ZK)
//! and yields proofs the Rust verifier accepts (ZK). Requires the `instance/` dumps produced by the
//! bb-side `BbRefDump` gtest (regenerable, not committed).
mod common;
use bb_ref::base::field::Fr;
use bb_ref::base::io::decode_fields;
use bb_ref::base::srs::bn254_g2;
use bb_ref::base::{Bn254, CommitmentKey, OsRng, Vk};
use bb_ref::honk::prover_instance::ProverInstance;
use bb_ref::honk::ultra_prover::prove_ultra;
use bb_ref::honk::ultra_verifier::verify_ultra;
use bb_ref::honk::{ULTRA, ULTRA_ZK};

fn instance_dir(prog: &str, mode: &str) -> std::path::PathBuf {
    common::fixture_dir(&format!("instance/{prog}/{mode}"))
}

fn check_nozk(prog: &str) {
    let dir = instance_dir(prog, "nozk");
    if !dir.join("proof.bin").exists() {
        eprintln!("skipping {prog}: no instance dump");
        return;
    }
    let mut inst = ProverInstance::load_dump(&ULTRA, &dir);
    let ck = CommitmentKey::new(inst.max_end_index);
    let vk = inst.compute_vk(&ck);
    assert_eq!(vk.to_bytes(), std::fs::read(dir.join("vk")).unwrap(), "{prog}: VK mismatch");
    let proof = prove_ultra(&mut inst, &vk, &mut OsRng);
    let expected = decode_fields(&std::fs::read(dir.join("proof.bin")).unwrap());
    assert_eq!(proof.len(), expected.len(), "{prog}: proof length");
    let first_diff = proof.iter().zip(&expected).position(|(a, b)| a != b);
    assert!(first_diff.is_none(), "{prog}: proof differs from bb at field {}", first_diff.unwrap());
}

fn check_zk(prog: &str) {
    let dir = instance_dir(prog, "zk");
    if !dir.join("proof.bin").exists() {
        eprintln!("skipping {prog}: no instance dump");
        return;
    }
    let mut inst = ProverInstance::load_dump(&ULTRA_ZK, &dir);
    let ck = CommitmentKey::new(inst.max_end_index);
    let vk: Vk<Bn254> = inst.compute_vk(&ck);
    assert_eq!(vk.to_bytes(), std::fs::read(dir.join("vk")).unwrap(), "{prog}: VK mismatch");
    let num_pi = inst.public_inputs.len();
    let proof = prove_ultra(&mut inst, &vk, &mut OsRng);
    let expected = decode_fields(&std::fs::read(dir.join("proof.bin")).unwrap());
    assert_eq!(proof.len(), expected.len(), "{prog}: proof length");
    let (pis, rest): (&[Fr], &[Fr]) = proof.split_at(num_pi - 8);
    assert!(verify_ultra(&ULTRA_ZK, &vk, pis, rest, &bn254_g2()), "{prog}: Rust ZK proof rejected by Rust verifier");
}

macro_rules! prove_tests {
    ($($name:ident: $prog:literal),* $(,)?) => { $(
        mod $name {
            #[test] fn nozk() { super::check_nozk($prog); }
            #[test] fn zk() { super::check_zk($prog); }
        }
    )* };
}

prove_tests! {
    a_1_mul: "a_1_mul",
    array_dynamic: "array_dynamic",
    poseidon: "no_predicates_numeric_generic_poseidon",
    embedded_curve_ops: "embedded_curve_ops",
    unsafe_range_constraint: "unsafe_range_constraint",
}
