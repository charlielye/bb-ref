//! M3 exit: circuits built from ACIR by the Rust builder reproduce bb's proving instance exactly —
//! every polynomial, the VK, and (non-ZK) the proof are byte-identical to bb's dumps; ZK proofs
//! from Rust-built instances verify. Needs the `instance/` dumps and the acir_tests programs.
use crate::common;
use bb_ref::acir::{build_circuit, decode_program, decode_witness};
use bb_ref::base::field::{from_bytes_be, Fr};
use bb_ref::base::io::decode_fields;
use bb_ref::base::srs::bn254_g2;
use bb_ref::base::{CommitmentKey, NativeTranscript, OsRng};
use bb_ref::honk::circuit_checker::check_circuit;
use bb_ref::honk::oink_prover::prove_oink;
use bb_ref::honk::prover_instance::ProverInstance;
use bb_ref::honk::ultra_prover::prove_ultra;
use bb_ref::honk::ultra_verifier::verify_ultra;
use bb_ref::honk::{FlavorDesc, ULTRA, ULTRA_ZK};
use std::path::PathBuf;

fn acir_tests_dir() -> PathBuf {
    std::env::var("ACIR_TESTS_DIR").map(PathBuf::from).unwrap_or_else(|_| {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("pin/aztec-packages/barretenberg/acir_tests/acir_tests")
    })
}

fn build(prog: &str, flavor: &'static FlavorDesc) -> ProverInstance {
    let dir = acir_tests_dir().join(prog).join("target");
    let circuit = decode_program(&std::fs::read(dir.join("program.json")).expect("program.json"));
    let witness = decode_witness(&std::fs::read(dir.join("witness.gz")).expect("witness.gz"), &mut OsRng);
    let mut builder = build_circuit(&circuit, Some(&witness));
    assert!(builder.failed.is_none(), "{prog}: builder failure {:?}", builder.failed);
    ProverInstance::from_builder(flavor, &mut builder, &mut OsRng)
}

/// Every polynomial and all metadata equal bb's dump; then the non-ZK proof is byte-equal.
fn check_nozk(prog: &str) {
    let dump = common::fixture_dir(&format!("instance/{prog}/nozk"));
    if !dump.join("proof.bin").exists() {
        eprintln!("skipping {prog}: no instance dump");
        return;
    }
    let mut inst = build(prog, &ULTRA);
    let expected = ProverInstance::load_dump(&ULTRA, &dump);
    assert_eq!(inst.dyadic_size, expected.dyadic_size, "{prog}: dyadic size");
    assert_eq!(
        inst.final_active_wire_idx, expected.final_active_wire_idx,
        "{prog}: final active wire"
    );
    assert_eq!(inst.max_end_index, expected.max_end_index, "{prog}: max end index");
    assert_eq!(
        inst.pub_inputs_offset, expected.pub_inputs_offset,
        "{prog}: pub inputs offset"
    );
    assert_eq!(inst.public_inputs, expected.public_inputs, "{prog}: public inputs");
    assert_eq!(
        inst.memory_read_records, expected.memory_read_records,
        "{prog}: memory reads"
    );
    assert_eq!(
        inst.memory_write_records, expected.memory_write_records,
        "{prog}: memory writes"
    );
    assert_eq!(
        inst.rom_logup_records, expected.rom_logup_records,
        "{prog}: rom logup records"
    );
    for (e, (a, b)) in inst.layout.unshifted.iter().zip(inst.polys.iter().zip(&expected.polys)) {
        if let Some(i) = a.coeffs.iter().zip(&b.coeffs).position(|(x, y)| x != y) {
            panic!("{prog}: polynomial {} differs at row {i}", e.name());
        }
    }
    let ck = CommitmentKey::new(inst.max_end_index);
    let vk = inst.compute_vk(&ck);
    assert_eq!(vk.to_bytes(), std::fs::read(dump.join("vk")).unwrap(), "{prog}: VK");
    let proof = prove_ultra(&mut inst, &vk, &mut OsRng);
    let expected_proof = decode_fields(&std::fs::read(dump.join("proof.bin")).unwrap());
    assert_eq!(proof, expected_proof, "{prog}: proof");
    // Every relation vanishes on the (Oink-completed) instance.
    let mut inst = build(prog, &ULTRA);
    let out = prove_oink(&mut inst, &vk, &ck, &mut NativeTranscript::new(), &mut OsRng, true);
    assert_eq!(check_circuit(&inst, &out.params), None, "{prog}: relation failure");
}

fn check_zk(prog: &str) {
    let dump = common::fixture_dir(&format!("instance/{prog}/zk"));
    if !dump.join("vk").exists() {
        eprintln!("skipping {prog}: no instance dump");
        return;
    }
    let mut inst = build(prog, &ULTRA_ZK);
    let ck = CommitmentKey::new(inst.max_end_index);
    let vk = inst.compute_vk(&ck);
    assert_eq!(vk.to_bytes(), std::fs::read(dump.join("vk")).unwrap(), "{prog}: VK");
    let num_pi = inst.public_inputs.len();
    let proof = prove_ultra(&mut inst, &vk, &mut OsRng);
    let (pis, rest): (&[Fr], &[Fr]) = proof.split_at(num_pi - 8);
    assert!(
        verify_ultra(&ULTRA_ZK, &vk, pis, rest, &bn254_g2()),
        "{prog}: ZK proof rejected"
    );
}

macro_rules! builder_tests {
    ($($name:ident: $prog:literal),* $(,)?) => { $(
        mod $name {
            #[test] fn nozk() { super::check_nozk($prog); }
            #[test] fn zk() { super::check_zk($prog); }
        }
    )* };
}
builder_tests! {
    a_1_mul: "a_1_mul",
    array_dynamic: "array_dynamic",
    poseidon: "no_predicates_numeric_generic_poseidon",
    unsafe_range_constraint: "unsafe_range_constraint",
    ecdsa_secp256r1: "ecdsa_secp256r1",
    ecdsa_secp256r1_3x: "ecdsa_secp256r1_3x",
    ecdsa_secp256r1_high_s: "ecdsa_secp256r1_high_s",
    ecdsa_secp256r1_invalid_inputs: "ecdsa_secp256r1_invalid_inputs",
    ecdsa_secp256r1_invalid_pub_key_in_inactive_branch: "ecdsa_secp256r1_invalid_pub_key_in_inactive_branch",
    xor: "xor",
    bit_and: "bit_and",
}

/// VK hashes of every acir_tests program in the supported opcode subset, from `bb write_vk`.
#[test]
fn vk_hash_sweep() {
    let dir = common::fixture_dir("vk_hash");
    let mut entries: Vec<_> = std::fs::read_dir(&dir)
        .expect("vk_hash fixtures")
        .map(|e| e.unwrap().path())
        .collect();
    entries.sort();
    let mut failures = vec![];
    for path in &entries {
        let prog = path.file_name().unwrap().to_str().unwrap();
        let expected: Fr = from_bytes_be(&std::fs::read(path).unwrap());
        let target = acir_tests_dir().join(prog).join("target");
        let circuit = decode_program(&std::fs::read(target.join("program.json")).unwrap());
        let mut builder = build_circuit(&circuit, None);
        let inst = ProverInstance::from_builder(&ULTRA, &mut builder, &mut OsRng);
        let ck = CommitmentKey::new(inst.max_end_index);
        if inst.compute_vk(&ck).hash() != expected {
            failures.push(prog.to_string());
        }
    }
    assert!(!entries.is_empty());
    assert!(
        failures.is_empty(),
        "VK hash mismatch for {} of {} programs: {failures:?}",
        failures.len(),
        entries.len()
    );
}
