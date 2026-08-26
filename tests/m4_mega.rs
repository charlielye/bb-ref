//! M4 exit: Mega circuits (op queue, databus, bilinear gates, compressed Poseidon2) match bb —
//! `bb write_vk --scheme chonk --circuit_kind app` for every acir_tests program in the supported
//! subset, and (where dumped) bb's MegaApp proving instance and Oink proof.
mod common;
use bb_ref::acir::{build_circuit_mega, decode_program, decode_witness};
use bb_ref::base::io::decode_fields;
use bb_ref::base::{CommitmentKey, NativeTranscript, OsRng};
use bb_ref::circuit::EccOpQueue;
use bb_ref::honk::circuit_checker::check_circuit;
use bb_ref::honk::oink_prover::prove_oink;
use bb_ref::honk::prover_instance::ProverInstance;
use bb_ref::honk::MEGA_APP;
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;

fn acir_tests_dir() -> PathBuf {
    std::env::var("ACIR_TESTS_DIR").map(PathBuf::from).unwrap_or_else(|_| {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../aztec-packages2/barretenberg/acir_tests/acir_tests")
    })
}

fn mega_app_instance(prog: &str, with_witness: bool) -> ProverInstance {
    let dir = acir_tests_dir().join(prog).join("target");
    let circuit = decode_program(&std::fs::read(dir.join("program.json")).expect("program.json"));
    let witness = with_witness.then(|| decode_witness(&std::fs::read(dir.join("witness.gz")).expect("witness.gz")));
    let op_queue = Rc::new(RefCell::new(EccOpQueue::new()));
    let mut builder = build_circuit_mega(&circuit, witness.as_deref(), op_queue);
    ProverInstance::from_builder(&MEGA_APP, &mut builder, &mut OsRng)
}

/// sha256 of every MegaApp VK bb writes for the acir_tests subset.
#[test]
fn mega_app_vk_sweep() {
    let dir = common::fixture_dir("vk_sha256_mega_app");
    let mut entries: Vec<_> = std::fs::read_dir(&dir).expect("vk_sha256_mega_app fixtures").map(|e| e.unwrap().path()).collect();
    entries.sort();
    let mut failures = vec![];
    for path in &entries {
        let prog = path.file_name().unwrap().to_str().unwrap();
        let expected = std::fs::read_to_string(path).unwrap().trim().to_string();
        let inst = mega_app_instance(prog, false);
        let ck = CommitmentKey::new(inst.max_end_index);
        let got = hex::encode(Sha256::digest(inst.compute_vk(&ck).to_bytes()));
        if got != expected {
            failures.push(prog.to_string());
        }
    }
    assert!(!entries.is_empty());
    assert!(failures.is_empty(), "MegaApp VK mismatch for {} of {} programs: {failures:?}", failures.len(), entries.len());
}

/// bb-dumped MegaApp instances: every polynomial, the VK and the Oink proof are byte-identical.
fn check_mega_app_dump(prog: &str) {
    let dump = common::fixture_dir(&format!("instance/{prog}/mega_app"));
    if !dump.join("proof.bin").exists() {
        eprintln!("skipping {prog}: no mega_app instance dump");
        return;
    }
    let mut inst = mega_app_instance(prog, true);
    let expected = ProverInstance::load_dump(&MEGA_APP, &dump);
    assert_eq!(inst.dyadic_size, expected.dyadic_size, "{prog}: dyadic size");
    assert_eq!(inst.final_active_wire_idx, expected.final_active_wire_idx, "{prog}: final active wire");
    assert_eq!(inst.max_end_index, expected.max_end_index, "{prog}: max end index");
    assert_eq!(inst.pub_inputs_offset, expected.pub_inputs_offset, "{prog}: pub inputs offset");
    for (e, (a, b)) in inst.layout.unshifted.iter().zip(inst.polys.iter().zip(&expected.polys)) {
        if let Some(i) = a.coeffs.iter().zip(&b.coeffs).position(|(x, y)| x != y) {
            panic!("{prog}: polynomial {} differs at row {i}", e.name());
        }
    }
    let ck = CommitmentKey::new(inst.max_end_index);
    let vk = inst.compute_vk(&ck);
    assert_eq!(vk.to_bytes(), std::fs::read(dump.join("vk")).unwrap(), "{prog}: VK");
    let mut t = NativeTranscript::new();
    let out = prove_oink(&mut inst, &vk, &ck, &mut t, &mut OsRng);
    let expected_proof = decode_fields(&std::fs::read(dump.join("proof.bin")).unwrap());
    assert_eq!(t.export_proof(), expected_proof, "{prog}: Oink proof");
    assert_eq!(check_circuit(&inst, &out.params), None, "{prog}: relation failure");
}

#[test]
fn mega_app_dump_a_1_mul() {
    check_mega_app_dump("a_1_mul");
}
#[test]
fn mega_app_dump_array_dynamic() {
    check_mega_app_dump("array_dynamic");
}
#[test]
fn mega_app_dump_poseidon() {
    check_mega_app_dump("no_predicates_numeric_generic_poseidon");
}

use bb_ref::circuit::Builder;
use bb_ref::honk::{FlavorDesc, MEGA_KERNEL, MEGA_ZK};

/// Build a circuit script in Rust and compare with bb's dump for the given flavor. ZK flavors
/// draw masking values, so only the precomputed polynomials, VK and metadata are compared.
fn check_script(script: &str, flavor: &'static FlavorDesc, flavor_dir: &str) {
    let dump = common::fixture_dir(&format!("instance/scripts/{script}/{flavor_dir}"));
    if !dump.join("vk").exists() {
        eprintln!("skipping {script}/{flavor_dir}: no dump");
        return;
    }
    let text = std::fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!("fixtures/scripts/{script}.txt"))).unwrap();
    let ctx = Rc::new(RefCell::new(Builder::new_mega(Rc::new(RefCell::new(EccOpQueue::new())))));
    common::script::run_script(&ctx, &text);
    let mut builder = Rc::try_unwrap(ctx).ok().unwrap().into_inner();
    assert!(builder.failed.is_none(), "{script}: builder failure {:?}", builder.failed);
    let mut inst = ProverInstance::from_builder(flavor, &mut builder, &mut OsRng);
    let expected = ProverInstance::load_dump(flavor, &dump);
    assert_eq!(inst.dyadic_size, expected.dyadic_size, "{script}/{flavor_dir}: dyadic size");
    assert_eq!(inst.final_active_wire_idx, expected.final_active_wire_idx, "{script}/{flavor_dir}: final active wire");
    assert_eq!(inst.max_end_index, expected.max_end_index, "{script}/{flavor_dir}: max end index");
    assert_eq!(inst.pub_inputs_offset, expected.pub_inputs_offset, "{script}/{flavor_dir}: pub inputs offset");
    assert_eq!(inst.public_inputs, expected.public_inputs, "{script}/{flavor_dir}: public inputs");
    assert_eq!(inst.memory_read_records, expected.memory_read_records, "{script}/{flavor_dir}: memory reads");
    assert_eq!(inst.memory_write_records, expected.memory_write_records, "{script}/{flavor_dir}: memory writes");
    let m = inst.layout.num_masking;
    let compare = if flavor.has_zk { m..m + inst.layout.num_precomputed } else { 0..inst.layout.num_unshifted() };
    for i in compare {
        let e = inst.layout.unshifted[i];
        if let Some(r) = inst.polys[i].coeffs.iter().zip(&expected.polys[i].coeffs).position(|(x, y)| x != y) {
            panic!("{script}/{flavor_dir}: polynomial {} differs at row {r}", e.name());
        }
    }
    let ck = CommitmentKey::new(inst.max_end_index);
    let vk = inst.compute_vk(&ck);
    assert_eq!(vk.to_bytes(), std::fs::read(dump.join("vk")).unwrap(), "{script}/{flavor_dir}: VK");
    let mut t = NativeTranscript::new();
    let out = prove_oink(&mut inst, &vk, &ck, &mut t, &mut OsRng);
    if !flavor.has_zk {
        let expected_proof = decode_fields(&std::fs::read(dump.join("proof.bin")).unwrap());
        assert_eq!(t.export_proof(), expected_proof, "{script}/{flavor_dir}: Oink proof");
    }
    assert_eq!(check_circuit(&inst, &out.params), None, "{script}/{flavor_dir}: relation failure");
}

#[test]
fn script_mega_kernel() {
    check_script("mega_kernel", &MEGA_KERNEL, "kernel");
}
#[test]
fn script_mega_zk() {
    check_script("mega_zk", &MEGA_ZK, "zk");
}
#[test]
fn script_mega_app() {
    check_script("mega_app", &MEGA_APP, "app");
}
