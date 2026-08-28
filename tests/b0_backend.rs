//! B0 exit: backend (server protocol) circuits, recursion-free warm-up. `inbox_parity_64` — built
//! and executed with the pinned nargo (`fixtures/regen_backend.sh`) — reproduces bb's proving
//! instance, VK and non-ZK proof byte-for-byte; the ZK proof verifies. The VK-hash sweep compares
//! every artifact under `backend_vk_hash/` that bb-ref can already build (recursion circuits join
//! the supported set as the B-milestones land).

mod common;
use bb_ref::acir::format::{decode_program, decode_witness};
use bb_ref::acir::lower::build_circuit;
use bb_ref::base::field::from_bytes_be;
use bb_ref::base::io::decode_fields;
use bb_ref::base::srs::bn254_g2;
use bb_ref::base::{CommitmentKey, Fr, NativeTranscript, OsRng};
use bb_ref::honk::circuit_checker::check_circuit;
use bb_ref::honk::flavor::FlavorDesc;
use bb_ref::honk::oink_prover::prove_oink;
use bb_ref::honk::prover_instance::ProverInstance;
use bb_ref::honk::ultra_prover::prove_ultra;
use bb_ref::honk::ultra_verifier::verify_ultra;
use bb_ref::honk::{ULTRA, ULTRA_ZK};

fn build(name: &str, flavor: &'static FlavorDesc) -> ProverInstance {
    let dir = common::fixture_dir(&format!("backend/{name}"));
    let circuit = decode_program(&std::fs::read(dir.join("program.json")).expect("program.json"));
    let witness = decode_witness(&std::fs::read(dir.join("witness.gz")).expect("witness.gz"), &mut OsRng);
    let mut builder = build_circuit(&circuit, Some(&witness));
    assert!(builder.failed.is_none(), "{name}: builder failure {:?}", builder.failed);
    ProverInstance::from_builder(flavor, &mut builder, &mut OsRng)
}

fn check_nozk(name: &str) {
    let dump = common::fixture_dir(&format!("instance/backend/{name}/nozk"));
    if !dump.join("proof.bin").exists() {
        eprintln!("skipping {name}: no instance dump");
        return;
    }
    let mut inst = build(name, &ULTRA);
    let expected = ProverInstance::load_dump(&ULTRA, &dump);
    assert_eq!(inst.dyadic_size, expected.dyadic_size, "{name}: dyadic size");
    assert_eq!(inst.public_inputs, expected.public_inputs, "{name}: public inputs");
    for (e, (a, b)) in inst.layout.unshifted.iter().zip(inst.polys.iter().zip(&expected.polys)) {
        if let Some(i) = a.coeffs.iter().zip(&b.coeffs).position(|(x, y)| x != y) {
            panic!("{name}: polynomial {} differs at row {i}", e.name());
        }
    }
    let ck = CommitmentKey::new(inst.max_end_index);
    let vk = inst.compute_vk(&ck);
    assert_eq!(vk.to_bytes(), std::fs::read(dump.join("vk")).unwrap(), "{name}: VK");
    let proof = prove_ultra(&mut inst, &vk, &mut OsRng);
    let expected_proof = decode_fields(&std::fs::read(dump.join("proof.bin")).unwrap());
    assert_eq!(proof, expected_proof, "{name}: proof");
    let mut inst = build(name, &ULTRA);
    let out = prove_oink(&mut inst, &vk, &ck, &mut NativeTranscript::new(), &mut OsRng, true);
    assert_eq!(check_circuit(&inst, &out.params), None, "{name}: relation failure");
}

fn check_zk(name: &str) {
    let dump = common::fixture_dir(&format!("instance/backend/{name}/zk"));
    if !dump.join("vk").exists() {
        eprintln!("skipping {name}: no instance dump");
        return;
    }
    let mut inst = build(name, &ULTRA_ZK);
    let ck = CommitmentKey::new(inst.max_end_index);
    let vk = inst.compute_vk(&ck);
    assert_eq!(vk.to_bytes(), std::fs::read(dump.join("vk")).unwrap(), "{name}: VK");
    let num_pi = inst.public_inputs.len();
    let proof = prove_ultra(&mut inst, &vk, &mut OsRng);
    let (pis, rest): (&[Fr], &[Fr]) = proof.split_at(num_pi - 8);
    assert!(
        verify_ultra(&ULTRA_ZK, &vk, pis, rest, &bn254_g2()),
        "{name}: ZK proof rejected"
    );
}

macro_rules! backend_tests {
    ($($name:ident),* $(,)?) => { $(
        mod $name {
            #[test] fn nozk() { super::check_nozk(stringify!($name)); }
            #[test] fn zk() { super::check_zk(stringify!($name)); }
        }
    )* };
}
backend_tests! {
    inbox_parity_64,
}

/// The circuits bb-ref can currently build (grows per B-milestone; the rest of `backend_vk_hash/`
/// is fixture-complete but unsupported until the recursion lowerings land).
const SUPPORTED: &[&str] = &["inbox_parity_64"];

#[test]
fn backend_vk_hash_sweep() {
    let dir = common::fixture_dir("backend_vk_hash");
    let mut entries: Vec<_> = std::fs::read_dir(&dir)
        .expect("backend_vk_hash fixtures")
        .map(|e| e.unwrap().path())
        .collect();
    entries.sort();
    assert!(!entries.is_empty());
    let mut unsupported = 0;
    for path in &entries {
        let name = path.file_name().unwrap().to_str().unwrap();
        if !SUPPORTED.contains(&name) {
            unsupported += 1;
            continue;
        }
        let expected: Fr = from_bytes_be(&std::fs::read(path).unwrap());
        let program = common::fixture_dir(&format!("backend/{name}/program.json"));
        let circuit = decode_program(&std::fs::read(program).expect("program.json"));
        let mut builder = build_circuit(&circuit, None);
        let inst = ProverInstance::from_builder(&ULTRA, &mut builder, &mut OsRng);
        let ck = CommitmentKey::new(inst.max_end_index);
        assert_eq!(inst.compute_vk(&ck).hash(), expected, "{name}: VK hash");
    }
    eprintln!(
        "{} supported, {unsupported} not yet supported",
        entries.len() - unsupported
    );
}
