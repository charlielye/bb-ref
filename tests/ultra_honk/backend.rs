//! Backend (server protocol) circuits. `inbox_parity_64` — built and executed with the pinned
//! nargo (`tools/regen/regen_backend.sh`) — reproduces bb's proving instance, VK and non-ZK proof
//! byte-for-byte; the ZK proof verifies. The VK-hash sweep compares every artifact under
//! `backend_vk_hash/`.

use crate::common;
use bb_ref::acir::format::{decode_program, decode_witness};
use bb_ref::acir::lower::build_circuit;
use bb_ref::base::field::from_bytes_be;
use bb_ref::base::io::decode_fields;
use bb_ref::base::srs::bn254_g2;
use bb_ref::base::{CommitmentKey, Fr, OsRng};
use bb_ref::honk::flavor::FlavorDesc;
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
    let dump = common::require(
        common::fixture_dir(&format!("instance/backend/{name}/nozk")),
        "regen_backend.sh",
    );
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
}

fn check_zk(name: &str) {
    let dump = common::require(
        common::fixture_dir(&format!("instance/backend/{name}/zk")),
        "regen_backend.sh",
    );
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

/// Every `backend_vk_hash/` circuit, with the node's `--ipa_accumulation` flag (rollup_tx_base_public
/// has no bb vk_hash: stock bb refuses AVM recursion; tests/public_base.rs covers it).
const SUPPORTED: &[(&str, bool)] = &[
    ("rollup_root", false),
    ("inbox_parity_4", false),
    ("inbox_parity_16", false),
    ("inbox_parity_64", false),
    ("inbox_parity_256", false),
    ("inbox_parity_1024", false),
    ("rollup_checkpoint_padding", true),
    ("rollup_tx_merge", true),
    ("rollup_checkpoint_merge", true),
    ("rollup_checkpoint_root", true),
    ("rollup_checkpoint_root_single_block", true),
    ("rollup_block_merge", true),
    ("rollup_block_root", true),
    ("rollup_block_root_no_txs", true),
    ("rollup_block_root_single_tx", true),
    ("rollup_tx_base_private", true),
    ("chonk_verifier_public", true),
];

fn artifact(name: &str) -> std::path::PathBuf {
    let copied = common::fixture_dir(&format!("backend/{name}/program.json"));
    if copied.exists() {
        return copied;
    }
    common::require(
        common::protocol_circuits().join(format!("{name}.json")),
        "regen_inputs.sh",
    )
}

/// The VK hash of one `backend_vk_hash/` artifact against bb's (rollup_root's is the UltraKeccak
/// one: it is proven with `--oracle_hash keccak`, bb-prover honk.ts).
fn vk_hash_case(name: &str, full_only: bool) {
    if !common::in_tier(name, full_only) {
        return;
    }
    let (_, ipa) = SUPPORTED.iter().find(|(n, _)| *n == name).expect("supported circuit");
    let expected: Fr = from_bytes_be(&common::read(&format!("backend_vk_hash/{name}")));
    let circuit = decode_program(&std::fs::read(artifact(name)).expect("program.json"));
    let mut builder = bb_ref::acir::lower::build_circuit_opts(&circuit, None, *ipa);
    let inst = ProverInstance::from_builder(&ULTRA, &mut builder, &mut OsRng);
    let ck = CommitmentKey::new(inst.max_end_index);
    let vk = inst.compute_vk(&ck);
    let hash: Fr = if name == "rollup_root" {
        let kvk = bb_ref::base::vk::Vk::<bb_ref::base::KeccakBn254> {
            log_circuit_size: vk.log_circuit_size,
            num_public_inputs: vk.num_public_inputs,
            pub_inputs_offset: vk.pub_inputs_offset,
            comms: vk.comms,
        };
        use bb_ref::base::codec::Transcriptable;
        <Fr as Transcriptable<bb_ref::base::U256>>::from_fields(&[kvk.hash()])
    } else {
        vk.hash()
    };
    assert_eq!(hash, expected, "{name}: VK hash");
}

/// Every `backend_vk_hash/` artifact is a supported circuit with a sweep case below.
#[test]
fn backend_vk_hash_fixtures_are_all_swept() {
    let dir = common::fixture_dir("backend_vk_hash");
    for e in std::fs::read_dir(&dir).expect("backend_vk_hash fixtures") {
        let name = e.unwrap().file_name().into_string().unwrap();
        assert!(SUPPORTED.iter().any(|(n, _)| *n == name), "{name}: no sweep case");
    }
}

macro_rules! vk_hash_sweep {
    ($($name:ident: $full_only:expr),* $(,)?) => {
        mod vk_hash_sweep { $(
            #[test] fn $name() { super::vk_hash_case(stringify!($name), $full_only); }
        )* }
    };
}
// One test per circuit so they run in parallel; the fast tier keeps the six that take a second or
// two (still through ROLLUP_HONK recursion and its IPA claim).
vk_hash_sweep! {
    inbox_parity_4: false,
    inbox_parity_16: false,
    inbox_parity_64: false,
    inbox_parity_256: true,
    inbox_parity_1024: true,
    rollup_checkpoint_padding: false,
    rollup_block_root_no_txs: false,
    rollup_block_root_single_tx: false,
    rollup_tx_merge: true,
    rollup_checkpoint_merge: true,
    rollup_checkpoint_root: true,
    rollup_checkpoint_root_single_block: true,
    rollup_block_merge: true,
    rollup_block_root: true,
    rollup_tx_base_private: true,
    chonk_verifier_public: true,
    rollup_root: true,
}
