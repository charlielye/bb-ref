//! ACIR ingestion of the protocol subset. Every mock-protocol circuit's Chonk VK (apps,
//! kernels built against bb's mocked IVC state, the hiding kernel) is byte-equal to bb's and to the
//! artifact's; Rust proves the mock transaction flows bb's TS harness produces (`ivc-inputs.msgpack`)
//! and verifies bb's proofs of them; with bb's RNG tape the Rust proof is byte-identical.
mod common;
use bb_ref::acir::{build_circuit_mega, decode_program, decode_steps, prove_steps};
use bb_ref::base::io::{decode_fields, encode_fields};
use bb_ref::base::rng::TapeRng;
use bb_ref::base::srs::bn254_g2;
use bb_ref::base::vk::Vk;
use bb_ref::base::{Bn254, CommitmentKey, GrumpkinKey, OsRng};
use bb_ref::chonk::ivc::CircuitKind;
use bb_ref::chonk::proof::ChonkProof;
use bb_ref::chonk::verifier::chonk_verify;
use bb_ref::goblin::eccvm::FIXED_SIZE;
use bb_ref::honk::prover_instance::ProverInstance;
use bb_ref::honk::MEGA_ZK;
use std::path::Path;

const PROGRAMS: [(&str, CircuitKind); 7] = [
    ("app_creator", CircuitKind::App),
    ("app_reader", CircuitKind::App),
    ("mock_private_kernel_init", CircuitKind::Kernel),
    ("mock_private_kernel_inner", CircuitKind::Kernel),
    ("mock_private_kernel_reset", CircuitKind::Kernel),
    ("mock_private_kernel_tail", CircuitKind::Kernel),
    ("mock_hiding", CircuitKind::HidingKernel),
];

fn verify(vk: &Vk<Bn254>, proof: &ChonkProof) -> bool {
    chonk_verify(vk, proof, &bn254_g2(), &GrumpkinKey::new(FIXED_SIZE))
}

fn read_hiding_vk(path: &Path) -> Vk<Bn254> {
    Vk::<bb_ref::base::Bn254>::from_bytes(&std::fs::read(path).unwrap(), MEGA_ZK.layout().num_precomputed)
}

/// `bb write_vk --scheme chonk --circuit_kind <kind>`: the VK of every mock-protocol artifact.
#[test]
fn mock_protocol_vks_match_bb() {
    for (name, kind) in PROGRAMS {
        let artifact = common::read(&format!("acir/programs/{name}.json"));
        let circuit = decode_program(&artifact);
        let mut builder = build_circuit_mega(&circuit, None, None, &mut OsRng);
        let inst = ProverInstance::from_builder(kind.flavor(), &mut builder, &mut OsRng);
        let vk = inst.compute_vk(&CommitmentKey::new(inst.max_end_index)).to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&artifact).unwrap();
        let in_artifact = hex::decode(json["verificationKey"]["bytes"].as_str().unwrap()).unwrap();
        assert_eq!(vk, in_artifact, "{name}: VK differs from the artifact's");
        let fixture = common::fixture_dir(&format!("acir/vks/{name}.vk"));
        if fixture.exists() {
            assert_eq!(
                vk,
                std::fs::read(fixture).unwrap(),
                "{name}: VK differs from bb write_vk's"
            );
        }
    }
}

/// Rust verifies bb's proofs of the mock flows; the hiding kernel's pinned VK is bb's output VK.
#[test]
fn mock_flows_bb_proofs_verify() {
    let mut n = 0;
    for flow in ["mock_1_1", "mock_2_2", "mock_1_1_tape"] {
        let dir = common::fixture_dir(&format!("acir/{flow}"));
        if !dir.join("proof").exists() {
            eprintln!("skipping {flow}: no bb proof");
            continue;
        }
        let vk = read_hiding_vk(&dir.join("vk"));
        let proof = ChonkProof::from_fields(&decode_fields(&std::fs::read(dir.join("proof")).unwrap()));
        assert!(verify(&vk, &proof), "{flow}: bb proof rejected");
        if let Ok(inputs) = std::fs::read(dir.join("ivc-inputs.msgpack")) {
            let steps = decode_steps(&inputs);
            assert_eq!(
                steps.last().unwrap().vk.to_bytes(),
                vk.to_bytes(),
                "{flow}: pinned hiding VK vs bb's output VK"
            );
        }
        n += 1;
    }
    eprintln!("verified {n} bb mock flows");
}

/// Rust proves mock_1_1 (checking every step's pinned VK against its circuit), verifies the proof,
/// and leaves it for bb (`tools/regen/regen_acir.sh` runs `bb verify` on it).
#[test]
fn mock_flow_rust_proof() {
    let steps = decode_steps(&common::read("acir/mock_1_1/ivc-inputs.msgpack"));
    assert_eq!(steps.len(), 7);
    let (proof, vk) = prove_steps(steps, CommitmentKey::new(1 << 17), &mut OsRng, true, false);
    assert!(verify(&vk, &proof), "Rust proof rejected by the Rust verifier");
    let out = common::fixture_dir("acir/rust_1_1");
    std::fs::create_dir_all(&out).unwrap();
    std::fs::write(out.join("proof"), encode_fields(&proof.to_fields())).unwrap();
    std::fs::write(out.join("vk"), vk.to_bytes()).unwrap();
}

/// With bb's seeded debug engine (`BB_RNG_SEED=12345`, mirrored by `DebugRng`) the whole ChonkProof of
/// mock_1_1 is byte-identical to bb's — the tapeless equivalent of `mock_flow_byte_exact_with_tape`.
#[test]
fn mock_flow_byte_exact_with_seed() {
    use bb_ref::base::rng::DebugRng;
    let dir = common::fixture_dir("acir/mock_1_1_seed");
    if !dir.join("proof").exists() {
        eprintln!("skipping acir seed: no dump");
        return;
    }
    let mut rng = DebugRng::new(12345);
    let steps = decode_steps(&common::read("acir/mock_1_1/ivc-inputs.msgpack"));
    let (proof, vk) = prove_steps(steps, CommitmentKey::new(1 << 17), &mut rng, false, false);
    assert_eq!(
        encode_fields(&proof.to_fields()),
        std::fs::read(dir.join("proof")).unwrap(),
        "proof bytes"
    );
    assert_eq!(vk.to_bytes(), std::fs::read(dir.join("vk")).unwrap(), "vk bytes");
}

/// With bb's RNG tape the whole ChonkProof of mock_1_1 is byte-identical to bb's.
#[test]
fn mock_flow_byte_exact_with_tape() {
    let dir = common::fixture_dir("acir/mock_1_1_tape");
    if !dir.join("rng_tape.bin").exists() {
        eprintln!("skipping acir tape: no dump");
        return;
    }
    let mut tape = TapeRng::from_bytes(std::fs::read(dir.join("rng_tape.bin")).unwrap());
    let steps = decode_steps(&common::read("acir/mock_1_1/ivc-inputs.msgpack"));
    let (proof, vk) = prove_steps(steps, CommitmentKey::new(1 << 17), &mut tape, true, false);
    assert_eq!(
        vk.to_bytes(),
        std::fs::read(dir.join("vk")).unwrap(),
        "hiding kernel VK"
    );
    let expected = decode_fields(&std::fs::read(dir.join("proof")).unwrap());
    let fields = proof.to_fields();
    let first_diff = fields.iter().zip(&expected).position(|(a, b)| a != b);
    assert_eq!(first_diff, None, "ChonkProof differs from bb's (first differing field)");
    assert_eq!(fields.len(), expected.len(), "ChonkProof length");
    assert_eq!(tape.remaining(), 0, "unconsumed tape bytes");
}
