//! M12 exit: Chonk end-to-end natively. Rust runs the IVC over kernel-shaped circuits and bb
//! verifies the resulting `ChonkProof`; Rust verifies bb's mock IVC proof (real recursive kernels)
//! and bb's proofs of the pinned real transaction flows; proof field/msgpack layouts round-trip.
mod common;
use ark_ec::{AffineRepr, CurveGroup};
use bb_ref::base::codec::Transcriptable;
use bb_ref::base::io::{decode_fields, encode_fields};
use bb_ref::base::srs::bn254_g2;
use bb_ref::base::vk::Vk;
use bb_ref::base::{Bn254, CommitmentKey, Fr, G1Affine, GrumpkinKey, OsRng};
use bb_ref::chonk::batched::mega_zk_oink_length_without_public_inputs;
use bb_ref::chonk::ivc::{Chonk, CircuitKind};
use bb_ref::chonk::proof::ChonkProof;
use bb_ref::chonk::verifier::{chonk_verify, HIDING_KERNEL_PUBLIC_INPUTS_SIZE};
use bb_ref::goblin::eccvm::FIXED_SIZE;
use bb_ref::honk::MEGA_ZK;
use common::dummy_ivc::{app_circuit, hiding_circuit, kernel_circuit, MockDatabus};
use std::path::Path;

fn verify(vk: &Vk<Bn254>, proof: &ChonkProof) -> bool {
    chonk_verify(vk, proof, &bn254_g2(), &GrumpkinKey::new(FIXED_SIZE))
}

/// bb's `tamper_with_proof`: add the generator to the point encoded at `offset` (stays on the curve).
fn tamper_point(fields: &mut [Fr], offset: usize) {
    let p = <G1Affine as Transcriptable<Fr>>::from_fields(&fields[offset..offset + 4]);
    let bad = (p + G1Affine::generator()).into_affine();
    fields[offset..offset + 4].copy_from_slice(&bad.to_fields());
}

fn read_vk(path: &Path) -> Vk<Bn254> {
    Vk::from_bytes(&std::fs::read(path).unwrap(), MEGA_ZK.layout().num_precomputed)
}

fn check_bb_proof(dir: &Path) {
    let vk = read_vk(&dir.join("vk"));
    let fields = decode_fields(&std::fs::read(dir.join("proof_fields.bin")).unwrap());
    let proof = ChonkProof::from_fields(&fields);
    assert_eq!(ChonkProof::from_msgpack(&std::fs::read(dir.join("proof.msgpack")).unwrap()), proof, "msgpack layout");
    assert_eq!(proof.to_msgpack(), std::fs::read(dir.join("proof.msgpack")).unwrap(), "msgpack bytes");
    assert!(verify(&vk, &proof), "bb Chonk proof rejected");
    // the kernel return data commitment in the hiding kernel's IO (databus consistency)
    let mut bad = proof.clone();
    let pi_start = bad.hiding_oink_proof.len() - mega_zk_oink_length_without_public_inputs() - HIDING_KERNEL_PUBLIC_INPUTS_SIZE;
    tamper_point(&mut bad.hiding_oink_proof, pi_start + 8);
    assert!(!verify(&vk, &bad), "tampered hiding kernel public input accepted");
}

#[test]
fn rust_ivc_verifies_and_exports() {
    let kinds = vec![CircuitKind::App, CircuitKind::App, CircuitKind::Kernel, CircuitKind::Kernel, CircuitKind::HidingKernel];
    let mut ivc = Chonk::new(kinds.clone(), CommitmentKey::new(1 << 17));
    let mut bus = MockDatabus::default();
    for _ in 0..kinds.len() {
        let mut circuit = match ivc.current_kind() {
            CircuitKind::App => app_circuit(&ivc, &mut bus),
            CircuitKind::Kernel => kernel_circuit(&mut ivc, &mut bus),
            CircuitKind::HidingKernel => hiding_circuit(&mut ivc, &mut bus, &mut OsRng),
        };
        ivc.accumulate(&mut circuit, &mut OsRng);
    }
    let proof = ivc.prove(&mut OsRng);
    assert_eq!(ChonkProof::from_fields(&proof.to_fields()), proof, "field layout round trip");
    assert_eq!(ChonkProof::from_msgpack(&proof.to_msgpack()), proof, "msgpack round trip");
    assert!(verify(ivc.hiding_vk(), &proof), "Rust Chonk proof rejected by the Rust verifier");

    let out = common::fixture_dir("instance/chonk/rust");
    std::fs::create_dir_all(&out).unwrap();
    std::fs::write(out.join("proof_fields.bin"), encode_fields(&proof.to_fields())).unwrap();
    std::fs::write(out.join("proof.msgpack"), proof.to_msgpack()).unwrap();
    std::fs::write(out.join("vk"), ivc.hiding_vk().to_bytes()).unwrap();

    let mut bad = proof.clone();
    let kzg_w = bad.joint_proof.len() - 4;
    tamper_point(&mut bad.joint_proof, kzg_w);
    assert!(!verify(ivc.hiding_vk(), &bad), "tampered KZG opening accepted");
}

#[test]
fn verify_bb_mock_ivc() {
    let dir = common::fixture_dir("instance/chonk/bb_2apps");
    if !dir.join("vk").exists() {
        eprintln!("skipping bb mock ivc: no dump");
        return;
    }
    check_bb_proof(&dir);
}

#[test]
fn verify_pinned_flows() {
    let root = common::fixture_dir("chonk_flows");
    let Ok(entries) = std::fs::read_dir(&root) else {
        eprintln!("skipping pinned flows: no dump");
        return;
    };
    let mut n = 0;
    for e in entries {
        let dir = e.unwrap().path();
        if !dir.join("vk").exists() {
            continue;
        }
        let vk = read_vk(&dir.join("vk"));
        let proof = ChonkProof::from_fields(&decode_fields(&std::fs::read(dir.join("proof")).unwrap()));
        assert!(verify(&vk, &proof), "{}: bb proof rejected", dir.display());
        n += 1;
    }
    eprintln!("verified {n} pinned flows");
}
