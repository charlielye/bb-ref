//! The ECCVM prover/verifier round-trip in Rust, the fixed VK matches bb's constants, Rust
//! verifies bb's ECCVM proofs (`BbRefDump.EccvmProof` fixtures) and writes its own proofs for bb to
//! verify (`tools/regen/regen_merge.sh` runs that step).
use crate::common;
use bb_ref::base::codec::Transcriptable;
use bb_ref::base::field::to_bytes_be;
use bb_ref::base::io::decode_fields;
use bb_ref::base::poseidon2::Hasher;
use bb_ref::base::rng::TapeRng;
use bb_ref::base::{Fr, GrumpkinKey, NativeTranscript, OsRng, Poseidon2};
use bb_ref::goblin::eccvm::prover::eccvm_prove;
use bb_ref::goblin::eccvm::verifier::eccvm_verify;
use bb_ref::goblin::eccvm::{ent, fixed_vk, fixed_vk_hash, EccvmPolys, FIXED_SIZE, NUM_PRECOMPUTED};
use bb_ref::goblin::ipa::triple_ipa_verify;
use common::eccvm_ops::build_ops;
use std::path::Path;

fn verify(proof: &[Fr], ipa_proof: &[Fr], ck: &GrumpkinKey) -> bool {
    let mut t = NativeTranscript::from_proof(proof);
    let out = eccvm_verify::<bb_ref::base::Grumpkin>(&(), &mut t);
    out.ok && triple_ipa_verify(ck, &out.triple_ipa_claim, &mut NativeTranscript::from_proof(ipa_proof))
}

fn read_proof(path: &Path) -> Option<Vec<Fr>> {
    std::fs::read(path).ok().map(|b| decode_fields(&b))
}

fn write_proof(path: &Path, proof: &[Fr]) {
    std::fs::write(path, proof.iter().flat_map(to_bytes_be).collect::<Vec<u8>>()).unwrap();
}

#[test]
fn fixed_vk_matches_bb_constants() {
    let polys = EccvmPolys::from_op_queue(&build_ops("base"));
    let ck = GrumpkinKey::new(FIXED_SIZE);
    for (i, expected) in fixed_vk().iter().enumerate() {
        assert_eq!(ck.commit(polys.col(ent(1 + i))), *expected, "lagrange commitment {i}");
    }
    let _ = NUM_PRECOMPUTED;
    let fields: Vec<Fr> = fixed_vk().iter().flat_map(|c| c.to_fields()).collect();
    assert_eq!(Poseidon2::hash(&fields), fixed_vk_hash());
}

#[test]
fn eccvm_prove_and_verify() {
    let ck = GrumpkinKey::new(FIXED_SIZE);
    let q = build_ops("base");
    let mut t = NativeTranscript::new();
    let out = eccvm_prove(&q, &ck, &mut t, &mut OsRng);
    let proof = t.export_proof();
    // Leave the proof for bb to verify (tools/regen/regen_merge.sh).
    let dir = common::fixture_dir("instance/eccvm_proof/rust_base");
    std::fs::create_dir_all(&dir).unwrap();
    write_proof(&dir.join("eccvm_proof.bin"), &proof);
    write_proof(&dir.join("ipa_proof.bin"), &out.ipa_proof);

    assert!(verify(&proof, &out.ipa_proof, &ck), "Rust proof verifies");
    // "Libra:Sum" follows the 88 wire/derived commitments and the Libra concatenation commitment.
    let libra_sum_index = 2 * (1 + 88 + 1);
    let mut tampered = proof.clone();
    tampered[libra_sum_index] += Fr::from(1u64);
    assert!(!verify(&tampered, &out.ipa_proof, &ck), "tampered proof rejected");
    let mut tampered_ipa = out.ipa_proof.clone();
    *tampered_ipa.last_mut().unwrap() += Fr::from(1u64);
    assert!(!verify(&proof, &tampered_ipa, &ck), "tampered IPA proof rejected");
    if let Some(bb_proof) = read_proof(&common::fixture_dir("instance/eccvm_proof/base/eccvm_proof.bin")) {
        assert_eq!(proof.len(), bb_proof.len(), "proof length matches bb");
    }
}

#[test]
fn verify_bb_eccvm_proof() {
    let dump = common::fixture_dir("instance/eccvm_proof/base");
    let (Some(proof), Some(ipa_proof)) = (
        read_proof(&dump.join("eccvm_proof.bin")),
        read_proof(&dump.join("ipa_proof.bin")),
    ) else {
        eprintln!("skipping: no bb ECCVM proof dump");
        return;
    };
    let ck = GrumpkinKey::new(FIXED_SIZE);
    assert!(verify(&proof, &ipa_proof, &ck), "bb's ECCVM proof verifies in Rust");
}

/// With bb's CSPRNG tape replayed, the Rust ECCVM proof is byte-identical to bb's.
#[test]
fn eccvm_proof_byte_exact_with_tape() {
    let dir = common::fixture_dir("instance/eccvm_proof/base_tape");
    if !dir.join("rng_tape.bin").exists() {
        eprintln!("skipping eccvm tape: no dump");
        return;
    }
    let mut tape = TapeRng::from_bytes(std::fs::read(dir.join("rng_tape.bin")).unwrap());
    let ck = GrumpkinKey::new(FIXED_SIZE);
    let q = build_ops("base");
    let mut t = NativeTranscript::new();
    let out = eccvm_prove(&q, &ck, &mut t, &mut tape);
    let proof = t.export_proof();
    let expected = decode_fields(&std::fs::read(dir.join("eccvm_proof.bin")).unwrap());
    let first_diff = proof.iter().zip(&expected).position(|(a, b)| a != b);
    assert_eq!(
        first_diff, None,
        "ECCVM proof differs from bb's (first differing field index)"
    );
    assert_eq!(proof.len(), expected.len(), "ECCVM proof length");
    assert_eq!(
        out.ipa_proof,
        decode_fields(&std::fs::read(dir.join("ipa_proof.bin")).unwrap()),
        "IPA proof"
    );
    assert_eq!(tape.remaining(), 0, "unconsumed tape bytes");
}
