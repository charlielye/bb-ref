//! M11 exit: the joint MegaZK + Translator proof (`BbRefDump.Batched` fixture). Rust verifies bb's
//! Oink + joint proofs; Rust's own proofs verify in Rust and are written for bb's verify mode;
//! tampering is rejected.
mod common;
use bb_ref::base::field::{from_bytes_be, to_bytes_be, FieldLike};
use bb_ref::base::io::{decode_fields, encode_fields};
use bb_ref::base::rng::TapeRng;
use bb_ref::base::srs::bn254_g2;
use bb_ref::base::{CommitmentKey, Fq, Fr, G1Affine, NativeTranscript, OsRng};
use bb_ref::chonk::batched::{joint_prove, joint_verify, mega_zk_oink_length_without_public_inputs, JointVerifierInputs, JOINT_LOG_N};
use bb_ref::circuit::{Builder, EccOpQueue};
use bb_ref::goblin::translator::builder::TranslatorCircuit;
use bb_ref::goblin::translator::{Ent, TranslatorPolys, NUM_OP_QUEUE_WIRES};
use bb_ref::honk::oink::verify_oink;
use bb_ref::honk::oink_prover::prove_oink;
use bb_ref::honk::prover_instance::ProverInstance;
use bb_ref::honk::MEGA_ZK;
use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;

fn read_points(bytes: &[u8]) -> Vec<G1Affine> {
    bytes
        .chunks(64)
        .map(|b| G1Affine::new_unchecked(from_bytes_be::<Fq>(&b[..32]), from_bytes_be::<Fq>(&b[32..])))
        .collect()
}

fn verify(vk: &bb_ref::base::vk::Vk<bb_ref::base::Bn254>, oink_proof: &[Fr], joint_proof: &[Fr], inputs: &JointVerifierInputs) -> bool {
    let layout = MEGA_ZK.layout();
    let num_public_inputs = oink_proof.len() - mega_zk_oink_length_without_public_inputs();
    let mut t = NativeTranscript::from_proof(oink_proof);
    let oink = verify_oink::<bb_ref::base::Bn254>(&MEGA_ZK, &layout, vk, &vk.hash(), &mut t, num_public_inputs, false);
    let r = joint_verify(vk, &oink, joint_proof, inputs, &mut t);
    r.verified && r.pairing_points.check(&bn254_g2())
}

#[test]
fn batched_matches_bb() {
    let dump = common::fixture_dir("instance/batched");
    if !dump.join("joint_proof.bin").exists() {
        eprintln!("skipping batched: no dump");
        return;
    }
    let ck = CommitmentKey::new(1 << JOINT_LOG_N);

    // MegaZK circuit from the script, VK equal to bb's
    let text = std::fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/scripts/mega_zk.txt")).unwrap();
    let ctx = Rc::new(RefCell::new(Builder::new_mega(Rc::new(RefCell::new(EccOpQueue::new())))));
    common::script::run_script(&ctx, &text);
    let mut builder = Rc::try_unwrap(ctx).ok().unwrap().into_inner();
    let mut inst = ProverInstance::from_builder(&MEGA_ZK, &mut builder, &mut OsRng);
    let vk = inst.compute_vk(&ck);
    assert_eq!(vk.to_bytes(), std::fs::read(dump.join("vk")).unwrap(), "MegaZK VK");

    // translator key with bb's masking
    let q = common::translator_fixture::build_translator_queue(&dump);
    let v = Fq::from(11u64).invert();
    let x = Fq::from(13u64).invert();
    let circuit = TranslatorCircuit::new(v, x, &q);
    let mut polys = TranslatorPolys::from_circuit(&circuit, &common::translator_fixture::read_masking(&dump));
    let accumulated_result = circuit.accumulated_result();
    assert_eq!(
        to_bytes_be(&accumulated_result).to_vec(),
        std::fs::read(dump.join("accumulated_result.bin")).unwrap(),
        "accumulated result"
    );
    let op_queue_wire_commitments: [G1Affine; NUM_OP_QUEUE_WIRES] = std::array::from_fn(|i| ck.commit(&polys.cols[Ent::op as usize + i]));
    assert_eq!(
        op_queue_wire_commitments.to_vec(),
        read_points(&std::fs::read(dump.join("op_queue_wires.bin")).unwrap()),
        "op queue wire commitments"
    );
    let inputs = JointVerifierInputs {
        evaluation_input_x: x,
        batching_challenge_v: v,
        accumulated_result,
        op_queue_wire_commitments,
    };

    // bb's proofs verify in Rust
    let bb_oink = decode_fields(&std::fs::read(dump.join("oink_proof.bin")).unwrap());
    let bb_joint = decode_fields(&std::fs::read(dump.join("joint_proof.bin")).unwrap());
    assert!(verify(&vk, &bb_oink, &bb_joint, &inputs), "bb joint proof rejected");

    // Rust's proofs verify in Rust; written for bb's verify mode
    let mut t = NativeTranscript::new();
    let oink = prove_oink(&mut inst, &vk, &ck, &mut t, &mut OsRng, false);
    let rust_oink = t.export_proof();
    assert_eq!(rust_oink.len(), bb_oink.len(), "Oink proof length");
    joint_prove(&inst, &oink.params, &mut polys, &v, &x, &ck, &mut t, &mut OsRng);
    let rust_joint = t.export_proof();
    assert_eq!(rust_joint.len(), bb_joint.len(), "joint proof length");
    assert!(verify(&vk, &rust_oink, &rust_joint, &inputs), "Rust joint proof rejected");
    let out = dump.join("rust");
    std::fs::create_dir_all(&out).unwrap();
    std::fs::write(out.join("oink_proof.bin"), encode_fields(&rust_oink)).unwrap();
    std::fs::write(out.join("joint_proof.bin"), encode_fields(&rust_joint)).unwrap();
    std::fs::copy(dump.join("accumulated_result.bin"), out.join("accumulated_result.bin")).unwrap();
    std::fs::copy(dump.join("op_queue_wires.bin"), out.join("op_queue_wires.bin")).unwrap();

    // tampering: a claimed translator evaluation, and the ECCVM result the verifier is told
    let mut bad = rust_joint.clone();
    let idx = bad.len() - 200;
    bad[idx] += Fr::from(1u64);
    assert!(!verify(&vk, &rust_oink, &bad, &inputs), "tampered joint proof accepted");
    let bad_inputs = JointVerifierInputs {
        accumulated_result: accumulated_result + Fq::from(1u64),
        ..inputs
    };
    assert!(!verify(&vk, &rust_oink, &rust_joint, &bad_inputs), "wrong accumulated result accepted");
}

/// With bb's CSPRNG tape replayed (instance masking, ZK prefix, random ops, translator masking,
/// sparse Gemini mask, Libra), the Rust Oink and joint proofs are byte-identical to bb's.
#[test]
fn batched_byte_exact_with_tape() {
    let dump = common::fixture_dir("instance/batched_tape");
    if !dump.join("rng_tape.bin").exists() {
        eprintln!("skipping batched tape: no dump");
        return;
    }
    let mut tape = TapeRng::from_bytes(std::fs::read(dump.join("rng_tape.bin")).unwrap());
    let ck = CommitmentKey::new(1 << JOINT_LOG_N);
    let text = std::fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/scripts/mega_zk.txt")).unwrap();
    let ctx = Rc::new(RefCell::new(Builder::new_mega(Rc::new(RefCell::new(EccOpQueue::new())))));
    common::script::run_script(&ctx, &text);
    let mut builder = Rc::try_unwrap(ctx).ok().unwrap().into_inner();
    let mut inst = ProverInstance::from_builder(&MEGA_ZK, &mut builder, &mut tape);
    let vk = inst.compute_vk(&ck);
    let q = common::translator_fixture::build_translator_queue_from_rng(&mut tape);
    let v = Fq::from(11u64).invert();
    let x = Fq::from(13u64).invert();
    let circuit = TranslatorCircuit::new(v, x, &q);
    let masking = TranslatorPolys::random_masking(&mut tape);
    assert_eq!(masking, common::translator_fixture::read_masking(&dump), "translator masking values");
    let mut polys = TranslatorPolys::from_circuit(&circuit, &masking);

    let mut t = NativeTranscript::new();
    let oink = prove_oink(&mut inst, &vk, &ck, &mut t, &mut tape, false);
    let rust_oink = t.export_proof();
    let bb_oink = decode_fields(&std::fs::read(dump.join("oink_proof.bin")).unwrap());
    assert_eq!(rust_oink.iter().zip(&bb_oink).position(|(a, b)| a != b), None, "Oink proof differs from bb's (first differing field)");
    joint_prove(&inst, &oink.params, &mut polys, &v, &x, &ck, &mut t, &mut tape);
    let rust_joint = t.export_proof();
    let bb_joint = decode_fields(&std::fs::read(dump.join("joint_proof.bin")).unwrap());
    assert_eq!(
        rust_joint.iter().zip(&bb_joint).position(|(a, b)| a != b),
        None,
        "joint proof differs from bb's (first differing field)"
    );
    assert_eq!(rust_joint.len(), bb_joint.len());
    assert_eq!(tape.remaining(), 0, "unconsumed tape bytes");
}
