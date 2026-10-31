//! The generic Ultra verifier runs in-circuit over ULTRA arithmetic (non-goblin bn254
//! biggroup, native scalars) and reproduces bb's recursive-verifier circuit polynomial for
//! polynomial (`BbRefDump.UltraRecursion`, seeded: the verifier's masked batch_muls draw from the
//! engine).

mod common;
use bb_ref::acir::format::{decode_program, decode_witness};
use bb_ref::acir::lower::build_circuit;
use bb_ref::base::rng::DebugRng;
use bb_ref::base::{CommitmentKey, OsRng};
use bb_ref::circuit::Builder;
use bb_ref::honk::prover_instance::ProverInstance;
use bb_ref::honk::ultra_prover::prove_ultra;
use bb_ref::honk::ULTRA;
use bb_ref::rollup::{set_ultra_pairing_points_public, verify_recursive_ultra, vk_to_witnesses_ultra};
use bb_ref::stdlib::io::proof_to_witnesses;
use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;

fn acir_tests_dir() -> PathBuf {
    std::env::var("ACIR_TESTS").map(PathBuf::from).unwrap_or_else(|_| {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("pin/aztec-packages/barretenberg/acir_tests/acir_tests")
    })
}

#[test]
fn ultra_recursive_verifier_matches_bb() {
    let dump = common::fixture_dir("instance/ultra_recursion/a_1_mul");
    if !dump.join("vk").exists() {
        eprintln!("skipping ultra recursion: no dump");
        return;
    }
    // The inner proof: a_1_mul with non-ZK UltraHonk (deterministic, byte-exact vs bb since M3).
    let target = acir_tests_dir().join("a_1_mul/target");
    let circuit = decode_program(&std::fs::read(target.join("program.json")).unwrap());
    let witness = decode_witness(&std::fs::read(target.join("witness.gz")).unwrap(), &mut OsRng);
    let mut inner_builder = build_circuit(&circuit, Some(&witness));
    let mut inner_inst = ProverInstance::from_builder(&ULTRA, &mut inner_builder, &mut OsRng);
    let ck = CommitmentKey::new(inner_inst.max_end_index);
    let inner_vk = inner_inst.compute_vk(&ck);
    let inner_proof = prove_ultra(&mut inner_inst, &inner_vk, &mut OsRng);

    // The outer circuit: witness order mirrors bb (VKAndHash first, then the stdlib proof).
    bb_ref::base::rng::set_global(Box::new(DebugRng::new(12345)));
    let ctx = Rc::new(RefCell::new(Builder::new()));
    let (vk_ct, vk_hash_ct) = vk_to_witnesses_ultra(&ctx, &inner_vk);
    let proof_ct = proof_to_witnesses(&ctx, &inner_proof);
    let output = verify_recursive_ultra(&ULTRA, &ctx, &vk_ct, &vk_hash_ct, &proof_ct);
    set_ultra_pairing_points_public(&output.points_accumulator);
    drop(output);
    drop(vk_ct);
    drop(vk_hash_ct);
    drop(proof_ct);

    let mut builder = Rc::try_unwrap(ctx).ok().unwrap().into_inner();
    assert!(builder.failed.is_none(), "outer circuit failure: {:?}", builder.failed);
    let inst = ProverInstance::from_builder(&ULTRA, &mut builder, &mut OsRng);
    let expected = ProverInstance::load_dump(&ULTRA, &dump);
    assert_eq!(inst.dyadic_size, expected.dyadic_size, "dyadic size");
    if inst.public_inputs != expected.public_inputs {
        for (k, (a, b)) in inst.public_inputs.iter().zip(&expected.public_inputs).enumerate() {
            if a != b {
                eprintln!("public input {k} differs: rust {a:?} bb {b:?}");
            }
        }
        panic!("public inputs differ");
    }
    let compare: Vec<usize> = (0..inst.layout.num_unshifted()).collect();
    common::assert_polys_equal("ultra_recursion/a_1_mul", &inst, &expected, &builder, &compare);
    let outer_ck = CommitmentKey::new(inst.max_end_index);
    assert_eq!(
        inst.compute_vk(&outer_ck).to_bytes(),
        std::fs::read(dump.join("vk")).unwrap(),
        "outer VK"
    );
}
