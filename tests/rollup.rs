//! RollupIO end to end in-circuit — an inner rollup proof (random-claim RollupIO) is
//! recursively verified, its IPA claim reduced to an accumulator and re-proven, and the outer
//! circuit publishes RollupIO; every polynomial matches bb (`BbRefDump.UltraRollupRecursion`,
//! seeded).

mod common;
use bb_ref::base::rng::{set_global, DebugRng};
use bb_ref::base::{CommitmentKey, Fr, GrumpkinKey, OsRng};
use bb_ref::circuit::builder::AddQuad;
use bb_ref::circuit::Builder;
use bb_ref::honk::prover_instance::ProverInstance;
use bb_ref::honk::ultra_prover::prove_ultra;
use bb_ref::honk::ULTRA;
use bb_ref::rollup::ipa_recursive::{prove_accumulator_claim, reduce_verify_ct, StdlibTranscript};
use bb_ref::rollup::{
    add_default_rollup_io, set_rollup_io_public, verify_recursive_ultra_rollup, vk_to_witnesses_ultra,
};
use bb_ref::stdlib::io::proof_to_witnesses;
use std::cell::RefCell;
use std::rc::Rc;

/// Mirror of the dumper's seeded inner circuit: 64 random big-add gates then RollupIO defaults.
fn build_inner(ctx: &Rc<RefCell<Builder>>) {
    for _ in 0..(1 << 6) {
        let a: Fr = bb_ref::base::rng::global_field();
        let b: Fr = bb_ref::base::rng::global_field();
        let c: Fr = bb_ref::base::rng::global_field();
        let d = a + b + c;
        let mut builder = ctx.borrow_mut();
        let a_idx = builder.add_variable(a);
        let b_idx = builder.add_variable(b);
        let c_idx = builder.add_variable(c);
        let d_idx = builder.add_variable(d);
        builder.create_big_add_gate(
            AddQuad {
                a: a_idx,
                b: b_idx,
                c: c_idx,
                d: d_idx,
                a_scaling: Fr::from(1u64),
                b_scaling: Fr::from(1u64),
                c_scaling: Fr::from(1u64),
                d_scaling: -Fr::from(1u64),
                const_scaling: Fr::from(0u64),
            },
            false,
        );
    }
    add_default_rollup_io(ctx);
}

#[test]
fn ultra_rollup_recursion_matches_bb() {
    let dump = common::fixture_dir("instance/ultra_rollup_recursion");
    if !dump.join("vk").exists() {
        eprintln!("skipping rollup recursion: no dump");
        return;
    }
    set_global(Box::new(DebugRng::new(12345)));

    // Inner rollup circuit and combined honk+ipa proof.
    let inner_ctx = Rc::new(RefCell::new(Builder::new()));
    build_inner(&inner_ctx);
    let mut inner_builder = Rc::try_unwrap(inner_ctx).ok().unwrap().into_inner();
    assert!(
        inner_builder.failed.is_none(),
        "inner failure: {:?}",
        inner_builder.failed
    );
    let mut inner_inst = ProverInstance::from_builder(&ULTRA, &mut inner_builder, &mut OsRng);
    let ck = CommitmentKey::new(inner_inst.max_end_index);
    let inner_vk = inner_inst.compute_vk(&ck);
    let inner_proof = prove_ultra(&mut inner_inst, &inner_vk, &mut OsRng);
    if dump.join("inner_vk").exists() {
        assert_eq!(
            inner_vk.to_bytes(),
            std::fs::read(dump.join("inner_vk")).unwrap(),
            "inner VK"
        );
        let bb_inner = bb_ref::base::io::decode_fields(&std::fs::read(dump.join("inner_proof.bin")).unwrap());
        assert_eq!(inner_proof.len(), bb_inner.len(), "inner proof length");
        for (k, (a, b)) in inner_proof.iter().zip(&bb_inner).enumerate() {
            assert_eq!(a, b, "inner proof field {k}");
        }
        eprintln!("inner vk+proof byte-equal to bb");
    }

    // Outer circuit: recursive verify, single-claim IPA accumulation, RollupIO publish.
    let ctx = Rc::new(RefCell::new(Builder::new()));
    let (vk_ct, vk_hash_ct) = vk_to_witnesses_ultra(&ctx, &inner_vk);
    let proof_ct = proof_to_witnesses(&ctx, &inner_proof);
    let output = verify_recursive_ultra_rollup(&ULTRA, &ctx, &vk_ct, &vk_hash_ct, &proof_ct);
    // bb `HonkRecursionConstraintsOutput::finalize(has_ipa_claim=true)` with one nested claim.
    let mut nested_t = StdlibTranscript::from_proof(&output.ipa_proof);
    let accumulator = reduce_verify_ct(&ctx, &output.ipa_claim, &mut nested_t);
    let grumpkin_key = GrumpkinKey::new(bb_ref::rollup::ipa::POLY_LENGTH);
    let (accumulated_claim, ipa_proof) = prove_accumulator_claim(&grumpkin_key, accumulator);
    ctx.borrow_mut().ipa_proof = ipa_proof;
    set_rollup_io_public(&output.points_accumulator, &accumulated_claim);
    drop(nested_t);
    drop(output);
    drop(accumulated_claim);
    drop(vk_ct);
    drop(vk_hash_ct);
    drop(proof_ct);

    let mut builder = Rc::try_unwrap(ctx).ok().unwrap().into_inner();
    assert!(builder.failed.is_none(), "outer failure: {:?}", builder.failed);
    let inst = ProverInstance::from_builder(&ULTRA, &mut builder, &mut OsRng);
    let expected = ProverInstance::load_dump(&ULTRA, &dump);
    assert_eq!(inst.dyadic_size, expected.dyadic_size, "dyadic size");
    if inst.public_inputs != expected.public_inputs {
        for (k, (a, b)) in inst.public_inputs.iter().zip(&expected.public_inputs).enumerate() {
            if a != b {
                eprintln!("public input {k} differs: rust {a:?} bb {b:?}");
            }
        }
        panic!(
            "public inputs differ ({} vs {})",
            inst.public_inputs.len(),
            expected.public_inputs.len()
        );
    }
    let compare: Vec<usize> = (0..inst.layout.num_unshifted()).collect();
    common::assert_polys_equal("ultra_rollup_recursion", &inst, &expected, &builder, &compare);
    let outer_ck = CommitmentKey::new(inst.max_end_index);
    assert_eq!(
        inst.compute_vk(&outer_ck).to_bytes(),
        std::fs::read(dump.join("vk")).unwrap(),
        "outer VK"
    );
}
