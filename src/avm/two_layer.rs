//! bb's two-layer AVM recursive verifier (`two_layer_avm_recursive_verifier.hpp`), the AVM
//! recursion constraint of the public tx base rollup. Inside the outer (Ultra) circuit's witness
//! generation, the inner MegaAvm circuit ([`super::recursive`]) is built and proven — a MegaAvm
//! Honk proof, then a Goblin proof of its op queue (ECCVM, TripleIPA, Translator) on the same
//! transcript. The outer circuit then verifies those, and binds them to this AVM proof by
//! recomputing the inner circuit's published transcript hash.

use super::recursive::inner_circuit;
use super::verifier::hash_avm_transcript;
use crate::base::group::{GroupLike, PairingPoints};
use crate::base::rng::Rng;
use crate::base::srs::Srs;
use crate::base::vk::Vk;
use crate::base::{Bn254, Fq, Fr, NativeTranscript};
use crate::chonk::verifier::DeferredTripleIpaOpening;
use crate::goblin::eccvm::prover::eccvm_prove;
use crate::goblin::eccvm::verifier::eccvm_verify;
use crate::goblin::eccvm::FIXED_SIZE as ECCVM_FIXED_SIZE;
use crate::goblin::translator::builder::TranslatorCircuit;
use crate::goblin::translator::proof::{translator_prove, translator_verify};
use crate::goblin::translator::{TranslatorPolys, CIRCUIT_SIZE as TRANSLATOR_CIRCUIT_SIZE};
use crate::honk::flavor::{Ent, MEGA_AVM, MEGA_AVM_LOG_N};
use crate::honk::prover_instance::ProverInstance;
use crate::honk::ultra_prover::prove_ultra_on;
use crate::honk::ultra_verifier::reduce_to_pairing_check_on;
use crate::rollup::ipa_recursive::StdlibTranscript;
use crate::rollup::{aggregate_pair, reconstruct_default_io, vk_to_witnesses_ultra};
use crate::stdlib::bigfield::BigField;
use crate::stdlib::curve::{StdUltraBn254, StdUltraGrumpkin};
use crate::stdlib::io::proof_to_witnesses;
use crate::stdlib::{Ctx, FieldT};

/// bb `NUM_AVM_ULTRA_OPS`: the inner circuit's op count, fixed by the AVM's column count.
pub const NUM_AVM_ULTRA_OPS: usize = 2909;

/// bb `TwoLayerAvmRecursiveVerifier::InnerProverOutput`: `{π_M, π_G, VK_M}`.
pub struct InnerProof {
    pub mega_proof: Vec<Fr>,
    pub eccvm_proof: Vec<Fr>,
    pub ipa_proof: Vec<Fr>,
    pub translator_proof: Vec<Fr>,
    pub mega_vk: Vk<Bn254>,
}

/// bb `construct_and_prove_inner_recursive_verification_circuit`.
pub fn prove_inner(proof: &[Fr], public_inputs: &[Vec<Fr>], srs: &Srs, rng: &mut dyn Rng) -> InnerProof {
    let mut builder = inner_circuit(proof, public_inputs);
    let op_queue = builder.op_queue();
    let mut inst = ProverInstance::from_builder(&MEGA_AVM, &mut builder, rng);
    drop(builder);
    assert!(
        inst.log_n() <= MEGA_AVM_LOG_N,
        "AVMRecursiveVerifier: circuit size exceeded current upper bound. If expected, bump MEGA_AVM_LOG_N"
    );
    let ck = srs.bn254_key(inst.max_end_index.max(TRANSLATOR_CIRCUIT_SIZE));
    let mega_vk = inst.compute_vk(&ck);
    let mut t = NativeTranscript::new();
    prove_ultra_on::<Bn254>(&mut inst, &mega_vk, &ck, &mut t, rng);
    let mega_proof = t.export_proof();
    drop(inst);

    // bb `GoblinAvm::prove`: merge the inner circuit's ops, then the ECCVM and the Translator.
    let mut q = op_queue.write().unwrap();
    q.merge();
    let eccvm = eccvm_prove(&q, &srs.grumpkin_key(ECCVM_FIXED_SIZE), &mut t, rng);
    let eccvm_proof = t.export_proof();
    let (v, x) = (eccvm.batching_challenge_v, eccvm.evaluation_challenge_x);
    let circuit = TranslatorCircuit::with_mode(v, x, &q, true);
    let mut polys = TranslatorPolys::from_circuit(&circuit, &TranslatorPolys::random_masking(rng));
    drop(circuit);
    translator_prove(&mut polys, &v, &x, &ck, &mut t, rng);
    let translator_proof = t.export_proof();
    assert_eq!(
        q.ultra_ops.num_ops(),
        NUM_AVM_ULTRA_OPS,
        "The number of ultra ops in the AVM proof has changed. This should only happen if the number of columns in the AVM changed."
    );
    InnerProof {
        mega_proof,
        eccvm_proof,
        ipa_proof: eccvm.ipa_proof,
        translator_proof,
        mega_vk,
    }
}

pub struct OuterOutput {
    pub points_accumulator: PairingPoints<StdUltraBn254>,
    pub triple_ipa_opening: DeferredTripleIpaOpening,
    /// Native-value consistency of every reduction (the circuit enforces them).
    pub all_checks_passed: bool,
}

/// bb `construct_outer_recursive_verification_circuit` on the rollup's Ultra builder.
pub fn verify_outer(ctx: &Ctx, proof: &[FieldT], public_inputs: &[Vec<FieldT>], inner: &InnerProof) -> OuterOutput {
    let mut t = StdlibTranscript::new();
    // The inner circuit must be a genuine AVM verifier: its VK and hash are fixed in the outer circuit.
    let (mut vk, vk_hash) = vk_to_witnesses_ultra(ctx, &inner.mega_vk);
    for f in [&vk.log_circuit_size, &vk.num_public_inputs, &vk.pub_inputs_offset] {
        f.fix_witness();
    }
    for c in &mut vk.comms {
        c.fix_witness();
    }
    vk_hash.fix_witness();

    // Step 1: the Mega proof π_M (bb `UltraVerifier_<MegaAvmRecursiveFlavor_, GoblinAvmIO>`)
    let mega_proof = proof_to_witnesses(ctx, &inner.mega_proof);
    let mega = reduce_to_pairing_check_on::<StdUltraBn254>(&MEGA_AVM, &vk, &vk_hash, &mega_proof, ctx, &mut t);
    // bb `GoblinAvmIO::reconstruct_from_public`: the transcript hash, then the pairing points.
    let pi = &mega.public_inputs;
    let io_transcript_hash = pi[pi.len() - 9].clone();
    let io_points = reconstruct_default_io(pi);
    let mut points = aggregate_pair(io_points, mega.pcs_pairing_points);
    let layout = MEGA_AVM.layout();
    let ecc_op_wires = [Ent::ecc_op_wire_1, Ent::ecc_op_wire_2, Ent::ecc_op_wire_3, Ent::ecc_op_wire_4]
        .map(|e| mega.commitments[layout.idx(e)].clone());

    // Step 2: the Goblin proof π_G (bb `GoblinAvmRecursiveVerifier`): ECCVM, then Translator.
    let eccvm_fields = proof_to_witnesses(ctx, &inner.eccvm_proof);
    let ipa_fields = proof_to_witnesses(ctx, &inner.ipa_proof);
    let translator_fields = proof_to_witnesses(ctx, &inner.translator_proof);
    t.load_proof(&eccvm_fields);
    let eccvm = eccvm_verify::<StdUltraGrumpkin>(ctx, &mut t);
    let translator = translator_verify::<StdUltraBn254, BigField<Fq>>(
        ctx,
        &translator_fields,
        &eccvm.evaluation_challenge_x,
        &eccvm.batching_challenge_v,
        &eccvm.accumulated_result,
        &ecc_op_wires,
        &mut t,
    );

    // Step 3: aggregate the Translator's pairing points into the Mega ones.
    points = aggregate_pair(points, translator.pairing_points);

    // Step 4: the inner circuit verified this AVM proof and these public inputs.
    let computed_transcript_hash = hash_avm_transcript::<StdUltraBn254>(ctx, proof, public_inputs);
    let hash_ok = computed_transcript_hash.get_value() == io_transcript_hash.get_value();
    io_transcript_hash.assert_equal(&computed_transcript_hash);

    OuterOutput {
        points_accumulator: points,
        triple_ipa_opening: DeferredTripleIpaOpening {
            claim: eccvm.triple_ipa_claim,
            proof: ipa_fields,
        },
        all_checks_passed: mega.succeeded && eccvm.ok && translator.verified && hash_ok,
    }
}

/// bb `create_avm2_recursion_constraints_goblin` past the witness setup: the inner proof, then the
/// outer verification.
pub fn verify_two_layer(ctx: &Ctx, proof: &[FieldT], public_inputs: &[Vec<FieldT>], srs: &Srs, rng: &mut dyn Rng) -> OuterOutput {
    use crate::base::field::FieldLike;
    let native_proof: Vec<Fr> = proof.iter().map(FieldLike::value).collect();
    let native_public_inputs: Vec<Vec<Fr>> =
        public_inputs.iter().map(|c| c.iter().map(FieldLike::value).collect()).collect();
    let inner = prove_inner(&native_proof, &native_public_inputs, srs, rng);
    verify_outer(ctx, proof, public_inputs, &inner)
}
