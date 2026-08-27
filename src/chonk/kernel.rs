//! bb `Chonk::complete_kernel_circuit_logic`: the recursive verification a kernel performs of the
//! circuits folded since the previous kernel, plus its public-input tail.

use super::ivc::{Chonk, CircuitKind, VerifierInputs};
use crate::base::group::{GroupLike, PairingPoints};
use crate::base::rng::Rng;
use crate::base::vk::Vk;
use crate::base::Bn254;
use crate::goblin::batch_merge::{batch_merge_verify, ecc_op_hash_step, CHONK_MAX_NUM_CIRCUITS};
use crate::honk::decider::decider_verify;
use crate::honk::flavor::Ent;
use crate::honk::hypernova::{FoldingVerifier, VerifierClaim};
use crate::stdlib::io::{proof_to_witnesses, vk_to_witnesses, DataBusDepot, HidingKernelIo, KernelIo, MAX_APPS_PER_KERNEL};
use crate::stdlib::{Ctx, FieldT, GoblinElement, StdBn254};

const APP_CALLDATA: [Ent; MAX_APPS_PER_KERNEL] = [
    Ent::first_app_calldata,
    Ent::second_app_calldata,
    Ent::third_app_calldata,
    Ent::fourth_app_calldata,
    Ent::fifth_app_calldata,
];
const ECC_OP_WIRES: [Ent; 4] = [Ent::ecc_op_wire_1, Ent::ecc_op_wire_2, Ent::ecc_op_wire_3, Ent::ecc_op_wire_4];

/// A queue entry as circuit witnesses (bb `instantiate_stdlib_verification_queue`): the proof, then
/// the VK, then its hash.
struct StdlibVerifierInputs {
    proof: Vec<FieldT>,
    vk: Vk<StdBn254>,
    vk_hash: FieldT,
    kind: CircuitKind,
}

fn instantiate_stdlib_verification_queue(ctx: &Ctx, queue: Vec<VerifierInputs>) -> Vec<StdlibVerifierInputs> {
    queue
        .into_iter()
        .map(|e| {
            let proof = proof_to_witnesses(ctx, &e.proof);
            let vk = vk_to_witnesses(ctx, &e.vk);
            let vk_hash = FieldT::from_witness(ctx, e.vk.hash());
            StdlibVerifierInputs { proof, vk, vk_hash, kind: e.kind }
        })
        .collect()
}

/// bb `get_value<VerifierAccumulator>()`: the native values of an in-circuit accumulator.
fn claim_value(claim: &VerifierClaim<StdBn254>) -> VerifierClaim<Bn254> {
    VerifierClaim {
        challenge: claim.challenge.iter().map(FieldT::get_value).collect(),
        non_shifted_evaluation: claim.non_shifted_evaluation.get_value(),
        shifted_evaluation: claim.shifted_evaluation.get_value(),
        non_shifted_commitment: claim.non_shifted_commitment.value(),
        shifted_commitment: claim.shifted_commitment.value(),
    }
}

/// Complete the kernel circuit under construction in `ctx`: verify every queued instance, batch
/// their claims with the previous accumulator, and (for the hiding kernel) verify the decider and
/// the batch merge. The circuit must already contain the kernel's own logic and databus contents.
pub fn complete_kernel_circuit_logic(ivc: &mut Chonk, ctx: &Ctx, rng: &mut dyn Rng) {
    let queue = instantiate_stdlib_verification_queue(ctx, ivc.take_verification_queue());
    assert!(!queue.is_empty(), "kernel with nothing to verify");
    let is_init = queue[0].kind == CircuitKind::App;
    let is_hiding = ivc.current_kind() == CircuitKind::HidingKernel;
    ctx.borrow_mut().queue_ecc_eq();
    let mut depot = DataBusDepot::default();
    let num_claims = queue.len() + (!is_init) as usize;

    let mut prev_accumulator: Option<VerifierClaim<StdBn254>> = None;
    let mut prev_accum_hash: Option<FieldT> = None;
    if !is_init {
        let native = ivc.recursive_verifier_native_accum.as_ref().expect("no previous kernel accumulator");
        let claim = VerifierClaim::<StdBn254>::from_native(ctx, native);
        prev_accum_hash = Some(claim.hash());
        prev_accumulator = Some(claim);
    }

    let mut folding = FoldingVerifier::<StdBn254>::new();
    let mut points_accumulator: Vec<PairingPoints<StdBn254>> = Vec::new();
    let mut running_ecc_op_hash: Option<FieldT> = None;
    for entry in &queue {
        let flavor = entry.kind.flavor();
        let layout = flavor.layout();
        crate::circuit::builder::trace_phase("kernel: before instance");
        let (_, oink) = folding.accumulate_instance(flavor, &entry.vk, &entry.vk_hash, &entry.proof);
        crate::circuit::builder::trace_phase("kernel: instance verified");
        let commitment = |e: Ent| oink.commitments[layout.idx(e)].clone();
        let pairing_points = match entry.kind {
            CircuitKind::Kernel => {
                let io = KernelIo::reconstruct_from_public(&oink.public_inputs);
                io.kernel_return_data.incomplete_assert_equal(&commitment(Ent::kernel_calldata));
                for (i, app) in io.app_return_data.iter().enumerate() {
                    app.incomplete_assert_equal(&commitment(APP_CALLDATA[i]));
                }
                io.output_hn_accum_hash.assert_equal(prev_accum_hash.as_ref().expect("kernel verified in an init group"));
                depot.set_kernel_return_data_commitment(commitment(Ent::return_data));
                assert!(running_ecc_op_hash.is_none(), "a kernel must be the first entry of its group");
                running_ecc_op_hash = Some(io.ecc_op_hash);
                io.pairing_inputs
            }
            CircuitKind::App => {
                let n = oink.public_inputs.len();
                let pairing_inputs = PairingPoints::<StdBn254>::from_fields(&oink.public_inputs[n - 8..]);
                depot.set_app_return_data_commitment(commitment(Ent::return_data));
                pairing_inputs
            }
            CircuitKind::HidingKernel => unreachable!("the hiding kernel is never verified recursively"),
        };
        crate::circuit::builder::trace_phase("kernel: io processed");
        points_accumulator.push(pairing_points);
        let ecc_op_wires: Vec<GoblinElement> = ECC_OP_WIRES.iter().map(|e| commitment(*e)).collect();
        running_ecc_op_hash = Some(ecc_op_hash_step::<StdBn254>(&ecc_op_wires, running_ecc_op_hash.as_ref()));
    }
    let running_ecc_op_hash = running_ecc_op_hash.unwrap();

    crate::circuit::builder::trace_phase("kernel: ecc op hash");
    let batching_proof = proof_to_witnesses(ctx, &ivc.multilinear_batch_proof);
    let (_, output_accumulator) = folding.finalize(&batching_proof, prev_accumulator);
    crate::circuit::builder::trace_phase("kernel: batching verified");

    if is_hiding {
        assert_eq!(num_claims, 2, "the hiding kernel batches exactly two claims");
        let decider_proof = proof_to_witnesses(ctx, &ivc.decider_proof);
        folding.transcript.load_proof(&decider_proof);
        crate::circuit::builder::trace_phase("hiding: decider start");
        points_accumulator.push(decider_verify::<StdBn254>(&output_accumulator, &mut folding.transcript, ctx));
        crate::circuit::builder::trace_phase("hiding: decider verified");
        let batch_merge_proof = proof_to_witnesses(ctx, &ivc.batch_merge_proof);
        let merge = batch_merge_verify::<StdBn254>(&batch_merge_proof, &running_ecc_op_hash, CHONK_MAX_NUM_CIRCUITS, ctx);
        crate::circuit::builder::trace_phase("hiding: batch merge verified");
        points_accumulator.push(merge.pairing_points);
        let pairing_inputs = PairingPoints::aggregate_multiple(&points_accumulator);
        crate::circuit::builder::trace_phase("hiding: aggregated");
        ctx.borrow_mut().queue_ecc_random_op(rng);
        ctx.borrow_mut().queue_ecc_random_op(rng);
        HidingKernelIo {
            pairing_inputs,
            kernel_return_data: depot.get_kernel_return_data_commitment(ctx),
            ecc_op_tables: merge.merged_commitments,
        }
        .set_public();
    } else {
        let pairing_inputs = PairingPoints::aggregate_multiple(&points_accumulator);
        ivc.recursive_verifier_native_accum = Some(claim_value(&output_accumulator));
        let kernel_return_data = depot.get_kernel_return_data_commitment(ctx);
        let app_return_data = std::array::from_fn(|i| depot.get_app_return_data_commitment(ctx, i));
        let output_hn_accum_hash = output_accumulator.hash();
        KernelIo {
            pairing_inputs,
            kernel_return_data,
            app_return_data,
            ecc_op_hash: running_ecc_op_hash,
            output_hn_accum_hash,
        }
        .set_public();
    }
}
