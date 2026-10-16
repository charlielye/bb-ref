//! bb `mock_verifier_inputs` and `create_mock_chonk_from_constraints`: the IVC state a kernel is
//! built against when only its VK is wanted (no witness, so no real proofs). Proofs and VKs have
//! the real shapes, so the kernel circuit — hence its VK — is the same; values are arbitrary
//! except where the verifier branches on them (the subtable sizes of the batch merge proof).

use super::lower::{io_public_inputs_size, RecursionConstraint, HN, HN_FINAL, OINK};
use crate::base::codec::Transcriptable;
use crate::base::rng::Rng;
use crate::base::vk::Vk;
use crate::base::{Bn254, CommitmentKey, Fr, G1Affine};
use crate::chonk::ivc::{Chonk, CircuitKind, VerifierInputs};
use crate::circuit::{Builder, EccOpQueue, NUM_ZERO_ROWS};
use crate::goblin::batch_merge::CHONK_MAX_NUM_CIRCUITS;
use crate::honk::flavor::{FlavorDesc, MEGA_KERNEL};
use crate::honk::hypernova::VerifierClaim;
use crate::honk::multilinear_batching::{UNIVARIATE_LENGTH, VIRTUAL_LOG_N as MLB_LOG_N};
use crate::stdlib::io::{AppIo, KernelIo, MAX_APPS_PER_KERNEL};
use crate::stdlib::Ctx;
use ark_ec::AffineRepr;
use std::cell::RefCell;
use std::rc::Rc;

const NUM_WIRES: usize = 4;

fn push_commitments(out: &mut Vec<Fr>, n: usize) {
    let one = <G1Affine as Transcriptable<Fr>>::to_fields(&<G1Affine as AffineRepr>::generator());
    for _ in 0..n {
        out.extend_from_slice(&one);
    }
}

fn push_random(out: &mut Vec<Fr>, n: usize, rng: &mut dyn Rng) {
    for _ in 0..n {
        out.push(rng.fr());
    }
}

/// bb `create_mock_oink_proof`: the default IO as public inputs (verified circuits have no ACIR
/// public inputs), then one commitment per witness entity.
fn mock_oink_proof(kind: CircuitKind) -> Vec<Fr> {
    let ctx: Ctx = Rc::new(RefCell::new(Builder::from_acir_mega(
        EccOpQueue::shared(),
        &[],
        vec![],
        false,
    )));
    match kind {
        CircuitKind::App => AppIo::add_default(&ctx),
        CircuitKind::Kernel => KernelIo::add_default(&ctx),
        CircuitKind::HidingKernel => unreachable!("the hiding kernel is never verified recursively"),
    }
    let b = ctx.borrow();
    let mut proof: Vec<Fr> = b.public_inputs().iter().map(|i| b.get_variable(*i)).collect();
    push_commitments(&mut proof, kind.flavor().layout().num_witness);
    proof
}

/// bb `create_mock_sumcheck_proof`: the round univariates and the multilinear evaluations.
fn mock_sumcheck_proof(flavor: &FlavorDesc, rng: &mut dyn Rng) -> Vec<Fr> {
    let layout = flavor.layout();
    let mut proof = vec![];
    push_random(
        &mut proof,
        flavor.virtual_log_n * layout.batched_len + layout.num_all(),
        rng,
    );
    proof
}

fn mock_instance_proof(kind: CircuitKind, rng: &mut dyn Rng) -> Vec<Fr> {
    let mut proof = mock_oink_proof(kind);
    proof.extend(mock_sumcheck_proof(kind.flavor(), rng));
    proof
}

/// bb `create_mock_multilinear_batch_proof`.
fn mock_batching_proof(num_claims: usize, rng: &mut dyn Rng) -> Vec<Fr> {
    let mut proof = vec![];
    push_random(&mut proof, MLB_LOG_N * UNIVARIATE_LENGTH + 3 * num_claims, rng);
    proof
}

/// bb `create_mock_pcs_proof<MegaKernelFlavor>`: the decider's Gemini folds and evaluations, Shplonk Q and KZG W.
fn mock_decider_proof(rng: &mut dyn Rng) -> Vec<Fr> {
    let n = MEGA_KERNEL.virtual_log_n;
    let mut proof = vec![];
    push_commitments(&mut proof, n - 1);
    push_random(&mut proof, n, rng);
    push_commitments(&mut proof, 2);
    proof
}

/// bb `create_mock_batch_merge_proof`: one subtable per wire slot, the ZK columns, a single
/// subtable of size 2 (sizes the verifier's indicator logic accepts), the merged and degree-check
/// commitments, the evaluations, and the two opening commitments.
fn mock_batch_merge_proof(rng: &mut dyn Rng) -> Vec<Fr> {
    let m = CHONK_MAX_NUM_CIRCUITS;
    let mut proof = vec![];
    push_commitments(&mut proof, m * NUM_WIRES);
    push_commitments(&mut proof, NUM_WIRES);
    proof.push(Fr::from(1u64));
    proof.push(Fr::from(2u64));
    proof.extend(vec![Fr::from(0u64); m - 1]);
    push_commitments(&mut proof, NUM_WIRES + 1);
    push_random(&mut proof, m * NUM_WIRES + NUM_WIRES + NUM_WIRES + 1, rng);
    push_commitments(&mut proof, 2);
    proof
}

/// bb `create_mock_honk_vk`: a VK of the padded circuit size with `one` for every commitment.
fn mock_vk(kind: CircuitKind) -> Vk<Bn254> {
    let flavor = kind.flavor();
    Vk {
        log_circuit_size: Fr::from(flavor.virtual_log_n as u64),
        num_public_inputs: Fr::from(io_public_inputs_size(kind) as u64),
        pub_inputs_offset: Fr::from(NUM_ZERO_ROWS as u64),
        comms: vec![<G1Affine as AffineRepr>::generator(); flavor.layout().num_precomputed],
    }
}

/// bb `mock_chonk_accumulation`: what accumulating one circuit of the kernel's group leaves behind.
fn mock_accumulation(ivc: &mut Chonk, is_kernel: bool, is_hiding: bool, rng: &mut dyn Rng) {
    ivc.recursive_verifier_native_accum = Some(VerifierClaim {
        challenge: vec![Fr::from(0u64); MEGA_KERNEL.virtual_log_n],
        non_shifted_evaluation: Fr::from(0u64),
        shifted_evaluation: Fr::from(0u64),
        non_shifted_commitment: <G1Affine as AffineRepr>::generator(),
        shifted_commitment: <G1Affine as AffineRepr>::generator(),
    });
    let kind = if is_kernel {
        CircuitKind::Kernel
    } else {
        CircuitKind::App
    };
    ivc.verification_queue.push(VerifierInputs {
        proof: mock_instance_proof(kind, rng),
        vk: mock_vk(kind),
        kind,
    });
    let is_init = ivc.verification_queue[0].kind == CircuitKind::App;
    let num_claims = ivc.verification_queue.len() + (!is_init) as usize;
    if num_claims >= 2 {
        ivc.multilinear_batch_proof = mock_batching_proof(num_claims, rng);
    }
    if is_hiding {
        ivc.batch_merge_proof = mock_batch_merge_proof(rng);
        ivc.decider_proof = mock_decider_proof(rng);
    }
    let n = ivc.num_accumulated();
    ivc.set_num_circuits_accumulated_for_mocking(n + 1);
}

/// bb `create_mock_chonk_from_constraints`: infer the kernel's position from its proof types (OINK
/// first: init kernel; HN_FINAL: hiding kernel; otherwise a kernel proof then app proofs) and mock
/// the accumulation of its group.
pub fn mock_chonk_from_constraints(constraints: &[RecursionConstraint], rng: &mut dyn Rng) -> Chonk {
    assert!(
        !constraints.is_empty(),
        "at least one recursion constraint is required to determine the IVC state"
    );
    let types: Vec<u32> = constraints.iter().map(|c| c.proof_type).collect();
    let is_init = types[0] == OINK;
    let is_hiding = types.len() == 1 && types[0] == HN_FINAL;
    assert!(
        types.len() <= MAX_APPS_PER_KERNEL + (!is_init) as usize,
        "too many recursion constraints"
    );
    let tail = [CircuitKind::Kernel, CircuitKind::Kernel, CircuitKind::HidingKernel];
    let (group, kinds, target): (Vec<(bool, bool)>, Vec<CircuitKind>, usize) = if is_init {
        assert!(
            types[1..].iter().all(|t| *t == HN),
            "subsequent constraints in an init kernel must be HN"
        );
        let mut kinds = vec![CircuitKind::App; types.len()];
        kinds.extend(tail);
        (vec![(false, false); types.len()], kinds, types.len())
    } else if is_hiding {
        // the group is the tail kernel (index 2); the target is the hiding kernel
        (
            vec![(true, true)],
            vec![
                CircuitKind::App,
                CircuitKind::Kernel,
                CircuitKind::Kernel,
                CircuitKind::HidingKernel,
            ],
            3,
        )
    } else {
        assert!(
            types.iter().all(|t| *t == HN),
            "constraints in an inner/reset/tail kernel must be HN"
        );
        let mut group = vec![(true, false)];
        group.extend(vec![(false, false); types.len() - 1]);
        let mut kinds = vec![CircuitKind::App, CircuitKind::Kernel];
        kinds.extend(vec![CircuitKind::App; types.len() - 1]);
        let target = kinds.len();
        kinds.extend(tail);
        (group, kinds, target)
    };
    let mut ivc = Chonk::new(kinds, CommitmentKey::empty());
    for (is_kernel, hiding) in group {
        mock_accumulation(&mut ivc, is_kernel, hiding, rng);
    }
    ivc.set_num_circuits_accumulated_for_mocking(target);
    ivc
}
