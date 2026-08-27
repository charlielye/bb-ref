//! bb `Chonk`: the IVC driver. Circuits are accumulated one at a time (apps and kernels are folded
//! per kernel group; the hiding kernel is proven with the joint MegaZK + Translator proof) and
//! `prove` emits the `ChonkProof`.

use super::batched::joint_prove;
use super::proof::ChonkProof;
use crate::base::rng::Rng;
use crate::base::timing;
use crate::base::vk::Vk;
use crate::base::{Bn254, CommitmentKey, Fr, GrumpkinKey, NativeTranscript};
use crate::circuit::op_queue::EccOpQueue;
use crate::circuit::Builder;
use crate::goblin::batch_merge::{batch_merge_prove, CHONK_MAX_NUM_CIRCUITS};
use crate::goblin::eccvm::prover::eccvm_prove;
use crate::goblin::eccvm::FIXED_SIZE as ECCVM_FIXED_SIZE;
use crate::goblin::merge::merge_prove;
use crate::goblin::translator::builder::TranslatorCircuit;
use crate::goblin::translator::TranslatorPolys;
use crate::honk::decider::decider_prove;
use crate::honk::flavor::{FlavorDesc, MEGA_APP, MEGA_KERNEL, MEGA_ZK};
use crate::honk::hypernova::{FoldingProver, ProverClaim, VerifierClaim};
use crate::honk::oink_prover::prove_oink;
use crate::honk::prover_instance::ProverInstance;
use std::cell::RefCell;
use std::rc::Rc;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CircuitKind {
    App,
    Kernel,
    HidingKernel,
}

impl CircuitKind {
    pub fn flavor(self) -> &'static FlavorDesc {
        match self {
            CircuitKind::App => &MEGA_APP,
            CircuitKind::Kernel => &MEGA_KERNEL,
            CircuitKind::HidingKernel => &MEGA_ZK,
        }
    }
}

/// A folded circuit's instance proof and VK, kept for the next kernel's recursive verifier.
pub struct VerifierInputs {
    pub proof: Vec<Fr>,
    pub vk: Vk<Bn254>,
    pub kind: CircuitKind,
}

pub struct Chonk {
    kinds: Vec<CircuitKind>,
    accumulated: usize,
    pub ck: CommitmentKey,
    pub op_queue: Rc<RefCell<EccOpQueue>>,
    folding_prover: Option<FoldingProver>,
    /// The folding transcript of the current group, continued by the decider (bb `prover_accumulation_transcript`).
    accumulation_transcript: NativeTranscript,
    prover_accumulator: Option<ProverClaim>,
    /// The previous kernel's output accumulator (bb `recursive_verifier_native_accum`): what the next
    /// kernel's recursive verifier starts from.
    pub recursive_verifier_native_accum: Option<VerifierClaim<Bn254>>,
    pub verification_queue: Vec<VerifierInputs>,
    /// The current kernel's multilinear batching proof (consumed by its recursive verifier).
    pub multilinear_batch_proof: Vec<Fr>,
    /// Consumed by the hiding kernel's recursive verifiers.
    pub decider_proof: Vec<Fr>,
    pub batch_merge_proof: Vec<Fr>,
    hiding: Option<(ProverInstance, Vk<Bn254>)>,
}

impl Chonk {
    /// `ck` must cover the largest circuit and the translator (`2^17`).
    pub fn new(kinds: Vec<CircuitKind>, ck: CommitmentKey) -> Self {
        assert!(kinds.len() >= 4, "Chonk: at least 4 circuits");
        assert_eq!(kinds[0], CircuitKind::App, "Chonk: the first circuit must be an app");
        for (i, k) in kinds.iter().enumerate() {
            assert_eq!(*k == CircuitKind::HidingKernel, i + 1 == kinds.len(), "Chonk: the hiding kernel is exactly the last circuit");
        }
        Self {
            kinds,
            accumulated: 0,
            ck,
            op_queue: Rc::new(RefCell::new(EccOpQueue::new())),
            folding_prover: None,
            accumulation_transcript: NativeTranscript::new(),
            prover_accumulator: None,
            recursive_verifier_native_accum: None,
            verification_queue: Vec::new(),
            multilinear_batch_proof: Vec::new(),
            decider_proof: Vec::new(),
            batch_merge_proof: Vec::new(),
            hiding: None,
        }
    }

    pub fn current_kind(&self) -> CircuitKind {
        self.kinds[self.accumulated]
    }
    pub fn next_kind(&self) -> Option<CircuitKind> {
        self.kinds.get(self.accumulated + 1).copied()
    }
    pub fn num_circuits(&self) -> usize {
        self.kinds.len()
    }
    pub fn num_accumulated(&self) -> usize {
        self.accumulated
    }
    /// bb `set_num_circuits_accumulated_for_mocking`: position a mocked IVC at the circuit whose
    /// kernel logic is about to be built (no circuits are actually accumulated).
    pub fn set_num_circuits_accumulated_for_mocking(&mut self, n: usize) {
        assert!(n < self.kinds.len(), "Chonk: mock position past the last circuit");
        self.accumulated = n;
    }
    /// The previous kernel's output accumulator (what the next kernel verifies against).
    pub fn prover_accumulator(&self) -> Option<&ProverClaim> {
        self.prover_accumulator.as_ref()
    }
    /// The folded circuits a kernel must verify recursively (bb `instantiate_stdlib_verification_queue`);
    /// a kernel's builder takes them before the kernel is accumulated.
    pub fn take_verification_queue(&mut self) -> Vec<VerifierInputs> {
        std::mem::take(&mut self.verification_queue)
    }
    pub fn hiding_vk(&self) -> &Vk<Bn254> {
        &self.hiding.as_ref().expect("hiding kernel not accumulated").1
    }

    /// bb `Chonk::accumulate`. The circuit must have been built on `self.op_queue`; `vk` is its
    /// precomputed verification key (computed here when absent).
    pub fn accumulate(&mut self, circuit: &mut Builder, vk: Option<Vk<Bn254>>, rng: &mut dyn Rng) {
        assert!(self.accumulated < self.kinds.len(), "Chonk: every circuit has already been accumulated");
        let kind = self.current_kind();
        let next = self.next_kind();
        match kind {
            CircuitKind::HidingKernel => {
                let inst = ProverInstance::from_builder(&MEGA_ZK, circuit, rng);
                let vk = vk.unwrap_or_else(|| inst.compute_vk(&self.ck));
                self.hiding = Some((inst, vk));
                self.accumulated += 1;
            }
            CircuitKind::App | CircuitKind::Kernel => {
                self.accumulate_and_fold(circuit, vk, kind, next, rng);
                if next == Some(CircuitKind::HidingKernel) {
                    decider_prove(self.prover_accumulator.as_ref().unwrap(), &mut self.accumulation_transcript);
                    self.decider_proof = self.accumulation_transcript.export_proof();
                    timing::phase("decider");
                    let mut q = self.op_queue.borrow_mut();
                    q.construct_zk_columns(rng);
                    self.batch_merge_proof = batch_merge_prove(&q, CHONK_MAX_NUM_CIRCUITS, &self.ck);
                    timing::phase("batch merge");
                }
            }
        }
    }

    fn accumulate_and_fold(&mut self, circuit: &mut Builder, vk: Option<Vk<Bn254>>, kind: CircuitKind, next: Option<CircuitKind>, rng: &mut dyn Rng) {
        let is_init_group = self.accumulated == 0;
        assert_eq!(
            self.verification_queue.is_empty() && !is_init_group,
            kind == CircuitKind::Kernel,
            "Chonk: CircuitKind disagrees with the IVC state (kernels take the verification queue first)"
        );
        if kind == CircuitKind::Kernel || is_init_group {
            assert!(self.folding_prover.is_none());
            self.folding_prover = Some(FoldingProver::new());
        }
        let mut inst = ProverInstance::from_builder(kind.flavor(), circuit, rng);
        timing::phase("prover instance");
        let vk = vk.unwrap_or_else(|| inst.compute_vk(&self.ck));
        timing::phase("vk");
        let proof = self.folding_prover.as_mut().unwrap().accumulate_instance(&mut inst, &vk, &self.ck, rng);
        timing::phase("instance to accumulator (oink + sumcheck)");
        self.verification_queue.push(VerifierInputs { proof, vk, kind });
        if matches!(next, Some(CircuitKind::Kernel) | Some(CircuitKind::HidingKernel)) {
            self.prove_multilinear_batching();
            timing::phase("multilinear batching");
        }
        self.op_queue.borrow_mut().merge();
        self.accumulated += 1;
    }

    /// bb `Chonk::prove_multilinear_batching`: batch the group's claims (and the previous accumulator).
    fn prove_multilinear_batching(&mut self) {
        let mut prover = self.folding_prover.take().unwrap();
        let (proof, accumulator) = prover.finalize(self.prover_accumulator.take());
        self.multilinear_batch_proof = proof;
        self.prover_accumulator = Some(accumulator);
        self.accumulation_transcript = prover.transcript;
    }

    /// bb `Chonk::prove`: hiding kernel Oink, merge, ECCVM, then the joint MegaZK + Translator proof.
    pub fn prove(&mut self, rng: &mut dyn Rng) -> ChonkProof {
        let (mut inst, vk) = self.hiding.take().expect("hiding kernel not accumulated");
        let mut t = NativeTranscript::new();
        let oink = prove_oink(&mut inst, &vk, &self.ck, &mut t, rng, false);
        let hiding_oink_proof = t.export_proof();
        timing::phase("hiding oink");
        let mut q = self.op_queue.borrow_mut();
        merge_prove(&mut q, &self.ck, &mut t);
        let merge_proof = t.export_proof();
        timing::phase("merge");
        let eccvm = eccvm_prove(&q, &GrumpkinKey::new(ECCVM_FIXED_SIZE), &mut t, rng);
        let eccvm_proof = t.export_proof();
        timing::phase("eccvm");
        let (v, x) = (eccvm.batching_challenge_v, eccvm.evaluation_challenge_x);
        let circuit = TranslatorCircuit::new(v, x, &q);
        timing::phase("translator circuit");
        let mut polys = TranslatorPolys::from_circuit(&circuit, &TranslatorPolys::random_masking(rng));
        timing::phase("translator polys");
        joint_prove(&inst, &oink.params, &mut polys, &v, &x, &self.ck, &mut t, rng);
        let joint_proof = t.export_proof();
        timing::phase("joint proof");
        self.hiding = Some((inst, vk));
        ChonkProof {
            hiding_oink_proof,
            merge_proof,
            eccvm_proof,
            ipa_proof: eccvm.ipa_proof,
            joint_proof,
        }
    }
}
