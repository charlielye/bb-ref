//! ACIR → builder (bb `acir_to_constraint_buf` + `acir_format::build_constraints`). Opcodes are first
//! classified into constraint lists, then lowered in bb's fixed order: quads, big quads, ranges,
//! Poseidon2, Grumpkin MSM and addition, memory and databus blocks, HyperNova recursion (the kernel
//! logic), and finally the default (infinity) pairing points as public inputs for circuits that
//! verify nothing.

use super::format::{
    BlackBoxFuncCall, BlockType, Circuit, EmbeddedCurveAdd, FunctionInput, Logic, MultiScalarMul, Opcode,
    Witness,
};
use super::mock::mock_chonk_from_constraints;
use crate::base::field::FieldLike;
use crate::base::rng::Rng;
use crate::base::vk::Vk;
use crate::base::{Fr, GrumpkinAffine};
use crate::chonk::ivc::{Chonk, CircuitKind};
use crate::chonk::kernel::{complete_kernel_circuit_logic, VkWitnesses};
use crate::circuit::builder::MulQuad;
use crate::circuit::mega::BilinearBatchedEqGate;
use crate::circuit::{Builder, EccOpQueue, IS_CONSTANT};
use crate::stdlib::biggroup::Element;
use crate::stdlib::byte_array::ByteArray;
use crate::stdlib::cycle_group::{CycleGroup, CycleScalar};
use crate::stdlib::ecdsa::ecdsa_verify_signature;
use crate::stdlib::io::{AppIo, KernelIo, MAX_APPS_PER_KERNEL};
use crate::stdlib::keccak;
use crate::stdlib::logic::create_logic_constraint;
use crate::stdlib::memory::{RamTable, RomTable};
use crate::stdlib::{poseidon2, sha256, BoolT, Ctx, FieldT, StdBn254};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, PrimeField};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

const NUM_WIRES: usize = 4;
/// Pairing points occupy this many trailing public inputs (two bn254 points as four 136-bit limbs).
pub const PAIRING_POINTS_SIZE: usize = 8;

/// bb `PROOF_TYPE`: the HyperNova variants a kernel verifies.
pub const OINK: u32 = 1;
pub const HN: u32 = 2;
pub const HN_FINAL: u32 = 7;

/// bb `RecursionConstraint` (HyperNova subset): the witnesses holding the verification key of a
/// queued proof and its hash; the proof itself comes from the IVC state.
pub struct RecursionConstraint {
    pub key: Vec<u32>,
    pub key_hash: u32,
    pub proof_type: u32,
}

struct MemOp {
    write: bool,
    index: u32,
    value: u32,
}
enum BlockKind {
    Rom,
    Ram,
    CallData(usize),
    ReturnData,
}
struct BlockConstraint {
    init: Vec<u32>,
    trace: Vec<MemOp>,
    kind: BlockKind,
}
struct Poseidon2Constraint {
    state: Vec<u32>,
    result: Vec<u32>,
}
struct Sha256Constraint {
    inputs: Vec<FunctionInput>,
    hash_values: Vec<FunctionInput>,
    outputs: Vec<u32>,
}
/// bb `LogicConstraint`.
struct LogicConstraint {
    logic: Logic,
    is_xor_gate: bool,
}
/// bb `Keccakf1600` constraint: 25 input lanes and their output witnesses.
struct KeccakConstraint {
    state: Vec<FunctionInput>,
    result: Vec<u32>,
}
/// bb `EcdsaConstraint`: witness indices of the byte-wise inputs.
struct Aes128Constraint {
    inputs: Vec<FunctionInput>,
    iv: Vec<FunctionInput>,
    key: Vec<FunctionInput>,
    outputs: Vec<u32>,
}

struct BlakeConstraint {
    inputs: Vec<FunctionInput>,
    outputs: Vec<u32>,
}

struct EcdsaConstraint {
    hashed_message: Vec<u32>,
    signature: Vec<u32>,
    pub_x: Vec<u32>,
    pub_y: Vec<u32>,
    predicate: FunctionInput,
    result: u32,
}

/// One linear AssertZero with at most two witnesses (half of a batched-eq row).
struct BatchedEqEntry {
    w1: u32,
    w2: u32,
    c1: Fr,
    c2: Fr,
    q_c: Fr,
}

#[derive(Default)]
struct Constraints {
    max_witness_index: u32,
    quad: Vec<MulQuad>,
    big_quad: Vec<Vec<MulQuad>>,
    bilinear: Vec<BilinearBatchedEqGate>,
    batched_eq: Vec<BilinearBatchedEqGate>,
    range: Vec<(u32, u32)>,
    poseidon2: Vec<Poseidon2Constraint>,
    sha256: Vec<Sha256Constraint>,
    aes128: Vec<Aes128Constraint>,
    ecdsa_k1: Vec<EcdsaConstraint>,
    ecdsa_r1: Vec<EcdsaConstraint>,
    blake2s: Vec<BlakeConstraint>,
    blake3: Vec<BlakeConstraint>,
    logic: Vec<LogicConstraint>,
    keccak: Vec<KeccakConstraint>,
    msm: Vec<MultiScalarMul>,
    ec_add: Vec<EmbeddedCurveAdd>,
    blocks: BTreeMap<u32, BlockConstraint>,
    hn_recursion: Vec<RecursionConstraint>,
    honk_recursion: Vec<crate::acir::honk_recursion::HonkRecursionConstraint>,
    chonk_recursion: Vec<crate::acir::honk_recursion::HonkRecursionConstraint>,
    avm_recursion: Vec<crate::acir::honk_recursion::HonkRecursionConstraint>,
}

impl Constraints {
    fn note(&mut self, w: Witness) -> u32 {
        self.max_witness_index = self.max_witness_index.max(w.0);
        w.0
    }
    fn input(&mut self, i: &FunctionInput) -> u32 {
        match i {
            FunctionInput::Witness(w) => self.note(*w),
            FunctionInput::Constant(_) => panic!("constant inputs are not supported here"),
        }
    }
    fn note_input(&mut self, i: &FunctionInput) {
        if let FunctionInput::Witness(w) = i {
            self.note(*w);
        }
    }
}

/// bb `process_linear_terms`: coefficients keyed (and hence ordered) by witness index.
fn linear_terms(e: &super::format::Expression) -> BTreeMap<u32, Fr> {
    let mut m = BTreeMap::new();
    for (c, w) in &e.linear_combinations {
        *m.entry(w.0).or_insert(Fr::zero()) += c.0;
    }
    m
}

fn is_single_arithmetic_gate(e: &super::format::Expression, lin: &BTreeMap<u32, Fr>) -> bool {
    if lin.len() > NUM_WIRES || e.mul_terms.len() > 1 {
        return false;
    }
    if e.mul_terms.len() == 1 {
        let (lhs, rhs) = (e.mul_terms[0].1 .0, e.mul_terms[0].2 .0);
        let mut n = 2 + lin.len();
        if lhs != rhs {
            n -= lin.contains_key(&lhs) as usize + lin.contains_key(&rhs) as usize;
        } else {
            n -= lin.contains_key(&lhs) as usize;
        }
        return n <= NUM_WIRES;
    }
    lin.len() <= NUM_WIRES
}

fn empty_quad() -> MulQuad {
    let z = Fr::zero();
    MulQuad {
        a: IS_CONSTANT,
        b: IS_CONSTANT,
        c: IS_CONSTANT,
        d: IS_CONSTANT,
        mul_scaling: z,
        a_scaling: z,
        b_scaling: z,
        c_scaling: z,
        d_scaling: z,
        const_scaling: z,
    }
}

/// bb `split_into_mul_quad_gates`: one gate per product, linear terms filled into free wires in
/// witness-index order, the constant on the first gate, remaining linear terms on extra gates.
fn split_into_mul_quad_gates(e: &super::format::Expression, lin: &mut BTreeMap<u32, Fr>) -> Vec<MulQuad> {
    let take = |idx: &mut u32, scaling: &mut Fr, lin: &mut BTreeMap<u32, Fr>| {
        assert_eq!(*idx, IS_CONSTANT);
        let (w, c) = lin.pop_first().unwrap();
        *idx = w;
        *scaling += c;
    };
    let mut result = vec![];
    for (c, a, b) in &e.mul_terms {
        let mut q = MulQuad {
            a: a.0,
            b: b.0,
            mul_scaling: c.0,
            ..empty_quad()
        };
        if let Some(c) = lin.remove(&q.a) {
            q.a_scaling += c;
        }
        if let Some(c) = lin.remove(&q.b) {
            q.b_scaling += c;
        }
        result.push(q);
    }
    let mut first = true;
    for q in &mut result {
        if !lin.is_empty() {
            take(&mut q.c, &mut q.c_scaling, lin);
        }
        if first {
            q.const_scaling = e.q_c.0;
            if !lin.is_empty() {
                take(&mut q.d, &mut q.d_scaling, lin);
            }
            first = false;
        }
    }
    while !lin.is_empty() {
        let mut q = empty_quad();
        for (idx, s) in [
            (&mut q.a, &mut q.a_scaling),
            (&mut q.b, &mut q.b_scaling),
            (&mut q.c, &mut q.c_scaling),
        ] {
            if !lin.is_empty() {
                take(idx, s, lin);
            }
        }
        if first {
            q.const_scaling = e.q_c.0;
            if !lin.is_empty() {
                take(&mut q.d, &mut q.d_scaling, lin);
            }
            first = false;
        }
        result.push(q);
    }
    assert!(!result.is_empty(), "expression with no terms");
    result
}

/// Two products sharing exactly one wire: `(shared, other of the first, other of the second)`.
fn resolve_shared_wire_products(e: &super::format::Expression) -> Option<(u32, u32, u32)> {
    let (a, b) = (e.mul_terms[0].1 .0, e.mul_terms[0].2 .0);
    let (c, d) = (e.mul_terms[1].1 .0, e.mul_terms[1].2 .0);
    let mut shared = vec![];
    for w in if a != b { vec![a, b] } else { vec![a] } {
        if w == c || w == d {
            shared.push(w);
        }
    }
    if shared.len() != 1 {
        return None;
    }
    let s = shared[0];
    Some((s, if a == s { b } else { a }, if c == s { d } else { c }))
}

fn is_bilinear(e: &super::format::Expression, lin: &BTreeMap<u32, Fr>) -> bool {
    if e.mul_terms.len() != 2 {
        return false;
    }
    let Some((w_l, w_r, w_o)) = resolve_shared_wire_products(e) else {
        return false;
    };
    lin.keys().filter(|w| **w != w_l && **w != w_r && **w != w_o).count() <= 1
}

fn build_bilinear(e: &super::format::Expression, lin: &BTreeMap<u32, Fr>) -> BilinearBatchedEqGate {
    let (w_l, w_r, w_o) = resolve_shared_wire_products(e).unwrap();
    let mut g = BilinearBatchedEqGate {
        bilinear: true,
        a: w_l,
        b: w_r,
        c: w_o,
        d: IS_CONSTANT,
        q_l: Fr::zero(),
        q_r: Fr::zero(),
        q_o: Fr::zero(),
        q_4: Fr::zero(),
        q_c: e.q_c.0,
        q_m: e.mul_terms[0].0 .0,
        q_5: e.mul_terms[1].0 .0,
    };
    for (w, c) in lin {
        if *w == w_l {
            g.q_l = *c;
        } else if *w == w_r {
            g.q_r = *c;
        } else if *w == w_o {
            g.q_o = *c;
        } else {
            assert_eq!(g.d, IS_CONSTANT);
            g.d = *w;
            g.q_4 = *c;
        }
    }
    g
}

fn batched_eq_entry(e: &super::format::Expression, lin: &BTreeMap<u32, Fr>) -> BatchedEqEntry {
    let mut it = lin.iter();
    let (w1, c1) = it.next().unwrap();
    let (w2, c2) = it.next().map(|(w, c)| (*w, *c)).unwrap_or((IS_CONSTANT, Fr::zero()));
    BatchedEqEntry {
        w1: *w1,
        w2,
        c1: *c1,
        c2,
        q_c: e.q_c.0,
    }
}

/// Pair consecutive batched-eq entries into rows; an odd last entry gets an empty second half.
fn pair_batched_eq(entries: &[BatchedEqEntry]) -> Vec<BilinearBatchedEqGate> {
    entries
        .chunks(2)
        .map(|pair| {
            let e1 = &pair[0];
            let e2 = pair.get(1);
            BilinearBatchedEqGate {
                bilinear: false,
                a: e1.w1,
                b: e1.w2,
                c: e2.map_or(IS_CONSTANT, |e| e.w1),
                d: e2.map_or(IS_CONSTANT, |e| e.w2),
                q_l: e1.c1,
                q_r: e1.c2,
                q_o: e2.map_or(Fr::zero(), |e| e.c1),
                q_4: e2.map_or(Fr::zero(), |e| e.c2),
                q_c: e1.q_c,
                q_m: e2.map_or(Fr::zero(), |e| e.q_c),
                q_5: Fr::zero(),
            }
        })
        .collect()
}

fn classify(circuit: &Circuit, is_mega: bool) -> (Constraints, Vec<u32>) {
    let mut c = Constraints::default();
    let mut batched_eq_entries = vec![];
    let public_inputs: Vec<u32> = circuit
        .public_parameters
        .iter()
        .chain(&circuit.return_values)
        .map(|w| c.note(*w))
        .collect();
    for op in &circuit.opcodes {
        match op {
            Opcode::AssertZero(e) => {
                for (_, a, b) in &e.mul_terms {
                    c.note(*a);
                    c.note(*b);
                }
                for (_, w) in &e.linear_combinations {
                    c.note(*w);
                }
                let mut lin = linear_terms(e);
                if e.mul_terms.is_empty() && lin.is_empty() {
                    assert!(e.q_c.0.is_zero(), "unsatisfiable constant AssertZero");
                }
                if is_mega && is_bilinear(e, &lin) {
                    c.bilinear.push(build_bilinear(e, &lin));
                    continue;
                }
                if is_mega && e.mul_terms.is_empty() && !lin.is_empty() && lin.len() <= 2 {
                    batched_eq_entries.push(batched_eq_entry(e, &lin));
                    continue;
                }
                let single = is_single_arithmetic_gate(e, &lin);
                let quads = split_into_mul_quad_gates(e, &mut lin);
                if single {
                    assert_eq!(quads.len(), 1);
                    c.quad.push(quads.into_iter().next().unwrap());
                } else {
                    assert!(quads.len() > 1);
                    c.big_quad.push(quads);
                }
            }
            Opcode::BlackBoxFuncCall(bb) => match bb {
                BlackBoxFuncCall::RANGE { input, num_bits } => {
                    let w = c.input(input);
                    c.range.push((w, *num_bits));
                }
                BlackBoxFuncCall::Sha256Compression(s) => {
                    assert!(s.inputs.len() == 16 && s.hash_values.len() == 8 && s.outputs.len() == 8);
                    s.inputs.iter().chain(&s.hash_values).for_each(|i| c.note_input(i));
                    let outputs = s.outputs.iter().map(|w| c.note(*w)).collect();
                    c.sha256.push(Sha256Constraint {
                        inputs: s.inputs.clone(),
                        hash_values: s.hash_values.clone(),
                        outputs,
                    });
                }
                BlackBoxFuncCall::AND(l) | BlackBoxFuncCall::XOR(l) => {
                    c.note_input(&l.lhs);
                    c.note_input(&l.rhs);
                    c.note(l.output);
                    let is_xor_gate = matches!(bb, BlackBoxFuncCall::XOR(_));
                    c.logic.push(LogicConstraint {
                        logic: l.clone(),
                        is_xor_gate,
                    });
                }
                BlackBoxFuncCall::Keccakf1600(k) => {
                    assert!(k.inputs.len() == 25 && k.outputs.len() == 25);
                    k.inputs.iter().for_each(|i| c.note_input(i));
                    let result = k.outputs.iter().map(|w| c.note(*w)).collect();
                    c.keccak.push(KeccakConstraint {
                        state: k.inputs.clone(),
                        result,
                    });
                }
                BlackBoxFuncCall::AES128Encrypt(a) => {
                    assert!(a.inputs.len() % 16 == 0, "AES inputs must be a multiple of 16");
                    assert!(a.iv.len() == 16 && a.key.len() == 16 && a.outputs.len() == a.inputs.len());
                    a.inputs.iter().chain(&a.iv).chain(&a.key).for_each(|i| c.note_input(i));
                    let outputs = a.outputs.iter().map(|w| c.note(*w)).collect();
                    c.aes128.push(Aes128Constraint {
                        inputs: a.inputs.clone(),
                        iv: a.iv.clone(),
                        key: a.key.clone(),
                        outputs,
                    });
                }
                BlackBoxFuncCall::Blake2s(b) | BlackBoxFuncCall::Blake3(b) => {
                    assert_eq!(b.outputs.len(), 32);
                    b.inputs.iter().for_each(|i| c.note_input(i));
                    let outputs = b.outputs.iter().map(|w| c.note(*w)).collect();
                    let constraint = BlakeConstraint {
                        inputs: b.inputs.clone(),
                        outputs,
                    };
                    if matches!(bb, BlackBoxFuncCall::Blake2s(_)) {
                        c.blake2s.push(constraint);
                    } else {
                        c.blake3.push(constraint);
                    }
                }
                BlackBoxFuncCall::EcdsaSecp256k1(e) | BlackBoxFuncCall::EcdsaSecp256r1(e) => {
                    assert!(
                        e.public_key_x.len() == 32
                            && e.public_key_y.len() == 32
                            && e.signature.len() == 64
                            && e.hashed_message.len() == 32
                    );
                    c.note_input(&e.predicate);
                    let witnesses =
                        |c: &mut Constraints, inputs: &[FunctionInput]| inputs.iter().map(|i| c.input(i)).collect();
                    let hashed_message = witnesses(&mut c, &e.hashed_message);
                    let signature = witnesses(&mut c, &e.signature);
                    let pub_x = witnesses(&mut c, &e.public_key_x);
                    let pub_y = witnesses(&mut c, &e.public_key_y);
                    let result = c.note(e.output);
                    let constraint = EcdsaConstraint {
                        hashed_message,
                        signature,
                        pub_x,
                        pub_y,
                        predicate: e.predicate.clone(),
                        result,
                    };
                    if matches!(bb, BlackBoxFuncCall::EcdsaSecp256k1(_)) {
                        c.ecdsa_k1.push(constraint);
                    } else {
                        c.ecdsa_r1.push(constraint);
                    }
                }
                BlackBoxFuncCall::Poseidon2Permutation { inputs, outputs } => {
                    let state = inputs.iter().map(|i| c.input(i)).collect();
                    let result = outputs.iter().map(|w| c.note(*w)).collect();
                    c.poseidon2.push(Poseidon2Constraint { state, result });
                }
                BlackBoxFuncCall::MultiScalarMul(m) => {
                    assert_eq!(m.points.len(), m.scalars.len(), "MultiScalarMul input size mismatch");
                    m.points
                        .iter()
                        .chain(&m.scalars)
                        .chain([&m.predicate])
                        .for_each(|i| c.note_input(i));
                    m.outputs.iter().for_each(|w| {
                        c.note(*w);
                    });
                    c.msm.push(m.clone());
                }
                BlackBoxFuncCall::EmbeddedCurveAdd(e) => {
                    e.input1
                        .iter()
                        .chain(&e.input2)
                        .chain([&e.predicate])
                        .for_each(|i| c.note_input(i));
                    e.outputs.iter().for_each(|w| {
                        c.note(*w);
                    });
                    c.ec_add.push(e.clone());
                }
                BlackBoxFuncCall::RecursiveAggregation(r) => {
                    use crate::acir::honk_recursion as hr;
                    if matches!(
                        r.proof_type,
                        hr::HONK | hr::ROLLUP_HONK | hr::ROOT_ROLLUP_HONK | hr::CHONK | hr::AVM
                    ) {
                        assert!(
                            matches!(r.predicate, FunctionInput::Constant(_)),
                            "witness predicates on Honk recursion constraints are not supported"
                        );
                        let key = r.verification_key.iter().map(|i| c.input(i)).collect();
                        let proof = r.proof.iter().map(|i| c.input(i)).collect();
                        let public_inputs = r.public_inputs.iter().map(|i| c.input(i)).collect();
                        let key_hash = c.input(&r.key_hash);
                        let constraint = hr::HonkRecursionConstraint {
                            key,
                            key_hash,
                            proof,
                            public_inputs,
                            proof_type: r.proof_type,
                        };
                        if r.proof_type == hr::CHONK {
                            c.chonk_recursion.push(constraint);
                        } else if r.proof_type == hr::AVM {
                            c.avm_recursion.push(constraint);
                        } else {
                            c.honk_recursion.push(constraint);
                        }
                        continue;
                    }
                    match &r.predicate {
                        FunctionInput::Constant(p) if p.0.is_zero() => continue,
                        FunctionInput::Constant(_) => {}
                        FunctionInput::Witness(w) => {
                            c.note(*w);
                        }
                    }
                    assert!(
                        r.proof.is_empty() && r.public_inputs.is_empty(),
                        "HyperNova recursion constraints carry no proof or public inputs"
                    );
                    assert!(
                        matches!(r.proof_type, OINK | HN | HN_FINAL),
                        "unsupported proof type {}",
                        r.proof_type
                    );
                    let key = r.verification_key.iter().map(|i| c.input(i)).collect();
                    let key_hash = c.input(&r.key_hash);
                    c.hn_recursion.push(RecursionConstraint {
                        key,
                        key_hash,
                        proof_type: r.proof_type,
                    });
                }
            },
            Opcode::MemoryInit {
                block_id,
                init,
                block_type,
            } => {
                let kind = match block_type {
                    BlockType::Memory => BlockKind::Rom,
                    BlockType::CallData(id) => BlockKind::CallData(*id as usize),
                    BlockType::ReturnData => BlockKind::ReturnData,
                };
                assert!(
                    is_mega || matches!(kind, BlockKind::Rom),
                    "databus blocks need a Mega circuit"
                );
                let init = init.iter().map(|w| c.note(*w)).collect();
                c.blocks.insert(
                    *block_id,
                    BlockConstraint {
                        init,
                        trace: vec![],
                        kind,
                    },
                );
            }
            Opcode::MemoryOp { block_id, op } => {
                let (index, value) = (c.note(op.index), c.note(op.value));
                let block = c.blocks.get_mut(block_id).expect("MemoryOp on uninitialized block");
                match block.kind {
                    BlockKind::Rom if op.read => block.kind = BlockKind::Ram,
                    BlockKind::CallData(_) => assert!(!op.read, "calldata is read-only"),
                    BlockKind::ReturnData => panic!("return data has no operations"),
                    _ => {}
                }
                block.trace.push(MemOp {
                    write: op.read,
                    index,
                    value,
                });
            }
            Opcode::BrilligCall(_) => {}
            Opcode::Call(_) => panic!("Call opcode is not supported"),
        }
    }
    c.batched_eq = pair_batched_eq(&batched_eq_entries);
    (c, public_inputs)
}

/// Unused wires hold the constant zero (bb `set_zero_idx`).
fn resolve_zero(b: &Builder, q: &mut MulQuad) {
    assert_ne!(q.a, IS_CONSTANT, "wire a of a mul_quad must be a witness");
    for (idx, s) in [
        (&mut q.b, q.b_scaling),
        (&mut q.c, q.c_scaling),
        (&mut q.d, q.d_scaling),
    ] {
        if *idx == IS_CONSTANT {
            assert!(s.is_zero());
            *idx = b.zero_idx();
        }
    }
}

fn quad_value(b: &Builder, q: &MulQuad) -> Fr {
    let v = |i: u32| b.get_variable(i);
    v(q.a) * v(q.b) * q.mul_scaling
        + v(q.a) * q.a_scaling
        + v(q.b) * q.b_scaling
        + v(q.c) * q.c_scaling
        + v(q.d) * q.d_scaling
        + q.const_scaling
}

/// bb `create_big_quad_constraint`: chain gates through `w_4_shift`, each carrying the negated
/// partial sum in a fresh witness.
fn create_big_quad_constraint(b: &mut Builder, mut gates: Vec<MulQuad>) {
    let last = gates.len() - 1;
    for j in 0..last {
        resolve_zero(b, &mut gates[j]);
        b.create_big_mul_add_gate(&gates[j], true);
        let next_w4 = -quad_value(b, &gates[j]);
        let idx = b.add_variable(next_w4);
        gates[j + 1].d = idx;
        gates[j + 1].d_scaling = -Fr::one();
    }
    resolve_zero(b, &mut gates[last]);
    b.create_big_mul_add_gate(&gates[last], false);
}

/// bb `create_block_constraints`: ROM/RAM tables, or (Mega only) a databus column initialized
/// with the block's entries and read through databus read gates.

/// bb `bus_vector::set_values`: one writer per bus column, since reads index the column from row 0.
fn assert_bus_unwritten(ctx: &Ctx, bus: usize) {
    assert!(
        ctx.borrow().bus(bus).data.is_empty(),
        "bus_vector::set_values: bus_idx already written."
    );
}

fn create_block_constraints(ctx: &Ctx, block: &BlockConstraint) {
    let init: Vec<FieldT> = block.init.iter().map(|w| FieldT::from_witness_index(ctx, *w)).collect();
    match block.kind {
        BlockKind::Ram => {
            let mut table = RamTable::new(ctx, init);
            for op in &block.trace {
                let value = FieldT::from_witness_index(ctx, op.value);
                let index = FieldT::from_witness_index(ctx, op.index);
                if op.write {
                    table.write(&index, &value);
                } else {
                    value.assert_equal(&table.read(&index));
                }
            }
        }
        BlockKind::Rom => {
            let mut table = RomTable::new(ctx, init);
            for op in &block.trace {
                let value = FieldT::from_witness_index(ctx, op.value);
                let index = FieldT::from_witness_index(ctx, op.index);
                value.assert_equal(&table.read(&index));
            }
        }
        BlockKind::CallData(bus) => {
            assert!(bus <= MAX_APPS_PER_KERNEL, "databus app calldata index out of bounds");
            assert_bus_unwritten(ctx, bus);
            for w in &block.init {
                ctx.borrow_mut().add_public_calldata(bus, *w);
            }
            for op in &block.trace {
                let value = FieldT::from_witness_index(ctx, op.value);
                let read = ctx.borrow_mut().read_calldata(bus, op.index);
                value.assert_equal(&FieldT::from_witness_index(ctx, read));
            }
        }
        BlockKind::ReturnData => {
            assert_bus_unwritten(ctx, crate::circuit::mega::RETURNDATA);
            for w in &block.init {
                ctx.borrow_mut().add_public_return_data(*w);
            }
        }
    }
}

/// bb `to_field_ct`.
fn to_field_ct(ctx: &Ctx, input: &FunctionInput) -> FieldT {
    match input {
        FunctionInput::Constant(v) => FieldT::constant(v.0),
        FunctionInput::Witness(w) => FieldT::from_witness_index(ctx, w.0),
    }
}

fn set_witness(ctx: &Ctx, input: &FunctionInput, value: Fr) {
    if let FunctionInput::Witness(w) = input {
        ctx.borrow_mut().set_variable(w.0, value);
    }
}

/// bb `to_grumpkin_point`: a disabled constraint (predicate false) substitutes the generator so
/// the point is always valid; in write-VK mode witness coordinates are set to it too.
fn to_grumpkin_point(ctx: &Ctx, x: &FunctionInput, y: &FunctionInput, predicate: &BoolT) -> CycleGroup {
    let one = GrumpkinAffine::generator();
    let mut point_x = to_field_ct(ctx, x);
    let mut point_y = to_field_ct(ctx, y);
    let constant_coordinates = matches!(x, FunctionInput::Constant(_)) && matches!(y, FunctionInput::Constant(_));
    if ctx.borrow().is_write_vk_mode && !constant_coordinates {
        set_witness(ctx, x, one.x);
        set_witness(ctx, y, one.y);
    }
    if !predicate.is_constant() {
        point_x = FieldT::conditional_assign(predicate, &point_x, &FieldT::constant(one.x));
        point_y = FieldT::conditional_assign(predicate, &point_y, &FieldT::constant(one.y));
    } else {
        assert!(predicate.get_value(), "Grumpkin point with a constant false predicate");
    }
    CycleGroup::from_xy(point_x, point_y, true)
}

/// bb `to_grumpkin_scalar`: a disabled constraint uses the scalar 1.
fn to_grumpkin_scalar(ctx: &Ctx, lo: &FunctionInput, hi: &FunctionInput, predicate: &BoolT) -> CycleScalar {
    let mut lo_field = to_field_ct(ctx, lo);
    let mut hi_field = to_field_ct(ctx, hi);
    assert!(
        !(matches!(lo, FunctionInput::Constant(_)) && matches!(hi, FunctionInput::Witness(_))),
        "scalar lo is constant while hi is not"
    );
    if ctx.borrow().is_write_vk_mode {
        set_witness(ctx, lo, Fr::one());
        set_witness(ctx, hi, Fr::zero());
    }
    if !predicate.is_constant() {
        lo_field = FieldT::conditional_assign(predicate, &lo_field, &FieldT::constant(Fr::one()));
        hi_field = FieldT::conditional_assign(predicate, &hi_field, &FieldT::constant(Fr::zero()));
    } else {
        assert!(predicate.get_value(), "Grumpkin scalar with a constant false predicate");
    }
    CycleScalar::new(lo_field, hi_field)
}

/// The claimed result of an EC operation as circuit coordinates; in write-VK mode the witnesses
/// are set to the generator first.
fn claimed_result_fields(ctx: &Ctx, outputs: &[Witness; 2]) -> (FieldT, FieldT) {
    let x = FieldT::from_witness_index(ctx, outputs[0].0);
    let y = FieldT::from_witness_index(ctx, outputs[1].0);
    if ctx.borrow().is_write_vk_mode {
        let one = GrumpkinAffine::generator();
        let mut b = ctx.borrow_mut();
        b.set_variable(outputs[0].0, one.x);
        b.set_variable(outputs[1].0, one.y);
    }
    (x, y)
}

/// bb `create_logic_gate`: the computed result is copied into the ACIR result witness (set first
/// in write-VK mode).
fn create_logic_gate(ctx: &Ctx, l: &LogicConstraint) {
    let left = to_field_ct(ctx, &l.logic.lhs);
    let right = to_field_ct(ctx, &l.logic.rhs);
    let computed = create_logic_constraint(&left, &right, l.logic.num_bits as usize, l.is_xor_gate);
    if ctx.borrow().is_write_vk_mode {
        let value = computed.get_value();
        ctx.borrow_mut().set_variable(l.logic.output.0, value);
    }
    computed.assert_equal(&FieldT::from_witness_index(ctx, l.logic.output.0));
}

/// bb `fields_to_bytes`: one range-constrained byte per field.
fn fields_to_bytes(ctx: &Ctx, fields: &[FieldT]) -> ByteArray {
    let mut result = ByteArray::empty(ctx);
    for field in fields {
        result.write(&ByteArray::from_field(field, 1));
    }
    result
}

/// bb `create_ecdsa_verify_constraints<secp256r1>`: a disabled constraint (predicate false) verifies
/// a fixed valid-shaped input instead; write-VK mode fills the witnesses with the generator.
fn create_ecdsa_verify_constraints(ctx: &Ctx, input: &EcdsaConstraint) {
    let fields =
        |indices: &[u32]| -> Vec<FieldT> { indices.iter().map(|i| FieldT::from_witness_index(ctx, *i)).collect() };
    let mut hashed_message_fields = fields(&input.hashed_message);
    let mut r_fields = fields(&input.signature[..32]);
    let mut s_fields = fields(&input.signature[32..]);
    let mut pub_x_fields = fields(&input.pub_x);
    let mut pub_y_fields = fields(&input.pub_y);
    let result_field = FieldT::from_witness_index(ctx, input.result);
    let predicate = BoolT::from_field(&to_field_ct(ctx, &input.predicate));
    let coordinate_bytes =
        |p: &ark_secp256r1::Affine| (p.x.into_bigint().to_bytes_be(), p.y.into_bigint().to_bytes_be());
    if ctx.borrow().is_write_vk_mode {
        let (gx, gy) = coordinate_bytes(&ark_secp256r1::Affine::generator());
        let mut b = ctx.borrow_mut();
        for w in input.hashed_message.iter().chain(&input.signature) {
            b.set_variable(*w, Fr::zero());
        }
        for (w, byte) in input.pub_x.iter().zip(&gx).chain(input.pub_y.iter().zip(&gy)) {
            b.set_variable(*w, Fr::from(*byte as u64));
        }
        b.set_variable(input.result, Fr::one());
    }
    if !predicate.is_constant() {
        for idx in 0..32 {
            let unit = FieldT::constant(Fr::from(u64::from(idx == 0)));
            r_fields[idx] = FieldT::conditional_assign(&predicate, &r_fields[idx], &unit);
            s_fields[idx] = FieldT::conditional_assign(&predicate, &s_fields[idx], &unit);
            hashed_message_fields[idx] = FieldT::conditional_assign(&predicate, &hashed_message_fields[idx], &unit);
        }
        let two_g = (ark_secp256r1::Affine::generator() + ark_secp256r1::Affine::generator()).into_affine();
        let (default_x, default_y) = coordinate_bytes(&two_g);
        for i in 0..32 {
            pub_x_fields[i] = FieldT::conditional_assign(
                &predicate,
                &pub_x_fields[i],
                &FieldT::constant(Fr::from(default_x[i] as u64)),
            );
            pub_y_fields[i] = FieldT::conditional_assign(
                &predicate,
                &pub_y_fields[i],
                &FieldT::constant(Fr::from(default_y[i] as u64)),
            );
        }
    } else {
        assert!(
            predicate.get_value(),
            "ECDSA constraint with a constant false predicate"
        );
    }
    let hashed_message = fields_to_bytes(ctx, &hashed_message_fields);
    let pub_x_bytes = fields_to_bytes(ctx, &pub_x_fields);
    let pub_y_bytes = fields_to_bytes(ctx, &pub_y_fields);
    let r = fields_to_bytes(ctx, &r_fields);
    let s = fields_to_bytes(ctx, &s_fields);
    let result = BoolT::from_field(&result_field);
    let pub_x = crate::stdlib::biggroup::Fq::<ark_secp256r1::Config>::from_bytes(&pub_x_bytes);
    let pub_y = crate::stdlib::biggroup::Fq::<ark_secp256r1::Config>::from_bytes(&pub_y_bytes);
    let public_key = Element::<ark_secp256r1::Config>::new(pub_x, pub_y, false);
    let signature_result = ecdsa_verify_signature(&hashed_message, &public_key, &r, &s);
    signature_result.assert_equal(&BoolT::conditional_assign(&predicate, &result, &signature_result));
}

/// bb `create_aes128_constraints`: 16-byte blocks packed big-endian into fields (each byte
/// range-constrained), encrypted CBC, outputs asserted against the packed result witnesses.
fn create_aes128_constraints(ctx: &Ctx, a: &Aes128Constraint) {
    let convert_input = |inputs: &[FunctionInput]| {
        let mut converted = FieldT::constant(Fr::from(0u64));
        for input in inputs {
            converted = converted.mul(&FieldT::constant(Fr::from(256u64)));
            let byte = to_field_ct(ctx, input);
            byte.create_range_constraint(8);
            converted = converted.add(&byte);
        }
        converted
    };
    let convert_output = |outputs: &[u32]| {
        let mut converted = FieldT::constant(Fr::from(0u64));
        for output in outputs {
            converted = converted.mul(&FieldT::constant(Fr::from(256u64)));
            let byte = FieldT::from_witness_index(ctx, *output);
            byte.create_range_constraint(8);
            converted = converted.add(&byte);
        }
        converted
    };
    let converted_inputs: Vec<FieldT> = a.inputs.chunks(16).map(convert_input).collect();
    let converted_outputs: Vec<FieldT> = a.outputs.chunks(16).map(convert_output).collect();
    let output_bytes =
        crate::stdlib::aes128::encrypt_buffer_cbc(&converted_inputs, &convert_input(&a.iv), &convert_input(&a.key));
    for (out, expected) in output_bytes.iter().zip(&converted_outputs) {
        out.assert_equal(expected);
    }
}

/// bb `create_blake2s_constraints` / `create_blake3_constraints`: single-byte inputs written into
/// one byte array, hashed, output bytes bound to the result witnesses.
fn create_blake_constraints(ctx: &Ctx, b: &BlakeConstraint, is_blake3: bool) {
    let mut arr = ByteArray::constant_padding(0, 0);
    for input in &b.inputs {
        let element = to_field_ct(ctx, input);
        arr.write(&ByteArray::from_field(&element, 1));
    }
    let output_bytes = if is_blake3 {
        crate::stdlib::blake3s::hash(&arr)
    } else {
        crate::stdlib::blake2s::hash(&arr)
    };
    for (out, result) in output_bytes.bytes().iter().zip(&b.outputs) {
        out.assert_equal(&FieldT::from_witness_index(ctx, *result));
    }
}

/// bb `create_ecdsa_verify_constraints<secp256k1>` — the r1 arm with the k1 curve.
fn create_ecdsa_verify_constraints_k1(ctx: &Ctx, input: &EcdsaConstraint) {
    let fields =
        |indices: &[u32]| -> Vec<FieldT> { indices.iter().map(|i| FieldT::from_witness_index(ctx, *i)).collect() };
    let mut hashed_message_fields = fields(&input.hashed_message);
    let mut r_fields = fields(&input.signature[..32]);
    let mut s_fields = fields(&input.signature[32..]);
    let mut pub_x_fields = fields(&input.pub_x);
    let mut pub_y_fields = fields(&input.pub_y);
    let result_field = FieldT::from_witness_index(ctx, input.result);
    let predicate = BoolT::from_field(&to_field_ct(ctx, &input.predicate));
    let coordinate_bytes =
        |p: &ark_secp256k1::Affine| (p.x.into_bigint().to_bytes_be(), p.y.into_bigint().to_bytes_be());
    if ctx.borrow().is_write_vk_mode {
        let (gx, gy) = coordinate_bytes(&ark_secp256k1::Affine::generator());
        let mut b = ctx.borrow_mut();
        for w in input.hashed_message.iter().chain(&input.signature) {
            b.set_variable(*w, Fr::zero());
        }
        for (w, byte) in input.pub_x.iter().zip(&gx).chain(input.pub_y.iter().zip(&gy)) {
            b.set_variable(*w, Fr::from(*byte as u64));
        }
        b.set_variable(input.result, Fr::one());
    }
    if !predicate.is_constant() {
        for idx in 0..32 {
            let unit = FieldT::constant(Fr::from(u64::from(idx == 0)));
            r_fields[idx] = FieldT::conditional_assign(&predicate, &r_fields[idx], &unit);
            s_fields[idx] = FieldT::conditional_assign(&predicate, &s_fields[idx], &unit);
            hashed_message_fields[idx] = FieldT::conditional_assign(&predicate, &hashed_message_fields[idx], &unit);
        }
        let two_g = (ark_secp256k1::Affine::generator() + ark_secp256k1::Affine::generator()).into_affine();
        let (default_x, default_y) = coordinate_bytes(&two_g);
        for i in 0..32 {
            pub_x_fields[i] = FieldT::conditional_assign(
                &predicate,
                &pub_x_fields[i],
                &FieldT::constant(Fr::from(default_x[i] as u64)),
            );
            pub_y_fields[i] = FieldT::conditional_assign(
                &predicate,
                &pub_y_fields[i],
                &FieldT::constant(Fr::from(default_y[i] as u64)),
            );
        }
    } else {
        assert!(
            predicate.get_value(),
            "ECDSA constraint with a constant false predicate"
        );
    }
    let hashed_message = fields_to_bytes(ctx, &hashed_message_fields);
    let pub_x_bytes = fields_to_bytes(ctx, &pub_x_fields);
    let pub_y_bytes = fields_to_bytes(ctx, &pub_y_fields);
    let r = fields_to_bytes(ctx, &r_fields);
    let s = fields_to_bytes(ctx, &s_fields);
    let result = BoolT::from_field(&result_field);
    let pub_x = crate::stdlib::biggroup::Fq::<ark_secp256k1::Config>::from_bytes(&pub_x_bytes);
    let pub_y = crate::stdlib::biggroup::Fq::<ark_secp256k1::Config>::from_bytes(&pub_y_bytes);
    let public_key = Element::<ark_secp256k1::Config>::new(pub_x, pub_y, false);
    let signature_result = crate::stdlib::ecdsa::ecdsa_verify_signature_secp256k1(&hashed_message, &public_key, &r, &s);
    signature_result.assert_equal(&BoolT::conditional_assign(&predicate, &result, &signature_result));
}

/// bb `create_multi_scalar_mul_constraint`.
fn create_multi_scalar_mul_constraint(ctx: &Ctx, m: &MultiScalarMul) {
    let predicate = BoolT::from_field(&to_field_ct(ctx, &m.predicate));
    let (result_x, result_y) = claimed_result_fields(ctx, &m.outputs);
    let input_result = CycleGroup::from_xy(result_x, result_y, false);
    let mut points = vec![];
    let mut scalars = vec![];
    for i in (0..m.points.len()).step_by(2) {
        points.push(to_grumpkin_point(ctx, &m.points[i], &m.points[i + 1], &predicate));
        scalars.push(to_grumpkin_scalar(ctx, &m.scalars[i], &m.scalars[i + 1], &predicate));
    }
    let mut result = CycleGroup::batch_mul(&points, &scalars, false);
    let mut to_be_asserted_equal = CycleGroup::conditional_assign(&predicate, &input_result, &result);
    result.assert_equal(&mut to_be_asserted_equal);
}

/// bb `create_ec_add_constraint` (the claimed result point is built after the inputs).
fn create_ec_add_constraint(ctx: &Ctx, e: &EmbeddedCurveAdd) {
    let predicate = BoolT::from_field(&to_field_ct(ctx, &e.predicate));
    let (result_x, result_y) = claimed_result_fields(ctx, &e.outputs);
    let input1 = to_grumpkin_point(ctx, &e.input1[0], &e.input1[1], &predicate);
    let input2 = to_grumpkin_point(ctx, &e.input2[0], &e.input2[1], &predicate);
    let input_result = CycleGroup::from_xy(result_x, result_y, false);
    let mut result = input1.add(&input2);
    let mut to_be_asserted_equal = CycleGroup::conditional_assign(&predicate, &input_result, &result);
    result.assert_equal(&mut to_be_asserted_equal);
}

pub(super) fn io_public_inputs_size(kind: CircuitKind) -> usize {
    match kind {
        CircuitKind::App => AppIo::PUBLIC_INPUTS_SIZE,
        CircuitKind::Kernel => KernelIo::PUBLIC_INPUTS_SIZE,
        CircuitKind::HidingKernel => unreachable!("the hiding kernel is never verified recursively"),
    }
}

/// bb `process_hn_recursion_constraints`: hand the queued proofs' VKs, already witnesses of the
/// circuit, to the kernel logic. Without a witness (write-VK mode) those witnesses are set to the
/// queued VKs first so the circuit is satisfiable.
fn process_hn_recursion_constraints(
    ctx: &Ctx,
    constraints: &[RecursionConstraint],
    ivc: &mut Chonk,
    rng: &mut dyn Rng,
) {
    let queue = &ivc.verification_queue;
    assert_eq!(
        constraints.len(),
        queue.len(),
        "mismatch in number of recursive verifications during kernel creation"
    );
    if ctx.borrow().is_write_vk_mode {
        let mut b = ctx.borrow_mut();
        for (c, e) in constraints.iter().zip(queue) {
            for (w, v) in c.key.iter().zip(e.vk.to_fields()) {
                b.set_variable(*w, v);
            }
            b.set_variable(c.key_hash, e.vk.hash());
        }
    }
    let is_init = queue[0].kind == CircuitKind::App;
    let is_hiding = ivc.current_kind() == CircuitKind::HidingKernel;
    let mut keys: Vec<VkWitnesses> = Vec::with_capacity(constraints.len());
    for (i, (c, e)) in constraints.iter().zip(queue).enumerate() {
        let expected_type = if is_hiding {
            HN_FINAL
        } else if is_init && i == 0 {
            OINK
        } else {
            HN
        };
        assert_eq!(
            c.proof_type, expected_type,
            "ACIR proof_type disagrees with the IVC state"
        );
        let expected_kind = if i == 0 && !is_init {
            CircuitKind::Kernel
        } else {
            CircuitKind::App
        };
        assert_eq!(
            e.kind, expected_kind,
            "queued circuit kind disagrees with its position in the group"
        );
        assert_eq!(
            e.vk.num_public_inputs_usize(),
            io_public_inputs_size(e.kind),
            "IO size mismatch with VK num_public_inputs"
        );
        let num_comms = e.kind.flavor().layout().num_precomputed;
        assert_eq!(
            c.key.len(),
            Vk::<StdBn254>::num_fields(num_comms),
            "verification key has the wrong number of fields"
        );
        let fields: Vec<FieldT> = c.key.iter().map(|w| FieldT::from_witness_index(ctx, *w)).collect();
        keys.push((
            Vk::from_fields(&fields, num_comms),
            FieldT::from_witness_index(ctx, c.key_hash),
        ));
    }
    complete_kernel_circuit_logic(ivc, ctx, rng, Some(keys));
}

/// bb `DefaultIO::add_default`: two points at infinity as eight zero public inputs, fixed by gates.
pub fn add_default_pairing_points(b: &mut Builder) {
    for _ in 0..PAIRING_POINTS_SIZE {
        let idx = b.add_public_variable(Fr::zero());
        b.fix_witness(idx, Fr::zero());
    }
    b.finalize_public_inputs();
}

/// Build the (unfinalized) Ultra circuit of an ACIR program. Without a witness the circuit is built
/// over zero witnesses (bb's write-VK mode); the structure, and hence the VK, is the same.
pub fn build_circuit(circuit: &Circuit, witness: Option<&[Fr]>) -> Builder {
    build_circuit_opts(circuit, witness, false)
}

/// bb `create_circuit<UltraCircuitBuilder>` with `ProgramMetadata.has_ipa_claim` (the CLI's
/// `--ipa_accumulation` flag): backend circuits recursively verifying UltraRollup proofs
/// accumulate the nested IPA claims and publish `RollupIO`.
pub fn build_circuit_opts(circuit: &Circuit, witness: Option<&[Fr]>, has_ipa_claim: bool) -> Builder {
    let _g_cls = crate::base::bench::Scope::new("acir::classify");
    let (mut c, public_inputs) = classify(circuit, false);
    drop(_g_cls);
    assert!(c.hn_recursion.is_empty(), "recursion constraints need a Mega circuit");
    let honk_recursion = std::mem::take(&mut c.honk_recursion);
    let chonk_recursion = std::mem::take(&mut c.chonk_recursion);
    let avm_recursion = std::mem::take(&mut c.avm_recursion);
    let is_write_vk = witness.is_none();
    let builder = Builder::from_acir(&witness_or_zeros(witness, &c), public_inputs, is_write_vk);
    crate::base::timing::phase("build: from_acir");
    let ctx = lower(builder, c);
    crate::base::timing::phase("build: lower opcodes");
    if honk_recursion.is_empty() && chonk_recursion.is_empty() && avm_recursion.is_empty() && !has_ipa_claim {
        add_default_pairing_points(&mut ctx.borrow_mut());
    } else {
        super::honk_recursion::process_honk_recursion_constraints(
            &ctx,
            &honk_recursion,
            &chonk_recursion,
            &avm_recursion,
            is_write_vk,
            has_ipa_claim,
        );
        crate::base::timing::phase("build: recursion+io");
    }
    let _g_ib = crate::base::bench::Scope::new("acir::into_builder");
    let out = into_builder(ctx);
    drop(_g_ib);
    out
}

/// bb `translate_or_reject`: a kernel's arithmetization has no lookup or non-native-field gates,
/// and the hiding kernel's no elliptic or memory gates either, so ACIR that needs them is rejected
/// (bb names the first such opcode list, in its translation order).
pub fn check_representable(circuit: &Circuit, kind: CircuitKind) -> Result<(), String> {
    if kind == CircuitKind::App {
        return Ok(());
    }
    let hiding = kind == CircuitKind::HidingKernel;
    let (c, _) = classify(circuit, true);
    let lists: [(&str, bool, bool); 10] = [
        ("logic_constraints", !c.logic.is_empty(), true),
        ("aes128_constraints", !c.aes128.is_empty(), true),
        ("sha256_compression", !c.sha256.is_empty(), true),
        ("ecdsa_k1_constraints", !c.ecdsa_k1.is_empty(), true),
        ("ecdsa_r1_constraints", !c.ecdsa_r1.is_empty(), true),
        ("blake2s_constraints", !c.blake2s.is_empty(), true),
        ("blake3_constraints", !c.blake3.is_empty(), true),
        ("keccak_permutations", !c.keccak.is_empty(), true),
        ("multi_scalar_mul_constraints", !c.msm.is_empty(), hiding),
        ("ec_add_constraints", !c.ec_add.is_empty(), hiding),
    ];
    if let Some((name, ..)) = lists.iter().find(|(_, present, missing)| *present && *missing) {
        return Err(format!("ACIR contains {name}, which this arithmetization cannot represent."));
    }
    for b in c.blocks.values().filter(|_| hiding) {
        match b.kind {
            BlockKind::Rom => return Err("ACIR contains a ROM block, which this arithmetization cannot represent.".into()),
            BlockKind::Ram => return Err("ACIR contains a RAM block, which this arithmetization cannot represent.".into()),
            _ => {}
        }
    }
    Ok(())
}


/// The Mega circuit of an ACIR program (bb `create_circuit<MegaCircuitBuilder>`): AssertZero
/// opcodes that fit the bilinear / batched-eq gate use it, the op queue is the IVC's, and a
/// kernel's recursion constraints run the kernel logic against the IVC state. Without an IVC a
/// kernel is built against bb's mocked state (write-VK mode), which yields the same circuit.
pub fn build_circuit_mega(
    circuit: &Circuit,
    witness: Option<&[Fr]>,
    ivc: Option<&mut Chonk>,
    rng: &mut dyn Rng,
) -> Builder {
    let _g_cls2 = crate::base::bench::Scope::new("acir::classify");
    let (mut c, public_inputs) = classify(circuit, true);
    drop(_g_cls2);
    assert!(
        c.honk_recursion.is_empty() && c.chonk_recursion.is_empty() && c.avm_recursion.is_empty(),
        "Honk recursion constraints need an Ultra circuit"
    );
    let hn_recursion = std::mem::take(&mut c.hn_recursion);
    let mut mock;
    let ivc = match ivc {
        Some(ivc) => Some(ivc),
        None if hn_recursion.is_empty() => None,
        None => {
            assert!(witness.is_none(), "HN recursion requires an IVC outside write-VK mode");
            mock = mock_chonk_from_constraints(&hn_recursion);
            Some(&mut mock)
        }
    };
    let op_queue = ivc
        .as_ref()
        .map_or_else(|| EccOpQueue::shared(), |ivc| ivc.op_queue.clone());
    let _g_wit = crate::base::bench::Scope::new("acir::from_acir_mega");
    let builder = Builder::from_acir_mega(
        op_queue,
        &witness_or_zeros(witness, &c),
        public_inputs,
        witness.is_none(),
    );
    drop(_g_wit);
    crate::base::timing::phase("      build: witness vars");
    let ctx = lower(builder, c);
    crate::base::timing::phase("      build: acir lowering");
    if hn_recursion.is_empty() {
        add_default_pairing_points(&mut ctx.borrow_mut());
    } else {
        let _g_rec = crate::base::bench::Scope::new("acir::recursion_constraints");
        process_hn_recursion_constraints(&ctx, &hn_recursion, ivc.unwrap(), rng);
        drop(_g_rec);
    }
    crate::base::timing::phase("      build: recursion/kernel logic");
    let _g_ib = crate::base::bench::Scope::new("acir::into_builder");
    let out = into_builder(ctx);
    drop(_g_ib);
    out
}

/// A Chonk step's circuit lowered ahead of its turn (`prebuild_circuit_mega`), waiting for the IVC
/// state the rest of its build depends on.
pub struct Prebuilt {
    builder: Builder,
    hn_recursion: Vec<RecursionConstraint>,
    gaps: Vec<u32>,
}
// SAFETY: the builder's only `Rc` is its private op queue, checked unique, so it moves whole.
unsafe impl Send for Prebuilt {}

/// The part of `build_circuit_mega` that does not depend on the IVC, for another thread: the ACIR
/// lowering, against a private op queue, of a witness whose gaps (`decode_witness_gaps`) are still
/// zero. `None` when that would not equal the inline build: the lowering drew from the global
/// randomness, whose order the inline build fixes, or read a gap.
pub fn prebuild_circuit_mega(circuit: &Circuit, witness: &[Fr], gaps: Vec<u32>) -> Option<Prebuilt> {
    let (mut c, public_inputs) = classify(circuit, true);
    let hn_recursion = std::mem::take(&mut c.hn_recursion);
    let (builder, drew) = crate::base::rng::detached(|| {
        let op_queue = EccOpQueue::shared();
        into_builder(lower(Builder::from_acir_mega(op_queue, &witness_or_zeros(Some(witness), &c), public_inputs, false), c))
    });
    assert_eq!(std::sync::Arc::strong_count(&builder.mega.as_ref().unwrap().op_queue), 1);
    (!drew && !references_any(&builder, &gaps)).then_some(Prebuilt { builder, hn_recursion, gaps })
}

/// Whether any of `vars` is wired into a gate, a memory array or the databus, or copy-constrained.
fn references_any(b: &Builder, vars: &[u32]) -> bool {
    let mut is_var = vec![false; b.variables.len()];
    vars.iter().for_each(|&k| is_var[k as usize] = true);
    let hit = |w: &u32| is_var.get(*w as usize) == Some(&true);
    vars.iter().any(|&k| b.real_variable_index[k as usize] != k)
        || (b.blocks.blocks.iter()).any(|bl| bl.rows.iter().any(|r| r.wires.iter().any(hit)))
        || (b.memory.rom_arrays.iter()).any(|a| a.state.iter().flatten().any(hit))
        || (b.memory.ram_arrays.iter()).any(|a| a.state.iter().any(hit))
        || (b.mega.as_ref()).is_some_and(|m| m.databus.iter().any(|bus| bus.data.iter().any(hit)))
}

/// The rest of `build_circuit_mega`, in turn and in its order: the gaps' random fill (drawn where
/// `decode_witness` draws it), the op queue handed over, then the kernel logic.
pub fn finish_circuit_mega(prebuilt: Prebuilt, ivc: &mut Chonk, rng: &mut dyn Rng) -> Builder {
    let Prebuilt { mut builder, hn_recursion, gaps } = prebuilt;
    for k in gaps {
        builder.variables[k as usize] = rng.fr();
    }
    let mega = builder.mega.as_mut().unwrap();
    let private = std::mem::replace(&mut mega.op_queue, ivc.op_queue.clone());
    ivc.op_queue.write().unwrap().absorb_current(std::sync::Arc::into_inner(private).unwrap().into_inner().unwrap());
    let ctx = Rc::new(RefCell::new(builder));
    if hn_recursion.is_empty() {
        add_default_pairing_points(&mut ctx.borrow_mut());
    } else {
        let _g_rec = crate::base::bench::Scope::new("acir::recursion_constraints");
        process_hn_recursion_constraints(&ctx, &hn_recursion, ivc, rng);
    }
    into_builder(ctx)
}

fn witness_or_zeros(witness: Option<&[Fr]>, c: &Constraints) -> Vec<Fr> {
    match witness {
        Some(w) => {
            assert!(
                w.len() > c.max_witness_index as usize,
                "witness vector shorter than the circuit's witnesses"
            );
            w.to_vec()
        }
        None => vec![Fr::zero(); c.max_witness_index as usize + 1],
    }
}

fn into_builder(ctx: Ctx) -> Builder {
    Rc::try_unwrap(ctx).ok().expect("builder still shared").into_inner()
}

/// bb `build_constraints` up to the block constraints.
fn lower(builder: Builder, c: Constraints) -> Ctx {
    let ctx: Ctx = Rc::new(RefCell::new(builder));
    {
        crate::scope!("acir::quad_constraints");
        let mut b = ctx.borrow_mut();
        for mut q in c.quad {
            resolve_zero(&b, &mut q);
            b.create_big_mul_add_gate(&q, false);
        }
        for gates in c.big_quad {
            create_big_quad_constraint(&mut b, gates);
        }
        let z = b.zero_idx();
        for mut g in c.bilinear {
            assert!(g.a != IS_CONSTANT && g.b != IS_CONSTANT && g.c != IS_CONSTANT);
            if g.d == IS_CONSTANT {
                g.d = z;
            }
            b.create_bilinear_batched_eq_gate(&g);
        }
        for mut g in c.batched_eq {
            assert_ne!(g.a, IS_CONSTANT);
            for w in [&mut g.b, &mut g.c, &mut g.d] {
                if *w == IS_CONSTANT {
                    *w = z;
                }
            }
            b.create_bilinear_batched_eq_gate(&g);
        }
    }
    {
        crate::scope!("acir::logic_constraints");
        for l in &c.logic {
            create_logic_gate(&ctx, l);
        }
    }
    {
        crate::scope!("acir::range_constraints");
        for (w, num_bits) in c.range {
            ctx.borrow_mut().create_dyadic_range_constraint(w, num_bits as u64);
        }
    }
    {
        crate::scope!("acir::aes128_constraints");
        for a in &c.aes128 {
            create_aes128_constraints(&ctx, a);
        }
    }
    {
        crate::scope!("acir::sha256_compression");
        for s in &c.sha256 {
            let inputs: [FieldT; 16] = std::array::from_fn(|i| to_field_ct(&ctx, &s.inputs[i]));
            let hash_values: [FieldT; 8] = std::array::from_fn(|i| to_field_ct(&ctx, &s.hash_values[i]));
            let output = sha256::sha256_block(&hash_values, &inputs);
            for (out, result) in output.iter().zip(&s.outputs) {
                out.assert_equal(&FieldT::from_witness_index(&ctx, *result));
            }
        }
    }
    {
        crate::scope!("acir::ecdsa_k1_constraints");
        for e in &c.ecdsa_k1 {
            create_ecdsa_verify_constraints_k1(&ctx, e);
        }
    }
    {
        crate::scope!("acir::ecdsa_r1_constraints");
        for e in &c.ecdsa_r1 {
            create_ecdsa_verify_constraints(&ctx, e);
        }
    }
    {
        crate::scope!("acir::blake2s_constraints");
        for b in &c.blake2s {
            create_blake_constraints(&ctx, b, false);
        }
    }
    {
        crate::scope!("acir::blake3_constraints");
        for b in &c.blake3 {
            create_blake_constraints(&ctx, b, true);
        }
    }
    {
        crate::scope!("acir::keccak_permutations");
        for k in &c.keccak {
            let state: [FieldT; 25] = std::array::from_fn(|i| to_field_ct(&ctx, &k.state[i]));
            let output = keccak::permutation_opcode(&ctx, &state);
            for (out, result) in output.iter().zip(&k.result) {
                out.assert_equal(&FieldT::from_witness_index(&ctx, *result));
            }
        }
    }
    {
        crate::scope!("acir::poseidon2_constraints");
        for p in &c.poseidon2 {
            assert!(p.state.len() == 4 && p.result.len() == 4);
            let state: [FieldT; 4] = std::array::from_fn(|i| FieldT::from_witness_index(&ctx, p.state[i]));
            let out = poseidon2::permutation(&ctx, &state);
            for i in 0..4 {
                out[i].assert_equal(&FieldT::from_witness_index(&ctx, p.result[i]));
            }
        }
    }
    {
        crate::scope!("acir::multi_scalar_mul_constraints");
        for m in &c.msm {
            create_multi_scalar_mul_constraint(&ctx, m);
        }
    }
    {
        crate::scope!("acir::ec_add_constraints");
        for e in &c.ec_add {
            create_ec_add_constraint(&ctx, e);
        }
    }
    {
        crate::scope!("acir::block_constraints");
        for block in c.blocks.values() {
            create_block_constraints(&ctx, block);
        }
    }
    ctx
}
