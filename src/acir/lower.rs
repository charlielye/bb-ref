//! ACIR → builder (bb `acir_to_constraint_buf` + `acir_format::build_constraints`). Opcodes are first
//! classified into constraint lists, then lowered in bb's fixed order: quads, big quads, ranges,
//! Poseidon2, memory blocks, and finally the default (infinity) pairing points as public inputs.

use super::format::{field, BlackBoxFuncCall, Circuit, FunctionInput, Opcode, Witness};
use crate::base::field::FieldLike;
use crate::base::Fr;
use crate::circuit::builder::MulQuad;
use crate::circuit::{Builder, IS_CONSTANT};
use crate::stdlib::memory::{RamTable, RomTable};
use crate::stdlib::{poseidon2, Ctx, FieldT};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

const NUM_WIRES: usize = 4;
/// Pairing points occupy this many trailing public inputs (two bn254 points as four 136-bit limbs).
pub const PAIRING_POINTS_SIZE: usize = 8;

struct MemOp {
    write: bool,
    index: u32,
    value: u32,
}
struct BlockConstraint {
    init: Vec<u32>,
    trace: Vec<MemOp>,
    is_ram: bool,
}
struct Poseidon2Constraint {
    state: Vec<u32>,
    result: Vec<u32>,
}

#[derive(Default)]
struct Constraints {
    max_witness_index: u32,
    quad: Vec<MulQuad>,
    big_quad: Vec<Vec<MulQuad>>,
    range: Vec<(u32, u32)>,
    poseidon2: Vec<Poseidon2Constraint>,
    blocks: BTreeMap<u32, BlockConstraint>,
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
}

/// bb `process_linear_terms`: coefficients keyed (and hence ordered) by witness index.
fn linear_terms(e: &super::format::Expression) -> BTreeMap<u32, Fr> {
    let mut m = BTreeMap::new();
    for (c, w) in &e.linear_combinations {
        *m.entry(w.0).or_insert(Fr::zero()) += field(c);
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
    MulQuad { a: IS_CONSTANT, b: IS_CONSTANT, c: IS_CONSTANT, d: IS_CONSTANT, mul_scaling: z, a_scaling: z, b_scaling: z, c_scaling: z, d_scaling: z, const_scaling: z }
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
        let mut q = MulQuad { a: a.0, b: b.0, mul_scaling: field(c), ..empty_quad() };
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
            q.const_scaling = field(&e.q_c);
            if !lin.is_empty() {
                take(&mut q.d, &mut q.d_scaling, lin);
            }
            first = false;
        }
    }
    while !lin.is_empty() {
        let mut q = empty_quad();
        for (idx, s) in [(&mut q.a, &mut q.a_scaling), (&mut q.b, &mut q.b_scaling), (&mut q.c, &mut q.c_scaling)] {
            if !lin.is_empty() {
                take(idx, s, lin);
            }
        }
        if first {
            q.const_scaling = field(&e.q_c);
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

fn classify(circuit: &Circuit) -> (Constraints, Vec<u32>) {
    let mut c = Constraints::default();
    let public_inputs: Vec<u32> = circuit.public_parameters.iter().chain(&circuit.return_values).map(|w| c.note(*w)).collect();
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
                    assert!(field(&e.q_c).is_zero(), "unsatisfiable constant AssertZero");
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
                BlackBoxFuncCall::Poseidon2Permutation { inputs, outputs } => {
                    let state = inputs.iter().map(|i| c.input(i)).collect();
                    let result = outputs.iter().map(|w| c.note(*w)).collect();
                    c.poseidon2.push(Poseidon2Constraint { state, result });
                }
                other => panic!("unsupported black box function: {other:?}"),
            },
            Opcode::MemoryInit { block_id, init, block_type } => {
                assert!(matches!(block_type, super::format::BlockType::Memory), "databus blocks need a Mega circuit");
                let init = init.iter().map(|w| c.note(*w)).collect();
                c.blocks.insert(*block_id, BlockConstraint { init, trace: vec![], is_ram: false });
            }
            Opcode::MemoryOp { block_id, op } => {
                let (index, value) = (c.note(op.index), c.note(op.value));
                let block = c.blocks.get_mut(block_id).expect("MemoryOp on uninitialized block");
                block.is_ram |= op.read;
                block.trace.push(MemOp { write: op.read, index, value });
            }
            Opcode::BrilligCall(_) => {}
            Opcode::Call(_) => panic!("Call opcode is not supported"),
        }
    }
    (c, public_inputs)
}

/// Unused wires hold the constant zero (bb `set_zero_idx`).
fn resolve_zero(b: &Builder, q: &mut MulQuad) {
    assert_ne!(q.a, IS_CONSTANT, "wire a of a mul_quad must be a witness");
    for (idx, s) in [(&mut q.b, q.b_scaling), (&mut q.c, q.c_scaling), (&mut q.d, q.d_scaling)] {
        if *idx == IS_CONSTANT {
            assert!(s.is_zero());
            *idx = b.zero_idx();
        }
    }
}

fn quad_value(b: &Builder, q: &MulQuad) -> Fr {
    let v = |i: u32| b.get_variable(i);
    v(q.a) * v(q.b) * q.mul_scaling + v(q.a) * q.a_scaling + v(q.b) * q.b_scaling + v(q.c) * q.c_scaling + v(q.d) * q.d_scaling + q.const_scaling
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

fn create_block_constraints(ctx: &Ctx, block: &BlockConstraint) {
    let init: Vec<FieldT> = block.init.iter().map(|w| FieldT::from_witness_index(ctx, *w)).collect();
    if block.is_ram {
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
    } else {
        let mut table = RomTable::new(ctx, init);
        for op in &block.trace {
            assert!(!op.write);
            let value = FieldT::from_witness_index(ctx, op.value);
            let index = FieldT::from_witness_index(ctx, op.index);
            value.assert_equal(&table.read(&index));
        }
    }
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
    let (c, public_inputs) = classify(circuit);
    let zeros;
    let witness = match witness {
        Some(w) => {
            assert!(w.len() > c.max_witness_index as usize, "witness vector shorter than the circuit's witnesses");
            w
        }
        None => {
            zeros = vec![Fr::zero(); c.max_witness_index as usize + 1];
            &zeros
        }
    };
    let ctx: Ctx = Rc::new(RefCell::new(Builder::from_acir(witness, public_inputs, false)));
    {
        let mut b = ctx.borrow_mut();
        for mut q in c.quad {
            resolve_zero(&b, &mut q);
            b.create_big_mul_add_gate(&q, false);
        }
        for gates in c.big_quad {
            create_big_quad_constraint(&mut b, gates);
        }
        for (w, num_bits) in c.range {
            b.create_dyadic_range_constraint(w, num_bits as u64);
        }
    }
    for p in &c.poseidon2 {
        assert!(p.state.len() == 4 && p.result.len() == 4);
        let state: [FieldT; 4] = std::array::from_fn(|i| FieldT::from_witness_index(&ctx, p.state[i]));
        let out = poseidon2::permutation(&ctx, &state);
        for i in 0..4 {
            out[i].assert_equal(&FieldT::from_witness_index(&ctx, p.result[i]));
        }
    }
    for block in c.blocks.values() {
        create_block_constraints(&ctx, block);
    }
    add_default_pairing_points(&mut ctx.borrow_mut());
    Rc::try_unwrap(ctx).ok().expect("builder still shared").into_inner()
}
