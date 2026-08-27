//! Bitwise XOR/AND of two field elements (bb `stdlib/primitives/logic`): 32-bit chunks read from
//! the uint tables, the chunks tied back to the operands.

use super::field::{Ctx, FieldT};
use super::plookup::read_from_2_to_1_table;
use crate::base::field::{from_u256, u256, U256};
use crate::base::Fr;
use crate::circuit::plookup::MultiTableId;

/// bb `logic::create_logic_constraint` with its default chunking.
pub fn create_logic_constraint(a: &FieldT, b: &FieldT, num_bits: usize, is_xor_gate: bool) -> FieldT {
    assert!(num_bits > 0 && num_bits <= 252);
    if a.is_constant() && b.is_constant() {
        let (x, y) = (u256(&a.get_value()), u256(&b.get_value()));
        let limbs: [u64; 4] = std::array::from_fn(|i| if is_xor_gate { x.0[i] ^ y.0[i] } else { x.0[i] & y.0[i] });
        return FieldT::constant(from_u256(U256::new(limbs)));
    }
    if a.is_constant() {
        let ctx = b.ctx.clone().unwrap();
        let index = ctx.borrow_mut().put_constant_variable(a.get_value());
        return create_logic_constraint(&FieldT::from_witness_index(&ctx, index), b, num_bits, is_xor_gate);
    }
    if b.is_constant() {
        let ctx = a.ctx.clone().unwrap();
        let index = ctx.borrow_mut().put_constant_variable(b.get_value());
        return create_logic_constraint(a, &FieldT::from_witness_index(&ctx, index), num_bits, is_xor_gate);
    }
    let ctx: Ctx = a.ctx.clone().unwrap();
    let num_chunks = num_bits.div_ceil(32);
    let mut left = u256(&a.get_value());
    let mut right = u256(&b.get_value());
    let mut a_accumulator = FieldT::constant(Fr::from(0u64));
    let mut b_accumulator = FieldT::constant(Fr::from(0u64));
    let mut res = FieldT::constant(Fr::from(0u64));
    let table = if is_xor_gate {
        MultiTableId::Uint32Xor
    } else {
        MultiTableId::Uint32And
    };
    for i in 0..num_chunks {
        let chunk_size = if i != num_chunks - 1 { 32 } else { num_bits - i * 32 };
        let mask = (1u64 << chunk_size) - 1;
        let a_chunk = FieldT::from_witness(&ctx, Fr::from(left.0[0] & mask));
        let b_chunk = FieldT::from_witness(&ctx, Fr::from(right.0[0] & mask));
        let result_chunk = read_from_2_to_1_table(table, &a_chunk, &b_chunk);
        let scaling_factor = FieldT::constant(from_u256(U256::from(1u64) << (32 * i) as u32));
        a_accumulator = a_accumulator.add(&a_chunk.mul(&scaling_factor));
        b_accumulator = b_accumulator.add(&b_chunk.mul(&scaling_factor));
        if chunk_size != 32 {
            a_chunk.create_range_constraint(chunk_size as u64);
            b_chunk.create_range_constraint(chunk_size as u64);
        }
        res = res.add(&result_chunk.mul(&scaling_factor));
        left >>= 32;
        right >>= 32;
    }
    a.assert_equal(&a_accumulator);
    b.assert_equal(&b_accumulator);
    res
}
