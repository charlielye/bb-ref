//! The Translator (bb `translator_vm/`): a bn254-Fr circuit that re-computes, in 68-bit limbs, the
//! batched evaluation `Σ_i x^i (op_i + v·Px_i + v²·Py_i + v³·z1_i + v⁴·z2_i)` of the op queue that the
//! ECCVM opened over Grumpkin, tying the two proofs together. The mini circuit (2^13 rows, two per op)
//! is concatenated 16-fold into 2^17-row range-constraint columns.

pub mod builder;
pub mod check;
pub mod key;
pub mod relations;

use crate::base::field::from_hex;
use crate::base::poly::Polynomial;
use crate::base::{Fr, G1Affine};

pub const NUM_WIRES: usize = 81;
pub const NUM_LIMB_BITS: u32 = 68;
pub const NUM_LAST_LIMB_BITS: u32 = 50;
pub const NUM_LAST_QUOTIENT_LIMB_BITS: u32 = 52;
pub const NUM_Z_BITS: u32 = 128;
pub const MICRO_LIMB_BITS: u32 = 14;
pub const NUM_MICRO_LIMBS: usize = 6;
pub const NUM_BINARY_LIMBS: usize = 4;
pub const NUM_Z_LIMBS: usize = 2;
pub const RELATION_WIDE_LIMB_BITS: u32 = 84;
pub const RESULT_ROW: usize = 8;
pub const NUM_NO_OPS_START: usize = 1;
pub const NUM_RANDOM_OPS_START: usize = 3;
pub const NUM_RANDOM_OPS_END: usize = 2;
pub const LOG_MINI_CIRCUIT_SIZE: usize = 13;
pub const MINI_CIRCUIT_SIZE: usize = 1 << LOG_MINI_CIRCUIT_SIZE;
pub const CONCATENATION_GROUP_SIZE: usize = 16;
pub const CONST_TRANSLATOR_LOG_N: usize = LOG_MINI_CIRCUIT_SIZE + 4;
pub const CIRCUIT_SIZE: usize = 1 << CONST_TRANSLATOR_LOG_N;
pub const NUM_CONCATENATED_POLYS: usize = 5;
pub const SORT_STEP: u64 = 3;
pub const NUM_MASKED_ROWS_END: usize = NUM_RANDOM_OPS_END * 2;
pub const MAX_RANDOM_VALUES_PER_ORDERED: usize = CONCATENATION_GROUP_SIZE * NUM_MASKED_ROWS_END;
pub const RANDOMNESS_START: usize = 2;
pub const SORTED_STEPS_COUNT: usize = ((1 << MICRO_LIMB_BITS) / SORT_STEP as usize) + 1;
pub const MASKING_OVERFLOW_COLUMN: usize = MAX_RANDOM_VALUES_PER_ORDERED * (NUM_ORDERED - 1) / NUM_ORDERED;
pub const NUM_ORDERED: usize = 5;
pub const NUM_OP_QUEUE_WIRES: usize = 4;
/// Mini-circuit wires other than the four op-queue wires: 13 limb wires and 64 micro-limb wires.
pub const NUM_MINICIRCUIT_WIRES: usize = 77;

/// All Translator entities in bb `AllEntities` order.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Ent {
    gemini_masking_poly,
    ordered_extra_range_constraints_numerator,
    lagrange_first,
    lagrange_last,
    lagrange_odd_in_minicircuit,
    lagrange_even_in_minicircuit,
    lagrange_result_row,
    lagrange_last_in_minicircuit,
    lagrange_masking,
    lagrange_mini_masking,
    lagrange_real_last,
    lagrange_ordered_masking,
    op,
    x_lo_y_hi,
    x_hi_z_1,
    y_lo_z_2,
    p_x_low_limbs,
    p_x_high_limbs,
    p_y_low_limbs,
    p_y_high_limbs,
    z_low_limbs,
    z_high_limbs,
    accumulators_binary_limbs_0,
    accumulators_binary_limbs_1,
    accumulators_binary_limbs_2,
    accumulators_binary_limbs_3,
    quotient_low_binary_limbs,
    quotient_high_binary_limbs,
    relation_wide_limbs,
    p_x_low_limbs_range_constraint_0,
    p_x_low_limbs_range_constraint_1,
    p_x_low_limbs_range_constraint_2,
    p_x_low_limbs_range_constraint_3,
    p_x_low_limbs_range_constraint_4,
    p_x_low_limbs_range_constraint_tail,
    p_x_high_limbs_range_constraint_0,
    p_x_high_limbs_range_constraint_1,
    p_x_high_limbs_range_constraint_2,
    p_x_high_limbs_range_constraint_3,
    p_x_high_limbs_range_constraint_4,
    p_x_high_limbs_range_constraint_tail,
    p_y_low_limbs_range_constraint_0,
    p_y_low_limbs_range_constraint_1,
    p_y_low_limbs_range_constraint_2,
    p_y_low_limbs_range_constraint_3,
    p_y_low_limbs_range_constraint_4,
    p_y_low_limbs_range_constraint_tail,
    p_y_high_limbs_range_constraint_0,
    p_y_high_limbs_range_constraint_1,
    p_y_high_limbs_range_constraint_2,
    p_y_high_limbs_range_constraint_3,
    p_y_high_limbs_range_constraint_4,
    p_y_high_limbs_range_constraint_tail,
    z_low_limbs_range_constraint_0,
    z_low_limbs_range_constraint_1,
    z_low_limbs_range_constraint_2,
    z_low_limbs_range_constraint_3,
    z_low_limbs_range_constraint_4,
    z_low_limbs_range_constraint_tail,
    z_high_limbs_range_constraint_0,
    z_high_limbs_range_constraint_1,
    z_high_limbs_range_constraint_2,
    z_high_limbs_range_constraint_3,
    z_high_limbs_range_constraint_4,
    z_high_limbs_range_constraint_tail,
    accumulator_low_limbs_range_constraint_0,
    accumulator_low_limbs_range_constraint_1,
    accumulator_low_limbs_range_constraint_2,
    accumulator_low_limbs_range_constraint_3,
    accumulator_low_limbs_range_constraint_4,
    accumulator_low_limbs_range_constraint_tail,
    accumulator_high_limbs_range_constraint_0,
    accumulator_high_limbs_range_constraint_1,
    accumulator_high_limbs_range_constraint_2,
    accumulator_high_limbs_range_constraint_3,
    accumulator_high_limbs_range_constraint_4,
    accumulator_high_limbs_range_constraint_tail,
    quotient_low_limbs_range_constraint_0,
    quotient_low_limbs_range_constraint_1,
    quotient_low_limbs_range_constraint_2,
    quotient_low_limbs_range_constraint_3,
    quotient_low_limbs_range_constraint_4,
    quotient_low_limbs_range_constraint_tail,
    quotient_high_limbs_range_constraint_0,
    quotient_high_limbs_range_constraint_1,
    quotient_high_limbs_range_constraint_2,
    quotient_high_limbs_range_constraint_3,
    quotient_high_limbs_range_constraint_4,
    quotient_high_limbs_range_constraint_tail,
    relation_wide_limbs_range_constraint_0,
    relation_wide_limbs_range_constraint_1,
    relation_wide_limbs_range_constraint_2,
    relation_wide_limbs_range_constraint_3,
    ordered_range_constraints_0,
    ordered_range_constraints_1,
    ordered_range_constraints_2,
    ordered_range_constraints_3,
    ordered_range_constraints_4,
    z_perm,
    concatenated_range_constraints_0,
    concatenated_range_constraints_1,
    concatenated_range_constraints_2,
    concatenated_range_constraints_3,
    concatenated_non_range,
    x_lo_y_hi_shift,
    x_hi_z_1_shift,
    y_lo_z_2_shift,
    p_x_low_limbs_shift,
    p_x_high_limbs_shift,
    p_y_low_limbs_shift,
    p_y_high_limbs_shift,
    z_low_limbs_shift,
    z_high_limbs_shift,
    accumulators_binary_limbs_0_shift,
    accumulators_binary_limbs_1_shift,
    accumulators_binary_limbs_2_shift,
    accumulators_binary_limbs_3_shift,
    quotient_low_binary_limbs_shift,
    quotient_high_binary_limbs_shift,
    relation_wide_limbs_shift,
    p_x_low_limbs_range_constraint_0_shift,
    p_x_low_limbs_range_constraint_1_shift,
    p_x_low_limbs_range_constraint_2_shift,
    p_x_low_limbs_range_constraint_3_shift,
    p_x_low_limbs_range_constraint_4_shift,
    p_x_low_limbs_range_constraint_tail_shift,
    p_x_high_limbs_range_constraint_0_shift,
    p_x_high_limbs_range_constraint_1_shift,
    p_x_high_limbs_range_constraint_2_shift,
    p_x_high_limbs_range_constraint_3_shift,
    p_x_high_limbs_range_constraint_4_shift,
    p_x_high_limbs_range_constraint_tail_shift,
    p_y_low_limbs_range_constraint_0_shift,
    p_y_low_limbs_range_constraint_1_shift,
    p_y_low_limbs_range_constraint_2_shift,
    p_y_low_limbs_range_constraint_3_shift,
    p_y_low_limbs_range_constraint_4_shift,
    p_y_low_limbs_range_constraint_tail_shift,
    p_y_high_limbs_range_constraint_0_shift,
    p_y_high_limbs_range_constraint_1_shift,
    p_y_high_limbs_range_constraint_2_shift,
    p_y_high_limbs_range_constraint_3_shift,
    p_y_high_limbs_range_constraint_4_shift,
    p_y_high_limbs_range_constraint_tail_shift,
    z_low_limbs_range_constraint_0_shift,
    z_low_limbs_range_constraint_1_shift,
    z_low_limbs_range_constraint_2_shift,
    z_low_limbs_range_constraint_3_shift,
    z_low_limbs_range_constraint_4_shift,
    z_low_limbs_range_constraint_tail_shift,
    z_high_limbs_range_constraint_0_shift,
    z_high_limbs_range_constraint_1_shift,
    z_high_limbs_range_constraint_2_shift,
    z_high_limbs_range_constraint_3_shift,
    z_high_limbs_range_constraint_4_shift,
    z_high_limbs_range_constraint_tail_shift,
    accumulator_low_limbs_range_constraint_0_shift,
    accumulator_low_limbs_range_constraint_1_shift,
    accumulator_low_limbs_range_constraint_2_shift,
    accumulator_low_limbs_range_constraint_3_shift,
    accumulator_low_limbs_range_constraint_4_shift,
    accumulator_low_limbs_range_constraint_tail_shift,
    accumulator_high_limbs_range_constraint_0_shift,
    accumulator_high_limbs_range_constraint_1_shift,
    accumulator_high_limbs_range_constraint_2_shift,
    accumulator_high_limbs_range_constraint_3_shift,
    accumulator_high_limbs_range_constraint_4_shift,
    accumulator_high_limbs_range_constraint_tail_shift,
    quotient_low_limbs_range_constraint_0_shift,
    quotient_low_limbs_range_constraint_1_shift,
    quotient_low_limbs_range_constraint_2_shift,
    quotient_low_limbs_range_constraint_3_shift,
    quotient_low_limbs_range_constraint_4_shift,
    quotient_low_limbs_range_constraint_tail_shift,
    quotient_high_limbs_range_constraint_0_shift,
    quotient_high_limbs_range_constraint_1_shift,
    quotient_high_limbs_range_constraint_2_shift,
    quotient_high_limbs_range_constraint_3_shift,
    quotient_high_limbs_range_constraint_4_shift,
    quotient_high_limbs_range_constraint_tail_shift,
    relation_wide_limbs_range_constraint_0_shift,
    relation_wide_limbs_range_constraint_1_shift,
    relation_wide_limbs_range_constraint_2_shift,
    relation_wide_limbs_range_constraint_3_shift,
    ordered_range_constraints_0_shift,
    ordered_range_constraints_1_shift,
    ordered_range_constraints_2_shift,
    ordered_range_constraints_3_shift,
    ordered_range_constraints_4_shift,
    z_perm_shift,
}

pub const NUM_ALL_ENTITIES: usize = 190;
pub const NUM_PRECOMPUTED: usize = 11;
/// Entity index of wire `w` (bb `WireIds` order).
pub const FIRST_WIRE: usize = 12;
pub const FIRST_ORDERED: usize = 93;
pub const FIRST_CONCATENATED: usize = 99;
pub const FIRST_SHIFTED: usize = 104;
pub const FIRST_ORDERED_SHIFT: usize = 184;

/// The entity at index `i`.
pub fn ent(i: usize) -> Ent {
    assert!(i < NUM_ALL_ENTITIES);
    // SAFETY: `Ent` is `repr(u8)` with contiguous discriminants `0..NUM_ALL_ENTITIES`.
    unsafe { std::mem::transmute(i as u8) }
}

/// Entity index of the shift of entity `e` (to-be-shifted entities only).
pub fn shift_of(e: usize) -> usize {
    match e {
        13..=92 => e + 91,
        93..=97 => e + 91,
        98 => 189,
        _ => panic!("entity {e} is not shifted"),
    }
}

/// The fixed Translator verification key: the commitment to `ordered_extra_range_constraints_numerator`
/// (bb `TranslatorHardcodedVKAndHash`), and its hash.
pub fn fixed_vk() -> G1Affine {
    G1Affine::new_unchecked(from_hex("0x1ddbff0e1f0999f88ffa959e9505e5f489b57d6a7937c17a4d69fc871d5e9221"), from_hex("0x14149055853422bf016065386e8ea0ffb9425b454048e1cd14cfdca457aa7e17"))
}
pub fn fixed_vk_hash() -> Fr {
    from_hex("0x281228e56fbfb62a424c94bda780104c9b5e758b8a02f148ce5e98c2867fdfc1")
}

/// The Translator's polynomials, one per entity, all of the fixed circuit size.
pub struct TranslatorPolys {
    pub cols: Vec<Polynomial<Fr>>,
}

impl TranslatorPolys {
    pub fn zero() -> Self {
        Self { cols: (0..NUM_ALL_ENTITIES).map(|_| Polynomial::zero(CIRCUIT_SIZE)).collect() }
    }
    pub fn col(&self, e: Ent) -> &Polynomial<Fr> {
        &self.cols[e as usize]
    }
    pub fn row(&self, i: usize) -> Vec<Fr> {
        self.cols.iter().map(|c| c.coeffs[i]).collect()
    }
    /// Materialize every shifted column from its source (bb `set_shifted`).
    pub fn set_shifted(&mut self) {
        for e in (13..=98).filter(|e| *e <= 92 || *e >= 93) {
            let s = shift_of(e);
            self.cols[s] = self.cols[e].shifted();
        }
    }
}
