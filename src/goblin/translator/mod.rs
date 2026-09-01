//! The Translator (bb `translator_vm/`): a bn254-Fr circuit that re-computes, in 68-bit limbs, the
//! batched evaluation `Σ_i x^i (op_i + v·Px_i + v²·Py_i + v³·z1_i + v⁴·z2_i)` of the op queue that the
//! ECCVM opened over Grumpkin, tying the two proofs together. The mini circuit (2^13 rows, two per op)
//! is concatenated 16-fold into 2^17-row range-constraint columns.

pub mod builder;
pub mod check;
pub mod key;
pub mod relations;

use crate::base::field::{from_hex, FieldLike};
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
    G1Affine::new_unchecked(
        from_hex("0x1ddbff0e1f0999f88ffa959e9505e5f489b57d6a7937c17a4d69fc871d5e9221"),
        from_hex("0x14149055853422bf016065386e8ea0ffb9425b454048e1cd14cfdca457aa7e17"),
    )
}
pub fn fixed_vk_hash() -> Fr {
    from_hex("0x281228e56fbfb62a424c94bda780104c9b5e758b8a02f148ce5e98c2867fdfc1")
}

/// The Translator's polynomials, one per entity: the wires span the mini circuit, everything
/// else the fixed circuit size (values past a column's end are zero).
#[derive(Clone)]
pub struct TranslatorPolys {
    pub cols: Vec<Polynomial<Fr>>,
}

impl TranslatorPolys {
    pub fn zero() -> Self {
        let wires = FIRST_WIRE..FIRST_WIRE + NUM_WIRES;
        let wire_shifts: Vec<usize> = wires.clone().skip(1).map(shift_of).collect();
        let len = |e: usize| {
            if wires.contains(&e) || wire_shifts.contains(&e) {
                MINI_CIRCUIT_SIZE
            } else {
                CIRCUIT_SIZE
            }
        };
        Self {
            cols: (0..NUM_ALL_ENTITIES).map(|e| Polynomial::zero(len(e))).collect(),
        }
    }
    pub fn col(&self, e: Ent) -> &Polynomial<Fr> {
        &self.cols[e as usize]
    }
    pub fn row(&self, i: usize) -> Vec<Fr> {
        self.cols
            .iter()
            .map(|c| c.coeffs.get(i).copied().unwrap_or_else(Fr::zero))
            .collect()
    }
    /// Materialize every shifted column from its source (bb `set_shifted`).
    pub fn set_shifted(&mut self) {
        for e in (13..=98).filter(|e| *e <= 92 || *e >= 93) {
            let s = shift_of(e);
            self.cols[s] = self.cols[e].shifted();
        }
    }
}

/// Wires of concatenation group `g` (bb `partition_minicircuit_wires_into_groups`): the four groups
/// of 16 range-constraint wires, then the 13 limb wires padded with zeros.
pub fn concatenation_group_wires(g: usize) -> Vec<Option<usize>> {
    if g < 4 {
        (0..CONCATENATION_GROUP_SIZE)
            .map(|j| Some(NUM_OP_QUEUE_WIRES + 13 + g * CONCATENATION_GROUP_SIZE + j))
            .collect()
    } else {
        (0..CONCATENATION_GROUP_SIZE)
            .map(|j| (j < 13).then_some(NUM_OP_QUEUE_WIRES + j))
            .collect()
    }
}

/// bb `get_pcs_unshifted`: the 17 polynomials opened unshifted in the PCS.
pub const PCS_UNSHIFTED: [usize; 17] = [0, 1, 12, 13, 14, 15, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103];
/// bb `get_pcs_to_be_shifted`: the 14 polynomials opened at the shifted point.
pub const PCS_TO_BE_SHIFTED: [usize; 14] = [13, 14, 15, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103];
/// bb `get_pcs_shifted`: the shifted entities whose evaluations are sent (the concatenated shifts are
/// reconstructed from the minicircuit wire shifts instead).
pub const PCS_SHIFTED: [usize; 9] = [104, 105, 106, 184, 185, 186, 187, 188, 189];
/// bb `get_full_circuit_entities`: the 21 evaluations sent as `Sumcheck:evaluations_translator`.
pub const FULL_CIRCUIT_ENTITIES: [usize; 21] = [
    0, 1, 12, 13, 14, 15, 93, 94, 95, 96, 97, 98, 104, 105, 106, 184, 185, 186, 187, 188, 189,
];
pub const NUM_MINICIRCUIT_EVALUATIONS: usize = 2 * NUM_MINICIRCUIT_WIRES;

/// bb `get_minicircuit_wires` then `get_minicircuit_wires_shifted`: the 154 entities whose values are
/// sent after the mini-circuit rounds of sumcheck.
pub fn minicircuit_entities() -> impl Iterator<Item = usize> {
    (FIRST_WIRE + NUM_OP_QUEUE_WIRES..=92).chain(shift_of(FIRST_WIRE + NUM_OP_QUEUE_WIRES)..=shift_of(92))
}

/// The entities of concatenation group `g` (`None` = zero padding), unshifted or shifted.
pub fn concatenation_group_entities(g: usize, shifted: bool) -> Vec<Option<usize>> {
    concatenation_group_wires(g)
        .into_iter()
        .map(|w| {
            w.map(|w| {
                if shifted {
                    shift_of(FIRST_WIRE + w)
                } else {
                    FIRST_WIRE + w
                }
            })
        })
        .collect()
}

/// bb `TranslatorSelectorEvaluations::compute`: the ten Lagrange-type selectors evaluated at the
/// sumcheck challenge, in entity order (`lagrange_first` .. `lagrange_ordered_masking`).
pub fn selector_evaluations<T: FieldLike>(u: &[T]) -> [T; 10] {
    const D: usize = CONST_TRANSLATOR_LOG_N;
    const M: usize = LOG_MINI_CIRCUIT_SIZE;
    const LOG_NUM_MASKED: usize = 2;
    const LOG_RESULT_ROW: usize = 3;
    const LOG_RANDOMNESS_START: usize = 1;
    const LOG_MAX_RANDOM: usize = 6;
    assert_eq!(u.len(), D);
    let c: Vec<T> = u.iter().map(|x| T::one() - x).collect();
    let prod = |v: &[T], range: std::ops::Range<usize>| range.fold(T::one(), |acc, k| acc * &v[k]);
    let u_mp1_m1 = prod(u, LOG_NUM_MASKED + 1..M);
    let u_m_m1 = u[LOG_NUM_MASKED].clone() * &u_mp1_m1;
    let u_rp1_d1 = prod(u, LOG_MAX_RANDOM + 1..D);
    let u_r_d1 = u[LOG_MAX_RANDOM].clone() * &u_rp1_d1;
    let u_0_r1 = prod(u, 0..LOG_MAX_RANDOM);
    let u_0_m1 = prod(u, 0..LOG_NUM_MASKED);
    let c_rp1_m1 = prod(&c, LOG_RESULT_ROW + 1..M);
    let c_r_m1 = c[LOG_RESULT_ROW].clone() * &c_rp1_m1;
    let c_m_d1 = prod(&c, M..D);
    let c_r_d1 = c_r_m1.clone() * &c_m_d1;
    let c_0_r1 = prod(&c, 0..LOG_RESULT_ROW);
    let c_s_r1 = prod(&c, LOG_RANDOMNESS_START..LOG_RESULT_ROW);
    let lagrange_first = c_0_r1.clone() * &c_r_d1;
    let lagrange_last = u_0_r1.clone() * &u_r_d1;
    let lagrange_result_row = c_0_r1 * &u[LOG_RESULT_ROW] * &c_rp1_m1 * &c_m_d1;
    let lagrange_last_in_minicircuit = u_0_m1 * &c[LOG_NUM_MASKED] * &u_mp1_m1 * &c_m_d1;
    let lagrange_real_last = u_0_r1 * &c[LOG_MAX_RANDOM] * &u_rp1_d1;
    let lagrange_ordered_masking = u_r_d1;
    let lagrange_masking = u_m_m1.clone();
    let lagrange_mini_masking = c_r_d1 * &(T::one() - &c_s_r1) + &(u_m_m1.clone() * &c_m_d1);
    let inner_even_odd = T::one() - &c_r_m1 - &u_m_m1;
    let lagrange_even_in_minicircuit = c[0].clone() * &c_m_d1 * &inner_even_odd;
    let lagrange_odd_in_minicircuit = u[0].clone() * &c_m_d1 * &inner_even_odd;
    [
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
    ]
}

/// bb `reconstruct_concatenated_evaluations`: `F(u) = Σ_j L_j(u_top) f_j(u) / L_0(u_top)` over the
/// 16-point Lagrange basis on the top four challenges.
pub fn reconstruct_concatenated_evaluations<T: FieldLike>(groups: &[Vec<T>], u: &[T]) -> [T; NUM_CONCATENATED_POLYS] {
    const NUM_TOP_BITS: usize = 4;
    let basis: Vec<T> = (0..CONCATENATION_GROUP_SIZE)
        .map(|j| {
            (0..NUM_TOP_BITS).fold(T::one(), |acc, bit| {
                let uk = &u[CONST_TRANSLATOR_LOG_N - NUM_TOP_BITS + bit];
                acc * &(if (j >> bit) & 1 == 1 { uk.clone() } else { T::one() - uk })
            })
        })
        .collect();
    let padding_inv = basis[0].invert();
    std::array::from_fn(|g| {
        groups[g]
            .iter()
            .zip(&basis)
            .fold(T::zero(), |acc, (f, l)| acc + &(l.clone() * f))
            * &padding_inv
    })
}

/// bb `set_minicircuit_evaluations` + `complete_full_circuit_evaluations`: assemble the verifier's
/// claimed evaluations of all 190 entities from the transmitted values and the challenge; returns
/// the reconstructed evaluations of the shifted concatenated polynomials (needed by the PCS only).
pub fn complete_evaluations<T: FieldLike>(full_circuit: &[T], minicircuit: &[T], u: &[T]) -> Vec<T> {
    assert_eq!(full_circuit.len(), FULL_CIRCUIT_ENTITIES.len());
    assert_eq!(minicircuit.len(), NUM_MINICIRCUIT_EVALUATIONS);
    let mut evals: Vec<T> = (0..NUM_ALL_ENTITIES).map(|_| T::zero()).collect();
    for (e, v) in FULL_CIRCUIT_ENTITIES.iter().zip(full_circuit) {
        evals[*e] = v.clone();
    }
    for (e, v) in minicircuit_entities().zip(minicircuit) {
        evals[e] = v.clone();
    }
    // bb `complete_claimed_evaluations`: the selector evaluations come first, then the minicircuit
    // wires are scaled by L_0 of the top rounds.
    for (k, v) in selector_evaluations(u).into_iter().enumerate() {
        evals[2 + k] = v;
    }
    let l0 = u[LOG_MINI_CIRCUIT_SIZE..]
        .iter()
        .fold(T::one(), |acc, uk| acc * &(T::one() - uk));
    for e in minicircuit_entities() {
        let scaled = evals[e].clone() * &l0;
        evals[e] = scaled;
    }
    let concat = reconstruct_concatenated_evaluations(&group_evals(&evals, false), u);
    for (g, v) in concat.into_iter().enumerate() {
        evals[FIRST_CONCATENATED + g] = v;
    }
    evals
}

fn group_evals<T: FieldLike>(evals: &[T], shifted: bool) -> Vec<Vec<T>> {
    (0..NUM_CONCATENATED_POLYS)
        .map(|g| {
            concatenation_group_entities(g, shifted)
                .into_iter()
                .map(|e| e.map_or_else(T::zero, |e| evals[e].clone()))
                .collect()
        })
        .collect()
}

/// bb reconstructs the shifted concatenated evaluations at the top of `verify_joint_pcs`, not
/// during the sumcheck evaluation completion.
pub fn concat_shift_evaluations<T: FieldLike>(evals: &[T], u: &[T]) -> [T; NUM_CONCATENATED_POLYS] {
    reconstruct_concatenated_evaluations(&group_evals(evals, true), u)
}
