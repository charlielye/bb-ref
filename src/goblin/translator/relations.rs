//! The eight Translator relations (bb `relations/translator_vm/*_impl.hpp`), written once over
//! `FieldLike` in bb's operation order. A row is the slice of all 190 entity values (`Ent` order).

use super::builder::negative_modulus_limbs;
use super::{Ent, NUM_LIMB_BITS, MICRO_LIMB_BITS};
use crate::base::field::{FieldLike, NativeField};
use crate::base::Fr;
use crate::honk::relations::RelationParams;
use crate::honk::sumcheck::RelationSet;
use Ent::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TranslatorRel {
    Permutation,
    DeltaRange,
    Opcode,
    AccumulatorTransfer,
    Decomposition,
    NonNativeField,
    ZeroConstraints,
    ShiftableFirstCoeffZero,
}

/// bb `TranslatorFlavor::Relations` order.
pub const TRANSLATOR_RELATIONS: [TranslatorRel; 8] = [
    TranslatorRel::Permutation,
    TranslatorRel::DeltaRange,
    TranslatorRel::Opcode,
    TranslatorRel::AccumulatorTransfer,
    TranslatorRel::Decomposition,
    TranslatorRel::NonNativeField,
    TranslatorRel::ZeroConstraints,
    TranslatorRel::ShiftableFirstCoeffZero,
];

impl TranslatorRel {
    pub fn partial_lengths(self) -> Vec<usize> {
        match self {
            TranslatorRel::Permutation => vec![7, 3, 3],
            TranslatorRel::DeltaRange => [vec![6; 5], vec![3; 5]].concat(),
            TranslatorRel::Opcode => vec![6; 5],
            TranslatorRel::AccumulatorTransfer => [vec![4; 4], vec![3; 8]].concat(),
            TranslatorRel::Decomposition => [vec![4; 4], vec![3; 44]].concat(),
            TranslatorRel::NonNativeField => vec![4; 3],
            TranslatorRel::ZeroConstraints => vec![3; 68],
            TranslatorRel::ShiftableFirstCoeffZero => vec![3; 5],
        }
    }
    pub fn num_subrelations(self) -> usize {
        self.partial_lengths().len()
    }
    pub fn accumulate<T: FieldLike<Native = Fr>>(self, acc: &mut [T], r: &[T], p: &RelationParams<T>, scaling: &T) {
        match self {
            TranslatorRel::Permutation => permutation(acc, r, p, scaling),
            TranslatorRel::DeltaRange => delta_range(acc, r, scaling),
            TranslatorRel::Opcode => opcode(acc, r, scaling),
            TranslatorRel::AccumulatorTransfer => accumulator_transfer(acc, r, p, scaling),
            TranslatorRel::Decomposition => decomposition(acc, r, scaling),
            TranslatorRel::NonNativeField => non_native_field(acc, r, p, scaling),
            TranslatorRel::ZeroConstraints => zero_constraints(acc, r, scaling),
            TranslatorRel::ShiftableFirstCoeffZero => shiftable_first_coeff_zero(acc, r, scaling),
        }
    }
}

/// The Translator relations as a sumcheck [`RelationSet`].
pub struct TranslatorRelations;

impl<T: FieldLike<Native = Fr>> RelationSet<T> for TranslatorRelations {
    fn num_relations(&self) -> usize {
        TRANSLATOR_RELATIONS.len()
    }
    fn num_subrelations(&self, r: usize) -> usize {
        TRANSLATOR_RELATIONS[r].num_subrelations()
    }
    fn linearly_independent(&self, _r: usize, _j: usize) -> bool {
        true
    }
    fn offset_only(&self, _r: usize) -> bool {
        false
    }
    fn accumulate(&self, r: usize, acc: &mut [T], row: &[T], p: &RelationParams<T>, scaling: &T) {
        TRANSLATOR_RELATIONS[r].accumulate(acc, row, p, scaling)
    }
    fn partial_length(&self, r: usize) -> usize {
        TRANSLATOR_RELATIONS[r].partial_lengths().into_iter().max().unwrap()
    }
    /// bb `TranslatorFlavor::skip_entire_row`: an unused row of the (mostly empty) fixed-size
    /// trace, where no relation contributes.
    fn skip_row(&self, row0: &[T], row1: &[T]) -> bool {
        let at = |r: &[T], e: Ent| r[e as usize].clone();
        [row0, row1].iter().all(|r| {
            [ordered_range_constraints_0_shift, ordered_range_constraints_1_shift, ordered_range_constraints_2_shift, ordered_range_constraints_3_shift, ordered_range_constraints_4_shift].iter().all(|e| at(r, *e).is_zero())
                && (at(r, z_perm) - &at(r, z_perm_shift)).is_zero()
                && at(r, lagrange_last).is_zero()
        })
    }
    fn skip(&self, r: usize, row0: &[T], row1: &[T]) -> bool {
        let both = |f: &dyn Fn(&[T]) -> bool| f(row0) && f(row1);
        let at = |r: &[T], e: Ent| r[e as usize].clone();
        match TRANSLATOR_RELATIONS[r] {
            TranslatorRel::Permutation => both(&|r: &[T]| (at(r, z_perm) - &at(r, z_perm_shift)).is_zero()),
            TranslatorRel::DeltaRange => both(&|r: &[T]| {
                [(ordered_range_constraints_0, ordered_range_constraints_0_shift), (ordered_range_constraints_1, ordered_range_constraints_1_shift), (ordered_range_constraints_2, ordered_range_constraints_2_shift), (ordered_range_constraints_3, ordered_range_constraints_3_shift), (ordered_range_constraints_4, ordered_range_constraints_4_shift)]
                    .iter()
                    .all(|(e, es)| (at(r, *es) - &at(r, *e)).is_zero())
            }),
            TranslatorRel::Opcode => both(&|r: &[T]| (at(r, lagrange_even_in_minicircuit) + &at(r, lagrange_odd_in_minicircuit)).is_zero()),
            TranslatorRel::AccumulatorTransfer => both(&|r: &[T]| (at(r, lagrange_odd_in_minicircuit) + &at(r, lagrange_last_in_minicircuit) + &at(r, lagrange_result_row)).is_zero()),
            TranslatorRel::Decomposition | TranslatorRel::NonNativeField => both(&|r: &[T]| at(r, lagrange_even_in_minicircuit).is_zero()),
            TranslatorRel::ZeroConstraints => both(&|r: &[T]| (at(r, lagrange_odd_in_minicircuit) + &at(r, lagrange_even_in_minicircuit) + &at(r, lagrange_mini_masking) - &T::one()).is_zero()),
            TranslatorRel::ShiftableFirstCoeffZero => both(&|r: &[T]| at(r, lagrange_first).is_zero()),
        }
    }
}

fn c<T: FieldLike<Native = Fr>>(v: u64) -> T {
    T::constant(Fr::small(v))
}

/// `2^68`, `2^136`, `2^204`: the limb shifts, computed once.
static LIMB_SHIFTS: std::sync::LazyLock<[Fr; 3]> = std::sync::LazyLock::new(|| {
    let s = Fr::from(2u64).pow_u64(NUM_LIMB_BITS as u64);
    [s, s * s, s * s * s]
});
static NEG_MODULUS_LIMBS: std::sync::LazyLock<[Fr; 5]> = std::sync::LazyLock::new(negative_modulus_limbs);

/// bb `TranslatorPermutationRelationImpl::compute_grand_product_numerator`.
pub fn permutation_numerator<T: FieldLike<Native = Fr>>(r: &[T], p: &RelationParams<T>) -> T {
    let v = |e: Ent| r[e as usize].clone();
    let chosen_set = v(lagrange_masking) * &p.beta;
    let chosen_set2 = v(lagrange_ordered_masking) * &p.beta;
    (v(concatenated_range_constraints_0) + &chosen_set + &p.gamma)
        * (v(concatenated_range_constraints_1) + &chosen_set + &p.gamma)
        * (v(concatenated_range_constraints_2) + &chosen_set + &p.gamma)
        * (v(concatenated_range_constraints_3) + &chosen_set + &p.gamma)
        * (v(ordered_extra_range_constraints_numerator) + &chosen_set2 + &p.gamma)
}

/// bb `TranslatorPermutationRelationImpl::compute_grand_product_denominator`.
pub fn permutation_denominator<T: FieldLike<Native = Fr>>(r: &[T], p: &RelationParams<T>) -> T {
    let v = |e: Ent| r[e as usize].clone();
    let chosen_set = v(lagrange_ordered_masking) * &p.beta;
    (v(ordered_range_constraints_0) + &chosen_set + &p.gamma)
        * (v(ordered_range_constraints_1) + &chosen_set + &p.gamma)
        * (v(ordered_range_constraints_2) + &chosen_set + &p.gamma)
        * (v(ordered_range_constraints_3) + &chosen_set + &p.gamma)
        * (v(ordered_range_constraints_4) + &chosen_set + &p.gamma)
}

fn permutation<T: FieldLike<Native = Fr>>(acc: &mut [T], r: &[T], p: &RelationParams<T>, scaling: &T) {
    let v = |e: Ent| r[e as usize].clone();
    acc[0] += ((v(z_perm) + &v(lagrange_first)) * permutation_numerator(r, p) - &((v(z_perm_shift) + &v(lagrange_last)) * permutation_denominator(r, p))) * scaling;
    acc[1] += (v(lagrange_last) * &v(z_perm_shift)) * scaling;
    acc[2] += (v(lagrange_first) * &v(z_perm)) * scaling;
}

const ORDERED: [Ent; 5] = [ordered_range_constraints_0, ordered_range_constraints_1, ordered_range_constraints_2, ordered_range_constraints_3, ordered_range_constraints_4];
const ORDERED_SHIFT: [Ent; 5] = [ordered_range_constraints_0_shift, ordered_range_constraints_1_shift, ordered_range_constraints_2_shift, ordered_range_constraints_3_shift, ordered_range_constraints_4_shift];

fn delta_range<T: FieldLike<Native = Fr>>(acc: &mut [T], r: &[T], scaling: &T) {
    let v = |e: Ent| r[e as usize].clone();
    let maximum_sort_value = -c::<T>((1 << MICRO_LIMB_BITS) - 1);
    let not_last_or_masking = v(lagrange_real_last) + &v(lagrange_ordered_masking) - &T::one();
    for i in 0..5 {
        let delta = v(ORDERED_SHIFT[i]) - &v(ORDERED[i]);
        let mut tmp = delta.clone();
        tmp *= &(delta.clone() - &c(1));
        tmp *= &(delta.clone() - &c(2));
        tmp *= &(delta - &c(3));
        tmp *= &not_last_or_masking;
        tmp *= scaling;
        acc[i] += tmp;
    }
    for i in 0..5 {
        acc[5 + i] += v(lagrange_real_last) * (v(ORDERED[i]) + &maximum_sort_value) * scaling;
    }
}

const ACC: [Ent; 4] = [accumulators_binary_limbs_0, accumulators_binary_limbs_1, accumulators_binary_limbs_2, accumulators_binary_limbs_3];
const ACC_SHIFT: [Ent; 4] = [accumulators_binary_limbs_0_shift, accumulators_binary_limbs_1_shift, accumulators_binary_limbs_2_shift, accumulators_binary_limbs_3_shift];

fn opcode<T: FieldLike<Native = Fr>>(acc: &mut [T], r: &[T], scaling: &T) {
    let v = |e: Ent| r[e as usize].clone();
    let opv = v(Ent::op);
    let even = v(lagrange_even_in_minicircuit);
    let odd = v(lagrange_odd_in_minicircuit);
    let mut tmp = opv.clone() * (opv.clone() - &c(3));
    tmp *= &(opv.clone() - &c(4));
    tmp *= &(opv.clone() - &c(8));
    tmp *= &even;
    tmp += &(opv.clone() * &odd);
    tmp *= scaling;
    acc[0] += tmp;
    for i in 0..4 {
        let mut tmp = v(ACC[i]) - &v(ACC_SHIFT[i]);
        tmp *= &(opv.clone() - &c(3));
        tmp *= &(opv.clone() - &c(4));
        tmp *= &(opv.clone() - &c(8));
        tmp *= &even;
        tmp *= scaling;
        acc[1 + i] += tmp;
    }
}

fn accumulator_transfer<T: FieldLike<Native = Fr>>(acc: &mut [T], r: &[T], p: &RelationParams<T>, scaling: &T) {
    let v = |e: Ent| r[e as usize].clone();
    let odd = v(lagrange_odd_in_minicircuit);
    let last_in_mini = v(lagrange_last_in_minicircuit);
    let result_row = v(lagrange_result_row);
    let is_row_odd_except_last = odd * (last_in_mini.clone() - &T::one());
    for i in 0..4 {
        let mut tmp = v(ACC[i]) - &v(ACC_SHIFT[i]);
        tmp *= &is_row_odd_except_last;
        tmp *= scaling;
        acc[i] += tmp;
    }
    let last_by_scaling = last_in_mini * scaling;
    for i in 0..4 {
        acc[4 + i] += v(ACC[i]) * &last_by_scaling;
    }
    let result_by_scaling = result_row * scaling;
    for i in 0..4 {
        acc[8 + i] += (v(ACC[i]) - &p.accumulated_result[i]) * &result_by_scaling;
    }
}

const RC: [[Ent; 6]; 10] = [
    [p_x_low_limbs_range_constraint_0, p_x_low_limbs_range_constraint_1, p_x_low_limbs_range_constraint_2, p_x_low_limbs_range_constraint_3, p_x_low_limbs_range_constraint_4, p_x_low_limbs_range_constraint_tail],
    [p_x_high_limbs_range_constraint_0, p_x_high_limbs_range_constraint_1, p_x_high_limbs_range_constraint_2, p_x_high_limbs_range_constraint_3, p_x_high_limbs_range_constraint_4, p_x_high_limbs_range_constraint_tail],
    [p_y_low_limbs_range_constraint_0, p_y_low_limbs_range_constraint_1, p_y_low_limbs_range_constraint_2, p_y_low_limbs_range_constraint_3, p_y_low_limbs_range_constraint_4, p_y_low_limbs_range_constraint_tail],
    [p_y_high_limbs_range_constraint_0, p_y_high_limbs_range_constraint_1, p_y_high_limbs_range_constraint_2, p_y_high_limbs_range_constraint_3, p_y_high_limbs_range_constraint_4, p_y_high_limbs_range_constraint_tail],
    [z_low_limbs_range_constraint_0, z_low_limbs_range_constraint_1, z_low_limbs_range_constraint_2, z_low_limbs_range_constraint_3, z_low_limbs_range_constraint_4, z_low_limbs_range_constraint_tail],
    [z_high_limbs_range_constraint_0, z_high_limbs_range_constraint_1, z_high_limbs_range_constraint_2, z_high_limbs_range_constraint_3, z_high_limbs_range_constraint_4, z_high_limbs_range_constraint_tail],
    [accumulator_low_limbs_range_constraint_0, accumulator_low_limbs_range_constraint_1, accumulator_low_limbs_range_constraint_2, accumulator_low_limbs_range_constraint_3, accumulator_low_limbs_range_constraint_4, accumulator_low_limbs_range_constraint_tail],
    [accumulator_high_limbs_range_constraint_0, accumulator_high_limbs_range_constraint_1, accumulator_high_limbs_range_constraint_2, accumulator_high_limbs_range_constraint_3, accumulator_high_limbs_range_constraint_4, accumulator_high_limbs_range_constraint_tail],
    [quotient_low_limbs_range_constraint_0, quotient_low_limbs_range_constraint_1, quotient_low_limbs_range_constraint_2, quotient_low_limbs_range_constraint_3, quotient_low_limbs_range_constraint_4, quotient_low_limbs_range_constraint_tail],
    [quotient_high_limbs_range_constraint_0, quotient_high_limbs_range_constraint_1, quotient_high_limbs_range_constraint_2, quotient_high_limbs_range_constraint_3, quotient_high_limbs_range_constraint_4, quotient_high_limbs_range_constraint_tail],
];
const RC_SHIFT: [[Ent; 6]; 10] = [
    [p_x_low_limbs_range_constraint_0_shift, p_x_low_limbs_range_constraint_1_shift, p_x_low_limbs_range_constraint_2_shift, p_x_low_limbs_range_constraint_3_shift, p_x_low_limbs_range_constraint_4_shift, p_x_low_limbs_range_constraint_tail_shift],
    [p_x_high_limbs_range_constraint_0_shift, p_x_high_limbs_range_constraint_1_shift, p_x_high_limbs_range_constraint_2_shift, p_x_high_limbs_range_constraint_3_shift, p_x_high_limbs_range_constraint_4_shift, p_x_high_limbs_range_constraint_tail_shift],
    [p_y_low_limbs_range_constraint_0_shift, p_y_low_limbs_range_constraint_1_shift, p_y_low_limbs_range_constraint_2_shift, p_y_low_limbs_range_constraint_3_shift, p_y_low_limbs_range_constraint_4_shift, p_y_low_limbs_range_constraint_tail_shift],
    [p_y_high_limbs_range_constraint_0_shift, p_y_high_limbs_range_constraint_1_shift, p_y_high_limbs_range_constraint_2_shift, p_y_high_limbs_range_constraint_3_shift, p_y_high_limbs_range_constraint_4_shift, p_y_high_limbs_range_constraint_tail_shift],
    [z_low_limbs_range_constraint_0_shift, z_low_limbs_range_constraint_1_shift, z_low_limbs_range_constraint_2_shift, z_low_limbs_range_constraint_3_shift, z_low_limbs_range_constraint_4_shift, z_low_limbs_range_constraint_tail_shift],
    [z_high_limbs_range_constraint_0_shift, z_high_limbs_range_constraint_1_shift, z_high_limbs_range_constraint_2_shift, z_high_limbs_range_constraint_3_shift, z_high_limbs_range_constraint_4_shift, z_high_limbs_range_constraint_tail_shift],
    [accumulator_low_limbs_range_constraint_0_shift, accumulator_low_limbs_range_constraint_1_shift, accumulator_low_limbs_range_constraint_2_shift, accumulator_low_limbs_range_constraint_3_shift, accumulator_low_limbs_range_constraint_4_shift, accumulator_low_limbs_range_constraint_tail_shift],
    [accumulator_high_limbs_range_constraint_0_shift, accumulator_high_limbs_range_constraint_1_shift, accumulator_high_limbs_range_constraint_2_shift, accumulator_high_limbs_range_constraint_3_shift, accumulator_high_limbs_range_constraint_4_shift, accumulator_high_limbs_range_constraint_tail_shift],
    [quotient_low_limbs_range_constraint_0_shift, quotient_low_limbs_range_constraint_1_shift, quotient_low_limbs_range_constraint_2_shift, quotient_low_limbs_range_constraint_3_shift, quotient_low_limbs_range_constraint_4_shift, quotient_low_limbs_range_constraint_tail_shift],
    [quotient_high_limbs_range_constraint_0_shift, quotient_high_limbs_range_constraint_1_shift, quotient_high_limbs_range_constraint_2_shift, quotient_high_limbs_range_constraint_3_shift, quotient_high_limbs_range_constraint_4_shift, quotient_high_limbs_range_constraint_tail_shift],
];
const RC_WIDE: [Ent; 4] = [relation_wide_limbs_range_constraint_0, relation_wide_limbs_range_constraint_1, relation_wide_limbs_range_constraint_2, relation_wide_limbs_range_constraint_3];
const RC_WIDE_SHIFT: [Ent; 4] = [relation_wide_limbs_range_constraint_0_shift, relation_wide_limbs_range_constraint_1_shift, relation_wide_limbs_range_constraint_2_shift, relation_wide_limbs_range_constraint_3_shift];
const P_X_LOW: usize = 0;
const P_X_HIGH: usize = 1;
const P_Y_LOW: usize = 2;
const P_Y_HIGH: usize = 3;
const Z_LOW: usize = 4;
const Z_HIGH: usize = 5;
const ACC_LOW: usize = 6;
const ACC_HIGH: usize = 7;
const Q_LOW: usize = 8;
const Q_HIGH: usize = 9;

fn decomposition<T: FieldLike<Native = Fr>>(acc: &mut [T], r: &[T], scaling: &T) {
    let v = |e: Ent| r[e as usize].clone();
    let shift: T = c(1u64 << MICRO_LIMB_BITS);
    let shifts = [T::one(), shift.clone(), shift.sqr(), shift.sqr() * &shift, shift.sqr().sqr(), shift.sqr().sqr() * &shift];
    let even = v(lagrange_even_in_minicircuit);
    let opv = v(Ent::op);
    // Σ_i micro_i · 2^{14 i} − limb, over the given micro-limb entities.
    let recompose = |micro: &[Ent], limb: T| -> T {
        let mut sum = T::zero();
        for (i, m) in micro.iter().enumerate() {
            sum += &(v(*m) * &shifts[i]);
        }
        sum - &limb
    };
    let not_even_or_no_op_scaled = even.clone() * &opv * scaling;
    let mut tmp = recompose(&RC[ACC_LOW][..5], v(accumulators_binary_limbs_0));
    tmp *= &not_even_or_no_op_scaled;
    acc[0] += tmp;
    let mut tmp = recompose(&RC_SHIFT[ACC_LOW][..5], v(accumulators_binary_limbs_1));
    tmp *= &not_even_or_no_op_scaled;
    acc[1] += tmp;
    let mut tmp = recompose(&RC[ACC_HIGH][..5], v(accumulators_binary_limbs_2));
    tmp *= &not_even_or_no_op_scaled;
    acc[2] += tmp;
    let mut tmp = recompose(&RC_SHIFT[ACC_HIGH][..4], v(accumulators_binary_limbs_3));
    tmp *= &not_even_or_no_op_scaled;
    acc[3] += tmp;

    let mut push = |idx: usize, mut tmp: T| {
        tmp *= &even;
        tmp *= scaling;
        acc[idx] += tmp;
    };
    // limb decompositions (subrelations 4..21)
    push(4, recompose(&RC[P_Y_LOW][..5], v(p_y_low_limbs)));
    push(5, recompose(&RC_SHIFT[P_Y_LOW][..5], v(p_y_low_limbs_shift)));
    push(6, recompose(&RC[P_Y_HIGH][..5], v(p_y_high_limbs)));
    push(7, recompose(&RC_SHIFT[P_Y_HIGH][..4], v(p_y_high_limbs_shift)));
    push(8, recompose(&RC[Z_LOW][..5], v(z_low_limbs)));
    push(9, recompose(&RC_SHIFT[Z_LOW][..5], v(z_low_limbs_shift)));
    push(10, recompose(&RC[Z_HIGH][..5], v(z_high_limbs)));
    push(11, recompose(&RC_SHIFT[Z_HIGH][..5], v(z_high_limbs_shift)));
    push(12, recompose(&RC[P_X_LOW][..5], v(p_x_low_limbs)));
    push(13, recompose(&RC_SHIFT[P_X_LOW][..5], v(p_x_low_limbs_shift)));
    push(14, recompose(&RC[P_X_HIGH][..5], v(p_x_high_limbs)));
    push(15, recompose(&RC_SHIFT[P_X_HIGH][..4], v(p_x_high_limbs_shift)));
    push(16, recompose(&RC[Q_LOW][..5], v(quotient_low_binary_limbs)));
    push(17, recompose(&RC_SHIFT[Q_LOW][..5], v(quotient_low_binary_limbs_shift)));
    push(18, recompose(&RC[Q_HIGH][..5], v(quotient_high_binary_limbs)));
    push(19, recompose(&RC_SHIFT[Q_HIGH][..4], v(quotient_high_binary_limbs_shift)));
    let wide_lo = [RC_WIDE[0], RC_WIDE[1], RC_WIDE[2], RC_WIDE[3], p_x_high_limbs_range_constraint_tail_shift, accumulator_high_limbs_range_constraint_tail_shift];
    let wide_hi = [RC_WIDE_SHIFT[0], RC_WIDE_SHIFT[1], RC_WIDE_SHIFT[2], RC_WIDE_SHIFT[3], p_y_high_limbs_range_constraint_tail_shift, quotient_high_limbs_range_constraint_tail_shift];
    push(20, recompose(&wide_lo, v(relation_wide_limbs)));
    push(21, recompose(&wide_hi, v(relation_wide_limbs_shift)));
    // stricter top micro-limb checks (subrelations 22..41): top chunk · 2^{14 - bits} == tail
    let (s12, s10, s8, s4) = (c::<T>(4), c::<T>(16), c::<T>(64), c::<T>(1024));
    let tail_check = |top: Ent, factor: &T, tail: Ent| v(top) * factor - &v(tail);
    push(22, tail_check(RC[P_X_LOW][4], &s12, RC[P_X_LOW][5]));
    push(23, tail_check(RC_SHIFT[P_X_LOW][4], &s12, RC_SHIFT[P_X_LOW][5]));
    push(24, tail_check(RC[P_X_HIGH][4], &s12, RC[P_X_HIGH][5]));
    push(25, tail_check(RC_SHIFT[P_X_HIGH][3], &s8, RC_SHIFT[P_X_HIGH][4]));
    push(26, tail_check(RC[P_Y_LOW][4], &s12, RC[P_Y_LOW][5]));
    push(27, tail_check(RC_SHIFT[P_Y_LOW][4], &s12, RC_SHIFT[P_Y_LOW][5]));
    push(28, tail_check(RC[P_Y_HIGH][4], &s12, RC[P_Y_HIGH][5]));
    push(29, tail_check(RC_SHIFT[P_Y_HIGH][3], &s8, RC_SHIFT[P_Y_HIGH][4]));
    push(30, tail_check(RC[Z_LOW][4], &s12, RC[Z_LOW][5]));
    push(31, tail_check(RC_SHIFT[Z_LOW][4], &s12, RC_SHIFT[Z_LOW][5]));
    push(32, tail_check(RC[Z_HIGH][4], &s4, RC[Z_HIGH][5]));
    push(33, tail_check(RC_SHIFT[Z_HIGH][4], &s4, RC_SHIFT[Z_HIGH][5]));
    push(34, tail_check(RC[ACC_LOW][4], &s12, RC[ACC_LOW][5]));
    push(35, tail_check(RC_SHIFT[ACC_LOW][4], &s12, RC_SHIFT[ACC_LOW][5]));
    push(36, tail_check(RC[ACC_HIGH][4], &s12, RC[ACC_HIGH][5]));
    push(37, tail_check(RC_SHIFT[ACC_HIGH][3], &s8, RC_SHIFT[ACC_HIGH][4]));
    push(38, tail_check(RC[Q_LOW][4], &s12, RC[Q_LOW][5]));
    push(39, tail_check(RC_SHIFT[Q_LOW][4], &s12, RC_SHIFT[Q_LOW][5]));
    push(40, tail_check(RC[Q_HIGH][4], &s12, RC[Q_HIGH][5]));
    push(41, tail_check(RC_SHIFT[Q_HIGH][3], &s10, RC_SHIFT[Q_HIGH][4]));
    // wide limbs from two 68-bit limbs (subrelations 42..47)
    let limb_shift: T = T::constant(LIMB_SHIFTS[0]);
    let pair = |lo: Ent, hi: Ent, wide: Ent| (v(lo) + &(v(hi) * &limb_shift)) - &v(wide);
    push(42, pair(p_x_low_limbs, p_x_low_limbs_shift, x_lo_y_hi));
    push(43, pair(p_x_high_limbs, p_x_high_limbs_shift, x_hi_z_1));
    push(44, pair(p_y_low_limbs, p_y_low_limbs_shift, y_lo_z_2));
    push(45, pair(p_y_high_limbs, p_y_high_limbs_shift, x_lo_y_hi_shift));
    push(46, pair(z_low_limbs, z_high_limbs, x_hi_z_1_shift));
    push(47, pair(z_low_limbs_shift, z_high_limbs_shift, y_lo_z_2_shift));
}

fn non_native_field<T: FieldLike<Native = Fr>>(acc: &mut [T], r: &[T], p: &RelationParams<T>, scaling: &T) {
    let v = |e: Ent| r[e as usize].clone();
    let shift: T = T::constant(LIMB_SHIFTS[0]);
    let shiftx2: T = T::constant(LIMB_SHIFTS[1]);
    let shiftx3: T = T::constant(LIMB_SHIFTS[2]);
    let neg: [T; 5] = std::array::from_fn(|i| T::constant(NEG_MODULUS_LIMBS[i]));
    let x = &p.evaluation_input_x;
    let (v1, v2, v3, v4) = (&p.batching_challenge_v[0], &p.batching_challenge_v[1], &p.batching_challenge_v[2], &p.batching_challenge_v[3]);
    let opv = v(Ent::op);
    let (px0, px1, px2, px3) = (v(p_x_low_limbs), v(p_x_low_limbs_shift), v(p_x_high_limbs), v(p_x_high_limbs_shift));
    let (py0, py1, py2, py3) = (v(p_y_low_limbs), v(p_y_low_limbs_shift), v(p_y_high_limbs), v(p_y_high_limbs_shift));
    let (a0, a1, a2, a3) = (v(ACC[0]), v(ACC[1]), v(ACC[2]), v(ACC[3]));
    let (pa0, pa1, pa2, pa3) = (v(ACC_SHIFT[0]), v(ACC_SHIFT[1]), v(ACC_SHIFT[2]), v(ACC_SHIFT[3]));
    let (z10, z11) = (v(z_low_limbs), v(z_high_limbs));
    let (z20, z21) = (v(z_low_limbs_shift), v(z_high_limbs_shift));
    let (q0, q1, q2, q3) = (v(quotient_low_binary_limbs), v(quotient_low_binary_limbs_shift), v(quotient_high_binary_limbs), v(quotient_high_binary_limbs_shift));
    let (wide_lo, wide_hi) = (v(relation_wide_limbs), v(relation_wide_limbs_shift));
    let even = v(lagrange_even_in_minicircuit);

    let mut tmp = pa0.clone() * &x[0] + &opv + &(px0.clone() * &v1[0]) + &(py0.clone() * &v2[0]) + &(z10.clone() * &v3[0]) + &(z20.clone() * &v4[0]) + &(q0.clone() * &neg[0]) - &a0;
    tmp += &((pa1.clone() * &x[0] + &(pa0.clone() * &x[1]) + &(px0.clone() * &v1[1]) + &(px1.clone() * &v1[0]) + &(py0.clone() * &v2[1]) + &(py1.clone() * &v2[0]) + &(z10.clone() * &v3[1]) + &(z11.clone() * &v3[0]) + &(z20.clone() * &v4[1]) + &(z21.clone() * &v4[0]) + &(q0.clone() * &neg[1]) + &(q1.clone() * &neg[0]) - &a1) * &shift);
    tmp -= &(wide_lo.clone() * &shiftx2);
    tmp *= &(even.clone() * &opv);
    tmp *= scaling;
    acc[0] += tmp;

    let mut tmp = wide_lo + &(pa2.clone() * &x[0]) + &(pa1.clone() * &x[1]) + &(pa0.clone() * &x[2]) + &(px2.clone() * &v1[0]) + &(px1.clone() * &v1[1]) + &(px0.clone() * &v1[2]) + &(py2.clone() * &v2[0]) + &(py1.clone() * &v2[1]) + &(py0.clone() * &v2[2]) + &(z11.clone() * &v3[1]) + &(z10.clone() * &v3[2]) + &(z21.clone() * &v4[1]) + &(z20.clone() * &v4[2]) + &(q2.clone() * &neg[0]) + &(q1.clone() * &neg[1]) + &(q0.clone() * &neg[2]) - &a2;
    tmp += &((pa3.clone() * &x[0] + &(pa2.clone() * &x[1]) + &(pa1.clone() * &x[2]) + &(pa0.clone() * &x[3]) + &(px3.clone() * &v1[0]) + &(px2.clone() * &v1[1]) + &(px1.clone() * &v1[2]) + &(px0.clone() * &v1[3]) + &(py3.clone() * &v2[0]) + &(py2.clone() * &v2[1]) + &(py1.clone() * &v2[2]) + &(py0.clone() * &v2[3]) + &(z11.clone() * &v3[2]) + &(z10.clone() * &v3[3]) + &(z21.clone() * &v4[2]) + &(z20.clone() * &v4[3]) + &(q3.clone() * &neg[0]) + &(q2.clone() * &neg[1]) + &(q1.clone() * &neg[2]) + &(q0.clone() * &neg[3]) - &a3) * &shift);
    tmp -= &(wide_hi * &shiftx2);
    tmp *= &(even.clone() * &opv);
    tmp *= scaling;
    acc[1] += tmp;

    let from_two = |l0: &T, l1: &T| l0.clone() + &(l1.clone() * &shift);
    let from_four = |l0: &T, l1: &T, l2: &T, l3: &T| l0.clone() + &(l1.clone() * &shift) + &(l2.clone() * &shiftx2) + &(l3.clone() * &shiftx3);
    let p_x = from_four(&px0, &px1, &px2, &px3);
    let p_y = from_four(&py0, &py1, &py2, &py3);
    let prev = from_four(&pa0, &pa1, &pa2, &pa3);
    let current = from_four(&a0, &a1, &a2, &a3);
    let z1 = from_two(&z10, &z11);
    let z2 = from_two(&z20, &z21);
    let quotient = from_four(&q0, &q1, &q2, &q3);
    let mut tmp = prev * &x[4] + &opv + &(p_x * &v1[4]) + &(p_y * &v2[4]) + &(z1 * &v3[4]) + &(z2 * &v4[4]) + &(quotient * &neg[4]) - &current;
    tmp *= &(even * &opv);
    tmp *= scaling;
    acc[2] += tmp;
}

/// The entities that must be zero outside the mini circuit (bb `TranslatorZeroConstraintsRelation` order).
static ZERO_CONSTRAINT_ENTITIES: std::sync::LazyLock<Vec<Ent>> = std::sync::LazyLock::new(zero_constraint_entities);

fn zero_constraint_entities() -> Vec<Ent> {
    let mut out = Vec::with_capacity(68);
    for group in RC.iter() {
        out.extend_from_slice(&group[..5]);
    }
    out.extend_from_slice(&RC_WIDE);
    for group in RC.iter() {
        out.push(group[5]);
    }
    out.extend_from_slice(&[op, x_lo_y_hi, x_hi_z_1, y_lo_z_2]);
    out
}

fn zero_constraints<T: FieldLike<Native = Fr>>(acc: &mut [T], r: &[T], scaling: &T) {
    let v = |e: Ent| r[e as usize].clone();
    let not_in_minicircuit_or_masked = (v(lagrange_odd_in_minicircuit) + &v(lagrange_even_in_minicircuit) + &v(lagrange_mini_masking) - &T::one()) * scaling;
    for (i, e) in ZERO_CONSTRAINT_ENTITIES.iter().enumerate() {
        acc[i] += v(*e) * &not_in_minicircuit_or_masked;
    }
}

fn shiftable_first_coeff_zero<T: FieldLike<Native = Fr>>(acc: &mut [T], r: &[T], scaling: &T) {
    let v = |e: Ent| r[e as usize].clone();
    for i in 0..5 {
        acc[i] += v(lagrange_first) * &v(ORDERED[i]) * scaling;
    }
}
