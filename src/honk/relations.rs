//! The Honk relations, each written once over `FieldLike` and shared by the prover (pointwise on
//! extended edges), the native verifier, and the in-circuit verifier.
//!
//! Gate-exactness rule: bodies follow bb's *verifier* operation order (the non-`IsProverAccumulator`
//! branches), since in-circuit every operation is a gate. Sources: `relations/*.hpp`.

use super::flavor::{Ent, Layout, Rel};
use crate::base::field::{from_hex, FieldLike};
use crate::base::poseidon2_params::INTERNAL_MATRIX_DIAGONAL_MINUS_ONE;
use ark_ff::Field;
use Ent::*;

/// bb `RelationParameters` (only the members used by the flavors we port).
#[derive(Clone, Debug)]
pub struct RelationParams<T> {
    pub eta: T,
    pub eta_two: T,
    pub eta_three: T,
    pub rom_logup_gamma: T,
    pub beta: T,
    pub gamma: T,
    pub public_input_delta: T,
    pub beta_sqr: T,
    pub beta_cube: T,
}

impl<T: FieldLike> Default for RelationParams<T> {
    fn default() -> Self {
        let z = T::zero;
        Self { eta: z(), eta_two: z(), eta_three: z(), rom_logup_gamma: z(), beta: z(), gamma: z(), public_input_delta: z(), beta_sqr: z(), beta_cube: z() }
    }
}

/// One row of entity values (or claimed evaluations, or extended-edge points) indexed by entity.
pub struct Row<'a, T> {
    pub vals: &'a [T],
    pub layout: &'a Layout,
}

impl<'a, T> Row<'a, T> {
    pub fn e(&self, e: Ent) -> &T {
        &self.vals[self.layout.idx(e)]
    }
    /// The shift of a to-be-shifted entity.
    pub fn s(&self, e: Ent) -> &T {
        &self.vals[self.layout.shift_idx(e)]
    }
}

impl Rel {
    /// `acc[j] += subrelation_j(row) * scaling` (linearly dependent subrelations ignore `scaling`).
    pub fn accumulate<T: FieldLike>(self, acc: &mut [T], r: &Row<T>, p: &RelationParams<T>, scaling: &T) {
        match self {
            Rel::Permutation => permutation(acc, r, p, scaling),
            Rel::LogDerivLookup => logderiv_lookup(acc, r, p, scaling),
            Rel::Arithmetic => arithmetic(acc, r, scaling),
            Rel::DeltaRange => delta_range(acc, r, scaling),
            Rel::Elliptic => elliptic(acc, r, scaling),
            Rel::Memory => memory(acc, r, p, scaling),
            Rel::NonNativeField => non_native_field(acc, r, scaling),
            Rel::Poseidon2External => poseidon2_external(acc, r, scaling),
            Rel::Poseidon2Internal => poseidon2_internal(acc, r, scaling),
            Rel::Masking => {}
        }
    }
}

fn c<T: FieldLike>(v: u64) -> T {
    T::from_u64(v)
}

// relations/permutation_relation.hpp
fn permutation<T: FieldLike>(acc: &mut [T], r: &Row<T>, p: &RelationParams<T>, scaling: &T) {
    let w1pg = r.e(w_l).clone() + &p.gamma;
    let w2pg = r.e(w_r).clone() + &p.gamma;
    let w3pg = r.e(w_o).clone() + &p.gamma;
    let w4pg = r.e(w_4).clone() + &p.gamma;
    let mut t1 = r.e(id_1).clone() * &p.beta;
    t1 += &w1pg;
    t1 *= scaling;
    let mut t2 = r.e(id_2).clone() * &p.beta;
    t2 += &w2pg;
    let mut t3 = r.e(id_3).clone() * &p.beta;
    t3 += &w3pg;
    let mut t4 = r.e(id_4).clone() * &p.beta;
    t4 += &w4pg;
    let mut t5 = r.e(sigma_1).clone() * &p.beta;
    t5 += &w1pg;
    t5 *= scaling;
    let mut t6 = r.e(sigma_2).clone() * &p.beta;
    t6 += &w2pg;
    let mut t7 = r.e(sigma_3).clone() * &p.beta;
    t7 += &w3pg;
    let mut t8 = r.e(sigma_4).clone() * &p.beta;
    t8 += &w4pg;
    let numerator = t1 * &t2 * &t3 * &t4;
    let denominator = t5 * &t6 * &t7 * &t8;

    let mut public_input_term = r.e(lagrange_last).clone() * &p.public_input_delta;
    public_input_term += r.s(z_perm);
    acc[0] += &((r.e(z_perm).clone() + r.e(lagrange_first)) * &numerator - public_input_term * &denominator);
    acc[1] += &((r.e(lagrange_last).clone() * r.s(z_perm)) * scaling);
    acc[2] += &((r.e(lagrange_first).clone() * r.e(z_perm)) * scaling);
}

/// `table_1 + γ + table_2 β + table_3 β² + table_4 β³`
pub fn table_term<T: FieldLike>(r: &Row<T>, p: &RelationParams<T>) -> T {
    let mut t = (r.e(table_2).clone() * &p.beta) + &(r.e(table_3).clone() * &p.beta_sqr) + &(r.e(table_4).clone() * &p.beta_cube);
    t += r.e(table_1);
    t += &p.gamma;
    t
}

/// `(w_1 + γ + q_r w_1') + β(w_2 + q_m w_2') + β²(w_3 + q_c w_3') + β³ q_o`
pub fn lookup_term<T: FieldLike>(r: &Row<T>, p: &RelationParams<T>) -> T {
    let d1 = (r.e(q_r).clone() * r.s(w_l)) + &(r.e(w_l).clone() + &p.gamma);
    let d2 = (r.e(q_m).clone() * r.s(w_r)) + r.e(w_r);
    let d3 = (r.e(q_c).clone() * r.s(w_o)) + r.e(w_o);
    let table_index_entry = r.e(q_o).clone() * &p.beta_cube;
    let mut t = d2 * &p.beta + &(d3 * &p.beta_sqr);
    t += &(d1 + &table_index_entry);
    t
}

// relations/logderiv_lookup_relation.hpp
fn logderiv_lookup<T: FieldLike>(acc: &mut [T], r: &Row<T>, p: &RelationParams<T>, scaling: &T) {
    let inverses = r.e(lookup_inverses);
    let read_counts = r.e(lookup_read_counts);
    let read_selector = r.e(q_lookup);
    let read_tags = r.e(lookup_read_tags);
    // 1 - (1 - read_tag)(1 - q_lookup)
    let inverse_exists = -(read_tags.clone() * read_selector) + read_tags + read_selector;
    let table_term = table_term(r, p);
    let lookup_term = lookup_term(r, p);

    acc[0] += &((lookup_term.clone() * &table_term * inverses - &inverse_exists) * scaling);
    let mut tmp = read_selector.clone() * &table_term;
    tmp -= &(read_counts.clone() * &lookup_term);
    tmp *= inverses;
    acc[1] += &tmp;
    acc[2] += &((read_tags.clone() * read_tags - read_tags) * scaling);
}

// relations/ultra_arithmetic_relation.hpp
fn arithmetic<T: FieldLike>(acc: &mut [T], r: &Row<T>, scaling: &T) {
    let neg_half = T::constant(-(<T::Native as From<u64>>::from(2)).inverse().unwrap());
    let q_arith_sub_1 = r.e(q_arith).clone() - &c(1);
    let scaled_q_arith = r.e(q_arith).clone() * scaling;
    let tmp0 = (r.e(w_r).clone() * r.e(w_l) * &neg_half) * &((r.e(q_arith).clone() - &c(3)) * r.e(q_m));
    let mut tmp1 = (r.e(q_l).clone() * r.e(w_l)) + &(r.e(q_r).clone() * r.e(w_r)) + &(r.e(q_o).clone() * r.e(w_o)) + &(r.e(q_4).clone() * r.e(w_4)) + r.e(q_c);
    tmp1 += &(q_arith_sub_1.clone() * r.s(w_4));
    acc[0] += &((tmp0 + &tmp1) * &scaled_q_arith);

    let tmp_0 = r.e(w_l).clone() + r.e(w_4) - r.s(w_l) + r.e(q_m);
    let tmp_1 = tmp_0 * &(r.e(q_arith).clone() - &c(2));
    let tmp_2 = q_arith_sub_1 * &scaled_q_arith;
    acc[1] += &(tmp_1 * &tmp_2);
}

// relations/delta_range_constraint_relation.hpp
fn delta_range<T: FieldLike>(acc: &mut [T], r: &Row<T>, scaling: &T) {
    let qs = r.e(q_delta_range).clone() * scaling;
    let deltas = [
        r.e(w_r).clone() - r.e(w_l),
        r.e(w_o).clone() - r.e(w_r),
        r.e(w_4).clone() - r.e(w_o),
        r.s(w_l).clone() - r.e(w_4),
    ];
    for (i, d) in deltas.iter().enumerate() {
        // T = (D - 3) * D;  T * (T + 2) == D(D-1)(D-2)(D-3)
        let mut tmp = (d.clone() - &c(3)) * d;
        tmp *= &(tmp.clone() + &c(2));
        tmp *= &qs;
        acc[i] += &tmp;
    }
}

// relations/elliptic_relation.hpp (Grumpkin: y^2 = x^3 - 17)
fn elliptic<T: FieldLike>(acc: &mut [T], r: &Row<T>, scaling: &T) {
    let curve_b: T = T::constant(-<T::Native as From<u64>>::from(17));
    let x_3 = r.s(w_r);
    let y_1 = r.e(w_o);
    let y_2 = r.s(w_4);
    let x_1 = r.e(w_r);
    let x_2 = r.s(w_l);
    let y_3 = r.s(w_o);
    let q_is_double = r.e(q_m);
    let q_sign = r.e(q_l);

    let x2_sub_x1 = x_2.clone() - x_1;
    let x1_mul_3 = x_1.clone() + x_1 + x_1;
    let x3_sub_x1 = x_3.clone() - x_1;
    let x3_plus_two_x1 = x3_sub_x1.clone() + &x1_mul_3;
    let x3_plus_x2_plus_x1 = x3_plus_two_x1.clone() + &x2_sub_x1;

    let y2_sqr = y_2.sqr();
    let y1_sqr = y_1.sqr();
    let y2_mul_q_sign = y_2.clone() * q_sign;
    let x_add_identity = x3_plus_x2_plus_x1 * &x2_sub_x1.sqr() - &(y2_sqr + &y1_sqr) + &((y2_mul_q_sign.clone() + &y2_mul_q_sign) * y_1);

    let q_elliptic_by_scaling = r.e(q_elliptic).clone() * scaling;
    let q_elliptic_q_double_scaling = q_elliptic_by_scaling.clone() * q_is_double;
    let neg_q_elliptic_not_double_scaling = q_elliptic_q_double_scaling.clone() - &q_elliptic_by_scaling;
    acc[0] -= &(x_add_identity * &neg_q_elliptic_not_double_scaling);

    let y1_plus_y3 = y_1.clone() + y_3;
    let y_diff = y2_mul_q_sign - y_1;
    let y_add_identity = (y1_plus_y3.clone() * &x2_sub_x1) + &(x3_sub_x1.clone() * &y_diff);
    acc[1] -= &(y_add_identity * &neg_q_elliptic_not_double_scaling);

    let x_pow_4_mul_3 = (y1_sqr.clone() - &curve_b) * &x1_mul_3;
    let mut y1_sqr_mul_4 = y1_sqr.clone() + &y1_sqr;
    y1_sqr_mul_4 += &y1_sqr_mul_4.clone();
    let x1_pow_4_mul_9 = x_pow_4_mul_3.clone() + &x_pow_4_mul_3 + &x_pow_4_mul_3;
    let x_double_identity = x3_plus_two_x1 * &y1_sqr_mul_4 - &x1_pow_4_mul_9;
    acc[0] += &(x_double_identity * &q_elliptic_q_double_scaling);

    let x1_sqr_mul_3 = x1_mul_3 * x_1;
    let neg_y_double_identity = x1_sqr_mul_3 * &x3_sub_x1 + &((y_1.clone() + y_1) * &y1_plus_y3);
    acc[1] -= &(neg_y_double_identity * &q_elliptic_q_double_scaling);
}

// relations/memory_relation.hpp
fn memory<T: FieldLike>(acc: &mut [T], r: &Row<T>, p: &RelationParams<T>, scaling: &T) {
    let (w_1, w_2, w_3, w_4v) = (r.e(w_l), r.e(w_r), r.e(w_o), r.e(w_4));
    let (w_1s, w_2s, w_3s, w_4s) = (r.s(w_l), r.s(w_r), r.s(w_o), r.s(w_4));
    let (q_1, q_2, q_3, q_4v, q_mv, q_cv) = (r.e(q_l), r.e(q_r), r.e(q_o), r.e(q_4), r.e(q_m), r.e(q_c));
    let q_mem = r.e(q_memory);

    // qc + w1 η + w2 η₂ + w3 η₃ - w4
    let mut memory_record_check = w_3.clone() * &p.eta_three;
    memory_record_check += &(w_2.clone() * &p.eta_two);
    memory_record_check += &(w_1.clone() * &p.eta);
    memory_record_check += q_cv;
    let partial_record_check = memory_record_check.clone();
    memory_record_check = memory_record_check - w_4v;

    let neg_index_delta = w_1.clone() - w_1s;
    let index_delta_is_zero = neg_index_delta.clone() + &c(1);
    let record_delta = w_4s.clone() - w_4v;
    let index_increases_by_zero_or_one = neg_index_delta.sqr() + &neg_index_delta;
    let adjacent_values_match_if_adjacent_indices_match = index_delta_is_zero.clone() * &record_delta;

    let q_memory_by_scaling = q_mem.clone() * scaling;
    let q_one_by_two = q_1.clone() * q_2;
    let q_one_by_two_by_memory_by_scaling = q_one_by_two.clone() * &q_memory_by_scaling;
    acc[1] += &(adjacent_values_match_if_adjacent_indices_match * &q_one_by_two_by_memory_by_scaling);
    acc[2] += &(index_increases_by_zero_or_one.clone() * &q_one_by_two_by_memory_by_scaling);
    let rom_consistency_check_identity = memory_record_check.clone() * &q_one_by_two;

    // RAM consistency
    let neg_access_type = partial_record_check - w_4v;
    let access_check = neg_access_type.sqr() + &neg_access_type;
    let mut neg_next_gate_access_type = w_3s.clone() * &p.eta_three;
    neg_next_gate_access_type += &(w_2s.clone() * &p.eta_two);
    neg_next_gate_access_type += &(w_1s.clone() * &p.eta);
    neg_next_gate_access_type = neg_next_gate_access_type - w_4s;
    let value_delta = w_3s.clone() - w_3;
    let adjacent_values_match_if_adjacent_indices_match_and_next_access_is_a_read_operation =
        (index_delta_is_zero.clone() * &value_delta) * &(neg_next_gate_access_type.clone() + &c(1));
    let next_gate_access_type_is_boolean = neg_next_gate_access_type.sqr() + &neg_next_gate_access_type;
    let q_3_by_memory_and_scaling = q_3.clone() * &q_memory_by_scaling;
    acc[3] += &(adjacent_values_match_if_adjacent_indices_match_and_next_access_is_a_read_operation * &q_3_by_memory_and_scaling);
    acc[4] += &(index_increases_by_zero_or_one * &q_3_by_memory_and_scaling);
    acc[5] += &(next_gate_access_type_is_boolean * &q_3_by_memory_and_scaling);
    let ram_consistency_check_identity = access_check * &q_3_by_memory_and_scaling;

    // RAM timestamp consistency
    let timestamp_delta = w_2s.clone() - w_2;
    let ram_timestamp_check_identity = index_delta_is_zero * &timestamp_delta - w_3;

    let mut memory_identity = rom_consistency_check_identity;
    memory_identity += &(ram_timestamp_check_identity * &(q_4v.clone() * q_1));
    memory_identity += &(memory_record_check * &(q_mv.clone() * q_1));
    memory_identity *= &q_memory_by_scaling;
    memory_identity += &ram_consistency_check_identity;
    acc[0] += &memory_identity;

    // ROM LogUp
    let one_minus_q_1 = -q_1.clone() + &c(1);
    let q_logup_table = q_2.clone() * &one_minus_q_1;
    let q_logup_read = q_4v.clone() * &one_minus_q_1;
    let q_logup_any = q_logup_table.clone() + &q_logup_read;
    let denom = w_1.clone() + &(w_2.clone() * &p.eta) + &(q_cv.clone() * &p.eta_two) + &p.rom_logup_gamma;
    acc[6] += &(q_memory_by_scaling * &q_logup_any * &(w_4v.clone() * &denom - &c(1)));
    let mut logup_sum_contribution = q_logup_read - &(q_logup_table * w_3);
    logup_sum_contribution *= w_4v;
    logup_sum_contribution *= q_mem;
    acc[7] += &logup_sum_contribution;
}

// relations/non_native_field_relation.hpp
fn non_native_field<T: FieldLike>(acc: &mut [T], r: &Row<T>, scaling: &T) {
    let limb_size: T = T::constant(<T::Native as From<u128>>::from(1u128 << 68));
    let sublimb_shift: T = c(1 << 14);
    let (w_1, w_2, w_3, w_4v) = (r.e(w_l), r.e(w_r), r.e(w_o), r.e(w_4));
    let (w_1s, w_2s, w_3s, w_4s) = (r.s(w_l), r.s(w_r), r.s(w_o), r.s(w_4));
    let (q_2, q_3, q_4v, q_mv) = (r.e(q_r), r.e(q_o), r.e(q_4), r.e(q_m));

    let mut limb_subproduct = w_1.clone() * w_2s + &(w_1s.clone() * w_2);
    let mut gate_2 = w_1.clone() * w_4v + &(w_2.clone() * w_3) - w_3s;
    gate_2 *= &limb_size;
    gate_2 -= w_4s;
    gate_2 += &limb_subproduct;
    let gate_2 = gate_2 * q_4v;

    limb_subproduct *= &limb_size;
    limb_subproduct += &(w_1s.clone() * w_2s);
    let mut gate_1 = limb_subproduct.clone();
    gate_1 -= &(w_3.clone() + w_4v);
    let gate_1 = gate_1 * q_3;

    let mut gate_3 = limb_subproduct;
    gate_3 += w_4v;
    gate_3 -= &(w_3s.clone() + w_4s);
    let gate_3 = gate_3 * q_mv;

    let mut non_native_field_identity = gate_1 + &gate_2 + &gate_3;
    non_native_field_identity *= q_2;

    let mut limb_accumulator_1 = w_2s.clone() * &sublimb_shift;
    limb_accumulator_1 += w_1s;
    limb_accumulator_1 *= &sublimb_shift;
    limb_accumulator_1 += w_3;
    limb_accumulator_1 *= &sublimb_shift;
    limb_accumulator_1 += w_2;
    limb_accumulator_1 *= &sublimb_shift;
    limb_accumulator_1 += w_1;
    limb_accumulator_1 -= w_4v;
    let limb_accumulator_1 = limb_accumulator_1 * q_4v;

    let mut limb_accumulator_2 = w_3s.clone() * &sublimb_shift;
    limb_accumulator_2 += w_2s;
    limb_accumulator_2 *= &sublimb_shift;
    limb_accumulator_2 += w_1s;
    limb_accumulator_2 *= &sublimb_shift;
    limb_accumulator_2 += w_4v;
    limb_accumulator_2 *= &sublimb_shift;
    limb_accumulator_2 += w_3;
    limb_accumulator_2 -= w_4s;
    let limb_accumulator_2 = limb_accumulator_2 * q_mv;

    let mut limb_accumulator_identity = limb_accumulator_1 + &limb_accumulator_2;
    limb_accumulator_identity *= q_3;

    let q_nnf_by_scaling = r.e(q_nnf).clone() * scaling;
    let mut nnf_identity = non_native_field_identity + &limb_accumulator_identity;
    nnf_identity *= &q_nnf_by_scaling;
    acc[0] += &nnf_identity;
}

fn sbox<T: FieldLike>(x: T) -> T {
    x.sqr().sqr() * &x
}

// relations/poseidon2_external_relation.hpp
fn poseidon2_external<T: FieldLike>(acc: &mut [T], r: &Row<T>, scaling: &T) {
    let u1 = sbox(r.e(w_l).clone() + r.e(q_l));
    let u2 = sbox(r.e(w_r).clone() + r.e(q_r));
    let u3 = sbox(r.e(w_o).clone() + r.e(q_o));
    let u4 = sbox(r.e(w_4).clone() + r.e(q_4));
    let t0 = u1.clone() + &u2;
    let t1 = u3.clone() + &u4;
    let mut t2 = u2.clone() + &u2;
    t2 += &t1;
    let mut t3 = u4.clone() + &u4;
    t3 += &t0;
    let mut v4 = t1.clone() + &t1;
    v4 += &v4.clone();
    v4 += &t3;
    let mut v2 = t0.clone() + &t0;
    v2 += &v2.clone();
    v2 += &t2;
    let v1 = t3 + &v2;
    let v3 = t2 + &v4;
    let q_pos_by_scaling = r.e(q_poseidon2_external).clone() * scaling;
    acc[0] += &(q_pos_by_scaling.clone() * &(v1 - r.s(w_l)));
    acc[1] += &(q_pos_by_scaling.clone() * &(v2 - r.s(w_r)));
    acc[2] += &(q_pos_by_scaling.clone() * &(v3 - r.s(w_o)));
    acc[3] += &(q_pos_by_scaling * &(v4 - r.s(w_4)));
}

// relations/poseidon2_internal_relation.hpp
fn poseidon2_internal<T: FieldLike>(acc: &mut [T], r: &Row<T>, scaling: &T) {
    let d_minus_1: [T; 4] = INTERNAL_MATRIX_DIAGONAL_MINUS_ONE.map(|h| T::constant(from_hex(h)));
    let d1 = d_minus_1[0].clone() + &c(1);
    let s1 = r.e(w_l).clone() + r.e(q_l);
    let mut u1 = s1.sqr();
    u1 = u1.sqr();
    u1 *= &s1;
    let q_pos_by_scaling = r.e(q_poseidon2_internal).clone() * scaling;
    let partial_sum = r.e(w_r).clone() + r.e(w_o) + r.e(w_4);
    let scaled_u1 = u1 * &q_pos_by_scaling;

    let mut term = scaled_u1.clone() * &d1;
    term += &((partial_sum.clone() - r.s(w_l)) * &q_pos_by_scaling);
    acc[0] += &term;
    let v2 = r.e(w_r).clone() * &d_minus_1[1] + &partial_sum - r.s(w_r);
    acc[1] += &(v2 * &q_pos_by_scaling + &scaled_u1);
    let v3 = r.e(w_o).clone() * &d_minus_1[2] + &partial_sum - r.s(w_o);
    acc[2] += &(v3 * &q_pos_by_scaling + &scaled_u1);
    let v4 = r.e(w_4).clone() * &d_minus_1[3] + &partial_sum - r.s(w_4);
    acc[3] += &(v4 * &q_pos_by_scaling + &scaled_u1);
}
