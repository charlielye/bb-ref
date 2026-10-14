//! The Honk relations, each written once over `FieldLike` and shared by the prover (pointwise on
//! extended edges), the native verifier, and the in-circuit verifier.
//!
//! Gate-exactness rule: bodies follow bb's *verifier* operation order (the non-`IsProverAccumulator`
//! branches), since in-circuit every operation is a gate. Sources: `relations/*.hpp`.

use super::flavor::{Ent, Layout, Rel, BUS_SPECS};
use super::quad_params::quad_params;
use crate::base::field::{from_hex, FieldLike, NativeField};
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
    pub beta_quartic: T,
    /// ECCVM set relation: the inverse of the product the four inactive-row wNAF terms contribute.
    pub eccvm_set_permutation_delta: T,
    /// Translator: `x` as four 68-bit limbs plus the native value.
    pub evaluation_input_x: [T; 5],
    /// Translator: `v, v², v³, v⁴`, each as four 68-bit limbs plus the native value.
    pub batching_challenge_v: [[T; 5]; 4],
    /// Translator: the claimed accumulation result as four 68-bit limbs.
    pub accumulated_result: [T; 4],
    /// Prover only: `quad_batching_constants` of the Poseidon2 quad relations (QuadInternal,
    /// QuadInternalTerminal, TransitionEntry) for this sumcheck's separators; empty elsewhere.
    pub quad_batching: Vec<Vec<T>>,
}

impl<T: FieldLike> Default for RelationParams<T> {
    fn default() -> Self {
        let z = T::zero;
        Self {
            eta: z(),
            eta_two: z(),
            eta_three: z(),
            rom_logup_gamma: z(),
            beta: z(),
            gamma: z(),
            public_input_delta: z(),
            beta_sqr: z(),
            beta_cube: z(),
            beta_quartic: z(),
            eccvm_set_permutation_delta: z(),
            evaluation_input_x: std::array::from_fn(|_| z()),
            batching_challenge_v: std::array::from_fn(|_| std::array::from_fn(|_| z())),
            accumulated_result: std::array::from_fn(|_| z()),
            quad_batching: Vec::new(),
        }
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
            Rel::BilinearBatchedEq => bilinear_batched_eq(acc, r, scaling),
            Rel::EccOpQueue => ecc_op_queue(acc, r, scaling),
            Rel::MegaEccOpBoundary => mega_ecc_op_boundary(acc, r, scaling),
            Rel::Bus(b) => bus_lookup(b, acc, r, p, scaling),
            Rel::Poseidon2InitialExternal => poseidon2_initial_external(acc, r, scaling),
            Rel::Poseidon2QuadInternal | Rel::Poseidon2QuadInternalTerminal | Rel::Poseidon2TransitionEntry
                if T::IS_PROVER && !p.quad_batching.is_empty() =>
            {
                quad_batched(self, acc, r, &p.quad_batching, scaling)
            }
            Rel::Poseidon2QuadInternal => poseidon2_quad_internal(acc, r, scaling),
            Rel::Poseidon2QuadInternalTerminal => poseidon2_quad_internal_terminal(acc, r, scaling),
            Rel::Poseidon2TransitionEntry => poseidon2_transition_entry(acc, r, scaling),
        }
    }
}

fn c<T: FieldLike>(v: u64) -> T {
    T::constant(T::Native::small(v))
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
    // bb `UltraPermutationRelationImpl::accumulate`: the prover pairs the factors, (t1·t2)·(t3·t4),
    // so its short-product formulas apply (3 + 3 + 6 multiplications instead of the chain's
    // 4 + 6 + 8); the verifier circuit keeps the left-to-right chain, which fixes its gates.
    let (numerator, denominator) = if T::IS_PROVER {
        ((t1 * &t2) * &(t3 * &t4), (t5 * &t6) * &(t7 * &t8))
    } else {
        (t1 * &t2 * &t3 * &t4, t5 * &t6 * &t7 * &t8)
    };

    let mut public_input_term = r.e(lagrange_last).clone() * &p.public_input_delta;
    public_input_term += r.s(z_perm);
    acc[0] += &((r.e(z_perm).clone() + r.e(lagrange_first)) * &numerator - public_input_term * &denominator);
    acc[1] += &((r.e(lagrange_last).clone() * r.s(z_perm)) * scaling);
    acc[2] += &((r.e(lagrange_first).clone() * r.e(z_perm)) * scaling);
}

/// `table_1 + γ + table_2 β + table_3 β² + table_4 β³`
pub fn table_term<T: FieldLike>(r: &Row<T>, p: &RelationParams<T>) -> T {
    let mut t = (r.e(table_2).clone() * &p.beta)
        + &(r.e(table_3).clone() * &p.beta_sqr)
        + &(r.e(table_4).clone() * &p.beta_cube);
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
    let lookup_term = lookup_term(r, p);
    let table_term = table_term(r, p);

    acc[0] += &((lookup_term.clone() * &table_term * inverses - &inverse_exists) * scaling);
    let mut tmp = read_selector.clone() * &table_term;
    tmp -= &(read_counts.clone() * &lookup_term);
    tmp *= inverses;
    acc[1] += &tmp;
    acc[2] += &((read_tags.clone() * read_tags - read_tags) * scaling);
}

// relations/ultra_arithmetic_relation.hpp
fn arithmetic<T: FieldLike>(acc: &mut [T], r: &Row<T>, scaling: &T) {
    // -1/2 in T's native field, computed once (an inversion per call dominated the relation)
    static NEG_HALF_FR: std::sync::LazyLock<crate::base::Fr> =
        std::sync::LazyLock::new(|| -(crate::base::Fr::from(2u64)).inverse().unwrap());
    // Prover fast path for q_arith ≡ 1 on the edge (bb's common arithmetic gate): subrelation 1
    // carries q_arith − 1 and vanishes, (q_arith − 3)·(−1/2) = 1 and the w_4 shift term drops.
    if is_const(r.e(q_arith), 1) {
        let mut id = r.e(q_m).clone() * r.e(w_r) * r.e(w_l) + &(r.e(q_l).clone() * r.e(w_l));
        id += &(r.e(q_r).clone() * r.e(w_r));
        id += &(r.e(q_o).clone() * r.e(w_o));
        id += &(r.e(q_4).clone() * r.e(w_4));
        id += r.e(q_c);
        acc[0] += &(id * scaling);
        return;
    }
    let neg_half = k::<T>(*NEG_HALF_FR);
    let q_arith_sub_1 = r.e(q_arith).clone() - &c(1);
    let scaled_q_arith = r.e(q_arith).clone() * scaling;
    let tmp0 = (r.e(w_r).clone() * r.e(w_l) * &neg_half) * &((r.e(q_arith).clone() - &c(3)) * r.e(q_m));
    let mut tmp1 = (r.e(q_l).clone() * r.e(w_l))
        + &(r.e(q_r).clone() * r.e(w_r))
        + &(r.e(q_o).clone() * r.e(w_o))
        + &(r.e(q_4).clone() * r.e(w_4))
        + r.e(q_c);
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
    let x_add_identity =
        x3_plus_x2_plus_x1 * &x2_sub_x1.sqr() - &(y2_sqr + &y1_sqr) + &((y2_mul_q_sign.clone() + &y2_mul_q_sign) * y_1);

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

/// Prover-side: `v` is the constant `k` on the whole edge (never in-circuit).
fn is_const<T: FieldLike>(v: &T, k: u64) -> bool {
    T::IS_PROVER && v.as_const() == Some(T::Native::small(k))
}

/// `acc += t` over the live terms of a sum (`None`: no live term yet).
fn add_live<T: FieldLike>(acc: &mut Option<T>, t: T) {
    match acc {
        Some(a) => *a += &t,
        None => *acc = Some(t),
    }
}

// relations/memory_relation.hpp
fn memory<T: FieldLike>(acc: &mut [T], r: &Row<T>, p: &RelationParams<T>, scaling: &T) {
    let (w_1, w_2, w_3, w_4v) = (r.e(w_l), r.e(w_r), r.e(w_o), r.e(w_4));
    let (w_1s, w_2s, w_3s, w_4s) = (r.s(w_l), r.s(w_r), r.s(w_o), r.s(w_4));
    let (q_1, q_2, q_3, q_4v, q_mv, q_cv) = (r.e(q_l), r.e(q_r), r.e(q_o), r.e(q_4), r.e(q_m), r.e(q_c));
    let q_mem = r.e(q_memory);
    // Prover: a gate type whose selector product vanishes on the whole edge contributes exact
    // zeros, so its terms are not computed. In-circuit every type is live, in bb's order.
    let live = |v: &T| !is_const(v, 0);
    let (rom, ram) = (live(q_1) && live(q_2), live(q_3));
    let (timestamp, record) = (live(q_1) && live(q_4v), live(q_1) && live(q_mv));
    let logup = !is_const(q_1, 1) && (live(q_2) || live(q_4v));

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
    let adjacent_values_match_if_adjacent_indices_match = rom.then(|| index_delta_is_zero.clone() * &record_delta);

    let q_memory_by_scaling = q_mem.clone() * scaling;
    let rom_consistency_check_identity = adjacent_values_match_if_adjacent_indices_match.map(|adjacent| {
        let q_one_by_two = q_1.clone() * q_2;
        let q_one_by_two_by_memory_by_scaling = q_one_by_two.clone() * &q_memory_by_scaling;
        acc[1] += &(adjacent * &q_one_by_two_by_memory_by_scaling);
        acc[2] += &(index_increases_by_zero_or_one.clone() * &q_one_by_two_by_memory_by_scaling);
        memory_record_check.clone() * &q_one_by_two
    });

    // RAM consistency
    let ram_consistency_check_identity = ram.then(|| {
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
        acc[3] += &(adjacent_values_match_if_adjacent_indices_match_and_next_access_is_a_read_operation
            * &q_3_by_memory_and_scaling);
        acc[4] += &(index_increases_by_zero_or_one * &q_3_by_memory_and_scaling);
        acc[5] += &(next_gate_access_type_is_boolean * &q_3_by_memory_and_scaling);
        access_check * &q_3_by_memory_and_scaling
    });

    // RAM timestamp consistency
    let mut memory_identity = rom_consistency_check_identity;
    if timestamp {
        let timestamp_delta = w_2s.clone() - w_2;
        let ram_timestamp_check_identity = index_delta_is_zero * &timestamp_delta - w_3;
        add_live(&mut memory_identity, ram_timestamp_check_identity * &(q_4v.clone() * q_1));
    }
    if record {
        add_live(&mut memory_identity, memory_record_check * &(q_mv.clone() * q_1));
    }
    if let Some(m) = memory_identity.as_mut() {
        *m *= &q_memory_by_scaling;
    }
    if let Some(ram) = ram_consistency_check_identity {
        add_live(&mut memory_identity, ram);
    }
    if let Some(m) = memory_identity {
        acc[0] += &m;
    }

    // ROM LogUp
    if logup {
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
    x.pow5()
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

/// A bn254 scalar constant lifted into the relation's field type.
fn k<T: FieldLike>(v: crate::base::Fr) -> T {
    T::constant(T::Native::from_fr(v))
}

/// bb `bilinear_or_batched_eq_check_relation.hpp`: `q_bilinear_batched_eq` selects the bilinear
/// gate (1) or two independent linear equalities (2).
fn bilinear_batched_eq<T: FieldLike>(acc: &mut [T], r: &Row<T>, scaling: &T) {
    let q_cp = r.e(q_bilinear_batched_eq);
    let (w1, w2, w3, w4) = (r.e(w_l), r.e(w_r), r.e(w_o), r.e(w_4));
    let two_minus_q_cp = -q_cp.clone() + c::<T>(2);
    let q_cp_minus_1 = q_cp.clone() - c::<T>(1);
    let bilinear_gate = q_cp.clone() * &two_minus_q_cp;
    static HALF: std::sync::LazyLock<crate::base::Fr> =
        std::sync::LazyLock::new(|| crate::base::Fr::from(2u64).invert());
    let batched_eq_gate = q_cp.clone() * &q_cp_minus_1 * &k::<T>(*HALF);
    let scaled_bilinear_gate = bilinear_gate * scaling;
    let scaled_batched_eq_gate = batched_eq_gate * scaling;
    let products = r.e(q_m).clone() * w1 * w2 + r.e(q_5).clone() * w1 * w3;
    let linears =
        r.e(q_l).clone() * w1 + r.e(q_r).clone() * w2 + r.e(q_o).clone() * w3 + r.e(q_4).clone() * w4 + r.e(q_c);
    let bilinear = products + &linears;
    let batched_eq_half_1 = r.e(q_l).clone() * w1 + r.e(q_r).clone() * w2 + r.e(q_c);
    acc[0] += scaled_bilinear_gate * &bilinear + scaled_batched_eq_gate.clone() * &batched_eq_half_1;
    let batched_eq_half_2 = r.e(q_o).clone() * w3 + r.e(q_4).clone() * w4 + r.e(q_m);
    acc[1] += scaled_batched_eq_gate * &batched_eq_half_2;
}

/// bb `ecc_op_queue_relation.hpp`: the op wires copy the shifted wires on the ecc-op rows and
/// vanish elsewhere.
fn ecc_op_queue<T: FieldLike>(acc: &mut [T], r: &Row<T>, scaling: &T) {
    let lagrange_by_scaling = r.e(lagrange_ecc_op).clone() * scaling;
    let complement_by_scaling = -lagrange_by_scaling.clone() + scaling;
    let op = [ecc_op_wire_1, ecc_op_wire_2, ecc_op_wire_3, ecc_op_wire_4];
    let wires = [w_l, w_r, w_o, w_4];
    for i in 0..4 {
        let mut tmp = r.e(op[i]).clone() - r.s(wires[i]);
        tmp *= &lagrange_by_scaling;
        acc[i] += tmp;
    }
    for i in 0..4 {
        acc[4 + i] += r.e(op[i]).clone() * &complement_by_scaling;
    }
}

/// bb `MegaEccOpBoundaryRelation`: the op wires vanish on the offset rows (applied with the `L` factor).
fn mega_ecc_op_boundary<T: FieldLike>(acc: &mut [T], r: &Row<T>, scaling: &T) {
    for (i, e) in [ecc_op_wire_1, ecc_op_wire_2, ecc_op_wire_3, ecc_op_wire_4]
        .iter()
        .enumerate()
    {
        acc[i] += r.e(*e).clone() * scaling;
    }
}

/// bb `databus_lookup_relation.hpp` for one bus column.
fn bus_lookup<T: FieldLike>(bus: usize, acc: &mut [T], r: &Row<T>, p: &RelationParams<T>, scaling: &T) {
    let b = &BUS_SPECS[bus];
    let inverses = r.e(b.inverses);
    let read_counts = r.e(b.read_counts);
    let lookup_term = r.e(w_r).clone() * &p.beta + r.e(w_l) + &p.gamma;
    let table_term = r.e(databus_id).clone() * &p.beta + r.e(b.value) + &p.gamma;
    let read_selector = r.e(q_busread).clone() * r.e(b.selector);
    let common = lookup_term.clone() * &table_term * inverses - c::<T>(1);
    acc[0] += (common.clone() * &read_selector) * scaling;
    acc[1] += (common * read_counts) * scaling;
    let mut tmp = read_selector * &table_term;
    tmp -= read_counts.clone() * &lookup_term;
    tmp *= inverses;
    acc[2] += tmp;
    let indicator = r.e(b.indicator);
    acc[3] += (read_counts.clone() - indicator.clone() * read_counts) * scaling;
}

/// bb `poseidon2_initial_external_relation.hpp`: the next row holds `M_E · (w_l, w_r, w_o, w_4)`.
fn poseidon2_initial_external<T: FieldLike>(acc: &mut [T], r: &Row<T>, scaling: &T) {
    let (x0, x1, x2, x3) = (r.e(w_l), r.e(w_r), r.e(w_o), r.e(w_4));
    let q_by_scaling = r.e(q_poseidon2_external_initial).clone() * scaling;
    let t0 = x0.clone() + x1;
    let t1 = x2.clone() + x3;
    let t2 = x1.clone() + x1 + &t1;
    let t3 = x3.clone() + x3 + &t0;
    let mut y3 = t1.clone() + &t1;
    y3 = y3.clone() + &y3 + &t3;
    let mut y1 = t0.clone() + &t0;
    y1 = y1.clone() + &y1 + &t2;
    let y0 = t3 + &y1;
    let y2 = t2 + &y3;
    acc[0] += q_by_scaling.clone() * (y0 - r.s(w_l));
    acc[1] += q_by_scaling.clone() * (y1 - r.s(w_r));
    acc[2] += q_by_scaling.clone() * (y2 - r.s(w_o));
    acc[3] += q_by_scaling * (y3 - r.s(w_4));
}

fn pow5<T: FieldLike>(x: T) -> T {
    x.pow5()
}

/// bb `poseidon2_quad_internal_relation.hpp`: four internal rounds per row, linked to the next
/// compressed row through the forward Vandermonde encoding of the hidden lanes.
fn poseidon2_quad_internal<T: FieldLike>(acc: &mut [T], r: &Row<T>, scaling: &T) {
    let qp = quad_params();
    let (wl, wr, wo, w4) = (r.e(w_l), r.e(w_r), r.e(w_o), r.e(w_4));
    let (wl_s, wr_s, wo_s, w4_s) = (r.s(w_l), r.s(w_r), r.s(w_o), r.s(w_4));
    let d1 = k::<T>(qp.d1);
    let u_0 = pow5(wl.clone() + r.e(q_l));
    let u_1 = pow5(wr.clone() + r.e(q_r));
    let u_2 = pow5(wo.clone() + r.e(q_o));
    let u_3 = pow5(w4.clone() + r.e(q_4));
    let u_0_next = pow5(wl_s.clone() + r.e(q_m));
    let u_1_next = pow5(wr_s.clone() + r.e(q_c));
    let u_2_next = pow5(wo_s.clone() + r.e(q_5));
    let u_0_next_d1 = u_0_next.clone() * &d1;
    let cf0 = &qp.closed_form[0];
    let [l0, l1, l2] = &qp.forward_vandermonde_lhs;
    let wires = |row: &[crate::base::Fr; 7]| {
        wr.clone() * &k::<T>(row[0]) + wo.clone() * &k::<T>(row[1]) + w4.clone() * &k::<T>(row[2])
    };
    let us = |row: &[crate::base::Fr; 7]| {
        u_0.clone() * &k::<T>(row[3])
            + u_1.clone() * &k::<T>(row[4])
            + u_2.clone() * &k::<T>(row[5])
            + u_3.clone() * &k::<T>(row[6])
    };
    let wp0_full = wires(cf0) - wl_s;
    let wp1_full = wires(l0) - wr_s;
    let wp2_full = wires(l1) - wo_s + wr_s + wr_s;
    let wp3_full = wires(l2) - w4_s + wo_s + wr_s.clone() * &k::<T>(qp.sigma_plus_2);
    let q_times_scaling = r.e(q_poseidon2_quad_internal).clone() * scaling;
    let a0_body = us(cf0) + &wp0_full;
    acc[0] += q_times_scaling.clone() * &a0_body;
    let a1_body = us(l0) + &u_0_next_d1 + &wp1_full;
    acc[1] += q_times_scaling.clone() * &a1_body;
    let a2_body = us(l1) - (u_0_next_d1.clone() + &u_0_next_d1)
        + (u_0_next.clone() + &u_0_next + &u_0_next)
        + u_1_next.clone() * &d1
        + &wp2_full;
    acc[2] += q_times_scaling.clone() * &a2_body;
    let a3_body =
        us(l2) - u_0_next * &k::<T>(qp.b3_u0_coef) - u_1_next * &k::<T>(qp.d1_minus_3) + u_2_next * &d1 + &wp3_full;
    acc[3] += q_times_scaling * &a3_body;
}

/// bb `poseidon2_quad_internal_terminal_relation.hpp`: the last compressed row; the successor is
/// standard-encoded.
fn poseidon2_quad_internal_terminal<T: FieldLike>(acc: &mut [T], r: &Row<T>, scaling: &T) {
    let qp = quad_params();
    let (wl, wr, wo, w4) = (r.e(w_l), r.e(w_r), r.e(w_o), r.e(w_4));
    let u_0 = pow5(wl.clone() + r.e(q_l));
    let u_1 = pow5(wr.clone() + r.e(q_r));
    let u_2 = pow5(wo.clone() + r.e(q_o));
    let u_3 = pow5(w4.clone() + r.e(q_4));
    let cf = &qp.closed_form;
    let shifts = [r.s(w_l), r.s(w_r), r.s(w_o), r.s(w_4)];
    // bb's order: all wire terms, the selector scaling, all bodies, then the accumulations
    let wps: Vec<T> = (0..4)
        .map(|j| {
            wr.clone() * &k::<T>(cf[j][0]) + wo.clone() * &k::<T>(cf[j][1]) + w4.clone() * &k::<T>(cf[j][2]) - shifts[j]
        })
        .collect();
    let q_by_scaling = r.e(q_poseidon2_quad_internal_terminal).clone() * scaling;
    let bodies: Vec<T> = (0..4)
        .map(|j| {
            let u3_term = if j == 0 {
                u_3.clone() * &k::<T>(cf[0][6])
            } else {
                u_3.clone()
            };
            u_0.clone() * &k::<T>(cf[j][3])
                + u_1.clone() * &k::<T>(cf[j][4])
                + u_2.clone() * &k::<T>(cf[j][5])
                + u3_term
                + &wps[j]
        })
        .collect();
    for j in 0..4 {
        acc[j] += q_by_scaling.clone() * &bodies[j];
    }
}

/// bb `poseidon2_transition_entry_relation.hpp`: standard-encoded row followed by the first
/// compressed row.
fn poseidon2_transition_entry<T: FieldLike>(acc: &mut [T], r: &Row<T>, scaling: &T) {
    let qp = quad_params();
    let (wl, wr, wo, w4) = (r.e(w_l), r.e(w_r), r.e(w_o), r.e(w_4));
    let (wr_s, wo_s, w4_s) = (r.s(w_r), r.s(w_o), r.s(w_4));
    let d1 = k::<T>(qp.d1);
    let u_0 = pow5(wl.clone() + r.e(q_l));
    let u_1 = pow5(wr_s.clone() + r.e(q_r));
    let u_2 = pow5(wo_s.clone() + r.e(q_o));
    let q_by_scaling = r.e(q_poseidon2_transition_entry).clone() * scaling;
    let wp_0 = wr.clone() + wo + w4 - wr_s;
    let wp_1 =
        wr.clone() * &k::<T>(qp.a_one[0]) + wo.clone() * &k::<T>(qp.a_one[1]) + w4.clone() * &k::<T>(qp.a_one[2])
            - wo_s;
    let wp_2 =
        wr.clone() * &k::<T>(qp.a2_one[0]) + wo.clone() * &k::<T>(qp.a2_one[1]) + w4.clone() * &k::<T>(qp.a2_one[2])
            - w4_s;
    let a0_body = u_0.clone() * &d1 + &wp_0;
    acc[0] += q_by_scaling.clone() * &a0_body;
    let a1_body = u_1.clone() * &d1 + u_0.clone() * &c::<T>(3) + &wp_1;
    acc[1] += q_by_scaling.clone() * &a1_body;
    let a2_body = u_2 * &d1 + u_1 * &c::<T>(3) + u_0 * &k::<T>(qp.sum_a_one) + &wp_2;
    acc[2] += q_by_scaling * &a2_body;
}

/// S-box inputs `(wire, shifted, constant selector)` and linear wires `(wire, shifted)` of the
/// Poseidon2 quad relations' bodies (the terminal relation's S-boxes are the first four).
const QUAD_SBOX: [(Ent, bool, Ent); 7] = [
    (w_l, false, q_l),
    (w_r, false, q_r),
    (w_o, false, q_o),
    (w_4, false, q_4),
    (w_l, true, q_m),
    (w_r, true, q_c),
    (w_o, true, q_5),
];
const QUAD_WIRES: [(Ent, bool); 7] =
    [(w_r, false), (w_o, false), (w_4, false), (w_l, true), (w_r, true), (w_o, true), (w_4, true)];
const ENTRY_SBOX: [(Ent, bool, Ent); 3] = [(w_l, false, q_l), (w_r, true, q_r), (w_o, true, q_o)];
const ENTRY_WIRES: [(Ent, bool); 6] = [(w_r, false), (w_o, false), (w_4, false), (w_r, true), (w_o, true), (w_4, true)];

/// The Poseidon2 quad relations' subrelation bodies are fixed linear maps of shared S-box outputs
/// and wires under one selector factor, so for separator weights `w_j = α_j / α_0` the weighted
/// sum `Σ_j w_j A_j = Σ_i m_i u_i + Σ_k n_k v_k` is one body. Returns `m ‖ n` (bb golf).
pub fn quad_batching_constants<F: FieldLike>(rel: Rel, w: &[F]) -> Vec<F> {
    let qp = quad_params();
    let dot = |rows: &[&[crate::base::Fr; 7]], i: usize| {
        rows.iter().zip(w).fold(F::zero(), |a, (row, w)| a + w.clone() * &k::<F>(row[i]))
    };
    let (d1, three) = (k::<F>(qp.d1), c::<F>(3));
    let mut out: Vec<F>;
    match rel {
        Rel::Poseidon2QuadInternal => {
            let [l0, l1, l2] = &qp.forward_vandermonde_lhs;
            let rows = [&qp.closed_form[0], l0, l1, l2];
            out = (3..7).map(|i| dot(&rows, i)).collect();
            let b3 = k::<F>(qp.b3_u0_coef);
            out.push(w[1].clone() * &d1 + w[2].clone() * &(three - d1.clone() - &d1) - w[3].clone() * &b3);
            out.push(w[2].clone() * &d1 - w[3].clone() * &k::<F>(qp.d1_minus_3));
            out.push(w[3].clone() * &d1);
            out.extend((0..3).map(|i| dot(&rows, i)));
            out.push(-w[0].clone());
            out.push(w[2].clone() + &w[2] + &(w[3].clone() * &k::<F>(qp.sigma_plus_2)) - &w[1]);
            out.push(w[3].clone() - &w[2]);
            out.push(-w[3].clone());
        }
        Rel::Poseidon2QuadInternalTerminal => {
            let cf = &qp.closed_form;
            let rows = [&cf[0], &cf[1], &cf[2], &cf[3]];
            out = (3..6).map(|i| dot(&rows, i)).collect();
            out.push(w[0].clone() * &k::<F>(cf[0][6]) + &w[1] + &w[2] + &w[3]);
            out.extend((0..3).map(|i| dot(&rows, i)));
            out.extend(w.iter().map(|w| -w.clone()));
        }
        Rel::Poseidon2TransitionEntry => {
            out = vec![
                w[0].clone() * &d1 + w[1].clone() * &three + w[2].clone() * &k::<F>(qp.sum_a_one),
                w[1].clone() * &d1 + w[2].clone() * &three,
                w[2].clone() * &d1,
            ];
            let (a1, a2) = (qp.a_one.map(k::<F>), qp.a2_one.map(k::<F>));
            out.extend((0..3).map(|i| w[0].clone() + w[1].clone() * &a1[i] + w[2].clone() * &a2[i]));
            out.extend(w.iter().map(|w| -w.clone()));
        }
        _ => unreachable!("not a Poseidon2 quad relation"),
    }
    out
}

/// Prover: `q·scaling·(Σ m_i x_i⁵ + Σ n_k v_k)` into `acc[0]` (the other subrelations stay zero),
/// each `m_i` folded into the degree-1 factor of `x⁵ = x⁴·x`.
fn quad_batched<T: FieldLike>(rel: Rel, acc: &mut [T], r: &Row<T>, consts: &[Vec<T>], scaling: &T) {
    let (q, sbox, wires, consts) = match rel {
        Rel::Poseidon2QuadInternal => (q_poseidon2_quad_internal, &QUAD_SBOX[..], &QUAD_WIRES[..], &consts[0]),
        Rel::Poseidon2QuadInternalTerminal => {
            (q_poseidon2_quad_internal_terminal, &QUAD_SBOX[..4], &QUAD_WIRES[..], &consts[1])
        }
        _ => (q_poseidon2_transition_entry, &ENTRY_SBOX[..], &ENTRY_WIRES[..], &consts[2]),
    };
    let v = |(e, shifted): (Ent, bool)| if shifted { r.s(e) } else { r.e(e) };
    let (m, n) = consts.split_at(sbox.len());
    let mut body = v(wires[0]).clone() * &n[0];
    for (&wire, n) in wires.iter().zip(n).skip(1) {
        body += &(v(wire).clone() * n);
    }
    for (&(wire, shifted, sel), m) in sbox.iter().zip(m) {
        let x = v((wire, shifted)).clone() + r.e(sel);
        body += &(x.sqr().sqr() * &(x * m));
    }
    acc[0] += &(r.e(q).clone() * scaling * &body);
}
