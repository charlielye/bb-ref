//! The eight ECCVM relations (bb `relations/ecc_vm/*_impl.hpp`), written once over `FieldLike` in
//! bb's operation order. A row is the slice of all 119 entity values (`Ent` order).

use super::trace::{fq_cube_root_of_unity, offset_generator, offset_generator_base};
use super::{Ent, LAST_ADDITION_ROUND};
use crate::base::field::{FieldLike, NativeField};
use crate::base::Fq;
use crate::honk::relations::RelationParams;
use crate::honk::sumcheck::RelationSet;
use Ent::*;

/// The ECCVM relations as a sumcheck [`RelationSet`].
pub struct EccvmRelations;

impl<T: FieldLike<Native = Fq>> RelationSet<T> for EccvmRelations {
    fn num_relations(&self) -> usize {
        ECCVM_RELATIONS.len()
    }
    fn num_subrelations(&self, r: usize) -> usize {
        ECCVM_RELATIONS[r].num_subrelations()
    }
    fn linearly_independent(&self, r: usize, j: usize) -> bool {
        ECCVM_RELATIONS[r].linearly_independent(j)
    }
    fn offset_only(&self, _r: usize) -> bool {
        false
    }
    fn accumulate(&self, r: usize, acc: &mut [T], row: &[T], p: &RelationParams<T>, scaling: &T) {
        ECCVM_RELATIONS[r].accumulate(acc, row, p, scaling)
    }
    fn partial_length(&self, r: usize) -> usize {
        ECCVM_RELATIONS[r].partial_lengths().into_iter().max().unwrap()
    }
    fn skip(&self, r: usize, row0: &[T], row1: &[T]) -> bool {
        let both = |f: &dyn Fn(&[T]) -> bool| f(row0) && f(row1);
        match ECCVM_RELATIONS[r] {
            EccvmRel::Set => both(&|r: &[T]| {
                (r[z_perm as usize].clone() - &r[z_perm_shift as usize]).is_zero()
                    && r[transcript_mul as usize].is_zero()
                    && r[lagrange_last as usize].is_zero()
            }),
            EccvmRel::ShiftableInit => both(&|r: &[T]| r[lagrange_first as usize].is_zero()),
            _ => false,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EccvmRel {
    Transcript,
    PointTable,
    Wnaf,
    Msm,
    Set,
    Lookup,
    Bools,
    ShiftableInit,
}

/// bb `ECCVMFlavor::Relations` order.
pub const ECCVM_RELATIONS: [EccvmRel; 8] = [
    EccvmRel::Transcript,
    EccvmRel::PointTable,
    EccvmRel::Wnaf,
    EccvmRel::Msm,
    EccvmRel::Set,
    EccvmRel::Lookup,
    EccvmRel::Bools,
    EccvmRel::ShiftableInit,
];

impl EccvmRel {
    pub fn partial_lengths(self) -> Vec<usize> {
        match self {
            EccvmRel::Transcript => vec![8; 31],
            EccvmRel::PointTable => vec![6; 6],
            EccvmRel::Wnaf => vec![5; 23],
            EccvmRel::Msm => vec![8; 51],
            EccvmRel::Set => vec![22, 3],
            EccvmRel::Lookup => vec![9, 9],
            EccvmRel::Bools => vec![3; 23],
            EccvmRel::ShiftableInit => vec![3; 21],
        }
    }
    pub fn num_subrelations(self) -> usize {
        self.partial_lengths().len()
    }
    /// Only the lookup's second subrelation is a trace-wide sum.
    pub fn linearly_independent(self, subrelation: usize) -> bool {
        !(self == EccvmRel::Lookup && subrelation == 1)
    }
    pub fn accumulate<T: FieldLike<Native = Fq>>(self, acc: &mut [T], r: &[T], p: &RelationParams<T>, scaling: &T) {
        match self {
            EccvmRel::Transcript => transcript(acc, r, scaling),
            EccvmRel::PointTable => point_table(acc, r, scaling),
            EccvmRel::Wnaf => wnaf(acc, r, scaling),
            EccvmRel::Msm => msm(acc, r, scaling),
            EccvmRel::Set => set(acc, r, p, scaling),
            EccvmRel::Lookup => lookup(acc, r, p, scaling),
            EccvmRel::Bools => bools(acc, r, scaling),
            EccvmRel::ShiftableInit => shiftable_init(acc, r, scaling),
        }
    }
}

fn c<T: FieldLike<Native = Fq>>(v: u64) -> T {
    T::constant(Fq::small(v))
}

fn bools<T: FieldLike>(acc: &mut [T], r: &[T], scaling: &T) {
    const BOOLS: [Ent; 23] = [
        transcript_eq,
        transcript_add,
        transcript_mul,
        transcript_reset_accumulator,
        transcript_msm_transition,
        transcript_accumulator_not_empty,
        transcript_z1zero,
        transcript_z2zero,
        transcript_add_x_equal,
        transcript_add_y_equal,
        transcript_base_infinity,
        transcript_msm_infinity,
        transcript_msm_count_zero_at_transition,
        msm_transition,
        precompute_point_transition,
        msm_add,
        msm_double,
        msm_skew,
        precompute_select,
        msm_add1,
        msm_add2,
        msm_add3,
        msm_add4,
    ];
    for (j, e) in BOOLS.iter().enumerate() {
        let v = r[*e as usize].clone();
        acc[j] += (v.clone() * (v - T::one())) * scaling;
    }
}

fn shiftable_init<T: FieldLike>(acc: &mut [T], r: &[T], scaling: &T) {
    const INITS: [Ent; 21] = [
        z_perm,
        transcript_accumulator_not_empty,
        precompute_select,
        transcript_mul,
        transcript_pc,
        precompute_scalar_sum,
        precompute_dx,
        precompute_dy,
        precompute_tx,
        precompute_ty,
        msm_transition,
        msm_add,
        msm_double,
        msm_skew,
        msm_accumulator_x,
        msm_accumulator_y,
        msm_count,
        msm_round,
        msm_add1,
        msm_pc,
        transcript_msm_count,
    ];
    let scaled_first = r[lagrange_first as usize].clone() * scaling;
    for (j, e) in INITS.iter().enumerate() {
        acc[j] += scaled_first.clone() * &r[*e as usize];
    }
}

fn point_table<T: FieldLike>(acc: &mut [T], r: &[T], scaling: &T) {
    let v = |e: Ent| r[e as usize].clone();
    let one = T::one();
    let (tx, tx_shift, ty, ty_shift) = (
        v(precompute_tx),
        v(precompute_tx_shift),
        v(precompute_ty),
        v(precompute_ty_shift),
    );
    let (dx, dx_shift, dy, dy_shift) = (
        v(precompute_dx),
        v(precompute_dx_shift),
        v(precompute_dy),
        v(precompute_dy_shift),
    );
    let transition = v(precompute_point_transition);
    let first = v(lagrange_first);

    let two_x = tx.clone() + &tx;
    let three_x = two_x.clone() + &tx;
    let three_xx = tx.clone() * &three_x;
    let nine_xxxx = three_xx.sqr();
    let two_y = ty.clone() + &ty;
    let four_yy = two_y.sqr();
    let x_double_check = (dx.clone() + &two_x) * &four_yy - &nine_xxxx;
    let y_double_check = (ty.clone() + &dy) * &two_y + &(three_xx * (dx.clone() - &tx));
    acc[0] += transition.clone() * &x_double_check * scaling;
    acc[1] += transition.clone() * &y_double_check * scaling;
    let not_first_not_transition = (one.clone() - &first) * (one.clone() - &transition);
    acc[2] += not_first_not_transition.clone() * (dx.clone() - &dx_shift) * scaling;
    acc[3] += not_first_not_transition.clone() * (dy.clone() - &dy_shift) * scaling;

    let (x1, y1, x2, y2, x3, y3) = (tx_shift, ty_shift, dx, dy, tx, ty);
    let lambda_numerator = y2.clone() - &y1;
    let lambda_denominator = x2.clone() - &x1;
    let x_add_check = (x3.clone() + &x2 + &x1) * lambda_denominator.sqr() - lambda_numerator.sqr();
    let y_add_check = (y3 + &y1) * &lambda_denominator + &((x3 - &x1) * &lambda_numerator);
    acc[4] += not_first_not_transition.clone() * &x_add_check * scaling;
    acc[5] += not_first_not_transition * &y_add_check * scaling;
}

fn wnaf<T: FieldLike<Native = Fq>>(acc: &mut [T], r: &[T], scaling: &T) {
    let v = |e: Ent| r[e as usize].clone();
    let one = T::one();
    let first = v(lagrange_first);
    let scalar_sum = v(precompute_scalar_sum);
    let scalar_sum_shift = v(precompute_scalar_sum_shift);
    let q_transition = v(precompute_point_transition);
    let round = v(precompute_round);
    let round_shift = v(precompute_round_shift);
    let pc = v(precompute_pc);
    let pc_shift = v(precompute_pc_shift);
    let select = v(precompute_select);
    let select_shift = v(precompute_select_shift);
    let skew = v(precompute_skew);
    let slices = [
        v(precompute_s1hi),
        v(precompute_s1lo),
        v(precompute_s2hi),
        v(precompute_s2lo),
        v(precompute_s3hi),
        v(precompute_s3lo),
        v(precompute_s4hi),
        v(precompute_s4lo),
    ];
    for (j, s) in slices.iter().enumerate() {
        acc[j] += ((s.clone() - &one).sqr() - &one) * ((s.clone() - &c(2)).sqr() - &one) * scaling;
    }
    let to_wnaf = |hi: &T, lo: &T| {
        let mut t = hi.clone() + hi;
        t += &t.clone();
        t += lo;
        t.clone() + &t - &c(15)
    };
    let scaled_transition = q_transition.clone() * scaling;
    let scaled_transition_is_zero = -scaled_transition.clone() + scaling;
    let scaled_first = scaling.clone() * &first;
    let s1hi_shift = v(precompute_s1hi_shift);
    let s1hi_shift_msb_set = (s1hi_shift.clone() - &c(2)) * (s1hi_shift - &c(3));
    acc[20] += (scaled_transition.clone() + &scaled_first) * &select_shift * &s1hi_shift_msb_set;
    let w = [
        to_wnaf(&slices[0], &slices[1]),
        to_wnaf(&slices[2], &slices[3]),
        to_wnaf(&slices[4], &slices[5]),
        to_wnaf(&slices[6], &slices[7]),
    ];
    let mut row_slice = w[0].clone();
    for k in 1..4 {
        for _ in 0..4 {
            row_slice += &row_slice.clone();
        }
        row_slice += &w[k];
    }
    let sum_delta = scalar_sum * &c(1 << 16) + &row_slice;
    let check_sum = scalar_sum_shift.clone() - &sum_delta;
    acc[8] += select.clone() * &check_sum * &scaled_transition_is_zero;
    let scaled_first_minus_one = scaled_first.clone() - scaling;
    acc[22] += scaled_first_minus_one * (select_shift.clone() * (select.clone() - &one));
    let round_check = round_shift.clone() - &round - &one;
    let select_transition_plus_first = select.clone() * &scaled_transition + &scaled_first;
    acc[9] += select.clone()
        * (scaled_transition.clone() * (round.clone() - &round_check - &c(7)) + &(scaling.clone() * &round_check));
    acc[10] += select_transition_plus_first.clone() * &round_shift;
    acc[11] += select_transition_plus_first * &scalar_sum_shift;
    let pc_delta = pc_shift - &pc;
    acc[12] += select.clone() * (scaled_transition * (-pc_delta.clone() - &pc_delta - &one) + &(pc_delta * scaling));
    acc[13] += select.clone() * (skew.clone() * (skew - &c(7))) * scaling;
    let select_zero = (one.clone() - &select) * scaling;
    for k in 0..4 {
        acc[14 + k] += select_zero.clone() * (w[k].clone() + &c(15));
    }
    acc[18] += select_zero.clone() * &round;
    acc[19] += select_zero.clone() * &pc;
    acc[21] += select_zero * &q_transition;
}

fn msm<T: FieldLike<Native = Fq>>(acc: &mut [T], r: &[T], scaling: &T) {
    let v = |e: Ent| r[e as usize].clone();
    let one = T::one();
    let xs = [v(msm_x1), v(msm_x2), v(msm_x3), v(msm_x4)];
    let ys = [v(msm_y1), v(msm_y2), v(msm_y3), v(msm_y4)];
    let collision_inverse = [
        v(msm_collision_x1),
        v(msm_collision_x2),
        v(msm_collision_x3),
        v(msm_collision_x4),
    ];
    let lambda = [v(msm_lambda1), v(msm_lambda2), v(msm_lambda3), v(msm_lambda4)];
    let first = v(lagrange_first);
    let adds = [v(msm_add1), v(msm_add2), v(msm_add3), v(msm_add4)];
    let add1_shift = v(msm_add1_shift);
    let (acc_x, acc_y, acc_x_shift, acc_y_shift) = (
        v(msm_accumulator_x),
        v(msm_accumulator_y),
        v(msm_accumulator_x_shift),
        v(msm_accumulator_y_shift),
    );
    let slices = [v(msm_slice1), v(msm_slice2), v(msm_slice3), v(msm_slice4)];
    let (transition, transition_shift) = (v(msm_transition), v(msm_transition_shift));
    let (round, round_shift, round_minus_31_inv) = (v(msm_round), v(msm_round_shift), v(msm_round_minus_31_inv));
    let (q_add, q_add_shift, q_skew, q_skew_shift, q_double, q_double_shift) = (
        v(msm_add),
        v(msm_add_shift),
        v(msm_skew),
        v(msm_skew_shift),
        v(msm_double),
        v(msm_double_shift),
    );
    let msm_size = v(msm_size_of_msm);
    let (pc, pc_shift, count, count_shift) = (v(msm_pc), v(msm_pc_shift), v(msm_count), v(msm_count_shift));
    let is_not_first_row = one.clone() - &first;

    // Conditional affine addition of (xb, yb) into (xa, ya): [x_out, y_out, slope_relation].
    let add = |xb: &T, yb: &T, xa: &T, ya: &T, lambda: &T, selector: &T, collision: &mut T| {
        let slope_relation =
            selector.clone() * (lambda.clone() * (xb.clone() - xa - &one) - &(yb.clone() - ya)) + lambda;
        *collision += &(selector.clone() * (xb.clone() - xa));
        let x_out = lambda.sqr() + &((-xb.clone() - xa - xa) * selector) + xa;
        let y_out = lambda.clone() * (xa.clone() - &x_out) + &((-ya.clone() - ya) * selector) + ya;
        (x_out, y_out, slope_relation)
    };
    let first_add = |xb: &T, yb: &T, xa: &T, ya: &T, lambda: &T, selector: &T, collision: &mut T| {
        let og = offset_generator_base();
        let (xo, yo) = (T::constant(og.x), T::constant(og.y));
        let x = xo * selector + &(xb.clone() * (-selector.clone() + &one));
        let y = yo * selector + &(yb.clone() * (-selector.clone() + &one));
        let slope_relation = lambda.clone() * (x.clone() - xa) - &(y.clone() - ya);
        *collision += &(xa.clone() - &x);
        let x_out = lambda.clone() * lambda + &(-x.clone() - xa);
        let y_out = lambda.clone() * (xa.clone() - &x_out) - ya;
        (x_out, y_out, slope_relation)
    };
    let mut x_collision = [T::zero(), T::zero(), T::zero(), T::zero()];
    let (x_t1, y_t1, add_slope1) = first_add(
        &acc_x,
        &acc_y,
        &xs[0],
        &ys[0],
        &lambda[0],
        &transition,
        &mut x_collision[0],
    );
    let (x_t2, y_t2, add_slope2) = add(&xs[1], &ys[1], &x_t1, &y_t1, &lambda[1], &adds[1], &mut x_collision[1]);
    let (x_t3, y_t3, add_slope3) = add(&xs[2], &ys[2], &x_t2, &y_t2, &lambda[2], &adds[2], &mut x_collision[2]);
    let (x_t4, y_t4, add_slope4) = add(&xs[3], &ys[3], &x_t3, &y_t3, &lambda[3], &adds[3], &mut x_collision[3]);
    acc[0] += q_add.clone() * (acc_x_shift.clone() - &x_t4) * scaling;
    acc[1] += q_add.clone() * (acc_y_shift.clone() - &y_t4) * scaling;
    for (j, s) in [add_slope1, add_slope2, add_slope3, add_slope4].iter().enumerate() {
        acc[2 + j] += q_add.clone() * s * scaling;
    }

    let dbl = |x: &T, y: &T, lambda: &T| {
        let two_x = x.clone() + x;
        let slope_relation = lambda.clone() * (y.clone() + y) - &((two_x.clone() + x) * x);
        let x_out = lambda.sqr() - &two_x;
        let y_out = lambda.clone() * (x.clone() - &x_out) - y;
        (x_out, y_out, slope_relation)
    };
    let (x_d1, y_d1, dbl_slope1) = dbl(&acc_x, &acc_y, &lambda[0]);
    let (x_d2, y_d2, dbl_slope2) = dbl(&x_d1, &y_d1, &lambda[1]);
    let (x_d3, y_d3, dbl_slope3) = dbl(&x_d2, &y_d2, &lambda[2]);
    let (x_d4, y_d4, dbl_slope4) = dbl(&x_d3, &y_d3, &lambda[3]);
    acc[6] += q_double.clone() * (acc_x_shift.clone() - &x_d4) * scaling;
    acc[7] += q_double.clone() * (acc_y_shift.clone() - &y_d4) * scaling;
    for (j, s) in [dbl_slope1, dbl_slope2, dbl_slope3, dbl_slope4].iter().enumerate() {
        acc[8 + j] += q_double.clone() * s * scaling;
    }

    static INVERSE_SEVEN: std::sync::LazyLock<Fq> = std::sync::LazyLock::new(|| Fq::from(7u64).invert());
    let inverse_seven = T::constant(*INVERSE_SEVEN);
    let skew_select: [T; 4] = std::array::from_fn(|k| slices[k].clone() * &inverse_seven);
    let mut x_skew_collision = [T::zero(), T::zero(), T::zero(), T::zero()];
    let (x_s1, y_s1, skew_slope1) = add(
        &xs[0],
        &ys[0],
        &acc_x,
        &acc_y,
        &lambda[0],
        &skew_select[0],
        &mut x_skew_collision[0],
    );
    let (x_s2, y_s2, skew_slope2) = add(
        &xs[1],
        &ys[1],
        &x_s1,
        &y_s1,
        &lambda[1],
        &skew_select[1],
        &mut x_skew_collision[1],
    );
    let (x_s3, y_s3, skew_slope3) = add(
        &xs[2],
        &ys[2],
        &x_s2,
        &y_s2,
        &lambda[2],
        &skew_select[2],
        &mut x_skew_collision[2],
    );
    let (x_s4, y_s4, skew_slope4) = add(
        &xs[3],
        &ys[3],
        &x_s3,
        &y_s3,
        &lambda[3],
        &skew_select[3],
        &mut x_skew_collision[3],
    );
    acc[12] += q_skew.clone() * (acc_x_shift.clone() - &x_s4) * scaling;
    acc[13] += q_skew.clone() * (acc_y_shift.clone() - &y_s4) * scaling;
    for (j, s) in [skew_slope1, skew_slope2, skew_slope3, skew_slope4].iter().enumerate() {
        acc[14 + j] += q_skew.clone() * s * scaling;
    }

    for k in 0..4 {
        let add_point = adds[k].clone() * &q_add + &(q_skew.clone() * &skew_select[k]);
        let x_delta = x_skew_collision[k].clone() * &q_skew + &(x_collision[k].clone() * &q_add);
        acc[18 + k] += (x_delta * &collision_inverse[k] - &add_point) * scaling;
        acc[22 + k] += (-adds[k].clone() + &one) * &slices[k] * scaling;
    }
    acc[26] += (q_add.clone() * &q_double + &(q_add.clone() * &q_skew) + &(q_double.clone() * &q_skew)) * scaling;

    let no_op_selector = (-q_add.clone() + &one)
        * (-q_double.clone() + &one)
        * (-q_skew.clone() + &one)
        * (-transition.clone() + &one)
        * (-first.clone() + &one);
    acc[45] += no_op_selector.clone() * (acc_x_shift.clone() - &acc_x) * scaling;
    acc[46] += no_op_selector * (acc_y_shift.clone() - &acc_y) * scaling;
    let curr_not_phase = (-q_add.clone() + &one) * (-q_double.clone() + &one) * (-q_skew.clone() + &one);
    let next_phase = q_add_shift.clone() + &q_double_shift + &q_skew_shift;
    acc[48] += curr_not_phase * &next_phase * (transition_shift.clone() - &one) * scaling;
    acc[41] += (adds[0].clone() - &q_add - &q_skew) * scaling;

    let round_delta = round_shift.clone() - &round;
    let round_transition = round_delta.clone() * (-transition_shift.clone() + &one);
    acc[27] += round_transition.clone() * (round_delta.clone() - &one) * scaling;
    acc[28] += round_transition.clone() * &q_skew_shift * (round.clone() - &c(LAST_ADDITION_ROUND)) * scaling;
    acc[29] += round_transition.clone() * (q_skew_shift.clone() + &q_double_shift - &one) * scaling;
    acc[44] += (-round_delta.clone() + &one) * &q_double_shift * scaling;
    acc[47] += q_double_shift.clone()
        * (one.clone() - &((round.clone() - &c(LAST_ADDITION_ROUND)) * &round_minus_31_inv))
        * scaling;
    acc[30] += round_transition * (-q_double_shift.clone() + &one) * (-q_skew_shift.clone() + &one) * scaling;
    acc[31] += q_double.clone() * (-q_add_shift.clone() + &one) * scaling;
    acc[42] += (-transition_shift.clone() + &one) * &q_skew * (-q_skew_shift.clone() + &one) * scaling;
    acc[43] += q_skew.clone() * (-round.clone() + &c(32)) * scaling;
    acc[32] += round_delta.clone() * &count_shift * scaling;
    acc[33] += (-transition_shift.clone() + &one)
        * (-round_delta.clone() + &one)
        * (count_shift.clone() - &count - &adds[0] - &adds[1] - &adds[2] - &adds[3])
        * scaling;
    acc[34] += is_not_first_row.clone() * (-transition_shift.clone() + &one) * &round_delta * &count_shift * scaling;
    acc[35] += transition.clone() * &round * scaling;
    acc[36] += is_not_first_row.clone() * &transition_shift * (msm_size.clone() + &pc_shift - &pc) * scaling;
    let active_phase = q_add.clone() + &q_double;
    acc[49] +=
        is_not_first_row * &active_phase * (-transition_shift.clone() + &one) * (pc_shift.clone() - &pc) * scaling;
    acc[50] += q_skew.clone() * &q_skew_shift * (pc_shift - &pc) * scaling;
    acc[37] += adds[1].clone() * (-adds[0].clone() + &one) * scaling;
    acc[38] += adds[2].clone() * (-adds[1].clone() + &one) * scaling;
    acc[39] += adds[3].clone() * (-adds[2].clone() + &one) * scaling;
    acc[40] +=
        (q_add.clone() * &q_add_shift + &(q_skew * &q_skew_shift)) * (-adds[3].clone() + &one) * &add1_shift * scaling;
}

fn transcript<T: FieldLike<Native = Fq>>(acc: &mut [T], r: &[T], scaling: &T) {
    let v = |e: Ent| r[e as usize].clone();
    let one = T::one();
    let (z1, z2, z1_zero, z2_zero) = (
        v(transcript_z1),
        v(transcript_z2),
        v(transcript_z1zero),
        v(transcript_z2zero),
    );
    let op = v(transcript_op);
    let (q_add, q_mul, q_mul_shift, q_eq) = (
        v(transcript_add),
        v(transcript_mul),
        v(transcript_mul_shift),
        v(transcript_eq),
    );
    let (mt, mcount, mcount_shift) = (
        v(transcript_msm_transition),
        v(transcript_msm_count),
        v(transcript_msm_count_shift),
    );
    let (pc, pc_shift) = (v(transcript_pc), v(transcript_pc_shift));
    let (acc_x_shift, acc_y_shift, acc_x, acc_y) = (
        v(transcript_accumulator_x_shift),
        v(transcript_accumulator_y_shift),
        v(transcript_accumulator_x),
        v(transcript_accumulator_y),
    );
    let (count_zero_at_transition, count_at_transition_inverse) = (
        v(transcript_msm_count_zero_at_transition),
        v(transcript_msm_count_at_transition_inverse),
    );
    let (msm_x, msm_y) = (v(transcript_msm_intermediate_x), v(transcript_msm_intermediate_y));
    let (px, py) = (v(transcript_Px), v(transcript_Py));
    let is_accumulator_empty = -v(transcript_accumulator_not_empty) + &one;
    let (first, last, second, third) = (
        v(lagrange_first),
        v(lagrange_last),
        v(lagrange_second),
        v(lagrange_third),
    );
    let is_accumulator_empty_shift = -v(transcript_accumulator_not_empty_shift) + &one;
    let q_reset = v(transcript_reset_accumulator);
    let p_infinity = v(transcript_base_infinity);
    let (px_inverse, py_inverse) = (v(transcript_base_x_inverse), v(transcript_base_y_inverse));
    let (add_x_equal, add_y_equal, add_lambda) = (
        v(transcript_add_x_equal),
        v(transcript_add_y_equal),
        v(transcript_add_lambda),
    );
    let msm_infinity = v(transcript_msm_infinity);

    let is_not_first_row = -first.clone() + &one;
    let is_not_last_row = -last.clone() + &one;
    let is_not_first_or_last_row = -first.clone() + &(-last.clone()) + &one;
    let is_not_infinity = -p_infinity.clone() + &one;
    let is_not_hiding_row = -second.clone() + &one;
    acc[0] += (z1 * &z1_zero) * scaling;
    acc[1] += (z2 * &z2_zero) * scaling;
    let mut tmp = q_add.clone() + &q_add;
    tmp += &q_mul;
    tmp += &tmp.clone();
    tmp += &q_eq;
    tmp += &tmp.clone();
    tmp += &q_reset;
    acc[2] += (tmp - &op) * scaling;
    let pc_delta = pc.clone() - &pc_shift;
    let num_muls_in_row = ((-z1_zero.clone() + &one) + &(-z2_zero.clone() + &one)) * (-p_infinity.clone() + &one);
    acc[3] += is_not_first_row.clone() * (pc_delta - &(q_mul.clone() * &num_muls_in_row)) * scaling;
    let msm_transition_check = q_mul.clone() * (-q_mul_shift + &one);
    let msm_count_total = mcount.clone() + &num_muls_in_row;
    let mut count_zero_check = count_zero_at_transition.clone() * &msm_count_total;
    count_zero_check +=
        &((msm_count_total * &count_at_transition_inverse - &one) * (-count_zero_at_transition.clone() + &one));
    acc[4] += msm_transition_check.clone() * &count_zero_check * scaling;
    acc[5] += (mt.clone() - &(msm_transition_check * (-count_zero_at_transition + &one))) * scaling;
    acc[6] += ((-q_mul.clone() + &one) * &mcount) * scaling;
    let msm_count_delta = mcount_shift - &mcount;
    acc[7] += is_not_first_row.clone()
        * (-mt.clone() + &one)
        * (msm_count_delta - &(q_mul.clone() * &num_muls_in_row))
        * scaling;
    let mut opcode_exclusion = q_mul.clone() * (q_add.clone() + &q_eq + &q_reset);
    opcode_exclusion += &(q_add.clone() * (q_mul.clone() + &q_eq + &q_reset));
    acc[8] += opcode_exclusion * scaling;

    let both_infinity = p_infinity.clone() * &is_accumulator_empty;
    let both_not_infinity = (-p_infinity.clone() + &one) * (-is_accumulator_empty.clone() + &one);
    let infinity_exclusion_check = p_infinity.clone() + &is_accumulator_empty - &both_infinity - &both_infinity;
    let eq_x_diff = px.clone() - &acc_x;
    let eq_y_diff = py.clone() - &acc_y;
    acc[9] +=
        q_eq.clone() * (eq_x_diff * &both_not_infinity + &infinity_exclusion_check) * &is_not_hiding_row * scaling;
    acc[10] +=
        q_eq.clone() * (eq_y_diff * &both_not_infinity + &infinity_exclusion_check) * &is_not_hiding_row * scaling;
    acc[11] += third.clone() * (-is_accumulator_empty.clone() + &one) * scaling;
    acc[12] += (third * &mcount + &(last * &pc)) * scaling;
    let validate_on_curve = q_add.clone() + &q_mul + &q_eq;
    let on_curve_check = py.clone() * &py - &(px.clone() * &px * &px) - &c(3);
    acc[13] += validate_on_curve * &on_curve_check * &is_not_infinity * &is_not_hiding_row * scaling;

    {
        let is_double = add_x_equal.clone() * &add_y_equal;
        let is_add = -add_x_equal.clone() + &one;
        let (rhs_x, rhs_y) = (acc_x.clone(), acc_y.clone());
        let (out_x, out_y) = (acc_x_shift.clone(), acc_y_shift.clone());
        let lambda = add_lambda.clone();
        let lhs_x = px.clone() * &q_add + &(msm_x.clone() * &mt);
        let lhs_y = py.clone() * &q_add + &(msm_y.clone() * &mt);
        let lhs_infinity = p_infinity.clone() * &q_add + &(msm_infinity.clone() * &mt);
        let rhs_infinity = is_accumulator_empty.clone();
        let result_is_lhs = rhs_infinity.clone() * (-lhs_infinity.clone() + &one);
        let result_is_rhs = (-rhs_infinity.clone() + &one) * &lhs_infinity;
        let result_infinity_from_inputs = lhs_infinity.clone() * &rhs_infinity;
        let result_infinity_from_operation = add_x_equal.clone() * (-add_y_equal.clone() + &one);
        let result_is_infinity = result_infinity_from_inputs + &result_infinity_from_operation;
        let any_add_is_active = q_add.clone() + &mt;

        // λ relation for the point added: the MSM output or the base point.
        let lambda_relation_for = |x: &T, y: &T, infinity: &T| {
            let mut rel = T::zero();
            rel += &((lambda.clone() * (rhs_x.clone() - x) - &(rhs_y.clone() - y)) * &is_add);
            rel += &((lambda.clone() * (y.clone() + y) - &(x.clone() * x * &c(3))) * &is_double);
            rel *= &((-infinity.clone() + &one) * (-is_accumulator_empty.clone() + &one));
            rel += &(lambda.clone() * (infinity.clone() + &is_accumulator_empty + &result_infinity_from_operation));
            rel
        };
        let mut transcript_lambda_relation = lambda_relation_for(&msm_x, &msm_y, &msm_infinity) * &mt;
        transcript_lambda_relation += &(lambda_relation_for(&px, &py, &p_infinity) * &q_add);
        acc[14] += transcript_lambda_relation * scaling;

        let propagate = q_mul.clone() * (-mt.clone() + &one) + &(q_eq.clone() * (-q_reset.clone() + &one));
        {
            let lambda_sqr = lambda.clone() * &lambda;
            let mut x3 = lambda_sqr - &lhs_x - &rhs_x;
            let mut y3 = lambda.clone() * (lhs_x.clone() - &x3) - &lhs_y;
            x3 += &(result_is_lhs.clone() * (rhs_x.clone() + &lhs_x + &lhs_x));
            x3 += &(result_is_rhs.clone() * (lhs_x.clone() + &rhs_x + &rhs_x));
            x3 += &(result_is_infinity.clone() * (lhs_x.clone() + &rhs_x));
            y3 += &(result_is_lhs.clone() * (lhs_y.clone() + &lhs_y));
            y3 += &(result_is_rhs.clone() * (lhs_y.clone() + &rhs_y));
            y3 += &(result_is_infinity.clone() * &lhs_y);
            let opcode_is_zero = is_not_first_row.clone()
                * (-q_add.clone() + &one)
                * (-q_mul.clone() + &one)
                * (-q_reset.clone() + &one)
                * (-q_eq.clone() + &one);
            let mut add_x = (x3 - &out_x) * &any_add_is_active;
            add_x += &(propagate.clone() * &is_not_last_row * (out_x.clone() - &acc_x));
            add_x += &(out_x.clone() * &q_reset);
            add_x += &(out_x * &opcode_is_zero);
            let mut add_y = (y3 - &out_y) * &any_add_is_active;
            add_y += &(propagate.clone() * &is_not_last_row * (out_y.clone() - &acc_y));
            add_y += &(out_y.clone() * &q_reset);
            add_y += &(out_y * &opcode_is_zero);
            acc[15] += add_x * scaling;
            acc[16] += add_y * scaling;
        }
        {
            let og = offset_generator();
            let (x1, y1) = (T::constant(og.x), -T::constant(og.y));
            let (x2, y2) = (v(transcript_msm_x), v(transcript_msm_y));
            let (x3, y3) = (msm_x.clone(), msm_y.clone());
            let x_term = (x3.clone() + &x2 + &x1) * (x2.clone() - &x1) * (x2.clone() - &x1)
                - &((y2.clone() - &y1) * (y2.clone() - &y1));
            let y_term = (x1.clone() - &x3) * (y2.clone() - &y1) - &((x2.clone() - &x1) * (y1.clone() + &y3));
            let subtract_x = x_term * (-msm_infinity.clone() + &one) + &(msm_infinity.clone() * &x3);
            let subtract_y = y_term * (-msm_infinity.clone() + &one) + &(msm_infinity.clone() * &y3);
            acc[26] += mt.clone() * &subtract_x * scaling;
            acc[27] += mt.clone() * &subtract_y * scaling;
            let x_diff = x2 - &x1;
            let y_sum = y2 + &y1;
            acc[28] += mt.clone() * &msm_infinity * &x_diff * scaling;
            acc[29] += mt.clone() * &msm_infinity * &y_sum * scaling;
            let msm_x_inverse = v(transcript_msm_x_inverse);
            let inverse_term = (-msm_infinity.clone() + &one) * (x_diff * &msm_x_inverse - &one);
            acc[30] += mt.clone() * &inverse_term * scaling;
        }
        let preserve =
            propagate * (is_accumulator_empty.clone() - &is_accumulator_empty_shift) * &is_not_first_or_last_row;
        let from_reset = q_reset.clone() * (-is_accumulator_empty_shift.clone() + &one);
        let from_add = any_add_is_active.clone() * (result_is_infinity - &is_accumulator_empty_shift);
        let opcode_is_zero = is_not_first_row.clone()
            * (-q_add.clone() + &one)
            * (-q_mul.clone() + &one)
            * (-q_reset.clone() + &one)
            * (-q_eq.clone() + &one);
        let from_noop = opcode_is_zero * (-is_accumulator_empty_shift.clone() + &one);
        acc[17] += (preserve + &((from_reset + &from_add) * &is_not_first_row) + &from_noop) * scaling;

        let x_diff = lhs_x - &rhs_x;
        let x_product = px_inverse * (-add_x_equal.clone() + &one) + &add_x_equal;
        let x_constant = add_x_equal.clone() - &one;
        acc[18] += (x_diff * &x_product + &x_constant) * &any_add_is_active * scaling;
        let y_diff = lhs_y - &rhs_y;
        let y_product = py_inverse * (-add_y_equal.clone() + &one) + &add_y_equal;
        let y_constant = add_y_equal.clone() - &one;
        acc[19] += (y_diff * &y_product + &y_constant) * &any_add_is_active * scaling;
    }
    acc[20] += second.clone() * (-q_eq + &one) * scaling;
    acc[21] += second * (-q_reset + &one) * scaling;
    acc[22] += p_infinity.clone() * &px * scaling;
    acc[23] += p_infinity * &py * scaling;
    acc[24] += is_accumulator_empty.clone() * &acc_x * scaling;
    acc[25] += is_accumulator_empty * &acc_y * scaling;
}

/// `2 * (4 * hi + lo) - 15`
fn to_wnaf<T: FieldLike>(hi: &T, lo: &T) -> T {
    let mut t = hi.clone() + hi;
    t += &t.clone();
    t += lo;
    t.clone() + &t - &T::from_u64(15)
}

/// bb `ECCVMSetRelationImpl::compute_grand_product_numerator`.
pub fn set_numerator<T: FieldLike<Native = Fq>>(r: &[T], p: &RelationParams<T>) -> T {
    let v = |e: Ent| r[e as usize].clone();
    let one = T::one();
    let round = v(precompute_round);
    let round4 = (round.clone() + &round) + &(round.clone() + &round);
    let (gamma, beta, beta_sqr, beta_cube, beta_quartic) =
        (&p.gamma, &p.beta, &p.beta_sqr, &p.beta_cube, &p.beta_quartic);
    let pc = v(precompute_pc);
    let select = v(precompute_select);
    let first_term_tag = beta_quartic.clone() * &c(1);
    let second_term_tag = beta_quartic.clone() * &c(2);
    let third_term_tag = beta_quartic.clone() * &c(3);
    let mut numerator = one.clone();
    let slices = [
        (precompute_s1hi, precompute_s1lo),
        (precompute_s2hi, precompute_s2lo),
        (precompute_s3hi, precompute_s3lo),
        (precompute_s4hi, precompute_s4lo),
    ];
    for (k, (hi, lo)) in slices.iter().enumerate() {
        let (s0, s1) = (v(*hi), v(*lo));
        let mut wnaf_slice = s0.clone() + &s0;
        wnaf_slice += &wnaf_slice.clone();
        wnaf_slice += &s1;
        let input =
            wnaf_slice + gamma + &(pc.clone() * beta) + &((round4.clone() + &c(k as u64)) * beta_sqr) + &first_term_tag;
        numerator *= &input;
    }
    {
        let skew = v(precompute_skew);
        let transition = v(precompute_point_transition);
        let skew_input = transition.clone()
            * (skew + gamma + &(pc.clone() * beta) + &((round4.clone() + &c(4)) * beta_sqr) + &first_term_tag)
            + &(-transition + &one);
        numerator *= &skew_input;
    }
    {
        let delta = &p.eccvm_set_permutation_delta;
        numerator *= &(select * (-delta.clone() + &one) + delta);
    }
    {
        let (table_x, table_y) = (v(precompute_tx), v(precompute_ty));
        let skew = v(precompute_skew);
        static NEGATIVE_INVERSE_SEVEN: std::sync::LazyLock<Fq> =
            std::sync::LazyLock::new(|| (-Fq::from(7u64)).invert());
        let negative_inverse_seven = T::constant(*NEGATIVE_INVERSE_SEVEN);
        let adjusted_skew = skew * &negative_inverse_seven;
        let wnaf_scalar_sum = v(precompute_scalar_sum);
        let w = [
            to_wnaf(&v(precompute_s1hi), &v(precompute_s1lo)),
            to_wnaf(&v(precompute_s2hi), &v(precompute_s2lo)),
            to_wnaf(&v(precompute_s3hi), &v(precompute_s3lo)),
            to_wnaf(&v(precompute_s4hi), &v(precompute_s4lo)),
        ];
        let mut row_slice = w[0].clone();
        for k in 1..4 {
            for _ in 0..4 {
                row_slice += &row_slice.clone();
            }
            row_slice += &w[k];
        }
        let mut scalar_sum_full = wnaf_scalar_sum.clone() + &wnaf_scalar_sum;
        for _ in 0..15 {
            scalar_sum_full += &scalar_sum_full.clone();
        }
        scalar_sum_full += &(row_slice + &adjusted_skew);
        let transition = v(precompute_point_transition);
        let read =
            pc.clone() + &(table_x * beta) + &(table_y * beta_sqr) + &(scalar_sum_full * beta_cube) + &second_term_tag;
        let read = transition.clone() * (read + gamma) + &(-transition + &one);
        numerator *= &read;
    }
    {
        let first = v(lagrange_first);
        let transition_shift = (-first + &one) * &v(msm_transition_shift);
        let write = v(msm_pc_shift)
            + &(v(msm_accumulator_x_shift) * beta)
            + &(v(msm_accumulator_y_shift) * beta_sqr)
            + &(v(msm_size_of_msm) * beta_cube)
            + &third_term_tag;
        let write = transition_shift.clone() * (write + gamma) + &(-transition_shift + &one);
        numerator *= &write;
    }
    numerator
}

/// bb `ECCVMSetRelationImpl::compute_grand_product_denominator`.
pub fn set_denominator<T: FieldLike<Native = Fq>>(r: &[T], p: &RelationParams<T>) -> T {
    let v = |e: Ent| r[e as usize].clone();
    let one = T::one();
    let (gamma, beta, beta_sqr, beta_cube, beta_quartic) =
        (&p.gamma, &p.beta, &p.beta_sqr, &p.beta_cube, &p.beta_quartic);
    let (pc, count, round) = (v(msm_pc), v(msm_count), v(msm_round));
    let first_term_tag = beta_quartic.clone() * &c(1);
    let second_term_tag = beta_quartic.clone() * &c(2);
    let third_term_tag = beta_quartic.clone() * &c(3);
    let mut denominator = one.clone();
    let reads = [
        (msm_add1, msm_slice1),
        (msm_add2, msm_slice2),
        (msm_add3, msm_slice3),
        (msm_add4, msm_slice4),
    ];
    for (k, (add, slice)) in reads.iter().enumerate() {
        let (add, slice) = (v(*add), v(*slice));
        let output = add.clone()
            * (slice
                + gamma
                + &((pc.clone() - &count - &c(k as u64)) * beta)
                + &(round.clone() * beta_sqr)
                + &first_term_tag)
            + &(-add + &one);
        denominator *= &output;
    }
    {
        let tpc = v(transcript_pc);
        let (px, py) = (v(transcript_Px), v(transcript_Py));
        let (z1, z2, z1_zero, z2_zero) = (
            v(transcript_z1),
            v(transcript_z2),
            v(transcript_z1zero),
            v(transcript_z2zero),
        );
        let base_infinity = v(transcript_base_infinity);
        let tmul = v(transcript_mul);
        let lookup_first = -z1_zero + &one;
        let lookup_second = -z2_zero + &one;
        let cube_root = T::constant(fq_cube_root_of_unity());
        let input1 =
            tpc.clone() + &(px.clone() * beta) + &(py.clone() * beta_sqr) + &(z1 * beta_cube) + &second_term_tag;
        let input2 =
            (tpc - &lookup_first) + &(px * &cube_root * beta) - &(py * beta_sqr) + &(z2 * beta_cube) + &second_term_tag;
        let input1 = (input1 + gamma) * &lookup_first + &(-lookup_first.clone() + &one);
        let input2 = (input2 + gamma) * &lookup_second + &(-lookup_second.clone() + &one);
        let product = (input1 * &input2) * (-base_infinity.clone() + &one) + &base_infinity;
        let write = tmul.clone() * &product + &(-tmul + &one);
        denominator *= &write;
    }
    {
        let tpc_shift = v(transcript_pc_shift);
        let (msm_x, msm_y) = (v(transcript_msm_x), v(transcript_msm_y));
        let transition = v(transcript_msm_transition);
        let tcount = v(transcript_msm_count);
        let (z1_zero, z2_zero) = (v(transcript_z1zero), v(transcript_z2zero));
        let tmul = v(transcript_mul);
        let base_infinity = v(transcript_base_infinity);
        let full_count = tcount + &(tmul * ((-z1_zero + &one) + &(-z2_zero + &one)) * (-base_infinity + &one));
        let read = tpc_shift + &(msm_x * beta) + &(msm_y * beta_sqr) + &(full_count * beta_cube) + &third_term_tag;
        let read = transition.clone() * (read + gamma) + &(-transition + &one);
        denominator *= &read;
    }
    denominator
}

fn set<T: FieldLike<Native = Fq>>(acc: &mut [T], r: &[T], p: &RelationParams<T>, scaling: &T) {
    let v = |e: Ent| r[e as usize].clone();
    let numerator = set_numerator(r, p);
    let denominator = set_denominator(r, p);
    let (first, last) = (v(lagrange_first), v(lagrange_last));
    let (zp, zp_shift) = (v(z_perm), v(z_perm_shift));
    acc[0] += ((zp + &first) * &numerator - &((zp_shift.clone() + &last) * &denominator)) * scaling;
    acc[1] += last * &zp_shift * scaling;
}

/// The four read terms (per MSM addition slot) and two table terms (positive / negative point
/// table halves) of the ECCVM lookup (bb `ECCVMLookupRelationImpl`).
pub fn lookup_terms<T: FieldLike<Native = Fq>>(r: &[T], p: &RelationParams<T>) -> [T; 6] {
    let v = |e: Ent| r[e as usize].clone();
    let (gamma, beta, beta_sqr, beta_cube) = (&p.gamma, &p.beta, &p.beta_sqr, &p.beta_cube);
    let current_pc = v(msm_pc) - &v(msm_count);
    let reads = [
        (msm_slice1, msm_x1, msm_y1),
        (msm_slice2, msm_x2, msm_y2),
        (msm_slice3, msm_x3, msm_y3),
        (msm_slice4, msm_x4, msm_y4),
    ];
    let read = |k: usize| {
        let (s, x, y) = reads[k];
        (current_pc.clone() - &c(k as u64)) + gamma + &(v(s) * beta) + &(v(x) * beta_sqr) + &(v(y) * beta_cube)
    };
    let pc = v(precompute_pc);
    let (tx, ty, round) = (v(precompute_tx), v(precompute_ty), v(precompute_round));
    let positive =
        pc.clone() + gamma + &((-round.clone() + &c(15)) * beta) + &(tx.clone() * beta_sqr) + &(ty.clone() * beta_cube);
    let negative = pc + gamma + &(round * beta) + &(tx * beta_sqr) - &(ty * beta_cube);
    [read(0), read(1), read(2), read(3), positive, negative]
}

pub fn lookup_inverse_exists<T: FieldLike>(r: &[T]) -> T {
    let write = r[precompute_select as usize].clone();
    let read = r[msm_add as usize].clone() + &r[msm_skew as usize];
    write.clone() + &read - &(write * &read)
}

fn lookup<T: FieldLike<Native = Fq>>(acc: &mut [T], r: &[T], p: &RelationParams<T>, scaling: &T) {
    let v = |e: Ent| r[e as usize].clone();
    let terms = lookup_terms(r, p);
    let inverses = v(lookup_inverses);
    let mut denominators: Vec<T> = terms.to_vec();
    for i in 1..6 {
        let prev = denominators[i - 1].clone();
        denominators[i] *= &prev;
    }
    acc[0] += (denominators[5].clone() * &inverses - &lookup_inverse_exists(r)) * scaling;
    let mut inverse_accumulator = inverses;
    for i in (1..6).rev() {
        denominators[i] = denominators[i - 1].clone() * &inverse_accumulator;
        inverse_accumulator = inverse_accumulator * &terms[i];
    }
    denominators[0] = inverse_accumulator;
    let read_predicates = [msm_add1, msm_add2, msm_add3, msm_add4];
    for (i, e) in read_predicates.iter().enumerate() {
        acc[1] += v(*e) * &denominators[i];
    }
    let select = v(precompute_select);
    acc[1] -= select.clone() * &denominators[4] * &v(lookup_read_counts_0);
    acc[1] -= select * &denominators[5] * &v(lookup_read_counts_1);
}
