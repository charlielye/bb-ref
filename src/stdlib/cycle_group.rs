//! Grumpkin points in a bn254 circuit (bb `stdlib::cycle_group` and `cycle_scalar`): affine
//! coordinates plus an infinity flag, elliptic gates for addition/doubling, and the Straus
//! variable-base multi-scalar multiplication over ROM point tables. The fixed-base plookup path
//! (points with precomputed tables) is not ported: no protocol kernel uses it.

use super::bool::BoolT;
use super::field::{same_ctx, Ctx, FieldT};
use crate::base::field::{from_u256, u256, FieldLike, U256};
use crate::base::generators::{default_generators, derive_generators};
use crate::base::{Fq, Fr, GrumpkinAffine};
use crate::circuit::builder::{EccAddGate, EccDblGate};
use ark_ec::short_weierstrass::{Projective, SWCurveConfig};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{AdditiveGroup, Field, PrimeField};
use ark_grumpkin::GrumpkinConfig;

type Element = Projective<GrumpkinConfig>;

/// bb `cycle_group::ROM_TABLE_BITS`.
pub const TABLE_BITS: usize = 4;
pub const NUM_BITS: usize = 254;
pub const LO_BITS: usize = 128;
pub const HI_BITS: usize = NUM_BITS - LO_BITS;

fn curve_b() -> Fr {
    GrumpkinConfig::COEFF_B
}
fn one() -> GrumpkinAffine {
    GrumpkinAffine::generator()
}
fn affine(e: Element) -> GrumpkinAffine {
    e.into_affine()
}
fn div_or_zero(n: Fr, d: Fr) -> Fr {
    if d.is_zero() {
        Fr::zero()
    } else {
        n * d.invert()
    }
}

/// bb `cycle_scalar`: a Grumpkin scalar as two limbs of 128 and 126 bits, checked to be below
/// the scalar field modulus.
#[derive(Clone)]
pub struct CycleScalar {
    pub lo: FieldT,
    pub hi: FieldT,
}

impl CycleScalar {
    pub fn new(lo: FieldT, hi: FieldT) -> Self {
        validate_split_in_field_unsafe(&lo, &hi, LO_BITS, Fq::MODULUS);
        Self { lo, hi }
    }
    pub fn constant(v: Fq) -> Self {
        let v = u256(&v);
        Self {
            lo: FieldT::constant(from_u256(U256::new([v.0[0], v.0[1], 0, 0]))),
            hi: FieldT::constant(from_u256(U256::new([v.0[2], v.0[3], 0, 0]))),
        }
    }
    pub fn is_constant(&self) -> bool {
        self.lo.is_constant() && self.hi.is_constant()
    }
    pub fn ctx(&self) -> Option<Ctx> {
        same_ctx(&self.lo.ctx, &self.hi.ctx)
    }

    /// bb `cycle_scalar(BigScalarField&)`: a bigfield grumpkin scalar recombined into the 128/126-bit
    /// halves, with `no_wrap_split_at` splits where limb bounds overflow.
    pub fn from_bigfield(scalar: &crate::stdlib::bigfield::BigField<crate::base::Fq>) -> Self {
        use crate::base::field::{from_u256, U256};
        use crate::stdlib::bigfield::NUM_LIMB_BITS as LIMB_BITS;
        use num_bigint::BigUint;
        const LO_BITS: usize = 128;
        const HI_BITS: usize = 126;
        if scalar.get_maximum_value() >= (BigUint::from(1u64) << (LO_BITS + HI_BITS)) {
            scalar.self_reduce();
        }
        let mut limb0 = scalar.get_limb(0).element;
        let mut limb1 = scalar.get_limb(1).element;
        let limb2 = scalar.get_limb(2).element;
        let limb3 = scalar.get_limb(3).element;
        let mut limb1_max = scalar.get_limb(1).maximum_value;
        let limb0_max = scalar.get_limb(0).maximum_value;
        let default_max = crate::stdlib::bigfield::BigField::<crate::base::Fq>::default_maximum_limb();
        if limb0_max > default_max {
            let limb0_max_bits = limb0_max.bits() as usize;
            let (limb0_lo, limb0_hi) =
                crate::stdlib::field::no_wrap_split_at(&limb0, LIMB_BITS as usize, limb0_max_bits);
            limb0 = limb0_lo;
            limb1 = limb1.add(&limb0_hi);
            limb1_max += &limb0_max >> LIMB_BITS;
        }
        let lo_bits_in_limb_1 = LO_BITS - LIMB_BITS as usize;
        let (limb1_lo, limb1_hi) = if limb1_max < (BigUint::from(1u64) << lo_bits_in_limb_1) {
            (limb1, FieldT::constant(Fr::from(0u64)))
        } else {
            let limb1_max_bits = limb1_max.bits() as usize;
            crate::stdlib::field::no_wrap_split_at(&limb1, lo_bits_in_limb_1, limb1_max_bits)
        };
        let shift_1 = FieldT::constant(from_u256(U256::from(1u64) << LIMB_BITS as u32));
        let lo = limb0.add(&limb1_lo.mul(&shift_1));
        let limb2_shift = FieldT::constant(from_u256(U256::from(1u64) << (2 * LIMB_BITS as usize - LO_BITS) as u32));
        let limb3_shift = FieldT::constant(from_u256(U256::from(1u64) << (3 * LIMB_BITS as usize - LO_BITS) as u32));
        let hi = limb1_hi.add_two(&limb2.mul(&limb2_shift), &limb3.mul(&limb3_shift));
        Self::new(lo, hi)
    }

    pub fn get_value(&self) -> Fq {
        let two_pow_128 = Fq::from(2u64).pow([LO_BITS as u64]);
        from_u256::<Fq>(u256(&self.lo.get_value())) + from_u256::<Fq>(u256(&self.hi.get_value())) * two_pow_128
    }
}

/// bb `validate_split_in_field_unsafe`: `lo + 2^lo_bits * hi < modulus` via a borrow bit and two
/// range constraints (the limbs themselves are assumed range-constrained elsewhere).
pub fn validate_split_in_field_unsafe(lo: &FieldT, hi: &FieldT, lo_bits: usize, modulus: U256) {
    let msb = 254 - 1;
    let hi_bits = msb + 1 - lo_bits;
    let r_lo = U256::new([modulus.0[0], modulus.0[1], 0, 0]);
    let r_hi = U256::new([modulus.0[2], modulus.0[3], 0, 0]);
    let need_borrow = u256(&lo.get_value()) >= r_lo;
    let both_constant = lo.is_constant() && hi.is_constant();
    let borrow = if both_constant {
        FieldT::constant(Fr::from(need_borrow as u64))
    } else {
        let ctx = same_ctx(&lo.ctx, &hi.ctx).unwrap();
        let b = FieldT::from_witness(&ctx, Fr::from(need_borrow as u64));
        ctx.borrow_mut().create_small_range_constraint(b.get_witness_index(), 1);
        b
    };
    let r_lo_minus_one = FieldT::constant(from_u256::<Fr>(r_lo) - Fr::one());
    let shift = FieldT::constant(from_u256::<Fr>(U256::new([0, 0, 1, 0])));
    let hi_diff = &(&FieldT::neg(hi) + &FieldT::constant(from_u256::<Fr>(r_hi))) - &borrow;
    let lo_diff = &(&FieldT::neg(lo) + &r_lo_minus_one) + &(&borrow * &shift);
    hi_diff.create_range_constraint(hi_bits as u64);
    lo_diff.create_range_constraint(lo_bits as u64);
}

#[derive(Clone)]
pub struct CycleGroup {
    pub x: FieldT,
    pub y: FieldT,
    pub is_infinity: BoolT,
    ctx: Option<Ctx>,
}

impl CycleGroup {
    /// bb `cycle_group(x, y, assert_on_curve)`: `(0, 0)` encodes infinity.
    pub fn from_xy(x: FieldT, y: FieldT, assert_on_curve: bool) -> Self {
        let x_sqr = x.sqr();
        let five_y = &y * &FieldT::constant(Fr::from(5u64));
        let is_infinity = y.madd(&five_y, &x_sqr).is_zero();
        Self::finish(x, y, is_infinity, assert_on_curve)
    }
    /// bb `cycle_group(x, y, is_infinity, assert_on_curve)`.
    pub fn from_xyi(x: FieldT, y: FieldT, is_infinity: BoolT, assert_on_curve: bool) -> Self {
        assert!(
            !(x.is_constant() && y.is_constant() && !is_infinity.is_constant()),
            "constant coordinates with a non-constant infinity flag"
        );
        Self::finish(x, y, is_infinity, assert_on_curve)
    }
    fn finish(mut x: FieldT, mut y: FieldT, is_infinity: BoolT, assert_on_curve: bool) -> Self {
        let ctx = same_ctx(&same_ctx(&x.ctx, &y.ctx), &is_infinity.ctx);
        if x.is_constant() != y.is_constant() {
            let c = ctx.clone().unwrap();
            if x.is_constant() {
                x.convert_constant_to_fixed_witness(&c);
            } else {
                y.convert_constant_to_fixed_witness(&c);
            }
        }
        let g = Self { x, y, is_infinity, ctx };
        // bb never aborts natively on an off-curve value (write-VK mock proofs contain garbage);
        // `validate_on_curve` records the constraint failure instead.
        if assert_on_curve {
            g.validate_on_curve();
        }
        g
    }
    pub fn constant(p: GrumpkinAffine) -> Self {
        let (x, y) = p.xy().unwrap_or((Fr::zero(), Fr::zero()));
        Self {
            x: FieldT::constant(x),
            y: FieldT::constant(y),
            is_infinity: BoolT::constant(p.is_zero()),
            ctx: None,
        }
    }
    /// bb `from_constant_witness`: fixed witnesses holding a constant point.
    /// bb `cycle_group::from_witness`: plain coordinate witnesses ((0,0) for infinity), on-curve checked.
    pub fn from_witness(ctx: &Ctx, p: GrumpkinAffine) -> Self {
        let (xv, yv) = if AffineRepr::is_zero(&p) {
            (Fr::from(0u64), Fr::from(0u64))
        } else {
            (p.x, p.y)
        };
        let x = FieldT::from_witness(ctx, xv);
        let y = FieldT::from_witness(ctx, yv);
        Self::from_xy(x, y, true)
    }

    pub fn from_constant_witness(ctx: &Ctx, p: GrumpkinAffine) -> Self {
        if p.is_zero() {
            return Self {
                x: FieldT::constant(Fr::zero()),
                y: FieldT::constant(Fr::zero()),
                is_infinity: BoolT::constant(true),
                ctx: Some(ctx.clone()),
            };
        }
        let (px, py) = p.xy().unwrap();
        let x = FieldT::from_witness(ctx, px);
        let y = FieldT::from_witness(ctx, py);
        x.assert_equal(&FieldT::constant(px));
        y.assert_equal(&FieldT::constant(py));
        Self {
            x,
            y,
            is_infinity: BoolT::constant(false),
            ctx: Some(ctx.clone()),
        }
    }
    pub fn ctx(&self) -> Option<Ctx> {
        self.ctx.clone()
    }
    pub fn get_value(&self) -> GrumpkinAffine {
        if self.is_infinity.get_value() {
            GrumpkinAffine::zero()
        } else {
            GrumpkinAffine::new_unchecked(self.x.get_value(), self.y.get_value())
        }
    }
    pub fn is_constant(&self) -> bool {
        self.x.is_constant() && self.y.is_constant() && self.is_infinity.is_constant()
    }
    pub fn is_constant_point_at_infinity(&self) -> bool {
        self.is_infinity.is_constant() && self.is_infinity.get_value()
    }
    pub fn validate_on_curve(&self) {
        let xx = &self.x * &self.x;
        let xxx = &xx * &self.x;
        let res = self
            .y
            .madd(&self.y, &(&FieldT::neg(&xxx) - &FieldT::constant(curve_b())));
        let res = &res * &self.is_infinity.not().to_field();
        res.assert_is_zero();
    }
    /// Force the coordinates of a point at infinity to `(0, 0)`.
    /// bb `cycle_group::set_public`: standardize (infinity to (0,0)) then publish both coordinates.
    /// bb `cycle_group::fix_witness`.
    pub fn fix_witness(&self) {
        self.x.fix_witness();
        self.y.fix_witness();
        self.is_infinity.fix_witness();
    }

    pub fn set_public(&self) -> u32 {
        let mut standard = self.clone();
        standard.standardize();
        let start = standard.x.set_public();
        standard.y.set_public();
        start
    }

    pub fn standardize(&mut self) {
        self.x = FieldT::conditional_assign(&self.is_infinity, &FieldT::constant(Fr::zero()), &self.x);
        self.y = FieldT::conditional_assign(&self.is_infinity, &FieldT::constant(Fr::zero()), &self.y);
    }

    pub fn dbl(&self, hint: Option<GrumpkinAffine>) -> Self {
        if self.is_constant_point_at_infinity() {
            return self.clone();
        }
        let modified_y = FieldT::conditional_assign(&self.is_infinity, &FieldT::constant(Fr::one()), &self.y);
        let (x3, y3) = match hint {
            Some(h) => (h.x, h.y),
            None => {
                let x1 = self.x.get_value();
                let y1 = modified_y.get_value();
                let y_pow_2 = y1.square();
                let x_pow_4 = x1 * (y_pow_2 - curve_b());
                let lambda_squared = div_or_zero(x_pow_4 * Fr::from(9u64), y_pow_2 * Fr::from(4u64));
                let lambda = div_or_zero(x1 * x1 * Fr::from(3u64), y1 + y1);
                let x3 = lambda_squared - x1 - x1;
                (x3, lambda * (x1 - x3) - y1)
            }
        };
        if self.is_constant() {
            return Self::from_xyi(
                FieldT::constant(x3),
                FieldT::constant(y3),
                self.is_infinity.clone(),
                false,
            );
        }
        let ctx = self.ctx.clone().unwrap();
        let result = Self::from_xyi(
            FieldT::from_witness(&ctx, x3),
            FieldT::from_witness(&ctx, y3),
            self.is_infinity.clone(),
            false,
        );
        ctx.borrow_mut().create_ecc_dbl_gate(EccDblGate {
            x1: self.x.get_witness_index(),
            y1: modified_y.get_witness_index(),
            x3: result.x.get_witness_index(),
            y3: result.y.get_witness_index(),
        });
        result
    }

    fn unconditional_add_or_subtract(&self, other: &Self, is_addition: bool, hint: Option<GrumpkinAffine>) -> Self {
        self.is_infinity.assert_equal(&BoolT::constant(false));
        other.is_infinity.assert_equal(&BoolT::constant(false));
        let ctx = same_ctx(&self.ctx, &other.ctx);
        let (lhs_constant, rhs_constant) = (self.is_constant(), other.is_constant());
        if lhs_constant && !rhs_constant {
            let lhs = Self::from_constant_witness(ctx.as_ref().unwrap(), self.get_value());
            return lhs.unconditional_add_or_subtract(other, is_addition, hint);
        }
        if !lhs_constant && rhs_constant {
            let rhs = Self::from_constant_witness(ctx.as_ref().unwrap(), other.get_value());
            return self.unconditional_add_or_subtract(&rhs, is_addition, hint);
        }
        let (x3, y3) = match hint {
            Some(h) => (h.x, h.y),
            None => {
                let (p1, p2) = (self.get_value().into_group(), other.get_value().into_group());
                let p3 = affine(if is_addition { p1 + p2 } else { p1 - p2 });
                (p3.x, p3.y)
            }
        };
        if lhs_constant && rhs_constant {
            return Self::from_xyi(
                FieldT::constant(x3),
                FieldT::constant(y3),
                BoolT::constant(false),
                false,
            );
        }
        let ctx = ctx.unwrap();
        let result = Self::from_xyi(
            FieldT::from_witness(&ctx, x3),
            FieldT::from_witness(&ctx, y3),
            BoolT::constant(false),
            false,
        );
        ctx.borrow_mut().create_ecc_add_gate(EccAddGate {
            x1: self.x.get_witness_index(),
            y1: self.y.get_witness_index(),
            x2: other.x.get_witness_index(),
            y2: other.y.get_witness_index(),
            x3: result.x.get_witness_index(),
            y3: result.y.get_witness_index(),
            is_addition,
        });
        result
    }
    /// Addition assuming neither operand is infinity and `x1 != x2`.
    pub fn unconditional_add(&self, other: &Self, hint: Option<GrumpkinAffine>) -> Self {
        self.unconditional_add_or_subtract(other, true, hint)
    }
    pub fn checked_unconditional_add(&self, other: &Self, hint: Option<GrumpkinAffine>) -> Self {
        let x_delta = &self.x - &other.x;
        if x_delta.is_constant() {
            assert!(!x_delta.get_value().is_zero());
        } else {
            x_delta.assert_is_not_zero();
        }
        self.unconditional_add(other, hint)
    }

    /// bb `operator+`: complete addition (doubling and infinity cases selected in-circuit).
    pub fn add(&self, other: &Self) -> Self {
        if self.is_constant_point_at_infinity() {
            return other.clone();
        }
        if other.is_constant_point_at_infinity() {
            return self.clone();
        }
        let x_coordinates_match = self.x.eq(&other.x);
        let y_coordinates_match = self.y.eq(&other.y);
        let (x1, y1, x2, y2) = (&self.x, &self.y, &other.x, &other.y);
        let x_diff = x2.add_two(&FieldT::neg(x1), &x_coordinates_match.to_field());
        let lambda = if (y1.is_constant() && y2.is_constant()) || x_diff.is_constant() {
            (y2 - y1).divide_no_zero_check(&x_diff)
        } else {
            let ctx = same_ctx(&self.ctx, &other.ctx).unwrap();
            let lambda = FieldT::from_witness(&ctx, div_or_zero(y2.get_value() - y1.get_value(), x_diff.get_value()));
            FieldT::evaluate_polynomial_identity(&x_diff, &lambda, &FieldT::neg(y2), y1);
            lambda
        };
        let add_result_x = lambda.madd(&lambda, &FieldT::neg(&(x2 + x1)));
        let add_result_y = lambda.madd(&(x1 - &add_result_x), &FieldT::neg(y1));
        let dbl_result = self.dbl(None);
        let double_predicate = x_coordinates_match.and(&y_coordinates_match);
        let mut result_x = FieldT::conditional_assign(&double_predicate, &dbl_result.x, &add_result_x);
        let mut result_y = FieldT::conditional_assign(&double_predicate, &dbl_result.y, &add_result_y);
        let lhs_infinity = self.is_infinity.clone();
        result_x = FieldT::conditional_assign(&lhs_infinity, &other.x, &result_x);
        result_y = FieldT::conditional_assign(&lhs_infinity, &other.y, &result_y);
        let rhs_infinity = other.is_infinity.clone();
        result_x = FieldT::conditional_assign(&rhs_infinity, &self.x, &result_x);
        result_y = FieldT::conditional_assign(&rhs_infinity, &self.y, &result_y);
        let infinity_predicate = x_coordinates_match.and(&y_coordinates_match.not());
        let mut result_is_infinity = infinity_predicate.and(&lhs_infinity.not().and(&rhs_infinity.not()));
        result_is_infinity = result_is_infinity.or(&lhs_infinity.and(&rhs_infinity));
        Self::from_xyi(result_x, result_y, result_is_infinity, false)
    }
    /// bb `operator-`.
    pub fn sub(&self, other: &Self) -> Self {
        if self.is_constant_point_at_infinity() {
            return other.neg();
        }
        if other.is_constant_point_at_infinity() {
            return self.clone();
        }
        let x_coordinates_match = self.x.eq(&other.x);
        let y_coordinates_match = self.y.eq(&other.y);
        let (x1, y1, x2, y2) = (&self.x, &self.y, &other.x, &other.y);
        let x_diff = x2.add_two(&FieldT::neg(x1), &x_coordinates_match.to_field());
        let lambda = if (y1.is_constant() && y2.is_constant()) || x_diff.is_constant() {
            (&FieldT::neg(y2) - y1).divide_no_zero_check(&x_diff)
        } else {
            let ctx = same_ctx(&self.ctx, &other.ctx).unwrap();
            let lambda = FieldT::from_witness(&ctx, div_or_zero(-y2.get_value() - y1.get_value(), x_diff.get_value()));
            FieldT::evaluate_polynomial_identity(&x_diff, &lambda, y2, y1);
            lambda
        };
        let sub_result_x = lambda.madd(&lambda, &FieldT::neg(&(x2 + x1)));
        let sub_result_y = lambda.madd(&(x1 - &sub_result_x), &FieldT::neg(y1));
        let dbl_result = self.dbl(None);
        let double_predicate = x_coordinates_match.and(&y_coordinates_match.not());
        let mut result_x = FieldT::conditional_assign(&double_predicate, &dbl_result.x, &sub_result_x);
        let mut result_y = FieldT::conditional_assign(&double_predicate, &dbl_result.y, &sub_result_y);
        let lhs_infinity = self.is_infinity.clone();
        result_x = FieldT::conditional_assign(&lhs_infinity, &other.x, &result_x);
        result_y = FieldT::conditional_assign(&lhs_infinity, &FieldT::neg(&other.y), &result_y);
        let rhs_infinity = other.is_infinity.clone();
        result_x = FieldT::conditional_assign(&rhs_infinity, &self.x, &result_x);
        result_y = FieldT::conditional_assign(&rhs_infinity, &self.y, &result_y);
        let infinity_predicate = x_coordinates_match.and(&y_coordinates_match);
        let mut result_is_infinity = infinity_predicate.and(&lhs_infinity.not().and(&rhs_infinity.not()));
        result_is_infinity = result_is_infinity.or(&lhs_infinity.and(&rhs_infinity));
        Self::from_xyi(result_x, result_y, result_is_infinity, false)
    }
    pub fn neg(&self) -> Self {
        let mut r = self.clone();
        r.y = FieldT::neg(&self.y).normalize();
        r
    }
    pub fn conditional_assign(predicate: &BoolT, lhs: &Self, rhs: &Self) -> Self {
        let x = FieldT::conditional_assign(predicate, &lhs.x, &rhs.x);
        let y = FieldT::conditional_assign(predicate, &lhs.y, &rhs.y);
        let is_infinity = BoolT::conditional_assign(predicate, &lhs.is_infinity, &rhs.is_infinity);
        Self::from_xyi(x, y, is_infinity, false)
    }
    pub fn assert_equal(&mut self, other: &mut Self) {
        self.standardize();
        other.standardize();
        self.x.assert_equal(&other.x);
        self.y.assert_equal(&other.y);
        self.is_infinity.assert_equal(&other.is_infinity);
    }

    /// bb `batch_mul`: `sum_i scalars[i] * points[i]`. Constant terms are folded natively;
    /// variable terms go through the Straus tables, offset by generators that are removed at the end.
    pub fn batch_mul(points: &[Self], scalars: &[CycleScalar]) -> Self {
        assert_eq!(points.len(), scalars.len(), "points/scalars size mismatch in batch mul");
        if scalars.is_empty() {
            return Self::constant(GrumpkinAffine::zero());
        }
        let fixed_base = default_generators(2);
        let mut variable_base_scalars = vec![];
        let mut variable_base_points = vec![];
        let mut can_unconditional_add = true;
        let mut has_non_constant_component = false;
        let mut constant_acc = Element::ZERO;
        for (point, scalar) in points.iter().zip(scalars) {
            if scalar.is_constant() && point.is_constant() {
                constant_acc += point.get_value() * scalar.get_value();
            } else if !scalar.is_constant() && point.is_constant() {
                if point.get_value().is_zero() {
                    let ctx = scalar.ctx().unwrap();
                    let mut b = ctx.borrow_mut();
                    b.create_limbed_range_constraint(scalar.lo.get_witness_index(), LO_BITS as u64, TABLE_BITS as u64);
                    b.create_limbed_range_constraint(scalar.hi.get_witness_index(), HI_BITS as u64, TABLE_BITS as u64);
                    continue;
                }
                assert!(
                    !fixed_base.contains(&point.get_value()),
                    "fixed-base plookup tables are not ported"
                );
                variable_base_scalars.push(scalar.clone());
                variable_base_points.push(point.clone());
                has_non_constant_component = true;
            } else {
                variable_base_scalars.push(scalar.clone());
                variable_base_points.push(point.clone());
                can_unconditional_add = false;
                has_non_constant_component = true;
            }
        }
        if !has_non_constant_component {
            return Self::constant(affine(constant_acc));
        }
        let mut offset_accumulator = -constant_acc;
        let offset_generators = derive_generators(b"cycle_group_offset_generator", variable_base_points.len() + 1, 0);
        let (mut result, offset_generator_delta) = Self::variable_base_batch_mul_internal(
            &variable_base_scalars,
            &variable_base_points,
            &offset_generators,
            can_unconditional_add,
        );
        offset_accumulator += offset_generator_delta;
        if constant_acc != Element::ZERO && can_unconditional_add {
            result = result.unconditional_add(&Self::constant(affine(-offset_accumulator)), None);
        } else {
            result = result.sub(&Self::constant(affine(offset_accumulator)));
        }
        result
    }

    /// bb `_variable_base_batch_mul_internal`: Straus with 4-bit windows; the native transcript
    /// supplies the addition/doubling results as hints.
    fn variable_base_batch_mul_internal(
        scalars: &[CycleScalar],
        points: &[Self],
        offset_generators: &[GrumpkinAffine],
        unconditional_add: bool,
    ) -> (Self, GrumpkinAffine) {
        let num_points = scalars.len();
        assert_eq!(offset_generators.len(), num_points + 1);
        let ctx = scalars
            .iter()
            .find_map(|s| s.ctx())
            .or_else(|| points.iter().find_map(|p| p.ctx()))
            .unwrap();
        let num_rounds = NUM_BITS.div_ceil(TABLE_BITS);
        let scalar_slices: Vec<StrausScalarSlices> = scalars
            .iter()
            .map(|s| StrausScalarSlices::new(&ctx, s, TABLE_BITS))
            .collect();
        let mut operation_transcript: Vec<Element> = vec![];
        let mut offset_generator_accumulator: Element = offset_generators[0].into_group();
        {
            let mut native_tables: Vec<Vec<Element>> = vec![];
            for (i, point) in points.iter().enumerate() {
                let table = StrausLookupTable::compute_native_table(
                    point.get_value().into_group(),
                    offset_generators[i + 1].into_group(),
                    TABLE_BITS,
                );
                operation_transcript.extend_from_slice(&table[1..]);
                native_tables.push(table);
            }
            let mut accumulator: Element = offset_generators[0].into_group();
            for i in 0..num_rounds {
                if i != 0 {
                    for _ in 0..TABLE_BITS {
                        accumulator.double_in_place();
                        operation_transcript.push(accumulator);
                        offset_generator_accumulator.double_in_place();
                    }
                }
                for j in 0..num_points {
                    let slice = scalar_slices[j].native[num_rounds - i - 1] as usize;
                    accumulator += native_tables[j][slice];
                    operation_transcript.push(accumulator);
                    offset_generator_accumulator += offset_generators[j + 1];
                }
            }
        }
        let hints: Vec<GrumpkinAffine> = Element::normalize_batch(&operation_transcript);
        let hints_per_table = (1usize << TABLE_BITS) - 1;
        let point_tables: Vec<StrausLookupTable> = (0..num_points)
            .map(|i| {
                StrausLookupTable::new(
                    &ctx,
                    &points[i],
                    &Self::constant(offset_generators[i + 1]),
                    TABLE_BITS,
                    Some(&hints[i * hints_per_table..(i + 1) * hints_per_table]),
                )
            })
            .collect();
        let mut hint_ptr = num_points * hints_per_table;
        let mut accumulator = Self::constant(offset_generators[0]);
        let mut coordinate_check_product = FieldT::constant(Fr::one());
        for i in 0..num_rounds {
            if i != 0 {
                for _ in 0..TABLE_BITS {
                    accumulator = accumulator.dbl(Some(hints[hint_ptr]));
                    hint_ptr += 1;
                }
            }
            for j in 0..num_points {
                let scalar_slice = &scalar_slices[j].slices[num_rounds - i - 1];
                let point = point_tables[j].read(scalar_slice);
                if !unconditional_add {
                    coordinate_check_product = &coordinate_check_product * &(&point.x - &accumulator.x);
                }
                accumulator = accumulator.unconditional_add(&point, Some(hints[hint_ptr]));
                hint_ptr += 1;
            }
        }
        if !unconditional_add {
            coordinate_check_product.assert_is_not_zero();
        }
        (accumulator, affine(offset_generator_accumulator))
    }
}

/// bb `straus_plookup_table`: a per-point plookup table `{ [G] + i.[P] }` for a CONSTANT base
/// point; zero construction gates, one lookup gate per read.
pub struct StrausPlookupTable {
    ctx: Ctx,
    table: usize,
    native_table: Vec<GrumpkinAffine>,
}

impl StrausPlookupTable {
    pub fn new(ctx: &Ctx, base_point: GrumpkinAffine, offset_generator: GrumpkinAffine, table_bits: usize) -> Self {
        Self::from_native(ctx, Self::native(base_point, offset_generator, table_bits))
    }

    /// The ctx-free half of construction, so callers building many tables can compute them in
    /// parallel and register sequentially (registration order is part of the circuit).
    pub fn native(
        base_point: GrumpkinAffine,
        offset_generator: GrumpkinAffine,
        table_bits: usize,
    ) -> Vec<GrumpkinAffine> {
        use ark_ec::CurveGroup;
        let table_size = 1usize << table_bits;
        let mut projective: Vec<Element> = Vec::with_capacity(table_size);
        projective.push(offset_generator.into_group());
        let base = base_point.into_group();
        for i in 1..table_size {
            let next = projective[i - 1] + base;
            projective.push(next);
        }
        Element::normalize_batch(&projective)
    }

    pub fn from_native(ctx: &Ctx, native_table: Vec<GrumpkinAffine>) -> Self {
        let mut columns: [Vec<Fr>; 3] = [vec![], vec![], vec![]];
        for (i, p) in native_table.iter().enumerate() {
            columns[0].push(Fr::from(i as u64));
            columns[1].push(p.x);
            columns[2].push(p.y);
        }
        let table = ctx
            .borrow_mut()
            .register_basic_lookup_table(crate::circuit::plookup::BasicTable {
                id: crate::circuit::plookup::BasicTableId::StrausEcPoint,
                table_index: 0,
                use_twin_keys: false,
                columns,
                lookup_gates: vec![],
            });
        Self {
            ctx: ctx.clone(),
            table,
            native_table,
        }
    }

    pub fn read(&self, index: &FieldT) -> CycleGroup {
        let mut index = index.clone();
        if index.is_constant() {
            let v = index.get_value();
            index = FieldT::from_witness(&self.ctx, v);
            index.assert_equal(&FieldT::constant(v));
        }
        let native_index = u256(&index.get_value()).0[0] as usize;
        let point = self.native_table[native_index];
        let (x_idx, y_idx) = {
            let mut b = self.ctx.borrow_mut();
            (b.add_variable(point.x), b.add_variable(point.y))
        };
        self.ctx.borrow_mut().create_standalone_lookup_gate(
            [index.get_witness_index(), x_idx, y_idx],
            self.table,
            crate::circuit::plookup::LookupEntry {
                key: [native_index as u64, 0],
                value: [point.x, point.y],
            },
        );
        let x = FieldT::from_witness_index(&self.ctx, x_idx);
        let y = FieldT::from_witness_index(&self.ctx, y_idx);
        CycleGroup::from_xyi(x, y, BoolT::constant(false), false)
    }
}

impl CycleGroup {
    /// bb `cycle_group::fixed_batch_mul`: MSM over CONSTANT points via per-point plookup tables.
    pub fn fixed_batch_mul(constant_points: &[Self], scalars: &[CycleScalar], table_bits: usize) -> Self {
        assert_eq!(
            constant_points.len(),
            scalars.len(),
            "points/scalars size mismatch in fixed_batch_mul"
        );
        if scalars.is_empty() {
            return Self::constant(GrumpkinAffine::zero());
        }
        let mut plookup_scalars = vec![];
        let mut plookup_points = vec![];
        let mut has_non_constant_component = false;
        let mut constant_acc = Element::ZERO;
        for (point, scalar) in constant_points.iter().zip(scalars) {
            assert!(point.is_constant(), "fixed_batch_mul requires constant points");
            if scalar.is_constant() {
                constant_acc += point.get_value() * scalar.get_value();
            } else {
                if point.get_value().is_zero() {
                    let ctx = scalar.ctx().unwrap();
                    let mut b = ctx.borrow_mut();
                    b.create_limbed_range_constraint(scalar.lo.get_witness_index(), LO_BITS as u64, table_bits as u64);
                    b.create_limbed_range_constraint(scalar.hi.get_witness_index(), HI_BITS as u64, table_bits as u64);
                    continue;
                }
                plookup_scalars.push(scalar.clone());
                plookup_points.push(point.get_value());
                has_non_constant_component = true;
            }
        }
        if !has_non_constant_component {
            return Self::constant(affine(constant_acc));
        }
        let offset_generators = derive_generators(b"cycle_group_offset_generator", plookup_points.len() + 1, 0);
        let mut offset_accumulator = -constant_acc;
        let (accumulator, offset_generator_delta) = Self::fixed_base_plookup_batch_mul_internal(
            &plookup_scalars,
            &plookup_points,
            &offset_generators,
            table_bits,
        );
        offset_accumulator += offset_generator_delta.into_group();
        if constant_acc != Element::ZERO {
            accumulator.unconditional_add(&Self::constant(affine(-offset_accumulator)), None)
        } else {
            accumulator.sub(&Self::constant(affine(offset_accumulator)))
        }
    }

    /// bb `_fixed_base_plookup_batch_mul_internal`: Straus over plookup tables with native hints.
    fn fixed_base_plookup_batch_mul_internal(
        scalars: &[CycleScalar],
        base_points: &[GrumpkinAffine],
        offset_generators: &[GrumpkinAffine],
        table_bits: usize,
    ) -> (Self, GrumpkinAffine) {
        use ark_ec::CurveGroup;
        assert!(!scalars.is_empty());
        assert_eq!(scalars.len(), base_points.len());
        assert_eq!(offset_generators.len(), base_points.len() + 1);
        let ctx = scalars.iter().find_map(|s| s.ctx()).unwrap();
        assert_eq!(LO_BITS % table_bits, 0, "table_bits must divide LO_BITS");
        let num_rounds = NUM_BITS.div_ceil(table_bits);

        let scalar_slices: Vec<StrausScalarSlices> = scalars
            .iter()
            .map(|s| StrausScalarSlices::new(&ctx, s, table_bits))
            .collect();

        let native_tables: Vec<Vec<GrumpkinAffine>> = {
            use rayon::prelude::*;
            base_points
                .par_iter()
                .enumerate()
                .map(|(i, p)| StrausPlookupTable::native(*p, offset_generators[i + 1], table_bits))
                .collect()
        };
        let point_tables: Vec<StrausPlookupTable> = native_tables
            .into_iter()
            .map(|t| StrausPlookupTable::from_native(&ctx, t))
            .collect();

        // Native Straus transcript for hints.
        let mut operation_transcript: Vec<Element> = vec![];
        let mut offset_generator_accumulator: Element = offset_generators[0].into_group();
        {
            let mut accumulator: Element = offset_generators[0].into_group();
            for i in 0..num_rounds {
                if i != 0 {
                    for _ in 0..table_bits {
                        accumulator.double_in_place();
                        operation_transcript.push(accumulator);
                        offset_generator_accumulator.double_in_place();
                    }
                }
                for (j, table) in point_tables.iter().enumerate() {
                    let slice_value = scalar_slices[j].native[num_rounds - i - 1] as usize;
                    accumulator += table.native_table[slice_value].into_group();
                    operation_transcript.push(accumulator);
                    offset_generator_accumulator += offset_generators[j + 1].into_group();
                }
            }
        }
        let operation_hints = Element::normalize_batch(&operation_transcript);

        let mut hint = operation_hints.iter();
        let mut accumulator = Self::constant(offset_generators[0]);
        for i in 0..num_rounds {
            if i != 0 {
                for _ in 0..table_bits {
                    accumulator = accumulator.dbl(Some(*hint.next().unwrap()));
                }
            }
            for (j, table) in point_tables.iter().enumerate() {
                let scalar_slice = scalar_slices[j].slices[num_rounds - i - 1].clone();
                let point = table.read(&scalar_slice);
                accumulator = accumulator.unconditional_add(&point, Some(*hint.next().unwrap()));
            }
        }
        (accumulator, affine(offset_generator_accumulator))
    }
}

/// bb `straus_scalar_slices`: a scalar's limbs in `table_bits` windows, low limb first.
pub struct StrausScalarSlices {
    pub slices: Vec<FieldT>,
    pub native: Vec<u64>,
}

impl StrausScalarSlices {
    fn compute(ctx: &Ctx, scalar: &FieldT, num_bits: usize, table_bits: usize) -> (Vec<FieldT>, Vec<u64>) {
        let num_slices = num_bits.div_ceil(table_bits);
        if scalar.is_constant() {
            let mask = (1u64 << table_bits) - 1;
            let mut raw = u256(&scalar.get_value());
            let mut slices = vec![];
            let mut native = vec![];
            for _ in 0..num_slices {
                let v = raw.0[0] & mask;
                slices.push(FieldT::constant(Fr::from(v)));
                native.push(v);
                raw = crate::base::field::u256_shr(raw, table_bits as u32);
            }
            return (slices, native);
        }
        let indices = ctx.borrow_mut().create_limbed_range_constraint(
            scalar.get_witness_index(),
            num_bits as u64,
            table_bits as u64,
        );
        let slices: Vec<FieldT> = indices.iter().map(|i| FieldT::from_witness_index(ctx, *i)).collect();
        let native = slices.iter().map(|s| u256(&s.get_value()).0[0]).collect();
        (slices, native)
    }
    pub fn new(ctx: &Ctx, scalar: &CycleScalar, table_bits: usize) -> Self {
        let (hi, hi_native) = Self::compute(ctx, &scalar.hi, HI_BITS, table_bits);
        let (mut slices, mut native) = Self::compute(ctx, &scalar.lo, LO_BITS, table_bits);
        slices.extend(hi);
        native.extend(hi_native);
        Self { slices, native }
    }
}

/// bb `straus_lookup_table`: `offset + i * base` for `i < 2^table_bits` in a ROM array of point pairs.
pub struct StrausLookupTable {
    ctx: Ctx,
    rom_id: usize,
    table_bits: usize,
}

impl StrausLookupTable {
    pub fn compute_native_table(base_point: Element, offset_generator: Element, table_bits: usize) -> Vec<Element> {
        let mut table = vec![offset_generator];
        for i in 1..(1usize << table_bits) {
            table.push(table[i - 1] + base_point);
        }
        table
    }
    pub fn new(
        ctx: &Ctx,
        base_point: &CycleGroup,
        offset_generator: &CycleGroup,
        table_bits: usize,
        hints: Option<&[GrumpkinAffine]>,
    ) -> Self {
        let table_size = 1usize << table_bits;
        let fallback = CycleGroup::constant(one());
        let modded_x = FieldT::conditional_assign(&base_point.is_infinity, &fallback.x, &base_point.x);
        let modded_y = FieldT::conditional_assign(&base_point.is_infinity, &fallback.y, &base_point.y);
        let mut modded_base_point = CycleGroup::from_xyi(modded_x, modded_y, BoolT::constant(false), false);
        let hints_available = hints.is_some() && !base_point.is_infinity.get_value();
        let hint = |i: usize| if hints_available { Some(hints.unwrap()[i]) } else { None };
        let mut point_table: Vec<CycleGroup> = Vec::with_capacity(table_size);
        if base_point.is_constant() && !base_point.is_infinity.get_value() {
            assert_ne!(
                base_point.get_value(),
                offset_generator.get_value(),
                "straus table: base point coincides with the offset generator"
            );
            modded_base_point = CycleGroup::from_constant_witness(ctx, modded_base_point.get_value());
            point_table.push(CycleGroup::from_constant_witness(ctx, offset_generator.get_value()));
            for i in 1..table_size {
                let next = point_table[i - 1].unconditional_add(&modded_base_point, hint(i - 1));
                point_table.push(next);
            }
        } else {
            let mut coordinate_check_product = FieldT::constant(Fr::one());
            point_table.push(offset_generator.clone());
            for i in 1..table_size {
                let x_diff = &point_table[i - 1].x - &modded_base_point.x;
                coordinate_check_product = &coordinate_check_product * &x_diff;
                let next = point_table[i - 1].unconditional_add(&modded_base_point, hint(i - 1));
                point_table.push(next);
            }
            coordinate_check_product.assert_is_not_zero();
            for i in 1..table_size {
                point_table[i] =
                    CycleGroup::conditional_assign(&base_point.is_infinity, offset_generator, &point_table[i]);
            }
        }
        let rom_id = ctx.borrow_mut().create_rom_array(table_size);
        for (i, p) in point_table.iter_mut().enumerate() {
            if p.is_constant() {
                *p = CycleGroup::from_constant_witness(ctx, p.get_value());
            }
            ctx.borrow_mut()
                .set_rom_element_pair(rom_id, i, [p.x.get_witness_index(), p.y.get_witness_index()]);
        }
        Self {
            ctx: ctx.clone(),
            rom_id,
            table_bits,
        }
    }
    pub fn read(&self, index: &FieldT) -> CycleGroup {
        assert!(
            u256(&index.get_value()).0[0] < (1u64 << self.table_bits),
            "straus table: index out of range"
        );
        let index = if index.is_constant() {
            let w = FieldT::from_witness(&self.ctx, index.get_value());
            w.assert_equal(index);
            w
        } else {
            index.clone()
        };
        let [x_idx, y_idx] = self
            .ctx
            .borrow_mut()
            .read_rom_array_pair(self.rom_id, index.get_witness_index());
        CycleGroup::from_xyi(
            FieldT::from_witness_index(&self.ctx, x_idx),
            FieldT::from_witness_index(&self.ctx, y_idx),
            BoolT::constant(false),
            false,
        )
    }
}

impl std::fmt::Debug for CycleGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CycleGroup({:?})", self.get_value())
    }
}
impl PartialEq for CycleGroup {
    fn eq(&self, other: &Self) -> bool {
        self.get_value() == other.get_value()
    }
}

impl crate::base::group::GroupLike<crate::stdlib::bigfield::BigField<Fq>> for CycleGroup {
    type Native = GrumpkinAffine;
    fn one(_ctx: &Ctx) -> Self {
        CycleGroup::constant(GrumpkinAffine::generator())
    }
    fn constant(_ctx: &Ctx, p: GrumpkinAffine) -> Self {
        CycleGroup::constant(p)
    }
    fn from_witness(ctx: &Ctx, p: GrumpkinAffine) -> Self {
        CycleGroup::from_witness(ctx, p)
    }
    fn value(&self) -> GrumpkinAffine {
        self.get_value()
    }
    fn neg(&self) -> Self {
        CycleGroup::neg(self)
    }
    fn add(&self, other: &Self) -> Self {
        CycleGroup::add(self, other)
    }
    fn scalar_mul(&self, s: &crate::stdlib::bigfield::BigField<Fq>) -> Self {
        <Self as crate::base::group::GroupLike<crate::stdlib::bigfield::BigField<Fq>>>::batch_mul(
            &[self.clone()],
            std::slice::from_ref(s),
        )
    }
    fn batch_mul(points: &[Self], scalars: &[crate::stdlib::bigfield::BigField<Fq>]) -> Self {
        let cycle_scalars: Vec<CycleScalar> = scalars.iter().map(CycleScalar::from_bigfield).collect();
        CycleGroup::batch_mul(points, &cycle_scalars)
    }
    fn fix_witness(&mut self) {
        CycleGroup::fix_witness(self);
    }
    fn enforce_equal(&self, other: &Self) {
        let mut a = self.clone();
        let mut b = other.clone();
        CycleGroup::assert_equal(&mut a, &mut b);
    }
}
