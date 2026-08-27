//! Points of a foreign short-Weierstrass curve with `bigfield` coordinates (bb
//! `stdlib/primitives/biggroup`, the non-goblin `element`): complete addition/doubling with
//! explicit infinity flags, chained additions, Montgomery ladders and the Strauss multi-scalar
//! multiplication over ROM point tables. Line-by-line port of `biggroup_impl/nafs/tables`.

use super::bigfield::{BigField, NUM_LIMBS, NUM_LIMB_BITS};
use super::bool::BoolT;
use super::field::{Ctx, FieldT};
use super::memory::TwinRomTable;
use crate::base::Fr;
use ark_ec::short_weierstrass::{Affine, Projective, SWCurveConfig};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{Field, PrimeField, Zero};
use num_bigint::BigUint;

/// The per-curve constants bb keeps in `precomputed_generators_*_impl.hpp`.
pub trait BigGroupCurve: SWCurveConfig<BaseField: PrimeField, ScalarField: PrimeField> {
    fn biggroup_offset_generator() -> Affine<Self>;
}

pub type Fq<P> = BigField<<P as ark_ec::CurveConfig>::BaseField>;
pub type Scalar<P> = BigField<<P as ark_ec::CurveConfig>::ScalarField>;

pub struct Element<P: BigGroupCurve> {
    x: Fq<P>,
    y: Fq<P>,
    is_infinity: BoolT,
}

impl<P: BigGroupCurve> Clone for Element<P> {
    fn clone(&self) -> Self {
        Self { x: self.x.clone(), y: self.y.clone(), is_infinity: self.is_infinity.clone() }
    }
}

fn to_big<F: PrimeField>(f: &F) -> BigUint {
    f.into_bigint().into()
}

/// Accumulator of a chain of additions whose `y` is only materialized at the end (bb
/// `chain_add_accumulator`).
#[derive(Clone)]
pub struct ChainAddAccumulator<P: BigGroupCurve> {
    x1_prev: Fq<P>,
    y1_prev: Fq<P>,
    lambda_prev: Fq<P>,
    x3_prev: Fq<P>,
    y3_prev: Fq<P>,
    is_full_element: bool,
}

impl<P: BigGroupCurve> ChainAddAccumulator<P> {
    fn from_element(input: &Element<P>) -> Self {
        let z = Fq::<P>::zero;
        Self { x1_prev: z(), y1_prev: z(), lambda_prev: z(), x3_prev: input.x.clone(), y3_prev: input.y.clone(), is_full_element: true }
    }
}

impl<P: BigGroupCurve> Element<P> {
    fn has_a() -> bool {
        !P::COEFF_A.is_zero()
    }
    fn curve_a() -> BigUint {
        to_big(&P::COEFF_A)
    }
    fn curve_b() -> BigUint {
        to_big(&P::COEFF_B)
    }

    /// bb `element(x, y, assert_on_curve)`: the infinity flag is `x = y = 0`.
    pub fn new(x: Fq<P>, y: Fq<P>, assert_on_curve: bool) -> Self {
        let mut limb_sum = FieldT::constant(Fr::from(0u64));
        for i in 0..NUM_LIMBS {
            limb_sum += &x.get_limb(i).element;
        }
        for i in 0..NUM_LIMBS {
            limb_sum += &y.get_limb(i).element;
        }
        let is_infinity = limb_sum.is_zero();
        let e = Self { x, y, is_infinity };
        if assert_on_curve {
            let _ = e.validate_on_curve(true);
        }
        e
    }
    /// bb `element(x, y, is_infinity, assert_on_curve)`.
    pub fn with_infinity(x: Fq<P>, y: Fq<P>, is_infinity: &BoolT, assert_on_curve: bool) -> Self {
        assert!(!(x.is_constant() && y.is_constant() && !is_infinity.is_constant()));
        let e = Self { x, y, is_infinity: is_infinity.normalize() };
        if assert_on_curve {
            let _ = e.validate_on_curve(true);
        }
        e
    }
    pub fn from_witness(ctx: &Ctx, input: &Affine<P>) -> Self {
        let (x, y) = if input.is_zero() {
            (Fq::<P>::from_witness(ctx, &P::BaseField::zero()), Fq::<P>::from_witness(ctx, &P::BaseField::zero()))
        } else {
            (Fq::<P>::from_witness(ctx, &input.x().unwrap()), Fq::<P>::from_witness(ctx, &input.y().unwrap()))
        };
        let is_infinity = BoolT::from_witness(ctx, input.is_zero());
        Self::with_infinity(x, y, &is_infinity, true)
    }
    pub fn one(ctx: &Ctx) -> Self {
        let g = P::GENERATOR;
        let x = Fq::<P>::constant(Some(ctx.clone()), &to_big(&g.x().unwrap()));
        let y = Fq::<P>::constant(Some(ctx.clone()), &to_big(&g.y().unwrap()));
        Self::with_infinity(x, y, &BoolT::constant(false), false)
    }
    pub fn constant_point(ctx: Option<Ctx>, p: &Affine<P>) -> Self {
        let x = Fq::<P>::constant(ctx.clone(), &to_big(&p.x().unwrap()));
        let y = Fq::<P>::constant(ctx, &to_big(&p.y().unwrap()));
        Self::new(x, y, false)
    }
    pub fn x(&self) -> &Fq<P> {
        &self.x
    }
    pub fn y(&self) -> &Fq<P> {
        &self.y
    }
    pub fn is_point_at_infinity(&self) -> BoolT {
        self.is_infinity.clone()
    }
    pub fn is_constant(&self) -> bool {
        assert_eq!(self.x.is_constant(), self.y.is_constant());
        self.x.is_constant()
    }
    pub fn ctx(&self) -> Option<Ctx> {
        self.x.ctx().or_else(|| self.y.ctx())
    }
    pub fn get_value(&self) -> Affine<P> {
        if self.is_infinity.get_value() {
            return Affine::<P>::zero();
        }
        Affine::<P>::new_unchecked(self.x.get_native_value(), self.y.get_native_value())
    }

    /// bb `validate_on_curve`: `y² = x³ + ax + b` (`0 = 0` for infinity); returns the residual
    /// when `assert_is_on_curve` is false.
    pub fn validate_on_curve(&self, assert_is_on_curve: bool) -> Fq<P> {
        if self.is_constant() {
            let on_curve = self.get_value().is_on_curve();
            assert!(on_curve, "biggroup::validate_on_curve: constant point not on curve");
            return Fq::<P>::from_u64(if on_curve { 0 } else { 1 });
        }
        self.x.assert_zero_if(&self.is_infinity);
        self.y.assert_zero_if(&self.is_infinity);
        let ctx = self.ctx();
        let b = Fq::<P>::constant(ctx.clone(), &Self::curve_b());
        let adjusted_b = Fq::<P>::conditional_assign(&self.is_infinity, &Fq::<P>::zero(), &b);
        if !Self::has_a() {
            let x_sqr = self.x.sqr();
            let neg_y = self.y.neg();
            Fq::<P>::mult_madd(&[x_sqr, self.y.clone()], &[self.x.clone(), neg_y], &[adjusted_b], assert_is_on_curve)
        } else {
            let a = Fq::<P>::constant(ctx, &Self::curve_a());
            let adjusted_a = Fq::<P>::conditional_assign(&self.is_infinity, &Fq::<P>::zero(), &a);
            let x_sqr = self.x.sqr();
            let neg_y = self.y.neg();
            Fq::<P>::mult_madd(
                &[x_sqr, self.x.clone(), self.y.clone()],
                &[self.x.clone(), adjusted_a, neg_y],
                &[adjusted_b],
                assert_is_on_curve,
            )
        }
    }

    pub fn neg(&self) -> Self {
        Self { x: self.x.clone(), y: self.y.neg(), is_infinity: self.is_infinity.clone() }
    }
    pub fn conditional_negate(&self, predicate: &BoolT) -> Self {
        Self { x: self.x.clone(), y: self.y.conditional_negate(predicate), is_infinity: self.is_infinity.clone() }
    }
    /// `predicate ? other : self`.
    pub fn conditional_select(&self, other: &Self, predicate: &BoolT) -> Self {
        if predicate.is_constant() {
            return if predicate.get_value() { other.clone() } else { self.clone() };
        }
        let x = self.x.conditional_select(&other.x, predicate);
        let y = self.y.conditional_select(&other.y, predicate);
        let is_infinity = BoolT::conditional_assign(predicate, &other.is_point_at_infinity(), &self.is_point_at_infinity());
        Self { x, y, is_infinity }
    }
    pub fn conditional_assign(predicate: &BoolT, lhs: &Self, rhs: &Self) -> Self {
        rhs.conditional_select(lhs, predicate)
    }
    pub fn incomplete_assert_equal(&self, other: &Self) {
        self.is_point_at_infinity().assert_equal(&other.is_point_at_infinity());
        self.x.assert_equal(&other.x);
        self.y.assert_equal(&other.y);
    }
    /// bb `get_standard_form`: coordinates forced to `(0, 0)` at infinity.
    pub fn get_standard_form(&self) -> Self {
        let zero = Fq::<P>::constant(self.ctx(), &BigUint::from(0u64));
        Self {
            x: Fq::<P>::conditional_assign(&self.is_infinity, &zero, &self.x),
            y: Fq::<P>::conditional_assign(&self.is_infinity, &zero, &self.y),
            is_infinity: self.is_infinity.clone(),
        }
    }

    // ---- complete addition and doubling ----

    fn dbl_lambda_numerator(&self) -> Fq<P> {
        let xx = self.x.mul(&self.x);
        let mut n = xx.add(&xx).add(&xx);
        if Self::has_a() {
            let a = Fq::<P>::constant(self.ctx(), &Self::curve_a());
            n = n.add(&a);
        }
        n
    }

    /// bb `add_internal`: complete addition, without the standard-form fixup.
    pub fn add_internal(&self, other: &Self) -> Self {
        let x_coordinates_match = other.x.eq(&self.x);
        let y_coordinates_match = self.y.eq(&other.y);
        let infinity_predicate = x_coordinates_match.and(&y_coordinates_match.not());
        let double_predicate = x_coordinates_match.and(&y_coordinates_match);
        let lhs_infinity = self.is_point_at_infinity();
        let rhs_infinity = other.is_point_at_infinity();
        let has_infinity_input = lhs_infinity.or(&rhs_infinity);
        let add_lambda_numerator = other.y.sub(&self.y);
        let dbl_lambda_numerator = self.dbl_lambda_numerator();
        let lambda_numerator = Fq::<P>::conditional_assign(&double_predicate, &dbl_lambda_numerator, &add_lambda_numerator);
        let add_lambda_denominator = other.x.sub(&self.x);
        let dbl_lambda_denominator = self.y.add(&self.y);
        let mut lambda_denominator = Fq::<P>::conditional_assign(&double_predicate, &dbl_lambda_denominator, &add_lambda_denominator);
        let safe_denominator_needed = has_infinity_input.or(&infinity_predicate);
        lambda_denominator = Fq::<P>::conditional_assign(&safe_denominator_needed, &Fq::<P>::one(), &lambda_denominator);
        let lambda = lambda_numerator.div(&lambda_denominator);
        let neg_ox = other.x.neg();
        let neg_x = self.x.neg();
        let mut x3 = lambda.sqradd(&[neg_ox, neg_x]);
        let x_minus_x3 = self.x.sub(&x3);
        let neg_y = self.y.neg();
        let mut y3 = lambda.madd(&x_minus_x3, &[neg_y]);
        x3 = Fq::<P>::conditional_assign(&lhs_infinity, &other.x, &x3);
        y3 = Fq::<P>::conditional_assign(&lhs_infinity, &other.y, &y3);
        x3 = Fq::<P>::conditional_assign(&rhs_infinity, &self.x, &x3);
        y3 = Fq::<P>::conditional_assign(&rhs_infinity, &self.y, &y3);
        let result_is_infinity = infinity_predicate.and(&has_infinity_input.not()).or(&lhs_infinity.and(&rhs_infinity));
        Self::with_infinity(x3, y3, &result_is_infinity, false)
    }
    pub fn add(&self, other: &Self) -> Self {
        self.add_internal(other).get_standard_form()
    }
    /// bb `subtract_internal`.
    pub fn subtract_internal(&self, other: &Self) -> Self {
        let x_coordinates_match = other.x.eq(&self.x);
        let y_coordinates_match = self.y.eq(&other.y);
        let infinity_predicate = x_coordinates_match.and(&y_coordinates_match);
        let double_predicate = x_coordinates_match.and(&y_coordinates_match.not());
        let lhs_infinity = self.is_point_at_infinity();
        let rhs_infinity = other.is_point_at_infinity();
        let has_infinity_input = lhs_infinity.or(&rhs_infinity);
        let add_lambda_numerator = other.y.neg().sub(&self.y);
        let dbl_lambda_numerator = self.dbl_lambda_numerator();
        let lambda_numerator = Fq::<P>::conditional_assign(&double_predicate, &dbl_lambda_numerator, &add_lambda_numerator);
        let add_lambda_denominator = other.x.sub(&self.x);
        let dbl_lambda_denominator = self.y.add(&self.y);
        let mut lambda_denominator = Fq::<P>::conditional_assign(&double_predicate, &dbl_lambda_denominator, &add_lambda_denominator);
        let safe_denominator_needed = has_infinity_input.or(&infinity_predicate);
        lambda_denominator = Fq::<P>::conditional_assign(&safe_denominator_needed, &Fq::<P>::one(), &lambda_denominator);
        let lambda = lambda_numerator.div(&lambda_denominator);
        let neg_ox = other.x.neg();
        let neg_x = self.x.neg();
        let mut x3 = lambda.sqradd(&[neg_ox, neg_x]);
        let x_minus_x3 = self.x.sub(&x3);
        let neg_y = self.y.neg();
        let mut y3 = lambda.madd(&x_minus_x3, &[neg_y]);
        x3 = Fq::<P>::conditional_assign(&lhs_infinity, &other.x, &x3);
        let neg_oy = other.y.neg();
        y3 = Fq::<P>::conditional_assign(&lhs_infinity, &neg_oy, &y3);
        x3 = Fq::<P>::conditional_assign(&rhs_infinity, &self.x, &x3);
        y3 = Fq::<P>::conditional_assign(&rhs_infinity, &self.y, &y3);
        let result_is_infinity = infinity_predicate.and(&has_infinity_input.not()).or(&lhs_infinity.and(&rhs_infinity));
        Self::with_infinity(x3, y3, &result_is_infinity, false)
    }
    pub fn sub(&self, other: &Self) -> Self {
        self.subtract_internal(other).get_standard_form()
    }

    fn not_infinity(x: &Fq<P>) -> BoolT {
        let _ = x;
        BoolT::constant(false)
    }

    /// bb `checked_unconditional_add`: incomplete addition, `x` coordinates asserted distinct.
    pub fn checked_unconditional_add(&self, other: &Self) -> Self {
        other.x.assert_is_not_equal(&self.x);
        let neg_y = self.y.neg();
        let denominator = other.x.sub(&self.x);
        let lambda = Fq::<P>::div_check_denominator_nonzero_off(&[other.y.clone(), neg_y], &denominator);
        let neg_ox = other.x.neg();
        let neg_x = self.x.neg();
        let x3 = lambda.sqradd(&[neg_ox, neg_x]);
        let x_minus_x3 = self.x.sub(&x3);
        let neg_y = self.y.neg();
        let y3 = lambda.madd(&x_minus_x3, &[neg_y]);
        Self::with_infinity(x3.clone(), y3, &Self::not_infinity(&x3), false)
    }
    pub fn checked_unconditional_subtract(&self, other: &Self) -> Self {
        other.x.assert_is_not_equal(&self.x);
        let denominator = other.x.sub(&self.x);
        let lambda = Fq::<P>::div_check_denominator_nonzero_off(&[other.y.clone(), self.y.clone()], &denominator);
        let neg_ox = other.x.neg();
        let neg_x = self.x.neg();
        let x3 = lambda.sqradd(&[neg_ox, neg_x]);
        let x3_minus_x = x3.sub(&self.x);
        let neg_y = self.y.neg();
        let y3 = lambda.madd(&x3_minus_x, &[neg_y]);
        Self::with_infinity(x3.clone(), y3, &Self::not_infinity(&x3), false)
    }
    /// bb `checked_unconditional_add_sub`: `(self + other, self - other)` sharing the denominator.
    pub fn checked_unconditional_add_sub(&self, other: &Self) -> [Self; 2] {
        other.x.assert_is_not_equal(&self.x);
        let denominator = other.x.sub(&self.x);
        let x2x1 = other.x.add(&self.x).neg();
        let neg_y = self.y.neg();
        let lambda1 = Fq::<P>::div_check_denominator_nonzero_off(&[other.y.clone(), neg_y], &denominator);
        let x_3 = lambda1.sqradd(&[x2x1.clone()]);
        let x_minus_x3 = self.x.sub(&x_3);
        let neg_y = self.y.neg();
        let y_3 = lambda1.madd(&x_minus_x3, &[neg_y]);
        let neg_oy = other.y.neg();
        let neg_y = self.y.neg();
        let lambda2 = Fq::<P>::div_check_denominator_nonzero_off(&[neg_oy, neg_y], &denominator);
        let x_4 = lambda2.sqradd(&[x2x1]);
        let x_minus_x4 = self.x.sub(&x_4);
        let neg_y = self.y.neg();
        let y_4 = lambda2.madd(&x_minus_x4, &[neg_y]);
        let not_infinity = BoolT::constant(false);
        [Self::with_infinity(x_3, y_3, &not_infinity, false), Self::with_infinity(x_4, y_4, &not_infinity, false)]
    }
    /// bb `dbl_internal`.
    pub fn dbl_internal(&self) -> Self {
        let is_infinity = self.is_point_at_infinity();
        let two_y = self.y.add(&self.y);
        let one = Fq::<P>::constant(self.ctx(), &BigUint::from(1u64));
        let denominator = Fq::<P>::conditional_assign(&is_infinity, &one, &two_y);
        let two_x = self.x.add(&self.x);
        let three_x = two_x.add(&self.x);
        let to_sub: Vec<Fq<P>> = if Self::has_a() { vec![Fq::<P>::constant(self.ctx(), &Self::curve_a())] } else { vec![] };
        let neg_lambda = Fq::<P>::msub_div(&[self.x.clone()], &[three_x], &denominator, &to_sub, true);
        let neg_two_x = two_x.neg();
        let x_3 = neg_lambda.sqradd(&[neg_two_x]);
        let x3_minus_x = x_3.sub(&self.x);
        let neg_y = self.y.neg();
        let y_3 = neg_lambda.madd(&x3_minus_x, &[neg_y]);
        Self::with_infinity(x_3, y_3, &is_infinity, false)
    }
    pub fn dbl(&self) -> Self {
        self.dbl_internal().get_standard_form()
    }

    // ---- chained additions ----

    pub fn chain_add_start(p1: &Self, p2: &Self) -> ChainAddAccumulator<P> {
        p1.x.assert_is_not_equal(&p2.x);
        let neg_y1 = p1.y.neg();
        let denominator = p2.x.sub(&p1.x);
        let lambda = Fq::<P>::div_check_denominator_nonzero_off(&[p2.y.clone(), neg_y1], &denominator);
        let neg_x2 = p2.x.neg();
        let neg_x1 = p1.x.neg();
        let x3 = lambda.sqradd(&[neg_x2, neg_x1]);
        ChainAddAccumulator { x1_prev: p1.x.clone(), y1_prev: p1.y.clone(), lambda_prev: lambda, x3_prev: x3, y3_prev: Fq::<P>::zero(), is_full_element: false }
    }
    pub fn chain_add(p1: &Self, acc: &ChainAddAccumulator<P>) -> ChainAddAccumulator<P> {
        if acc.is_full_element {
            return Self::chain_add_start(p1, &Self::with_infinity(acc.x3_prev.clone(), acc.y3_prev.clone(), &BoolT::constant(false), false));
        }
        p1.x.assert_is_not_equal(&acc.x3_prev);
        let x2 = &acc.x3_prev;
        let x2_minus_x1 = x2.sub(&acc.x1_prev);
        let x2_minus_px = x2.sub(&p1.x);
        let lambda = Fq::<P>::msub_div(&[acc.lambda_prev.clone()], &[x2_minus_x1], &x2_minus_px, &[acc.y1_prev.clone(), p1.y.clone()], false);
        let neg_x2 = x2.neg();
        let neg_px = p1.x.neg();
        let x3 = lambda.sqradd(&[neg_x2, neg_px]);
        ChainAddAccumulator { x3_prev: x3, x1_prev: p1.x.clone(), y1_prev: p1.y.clone(), lambda_prev: lambda, y3_prev: Fq::<P>::zero(), is_full_element: false }
    }
    pub fn chain_add_end(acc: &ChainAddAccumulator<P>) -> Self {
        if acc.is_full_element {
            return Self::with_infinity(acc.x3_prev.clone(), acc.y3_prev.clone(), &BoolT::constant(false), false);
        }
        let x1_minus_x3 = acc.x1_prev.sub(&acc.x3_prev);
        let neg_y1 = acc.y1_prev.neg();
        let y3 = acc.lambda_prev.madd(&x1_minus_x3, &[neg_y1]);
        Self::with_infinity(acc.x3_prev.clone(), y3, &BoolT::constant(false), false)
    }

    /// bb `multiple_montgomery_ladder`: `2·self + Σ add_i` with the intermediate `y` kept symbolic.
    pub fn multiple_montgomery_ladder(&self, add: &[ChainAddAccumulator<P>]) -> Self {
        struct CompositeY<P: BigGroupCurve> {
            mul_left: Vec<Fq<P>>,
            mul_right: Vec<Fq<P>>,
            add: Vec<Fq<P>>,
            is_negative: bool,
        }
        if add.is_empty() {
            return self.clone();
        }
        self.x.assert_is_not_equal(&add[0].x3_prev);
        let lambda1 = if !add[0].is_full_element {
            let x1_minus_x3 = add[0].x1_prev.sub(&add[0].x3_prev);
            let denominator = self.x.sub(&add[0].x3_prev);
            let neg_y1 = add[0].y1_prev.neg();
            let neg_y = self.y.neg();
            Fq::<P>::msub_div(&[add[0].lambda_prev.clone()], &[x1_minus_x3], &denominator, &[neg_y1, neg_y], false)
        } else {
            let numerator = self.y.sub(&add[0].y3_prev);
            let denominator = self.x.sub(&add[0].x3_prev);
            Fq::<P>::div_check_denominator_nonzero_off(&[numerator], &denominator)
        };
        let neg_x3p = add[0].x3_prev.neg();
        let neg_x = self.x.neg();
        let x_3 = lambda1.madd(&lambda1, &[neg_x3p, neg_x]);
        self.x.assert_is_not_equal(&x_3);
        let two_y = self.y.add(&self.y);
        let x_minus_x3 = self.x.sub(&x_3);
        let mut lambda2 = Fq::<P>::div_check_denominator_nonzero_off(&[two_y], &x_minus_x3).sub(&lambda1);
        let neg_x3 = x_3.neg();
        let neg_x = self.x.neg();
        let mut x_4 = lambda2.sqradd(&[neg_x3, neg_x]);
        let num_points_even = add.len() % 2 == 0;
        let mut previous_y = CompositeY::<P> {
            mul_left: vec![lambda2.clone()],
            mul_right: vec![if num_points_even { x_4.sub(&self.x) } else { self.x.sub(&x_4) }],
            add: vec![if num_points_even { self.y.clone() } else { self.y.neg() }],
            is_negative: num_points_even,
        };
        // bb evaluates `previous_y.add` before `mul_right`; both are gate-free for plain elements
        // except the negation, which the order above preserves by construction of the vectors.
        let mut previous_x = x_4.clone();
        for a in add.iter().skip(1) {
            previous_x.assert_is_not_equal(&a.x3_prev);
            let negate_add_y = !previous_y.is_negative;
            let mut lambda1_left = previous_y.mul_left.clone();
            let mut lambda1_right = previous_y.mul_right.clone();
            let mut lambda1_add = previous_y.add.clone();
            if !a.is_full_element {
                lambda1_left.push(a.lambda_prev.clone());
                lambda1_right.push(if negate_add_y { a.x3_prev.sub(&a.x1_prev) } else { a.x1_prev.sub(&a.x3_prev) });
                lambda1_add.push(if negate_add_y { a.y1_prev.clone() } else { a.y1_prev.neg() });
            } else {
                lambda1_add.push(if negate_add_y { a.y3_prev.neg() } else { a.y3_prev.clone() });
            }
            let denominator = if negate_add_y { a.x3_prev.sub(&previous_x) } else { previous_x.sub(&a.x3_prev) };
            let lambda1 = Fq::<P>::msub_div(&lambda1_left, &lambda1_right, &denominator, &lambda1_add, false);
            let neg_x3p = a.x3_prev.neg();
            let neg_px = previous_x.neg();
            let x_3 = lambda1.madd(&lambda1, &[neg_x3p, neg_px]);
            previous_x.assert_is_not_equal(&x_3);
            let l2_denominator = if previous_y.is_negative { previous_x.sub(&x_3) } else { x_3.sub(&previous_x) };
            let mut partial_lambda2 = Fq::<P>::msub_div(&previous_y.mul_left, &previous_y.mul_right, &l2_denominator, &previous_y.add, false);
            partial_lambda2 = partial_lambda2.add(&partial_lambda2);
            lambda2 = partial_lambda2.sub(&lambda1);
            let neg_x3 = x_3.neg();
            let neg_px = previous_x.neg();
            x_4 = lambda2.sqradd(&[neg_x3, neg_px]);
            let mut y_4 = CompositeY::<P> {
                mul_left: vec![lambda2.clone()],
                mul_right: vec![if previous_y.is_negative { previous_x.sub(&x_4) } else { x_4.sub(&previous_x) }],
                add: vec![],
                is_negative: !previous_y.is_negative,
            };
            y_4.mul_left.extend(previous_y.mul_left.iter().cloned());
            y_4.mul_right.extend(previous_y.mul_right.iter().cloned());
            y_4.add.extend(previous_y.add.iter().cloned());
            previous_x = x_4.clone();
            previous_y = y_4;
        }
        assert!(!previous_y.is_negative);
        let y_out = Fq::<P>::mult_madd(&previous_y.mul_left, &previous_y.mul_right, &previous_y.add, false);
        Self::with_infinity(previous_x, y_out, &BoolT::constant(false), false)
    }

    // ---- scalars ----

    /// bb `compute_naf`: `num_rounds + 1` bools, `[num_rounds]` the skew, the rest the NAF from the
    /// most significant digit down (`true` = −1); the reconstruction is asserted equal to `scalar`.
    pub fn compute_naf(scalar: &Scalar<P>, max_num_bits: usize) -> Vec<BoolT> {
        let ctx = scalar.ctx().expect("compute_naf needs a builder");
        let modulus = Scalar::<P>::modulus();
        let mut scalar_multiplier = scalar.get_value() % &modulus;
        let num_rounds = if max_num_bits == 0 { modulus.bits() as usize } else { max_num_bits };
        let mut naf_entries: Vec<BoolT> = Vec::with_capacity(num_rounds + 1);
        let skew_value = !scalar_multiplier.bit(0);
        scalar_multiplier += BigUint::from(skew_value as u64);
        let mut entries_rev: Vec<BoolT> = Vec::with_capacity(num_rounds + 1);
        let skew = BoolT::from_witness_ranged(&ctx, skew_value);
        // bb fills naf_entries[num_rounds], then [num_rounds - 1 - i] for i in 0..num_rounds-1, then [0]
        let mut middle: Vec<BoolT> = Vec::with_capacity(num_rounds);
        for i in 0..num_rounds - 1 {
            let next_entry = scalar_multiplier.bit(i as u64 + 1);
            middle.push(BoolT::from_witness_ranged(&ctx, !next_entry));
        }
        let first = BoolT::from_witness_ranged(&ctx, false);
        first.fix_witness();
        naf_entries.push(first);
        for e in middle.iter().rev() {
            naf_entries.push(e.clone());
        }
        naf_entries.push(skew);
        entries_rev.clear();
        let reconstruct_half_naf = |nafs: &[BoolT]| -> (FieldT, FieldT) {
            let mut negative_accumulator = FieldT::constant(Fr::from(0u64));
            let mut positive_accumulator = FieldT::constant(Fr::from(0u64));
            for n in nafs {
                negative_accumulator = negative_accumulator.add(&negative_accumulator).add(&n.to_field());
                positive_accumulator = positive_accumulator.add(&positive_accumulator).add(&FieldT::constant(Fr::from(1u64))).sub(&n.to_field());
            }
            (positive_accumulator, negative_accumulator)
        };
        let (hi_accumulators, mut lo_accumulators) = if num_rounds > (NUM_LIMB_BITS * 2) as usize {
            let midpoint = num_rounds - (NUM_LIMB_BITS * 2) as usize;
            let hi = reconstruct_half_naf(&naf_entries[..midpoint]);
            let lo = reconstruct_half_naf(&naf_entries[midpoint..num_rounds]);
            (hi, lo)
        } else {
            let zero_idx = ctx.borrow().zero_idx();
            let zero = FieldT::from_witness_index(&ctx, zero_idx);
            let lo = reconstruct_half_naf(&naf_entries[..num_rounds]);
            ((zero.clone(), zero), lo)
        };
        let mut hi_accumulators = hi_accumulators;
        let lo_neg_with_skew = lo_accumulators.1.add(&naf_entries[num_rounds].to_field());
        let two_pow_136 = FieldT::constant(crate::base::field::from_u256(crate::base::field::U256::from(1u64) << (NUM_LIMB_BITS * 2) as u32));
        let overflow_check = lo_neg_with_skew.sub(&two_pow_136);
        let has_overflow = overflow_check.is_zero();
        lo_accumulators.1 = lo_neg_with_skew.mul(&has_overflow.not().to_field());
        hi_accumulators.1 = hi_accumulators.1.add(&has_overflow.to_field());
        let reconstructed_positive = Scalar::<P>::from_halves(&lo_accumulators.0, &hi_accumulators.0, false, 0);
        let reconstructed_negative = Scalar::<P>::from_halves(&lo_accumulators.1, &hi_accumulators.1, false, 0);
        let accumulator = reconstructed_positive.sub(&reconstructed_negative);
        if scalar.is_constant() {
            accumulator.self_reduce();
        }
        accumulator.assert_equal(scalar);
        naf_entries
    }

    // ---- ROM point tables ----

    fn create_group_element_rom_tables(rom_data: &[Self], limb_max: &mut [BigUint; NUM_LIMBS * 2]) -> [TwinRomTable; NUM_LIMBS + 1] {
        let mut x_lo = vec![];
        let mut x_hi = vec![];
        let mut y_lo = vec![];
        let mut y_hi = vec![];
        let mut prime = vec![];
        for e in rom_data {
            for i in 0..NUM_LIMBS {
                limb_max[i] = limb_max[i].clone().max(e.x.get_limb(i).maximum_value);
                limb_max[NUM_LIMBS + i] = limb_max[NUM_LIMBS + i].clone().max(e.y.get_limb(i).maximum_value);
            }
            x_lo.push([e.x.get_limb(0).element, e.x.get_limb(1).element]);
            x_hi.push([e.x.get_limb(2).element, e.x.get_limb(3).element]);
            y_lo.push([e.y.get_limb(0).element, e.y.get_limb(1).element]);
            y_hi.push([e.y.get_limb(2).element, e.y.get_limb(3).element]);
            prime.push([e.x.get_prime_basis_limb(), e.y.get_prime_basis_limb()]);
        }
        [TwinRomTable::new(x_lo), TwinRomTable::new(x_hi), TwinRomTable::new(y_lo), TwinRomTable::new(y_hi), TwinRomTable::new(prime)]
    }
    fn read_group_element_rom_tables(tables: &mut [TwinRomTable; NUM_LIMBS + 1], index: &FieldT, limb_max: &[BigUint; NUM_LIMBS * 2]) -> Self {
        let xlo = tables[0].read(index);
        let xhi = tables[1].read(index);
        let ylo = tables[2].read(index);
        let yhi = tables[3].read(index);
        let xyprime = tables[4].read(index);
        let x_fq = Fq::<P>::unsafe_construct_from_limbs_with_prime(&xlo[0], &xlo[1], &xhi[0], &xhi[1], &xyprime[0], false);
        let y_fq = Fq::<P>::unsafe_construct_from_limbs_with_prime(&ylo[0], &ylo[1], &yhi[0], &yhi[1], &xyprime[1], false);
        for i in 0..NUM_LIMBS {
            x_fq.set_limb_max(i, limb_max[i].clone());
            y_fq.set_limb_max(i, limb_max[NUM_LIMBS + i].clone());
        }
        Self::with_infinity(x_fq, y_fq, &BoolT::constant(false), false)
    }

    /// bb `compute_offset_generators`: the start and `2^(num_rounds-1)`-scaled end offsets.
    fn compute_offset_generators(num_rounds: usize) -> (Self, Self) {
        let offset_generator = P::biggroup_offset_generator();
        let end = (Projective::<P>::from(offset_generator) * P::ScalarField::from(2u64).pow([num_rounds as u64 - 1])).into_affine();
        (Self::constant_point(None, &offset_generator), Self::constant_point(None, &end))
    }

    /// bb `process_strauss_msm_rounds` over `max_num_bits`-bit scalars.
    fn process_strauss_msm_rounds(points: &[Self], scalars: &[Scalar<P>], max_num_bits: usize) -> Self {
        assert!(!points.is_empty() && points.len() == scalars.len());
        for s in scalars {
            assert!(s.get_value().bits() as usize <= max_num_bits, "process_strauss_msm: scalar out of range");
        }
        let num_rounds = max_num_bits;
        let msm_size = scalars.len();
        let mut point_table = BatchLookupTable::<P>::new(points);
        let naf_entries: Vec<Vec<BoolT>> = scalars.iter().map(|s| Self::compute_naf(s, num_rounds)).collect();
        let (offset_generator_start, offset_generator_end) = Self::compute_offset_generators(num_rounds);
        let initial = point_table.get_chain_initial_entry();
        let mut accumulator = Self::chain_add_end(&Self::chain_add(&offset_generator_start, &initial));
        const NUM_ROUNDS_PER_ITERATION: usize = 4;
        let num_iterations = (num_rounds - 1).div_ceil(NUM_ROUNDS_PER_ITERATION);
        let num_rounds_per_final_iteration = (num_rounds - 1) - (num_iterations - 1) * NUM_ROUNDS_PER_ITERATION;
        for i in 0..num_iterations {
            let inner_num_rounds = if i != num_iterations - 1 { NUM_ROUNDS_PER_ITERATION } else { num_rounds_per_final_iteration };
            let mut to_add = Vec::with_capacity(inner_num_rounds);
            for j in 0..inner_num_rounds {
                let nafs: Vec<BoolT> = (0..msm_size).map(|k| naf_entries[k][i * NUM_ROUNDS_PER_ITERATION + j + 1].clone()).collect();
                to_add.push(point_table.get_chain_add_accumulator(&nafs));
            }
            accumulator = accumulator.multiple_montgomery_ladder(&to_add);
        }
        for i in 0..msm_size {
            let skew = accumulator.subtract_internal(&points[i]);
            accumulator = accumulator.conditional_select(&skew, &naf_entries[i][num_rounds]);
        }
        accumulator.subtract_internal(&offset_generator_end)
    }

    /// bb `handle_points_at_infinity`: infinity points become the generator with a zero scalar.
    fn handle_points_at_infinity(points: &[Self], scalars: &[Scalar<P>]) -> (Vec<Self>, Vec<Scalar<P>>) {
        let ctx = points.iter().find_map(|p| p.ctx()).or_else(|| scalars.iter().find_map(|s| s.ctx())).expect("batch_mul needs a builder");
        let one = Self::one(&ctx);
        let mut out_points = vec![];
        let mut out_scalars = vec![];
        for (p, s) in points.iter().zip(scalars) {
            let is_inf = p.is_point_at_infinity();
            if is_inf.get_value() && is_inf.is_constant() {
                continue;
            }
            if s.get_value() == BigUint::from(0u64) && s.is_constant() {
                continue;
            }
            let point = p.conditional_select(&one, &is_inf);
            let scalar = Scalar::<P>::conditional_assign(&is_inf, &Scalar::<P>::zero(), s);
            out_points.push(point);
            out_scalars.push(scalar);
        }
        (out_points, out_scalars)
    }

    fn batch_mul_internal(points: &[Self], scalars: &[Scalar<P>], max_num_bits: usize, with_edgecases: bool) -> Self {
        assert!(!with_edgecases, "batch_mul with edge-case masking is not ported (needs a random offset point)");
        assert!(!points.is_empty() && points.len() == scalars.len());
        let builder = points[0].ctx();
        let (points, scalars) = Self::handle_points_at_infinity(points, scalars);
        let mut has_constant_terms = false;
        let mut constant_accumulator = Projective::<P>::zero();
        let mut new_points = vec![];
        let mut new_scalars = vec![];
        for (p, s) in points.iter().zip(&scalars) {
            if p.is_constant() && s.is_constant() {
                constant_accumulator += Projective::<P>::from(p.get_value()) * s.get_native_value();
                has_constant_terms = true;
            } else {
                new_points.push(p.clone());
                new_scalars.push(s.clone());
            }
        }
        let (points, scalars) = (new_points, new_scalars);
        let mut big_points = vec![];
        let mut big_scalars = vec![];
        let mut small_points = vec![];
        let mut small_scalars = vec![];
        for (p, s) in points.iter().zip(&scalars) {
            if max_num_bits == 0 {
                big_points.push(p.clone());
                big_scalars.push(s.clone());
            } else {
                small_points.push(p.clone());
                small_scalars.push(s.clone());
            }
        }
        let max_num_bits_in_field = Scalar::<P>::modulus().bits() as usize;
        let mut accumulator: Option<Self> = None;
        if has_constant_terms || (big_points.is_empty() && small_points.is_empty()) {
            let affine = constant_accumulator.into_affine();
            accumulator = Some(if affine.is_zero() {
                let zero = Fq::<P>::constant(builder.clone(), &BigUint::from(0u64));
                Self::new(zero.clone(), zero, true)
            } else {
                Self::constant_point(None, &affine)
            });
        }
        if !big_points.is_empty() {
            let big_result = Self::process_strauss_msm_rounds(&big_points, &big_scalars, max_num_bits_in_field);
            accumulator = Some(match accumulator {
                Some(a) => a.add_internal(&big_result),
                None => big_result,
            });
        }
        if !small_points.is_empty() {
            let effective = if max_num_bits == 0 { max_num_bits_in_field } else { max_num_bits };
            let small_result = Self::process_strauss_msm_rounds(&small_points, &small_scalars, effective);
            accumulator = Some(match accumulator {
                Some(a) => a.add_internal(&small_result),
                None => small_result,
            });
        }
        accumulator.unwrap()
    }
    /// bb `batch_mul(points, scalars, max_num_bits, with_edgecases)`.
    pub fn batch_mul(points: &[Self], scalars: &[Scalar<P>], max_num_bits: usize, with_edgecases: bool) -> Self {
        Self::batch_mul_internal(points, scalars, max_num_bits, with_edgecases).get_standard_form()
    }
    pub fn scalar_mul(&self, scalar: &Scalar<P>, max_num_bits: usize) -> Self {
        Self::batch_mul(&[self.clone()], &[scalar.clone()], max_num_bits, false)
    }
}

/// bb `lookup_table_plookup<length>`: all `±P_0 ± … ± P_{n-1}` combinations in ROM tables.
struct LookupTable<P: BigGroupCurve> {
    length: usize,
    element_table: Vec<Element<P>>,
    coordinates: [TwinRomTable; NUM_LIMBS + 1],
    limb_max: [BigUint; NUM_LIMBS * 2],
}

impl<P: BigGroupCurve> LookupTable<P> {
    fn new(inputs: &[Element<P>]) -> Self {
        let length = inputs.len();
        assert!((2..=6).contains(&length), "lookup_table_plookup supports 2 to 6 points");
        let table_size = 1usize << length;
        let mut t: Vec<Option<Element<P>>> = vec![None; table_size];
        let mut set = |i: usize, e: Element<P>| t[i] = Some(e);
        match length {
            2 => {
                let [a0, a1] = inputs[1].checked_unconditional_add_sub(&inputs[0]);
                set(0, a0);
                set(1, a1);
            }
            3 => {
                let [r0, r1] = inputs[1].checked_unconditional_add_sub(&inputs[0]);
                let [t0, t1] = inputs[2].checked_unconditional_add_sub(&r0);
                let [t2, t3] = inputs[2].checked_unconditional_add_sub(&r1);
                set(0, t0);
                set(1, t2);
                set(2, t3);
                set(3, t1);
            }
            4 => {
                let [t0, t1] = inputs[1].checked_unconditional_add_sub(&inputs[0]);
                let [t2, t3] = inputs[3].checked_unconditional_add_sub(&inputs[2]);
                let [f0, f3] = t2.checked_unconditional_add_sub(&t0);
                let [f1, f2] = t2.checked_unconditional_add_sub(&t1);
                let [f4, f7] = t3.checked_unconditional_add_sub(&t0);
                let [f5, f6] = t3.checked_unconditional_add_sub(&t1);
                for (i, e) in [f0, f1, f2, f3, f4, f5, f6, f7].into_iter().enumerate() {
                    set(i, e);
                }
            }
            5 => {
                let [a0, a1] = inputs[1].checked_unconditional_add_sub(&inputs[0]);
                let [t2, t3] = inputs[3].checked_unconditional_add_sub(&inputs[2]);
                let [e0, e3] = inputs[4].checked_unconditional_add_sub(&t2);
                let [e1, e2] = inputs[4].checked_unconditional_add_sub(&t3);
                let [f0, f3] = e0.checked_unconditional_add_sub(&a0);
                let [f1, f2] = e0.checked_unconditional_add_sub(&a1);
                let [f4, f7] = e1.checked_unconditional_add_sub(&a0);
                let [f5, f6] = e1.checked_unconditional_add_sub(&a1);
                let [f8, f11] = e2.checked_unconditional_add_sub(&a0);
                let [f9, f10] = e2.checked_unconditional_add_sub(&a1);
                let [f12, f15] = e3.checked_unconditional_add_sub(&a0);
                let [f13, f14] = e3.checked_unconditional_add_sub(&a1);
                for (i, e) in [f0, f1, f2, f3, f4, f5, f6, f7, f8, f9, f10, f11, f12, f13, f14, f15].into_iter().enumerate() {
                    set(i, e);
                }
            }
            _ => {
                let [a0, a1] = inputs[1].checked_unconditional_add_sub(&inputs[0]);
                let [e0, e1] = inputs[4].checked_unconditional_add_sub(&inputs[3]);
                let [c0, c3] = inputs[2].checked_unconditional_add_sub(&a0);
                let [c1, c2] = inputs[2].checked_unconditional_add_sub(&a1);
                let [f0, f3] = inputs[5].checked_unconditional_add_sub(&e0);
                let [f1, f2] = inputs[5].checked_unconditional_add_sub(&e1);
                let cs = [c0, c1, c2, c3];
                for (fi, f) in [f0, f1, f2, f3].iter().enumerate() {
                    for (ci, c) in cs.iter().enumerate() {
                        let [plus, minus] = f.checked_unconditional_add_sub(c);
                        set(fi * 8 + ci, plus);
                        set(fi * 8 + 7 - ci, minus);
                    }
                }
            }
        }
        let mut element_table: Vec<Element<P>> = t.into_iter().take(table_size / 2).map(|e| e.expect("table entry")).collect();
        for i in 0..table_size / 2 {
            let neg = element_table[table_size / 2 - 1 - i].neg();
            element_table.push(neg);
        }
        let mut limb_max: [BigUint; NUM_LIMBS * 2] = std::array::from_fn(|_| BigUint::from(0u64));
        let coordinates = Element::<P>::create_group_element_rom_tables(&element_table, &mut limb_max);
        Self { length, element_table, coordinates, limb_max }
    }
    fn get(&mut self, bits: &[BoolT]) -> Element<P> {
        assert_eq!(bits.len(), self.length);
        let accumulators: Vec<FieldT> = bits.iter().enumerate().map(|(i, b)| b.to_field().mul(&FieldT::constant(Fr::from(1u64 << i)))).collect();
        let index = FieldT::accumulate(&accumulators);
        Element::<P>::read_group_element_rom_tables(&mut self.coordinates, &index, &self.limb_max)
    }
    fn at(&self, idx: usize) -> Element<P> {
        self.element_table[idx].clone()
    }
}

/// bb `batch_lookup_table_plookup`: the points split into tables of 6, 5, 4, 3, 2 and a singleton.
struct BatchLookupTable<P: BigGroupCurve> {
    six_tables: Vec<LookupTable<P>>,
    five_tables: Vec<LookupTable<P>>,
    quad_tables: Vec<LookupTable<P>>,
    triple_tables: Vec<LookupTable<P>>,
    twin_tables: Vec<LookupTable<P>>,
    singletons: Vec<Element<P>>,
    num_points: usize,
}

impl<P: BigGroupCurve> BatchLookupTable<P> {
    fn new(points: &[Element<P>]) -> Self {
        let num_points = points.len();
        let mut num_fives = num_points / 5;
        let mut num_sixes = 0;
        if num_points == 1 {
            num_fives = 0;
        } else if num_fives * 5 == num_points - 1 {
            num_fives -= 1;
            num_sixes = 1;
        } else if num_fives * 5 == num_points - 2 && num_fives >= 2 {
            num_fives -= 2;
            num_sixes = 2;
        } else if num_fives * 5 == num_points - 3 && num_fives >= 3 {
            num_fives -= 3;
            num_sixes = 3;
        }
        let mut remaining = num_points - (num_fives * 5 + num_sixes * 6);
        let has_quad = remaining >= 4 && num_points >= 4;
        if has_quad {
            remaining -= 4;
        }
        let has_triple = remaining >= 3 && num_points >= 3;
        if has_triple {
            remaining -= 3;
        }
        let has_twin = remaining >= 2 && num_points >= 2;
        if has_twin {
            remaining -= 2;
        }
        let has_singleton = remaining != 0 && num_points >= 1;
        let mut t = Self { six_tables: vec![], five_tables: vec![], quad_tables: vec![], triple_tables: vec![], twin_tables: vec![], singletons: vec![], num_points };
        let mut offset = 0;
        for i in 0..num_sixes {
            t.six_tables.push(LookupTable::new(&points[offset + 6 * i..offset + 6 * i + 6]));
        }
        offset += 6 * num_sixes;
        for i in 0..num_fives {
            t.five_tables.push(LookupTable::new(&points[offset + 5 * i..offset + 5 * i + 5]));
        }
        offset += 5 * num_fives;
        if has_quad {
            t.quad_tables.push(LookupTable::new(&points[offset..offset + 4]));
        }
        if has_triple {
            t.triple_tables.push(LookupTable::new(&points[offset..offset + 3]));
        }
        if has_twin {
            t.twin_tables.push(LookupTable::new(&points[offset..offset + 2]));
        }
        if has_singleton {
            t.singletons.push(points[num_points - 1].clone());
        }
        t
    }
    fn get_chain_initial_entry(&self) -> ChainAddAccumulator<P> {
        let mut add_accumulator: Vec<Element<P>> = vec![];
        for tbl in &self.six_tables {
            add_accumulator.push(tbl.at(0));
        }
        for tbl in &self.five_tables {
            add_accumulator.push(tbl.at(0));
        }
        if let Some(q) = self.quad_tables.first() {
            add_accumulator.push(q.at(0));
        }
        if let Some(w) = self.twin_tables.first() {
            add_accumulator.push(w.at(0));
        }
        if let Some(tr) = self.triple_tables.first() {
            add_accumulator.push(tr.at(0));
        }
        if let Some(s) = self.singletons.first() {
            add_accumulator.push(s.clone());
        }
        if add_accumulator.len() >= 2 {
            let mut output = Element::<P>::chain_add_start(&add_accumulator[0], &add_accumulator[1]);
            for e in &add_accumulator[2..] {
                output = Element::<P>::chain_add(e, &output);
            }
            return output;
        }
        ChainAddAccumulator::from_element(&add_accumulator[0])
    }
    fn round_accumulator(&mut self, naf_entries: &[BoolT]) -> Vec<Element<P>> {
        let mut round_accumulator: Vec<Element<P>> = vec![];
        for (j, tbl) in self.six_tables.iter_mut().enumerate() {
            round_accumulator.push(tbl.get(&naf_entries[6 * j..6 * j + 6]));
        }
        let mut offset = self.six_tables.len() * 6;
        for (j, tbl) in self.five_tables.iter_mut().enumerate() {
            round_accumulator.push(tbl.get(&naf_entries[offset + 5 * j..offset + 5 * j + 5]));
        }
        offset += self.five_tables.len() * 5;
        if let Some(q) = self.quad_tables.first_mut() {
            round_accumulator.push(q.get(&naf_entries[offset..offset + 4]));
        }
        if let Some(tr) = self.triple_tables.first_mut() {
            round_accumulator.push(tr.get(&naf_entries[offset..offset + 3]));
        }
        if let Some(w) = self.twin_tables.first_mut() {
            round_accumulator.push(w.get(&naf_entries[offset..offset + 2]));
        }
        if let Some(s) = self.singletons.first() {
            round_accumulator.push(s.conditional_negate(&naf_entries[self.num_points - 1]));
        }
        round_accumulator
    }
    fn get_chain_add_accumulator(&mut self, naf_entries: &[BoolT]) -> ChainAddAccumulator<P> {
        let round_accumulator = self.round_accumulator(naf_entries);
        if round_accumulator.len() == 1 {
            return ChainAddAccumulator::from_element(&round_accumulator[0]);
        }
        let mut accumulator = Element::<P>::chain_add_start(&round_accumulator[0], &round_accumulator[1]);
        for e in &round_accumulator[2..] {
            accumulator = Element::<P>::chain_add(e, &accumulator);
        }
        accumulator
    }
}

impl BigGroupCurve for ark_secp256r1::Config {
    fn biggroup_offset_generator() -> Affine<Self> {
        let x = ark_secp256r1::Fq::from(BigUint::parse_bytes(b"b61bd0f5671bc04ec041799e87e735af4ed40920c6ca71e63c8010ff162bd90a", 16).unwrap());
        let y = ark_secp256r1::Fq::from(BigUint::parse_bytes(b"338540b43f94cbfe32a1e62d192ea7d5827f4a4a66bb781a02321033110e492b", 16).unwrap());
        Affine::new_unchecked(x, y)
    }
}
