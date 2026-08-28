//! In-circuit bn254 base-field elements and group elements for goblin circuits (bb
//! `stdlib::goblin_field`, `stdlib::element_goblin::goblin_element`). A base-field element is two
//! 136/118-bit limbs; every group operation is an entry in the ECC op queue, with the op's wires
//! copy-constrained to the operands.

use super::field::{Ctx, FieldT};
use crate::base::codec::Transcriptable;
use crate::base::field::{from_u256, u256, u256_low_bits, u256_shr, FieldLike, U256};
use crate::base::group::GroupLike;
use crate::base::{Fq, Fr, G1Affine};
use crate::circuit::op_queue::cube_root_of_unity;
use ark_ec::AffineRepr;
use ark_ff::BigInteger;
use std::fmt;

const LOWER_BITS: u32 = 136;

#[derive(Clone, PartialEq)]
pub struct GoblinField {
    pub limbs: [FieldT; 2],
}

fn split(v: &Fq) -> (Fr, Fr) {
    let u = u256(v);
    (
        from_u256(u256_low_bits(u, LOWER_BITS)),
        from_u256(u256_shr(u, LOWER_BITS)),
    )
}

impl GoblinField {
    pub fn constant(v: &Fq) -> Self {
        let (lo, hi) = split(v);
        Self {
            limbs: [FieldT::constant(lo), FieldT::constant(hi)],
        }
    }
    pub fn from_witness(ctx: &Ctx, v: &Fq) -> Self {
        let (lo, hi) = split(v);
        Self {
            limbs: [FieldT::from_witness(ctx, lo), FieldT::from_witness(ctx, hi)],
        }
    }
    pub fn value(&self) -> Fq {
        let mut v: U256 = u256(&self.limbs[1].get_value()) << LOWER_BITS;
        let overflow = v.add_with_carry(&u256(&self.limbs[0].get_value()));
        assert!(!overflow);
        from_u256(v)
    }
    pub fn is_constant(&self) -> bool {
        self.limbs[0].is_constant() && self.limbs[1].is_constant()
    }
    pub fn assert_equal(&self, other: &Self) {
        self.limbs[0].assert_equal(&other.limbs[0]);
        self.limbs[1].assert_equal(&other.limbs[1]);
    }
    pub fn set_public(&self) -> u32 {
        let start = self.limbs[0].set_public();
        self.limbs[1].set_public();
        start
    }
    pub fn convert_constant_to_fixed_witness(&mut self, ctx: &Ctx) {
        for limb in self.limbs.iter_mut() {
            limb.convert_constant_to_fixed_witness(ctx);
        }
    }
    pub fn fix_witness(&self) {
        for limb in &self.limbs {
            limb.fix_witness();
        }
    }
}

impl fmt::Debug for GoblinField {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "GoblinField({:?})", self.value())
    }
}

/// A bn254 point as two `GoblinField` coordinates; the point at infinity is `(0, 0)`.
#[derive(Clone, PartialEq)]
pub struct GoblinElement {
    pub x: GoblinField,
    pub y: GoblinField,
}

fn coordinates(p: &G1Affine) -> (Fq, Fq) {
    p.xy().unwrap_or((Fq::from(0u64), Fq::from(0u64)))
}

impl GoblinElement {
    pub fn ctx(&self) -> Ctx {
        self.x
            .limbs
            .iter()
            .chain(&self.y.limbs)
            .find_map(|l| l.ctx.clone())
            .expect("constant point without a builder")
    }
    pub fn constant_infinity() -> Self {
        Self {
            x: GoblinField::constant(&Fq::from(0u64)),
            y: GoblinField::constant(&Fq::from(0u64)),
        }
    }
    pub fn is_constant(&self) -> bool {
        self.x.is_constant() && self.y.is_constant()
    }
    /// bb `incomplete_assert_equal`: coordinate-wise limb equality.
    pub fn incomplete_assert_equal(&self, other: &Self) {
        self.x.assert_equal(&other.x);
        self.y.assert_equal(&other.y);
    }
    pub fn set_public(&self) -> u32 {
        let start = self.x.set_public();
        self.y.set_public();
        start
    }
    pub fn convert_constant_to_fixed_witness(&mut self, ctx: &Ctx) {
        self.x.convert_constant_to_fixed_witness(ctx);
        self.y.convert_constant_to_fixed_witness(ctx);
    }
    pub fn fix_witness(&self) {
        self.x.fix_witness();
        self.y.fix_witness();
    }
    fn from_op_wires(ctx: &Ctx, w: [u32; 4]) -> Self {
        let f = |i: u32| FieldT::from_witness_index(ctx, i);
        Self {
            x: GoblinField {
                limbs: [f(w[0]), f(w[1])],
            },
            y: GoblinField {
                limbs: [f(w[2]), f(w[3])],
            },
        }
    }
    fn assert_op_wires_equal(ctx: &Ctx, w: [u32; 4], p: &Self) {
        let f = |i: u32| FieldT::from_witness_index(ctx, i);
        f(w[0]).assert_equal(&p.x.limbs[0]);
        f(w[1]).assert_equal(&p.x.limbs[1]);
        f(w[2]).assert_equal(&p.y.limbs[0]);
        f(w[3]).assert_equal(&p.y.limbs[1]);
    }
    /// bb `operator-`: `self - other` through the op queue (add `other`, add the result, then an
    /// equality op pinned to `self`).
    pub fn sub(&self, other: &Self) -> Self {
        let ctx = self
            .x
            .limbs
            .iter()
            .chain(&self.y.limbs)
            .chain(&other.x.limbs)
            .chain(&other.y.limbs)
            .find_map(|l| l.ctx.clone())
            .expect("no builder");
        let other_value = other.value();
        let result_value = (self.value().into_group() - other_value.into_group()).into();
        let t1 = ctx.borrow_mut().queue_ecc_add_accum(other_value);
        Self::assert_op_wires_equal(&ctx, [t1.x_lo, t1.x_hi, t1.y_lo, t1.y_hi], other);
        let t2 = ctx.borrow_mut().queue_ecc_add_accum(result_value);
        let result = Self::from_op_wires(&ctx, [t2.x_lo, t2.x_hi, t2.y_lo, t2.y_hi]);
        let t3 = ctx.borrow_mut().queue_ecc_eq();
        Self::assert_op_wires_equal(&ctx, [t3.x_lo, t3.x_hi, t3.y_lo, t3.y_hi], self);
        result
    }
}

impl fmt::Debug for GoblinElement {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "GoblinElement({:?})", self.value())
    }
}

impl GroupLike<FieldT> for GoblinElement {
    type Native = G1Affine;
    fn one(ctx: &Ctx) -> Self {
        Self::constant(ctx, G1Affine::generator())
    }
    fn constant(_: &Ctx, p: G1Affine) -> Self {
        let (x, y) = coordinates(&p);
        Self {
            x: GoblinField::constant(&x),
            y: GoblinField::constant(&y),
        }
    }
    fn from_witness(ctx: &Ctx, p: G1Affine) -> Self {
        let (x, y) = coordinates(&p);
        Self {
            x: GoblinField::from_witness(ctx, &x),
            y: GoblinField::from_witness(ctx, &y),
        }
    }
    fn value(&self) -> G1Affine {
        let (x, y) = (self.x.value(), self.y.value());
        if x == Fq::from(0u64) && y == Fq::from(0u64) {
            G1Affine::identity()
        } else {
            G1Affine::new_unchecked(x, y)
        }
    }
    fn neg(&self) -> Self {
        Self::constant_infinity().sub(self)
    }
    fn add(&self, other: &Self) -> Self {
        Self::batch_mul(
            &[self.clone(), other.clone()],
            &[FieldT::constant(Fr::one()), FieldT::constant(Fr::one())],
        )
    }
    fn scalar_mul(&self, s: &FieldT) -> Self {
        Self::batch_mul(&[self.clone()], &[s.clone()])
    }
    /// bb `goblin_element::batch_mul`: one accumulate op per term (an add when the scalar is the
    /// constant one), then an equality op that yields the result.
    fn batch_mul(points: &[Self], scalars: &[FieldT]) -> Self {
        assert_eq!(points.len(), scalars.len());
        let ctx = points
            .iter()
            .flat_map(|p| p.x.limbs.iter().chain(&p.y.limbs))
            .chain(scalars)
            .find_map(|l| l.ctx.clone())
            .expect("no builder");
        for (point, scalar) in points.iter().zip(scalars) {
            let scalar_is_one = scalar.is_constant() && scalar.get_value() == Fr::one();
            let (point_value, scalar_value) = (point.value(), scalar.get_value());
            let t = if scalar_is_one {
                ctx.borrow_mut().queue_ecc_add_accum(point_value)
            } else {
                ctx.borrow_mut().queue_ecc_mul_accum(point_value, scalar_value)
            };
            Self::assert_op_wires_equal(&ctx, [t.x_lo, t.x_hi, t.y_lo, t.y_hi], point);
            if !scalar_is_one {
                let z_1 = FieldT::from_witness_index(&ctx, t.z_1);
                let z_2 = FieldT::from_witness_index(&ctx, t.z_2);
                let beta = FieldT::constant(cube_root_of_unity());
                scalar.assert_equal(&(&z_1 - &(&z_2 * &beta)));
            }
        }
        let t = ctx.borrow_mut().queue_ecc_eq();
        Self::from_op_wires(&ctx, [t.x_lo, t.x_hi, t.y_lo, t.y_hi])
    }
    fn enforce_equal(&self, other: &Self) {
        self.incomplete_assert_equal(other)
    }
}

impl Transcriptable<FieldT> for GoblinElement {
    fn num_fields() -> usize {
        4
    }
    fn to_fields(&self) -> Vec<FieldT> {
        vec![
            self.x.limbs[0].clone(),
            self.x.limbs[1].clone(),
            self.y.limbs[0].clone(),
            self.y.limbs[1].clone(),
        ]
    }
    fn from_fields(f: &[FieldT]) -> Self {
        Self {
            x: GoblinField {
                limbs: [f[0].clone(), f[1].clone()],
            },
            y: GoblinField {
                limbs: [f[2].clone(), f[3].clone()],
            },
        }
    }
}

/// Unused: Grumpkin elements never appear in goblin circuits; this keeps `GoblinElement` usable
/// as `C::G` for a `Curve` whose scalar field is `FieldT`.
impl Transcriptable<FieldT> for GoblinField {
    fn num_fields() -> usize {
        2
    }
    fn to_fields(&self) -> Vec<FieldT> {
        self.limbs.to_vec()
    }
    fn from_fields(f: &[FieldT]) -> Self {
        Self {
            limbs: [f[0].clone(), f[1].clone()],
        }
    }
}
