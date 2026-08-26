//! `FieldT`: a circuit field element `witness * multiplicative_constant + additive_constant`
//! (bb `stdlib::field_t`). Operations with a constant only update the scaling factors; operations
//! between two witnesses emit one arithmetic gate. The gate shapes are bb's exactly.

use crate::base::field::FieldLike;
use crate::base::Fr;
use crate::circuit::builder::{AddTriple, ArithmeticTriple, MulQuad};
use crate::circuit::{Builder, IS_CONSTANT};
use std::cell::RefCell;
use std::ops::{Add, Mul, Neg, Sub};
use std::rc::Rc;

pub type Ctx = Rc<RefCell<Builder>>;

#[derive(Clone)]
pub struct FieldT {
    pub ctx: Option<Ctx>,
    pub witness_index: u32,
    pub additive_constant: Fr,
    pub multiplicative_constant: Fr,
}

fn same_ctx(a: &Option<Ctx>, b: &Option<Ctx>) -> Option<Ctx> {
    match (a, b) {
        (Some(x), Some(y)) => {
            assert!(Rc::ptr_eq(x, y), "values from different builders");
            Some(x.clone())
        }
        (Some(x), None) | (None, Some(x)) => Some(x.clone()),
        (None, None) => None,
    }
}

impl FieldT {
    pub fn constant(v: Fr) -> Self {
        Self { ctx: None, witness_index: IS_CONSTANT, additive_constant: v, multiplicative_constant: Fr::one() }
    }
    pub fn from_witness_index(ctx: &Ctx, witness_index: u32) -> Self {
        Self { ctx: Some(ctx.clone()), witness_index, additive_constant: Fr::zero(), multiplicative_constant: Fr::one() }
    }
    /// A new witness holding `v` (bb `witness_t`).
    pub fn from_witness(ctx: &Ctx, v: Fr) -> Self {
        let idx = ctx.borrow_mut().add_variable(v);
        Self::from_witness_index(ctx, idx)
    }
    pub fn is_constant(&self) -> bool {
        self.witness_index == IS_CONSTANT
    }
    pub fn is_normalized(&self) -> bool {
        self.is_constant() || (self.multiplicative_constant == Fr::one() && self.additive_constant.is_zero())
    }
    pub fn get_value(&self) -> Fr {
        if self.is_constant() {
            return self.additive_constant;
        }
        self.multiplicative_constant * self.ctx.as_ref().unwrap().borrow().get_variable(self.witness_index) + self.additive_constant
    }
    fn ctx(&self) -> Ctx {
        self.ctx.clone().expect("witness without builder")
    }
    /// The index of a witness holding the represented value (adds a gate if not normalized).
    pub fn get_witness_index(&self) -> u32 {
        self.normalize().witness_index
    }
    /// A witness equal to the represented value with trivial scaling factors.
    pub fn normalize(&self) -> Self {
        if self.is_normalized() {
            return self.clone();
        }
        let ctx = self.ctx();
        let mut b = ctx.borrow_mut();
        let value = b.get_variable(self.witness_index);
        let idx = b.add_variable(value * self.multiplicative_constant + self.additive_constant);
        let z = b.zero_idx();
        b.create_add_gate(AddTriple {
            a: self.witness_index,
            b: z,
            c: idx,
            a_scaling: self.multiplicative_constant,
            b_scaling: Fr::zero(),
            c_scaling: -Fr::one(),
            const_scaling: self.additive_constant,
        });
        drop(b);
        Self::from_witness_index(&ctx, idx)
    }

    pub fn add(&self, other: &Self) -> Self {
        let ctx = same_ctx(&self.ctx, &other.ctx);
        let mut r = Self { ctx: ctx.clone(), witness_index: IS_CONSTANT, additive_constant: Fr::zero(), multiplicative_constant: Fr::one() };
        if self.witness_index == other.witness_index && !self.is_constant() {
            r.additive_constant = self.additive_constant + other.additive_constant;
            r.multiplicative_constant = self.multiplicative_constant + other.multiplicative_constant;
            r.witness_index = self.witness_index;
        } else if self.is_constant() && other.is_constant() {
            r.additive_constant = self.additive_constant + other.additive_constant;
        } else if !self.is_constant() && other.is_constant() {
            r.additive_constant = self.additive_constant + other.additive_constant;
            r.multiplicative_constant = self.multiplicative_constant;
            r.witness_index = self.witness_index;
        } else if self.is_constant() && !other.is_constant() {
            r.additive_constant = self.additive_constant + other.additive_constant;
            r.multiplicative_constant = other.multiplicative_constant;
            r.witness_index = other.witness_index;
        } else {
            let ctx = ctx.unwrap();
            let mut b = ctx.borrow_mut();
            let left = b.get_variable(self.witness_index);
            let right = b.get_variable(other.witness_index);
            let value = left * self.multiplicative_constant + right * other.multiplicative_constant + self.additive_constant + other.additive_constant;
            r.witness_index = b.add_variable(value);
            b.create_add_gate(AddTriple {
                a: self.witness_index,
                b: other.witness_index,
                c: r.witness_index,
                a_scaling: self.multiplicative_constant,
                b_scaling: other.multiplicative_constant,
                c_scaling: -Fr::one(),
                const_scaling: self.additive_constant + other.additive_constant,
            });
        }
        r
    }

    pub fn neg(&self) -> Self {
        let mut r = self.clone();
        r.additive_constant = -r.additive_constant;
        if !r.is_constant() {
            r.multiplicative_constant = -r.multiplicative_constant;
        }
        r
    }

    pub fn sub(&self, other: &Self) -> Self {
        self.add(&other.neg())
    }

    pub fn mul(&self, other: &Self) -> Self {
        let ctx = same_ctx(&self.ctx, &other.ctx);
        let mut r = Self { ctx: ctx.clone(), witness_index: IS_CONSTANT, additive_constant: Fr::zero(), multiplicative_constant: Fr::one() };
        if self.is_constant() && other.is_constant() {
            r.additive_constant = self.additive_constant * other.additive_constant;
        } else if !self.is_constant() && other.is_constant() {
            r.additive_constant = self.additive_constant * other.additive_constant;
            r.multiplicative_constant = self.multiplicative_constant * other.additive_constant;
            r.witness_index = self.witness_index;
        } else if self.is_constant() && !other.is_constant() {
            r.additive_constant = self.additive_constant * other.additive_constant;
            r.multiplicative_constant = other.multiplicative_constant * self.additive_constant;
            r.witness_index = other.witness_index;
        } else {
            let q_c = self.additive_constant * other.additive_constant;
            let q_r = self.additive_constant * other.multiplicative_constant;
            let q_l = self.multiplicative_constant * other.additive_constant;
            let q_m = self.multiplicative_constant * other.multiplicative_constant;
            let ctx = ctx.unwrap();
            let mut b = ctx.borrow_mut();
            let left = b.get_variable(self.witness_index);
            let right = b.get_variable(other.witness_index);
            let value = left * right * q_m + left * q_l + right * q_r + q_c;
            r.witness_index = b.add_variable(value);
            b.create_arithmetic_gate(ArithmeticTriple { a: self.witness_index, b: other.witness_index, c: r.witness_index, q_m, q_l, q_r, q_o: -Fr::one(), q_c });
        }
        r
    }

    /// `self + b + c` in one gate when all three are witnesses.
    pub fn add_two(&self, add_b: &Self, add_c: &Self) -> Self {
        if self.is_constant() || add_b.is_constant() || add_c.is_constant() {
            return self.add(add_b).add(add_c);
        }
        let ctx = same_ctx(&same_ctx(&self.ctx, &add_b.ctx), &add_c.ctx).unwrap();
        let mut b = ctx.borrow_mut();
        let const_scaling = self.additive_constant + add_b.additive_constant + add_c.additive_constant;
        let value = b.get_variable(self.witness_index) * self.multiplicative_constant
            + b.get_variable(add_b.witness_index) * add_b.multiplicative_constant
            + b.get_variable(add_c.witness_index) * add_c.multiplicative_constant
            + const_scaling;
        let idx = b.add_variable(value);
        b.create_big_mul_add_gate(
            &MulQuad {
                a: self.witness_index,
                b: add_b.witness_index,
                c: add_c.witness_index,
                d: idx,
                mul_scaling: Fr::zero(),
                a_scaling: self.multiplicative_constant,
                b_scaling: add_b.multiplicative_constant,
                c_scaling: add_c.multiplicative_constant,
                d_scaling: -Fr::one(),
                const_scaling,
            },
            false,
        );
        drop(b);
        Self::from_witness_index(&ctx, idx)
    }

    /// `self * to_mul + to_add` in one gate when the multiplicands are witnesses.
    pub fn madd(&self, to_mul: &Self, to_add: &Self) -> Self {
        if self.is_constant() || to_mul.is_constant() {
            return self.mul(to_mul).add(to_add);
        }
        let ctx = same_ctx(&same_ctx(&self.ctx, &to_mul.ctx), &to_add.ctx).unwrap();
        let mut b = ctx.borrow_mut();
        let mul_scaling = self.multiplicative_constant * to_mul.multiplicative_constant;
        let a_scaling = self.multiplicative_constant * to_mul.additive_constant;
        let b_scaling = to_mul.multiplicative_constant * self.additive_constant;
        let c_scaling = to_add.multiplicative_constant;
        let const_scaling = self.additive_constant * to_mul.additive_constant + to_add.additive_constant;
        let z = b.zero_idx();
        let var = |b: &Builder, f: &FieldT| if f.is_constant() { Fr::zero() } else { b.get_variable(f.witness_index) };
        let (va, vb, vc) = (var(&b, self), var(&b, to_mul), var(&b, to_add));
        let value = va * vb * mul_scaling + va * a_scaling + vb * b_scaling + vc * c_scaling + const_scaling;
        let idx = b.add_variable(value);
        let wire = |f: &FieldT| if f.is_constant() { z } else { f.witness_index };
        b.create_big_mul_add_gate(
            &MulQuad { a: wire(self), b: wire(to_mul), c: wire(to_add), d: idx, mul_scaling, a_scaling, b_scaling, c_scaling, d_scaling: -Fr::one(), const_scaling },
            false,
        );
        drop(b);
        Self::from_witness_index(&ctx, idx)
    }

    /// Constrain equality: a copy constraint when either side is normalized, one add gate otherwise.
    pub fn assert_equal(&self, rhs: &Self) {
        let ctx = same_ctx(&self.ctx, &rhs.ctx);
        if self.is_constant() && rhs.is_constant() {
            assert_eq!(self.get_value(), rhs.get_value(), "assert_equal: constants differ");
            return;
        }
        let ctx = ctx.unwrap();
        if self.is_constant() {
            let w = rhs.get_witness_index();
            ctx.borrow_mut().assert_equal_constant(w, self.get_value());
        } else if rhs.is_constant() {
            let w = self.get_witness_index();
            ctx.borrow_mut().assert_equal_constant(w, rhs.get_value());
        } else if self.is_normalized() || rhs.is_normalized() {
            let (a, b) = (self.get_witness_index(), rhs.get_witness_index());
            ctx.borrow_mut().assert_equal(a, b);
        } else {
            let mut b = ctx.borrow_mut();
            let z = b.zero_idx();
            b.create_add_gate(AddTriple {
                a: self.witness_index,
                b: rhs.witness_index,
                c: z,
                a_scaling: self.multiplicative_constant,
                b_scaling: -rhs.multiplicative_constant,
                c_scaling: Fr::zero(),
                const_scaling: self.additive_constant - rhs.additive_constant,
            });
            drop(b);
            if self.get_value() != rhs.get_value() {
                ctx.borrow_mut().failure("field_t::assert_equal");
            }
        }
    }

    pub fn set_public(&self) -> u32 {
        assert!(!self.is_constant());
        let w = self.get_witness_index();
        self.ctx().borrow_mut().set_public_input(w)
    }
}

macro_rules! ops {
    ($($tr:ident $m:ident),*) => {$(
        impl $tr for &FieldT { type Output = FieldT; fn $m(self, o: &FieldT) -> FieldT { FieldT::$m(self, o) } }
        impl $tr for FieldT { type Output = FieldT; fn $m(self, o: FieldT) -> FieldT { FieldT::$m(&self, &o) } }
        impl $tr<&FieldT> for FieldT { type Output = FieldT; fn $m(self, o: &FieldT) -> FieldT { FieldT::$m(&self, o) } }
        impl $tr<FieldT> for &FieldT { type Output = FieldT; fn $m(self, o: FieldT) -> FieldT { FieldT::$m(self, &o) } }
    )*};
}
ops!(Add add, Sub sub, Mul mul);
impl Neg for &FieldT {
    type Output = FieldT;
    fn neg(self) -> FieldT {
        FieldT::neg(self)
    }
}
