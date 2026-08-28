//! `FieldT`: a circuit field element `witness * multiplicative_constant + additive_constant`
//! (bb `stdlib::field_t`). Operations with a constant only update the scaling factors; operations
//! between two witnesses emit one arithmetic gate. The gate shapes are bb's exactly.

use super::bool::BoolT;
use crate::base::codec::{ChallengeField, FromChallenge, Transcriptable};
use crate::base::field::{from_u256, u256, u256_low_bits, u256_num_bits, u256_shr, FieldLike, U256};
use crate::base::Fr;
use crate::circuit::builder::{AddQuad, AddTriple, ArithmeticTriple, MulQuad, DEFAULT_PLOOKUP_RANGE_BITNUM};
use crate::circuit::{Builder, IS_CONSTANT};
use ark_ff::PrimeField;
use std::cell::RefCell;
use std::fmt;
use std::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use std::rc::Rc;

pub type Ctx = Rc<RefCell<Builder>>;

#[derive(Clone)]
pub struct FieldT {
    pub ctx: Option<Ctx>,
    pub witness_index: u32,
    pub additive_constant: Fr,
    pub multiplicative_constant: Fr,
}

pub(super) fn same_ctx(a: &Option<Ctx>, b: &Option<Ctx>) -> Option<Ctx> {
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
        Self {
            ctx: None,
            witness_index: IS_CONSTANT,
            additive_constant: v,
            multiplicative_constant: Fr::one(),
        }
    }
    pub fn from_witness_index(ctx: &Ctx, witness_index: u32) -> Self {
        Self {
            ctx: Some(ctx.clone()),
            witness_index,
            additive_constant: Fr::zero(),
            multiplicative_constant: Fr::one(),
        }
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
        self.multiplicative_constant * self.ctx.as_ref().unwrap().borrow().get_variable(self.witness_index)
            + self.additive_constant
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
        let mut r = Self {
            ctx: ctx.clone(),
            witness_index: IS_CONSTANT,
            additive_constant: Fr::zero(),
            multiplicative_constant: Fr::one(),
        };
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
            let value = left * self.multiplicative_constant
                + right * other.multiplicative_constant
                + self.additive_constant
                + other.additive_constant;
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
        let mut r = Self {
            ctx: ctx.clone(),
            witness_index: IS_CONSTANT,
            additive_constant: Fr::zero(),
            multiplicative_constant: Fr::one(),
        };
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
            b.create_arithmetic_gate(ArithmeticTriple {
                a: self.witness_index,
                b: other.witness_index,
                c: r.witness_index,
                q_m,
                q_l,
                q_r,
                q_o: -Fr::one(),
                q_c,
            });
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
        let var = |b: &Builder, f: &FieldT| {
            if f.is_constant() {
                Fr::zero()
            } else {
                b.get_variable(f.witness_index)
            }
        };
        let (va, vb, vc) = (var(&b, self), var(&b, to_mul), var(&b, to_add));
        let value = va * vb * mul_scaling + va * a_scaling + vb * b_scaling + vc * c_scaling + const_scaling;
        let idx = b.add_variable(value);
        let wire = |f: &FieldT| if f.is_constant() { z } else { f.witness_index };
        b.create_big_mul_add_gate(
            &MulQuad {
                a: wire(self),
                b: wire(to_mul),
                c: wire(to_add),
                d: idx,
                mul_scaling,
                a_scaling,
                b_scaling,
                c_scaling,
                d_scaling: -Fr::one(),
                const_scaling,
            },
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

    /// bb `divide_no_zero_check`: `self / other` with the divisor assumed non-zero.
    pub fn divide_no_zero_check(&self, other: &Self) -> Self {
        let ctx = same_ctx(&self.ctx, &other.ctx);
        let mut r = Self {
            ctx: ctx.clone(),
            witness_index: IS_CONSTANT,
            additive_constant: Fr::zero(),
            multiplicative_constant: Fr::one(),
        };
        let additive_multiplier = if other.additive_constant.is_zero() {
            Fr::one()
        } else {
            other.additive_constant.invert()
        };
        if self.is_constant() && other.is_constant() {
            r.additive_constant = self.additive_constant * additive_multiplier;
        } else if !self.is_constant() && other.is_constant() {
            r.additive_constant = self.additive_constant * additive_multiplier;
            r.multiplicative_constant = self.multiplicative_constant * additive_multiplier;
            r.witness_index = self.witness_index;
        } else if self.is_constant() && !other.is_constant() {
            if self.get_value().is_zero() {
                r.additive_constant = Fr::zero();
                r.multiplicative_constant = Fr::one();
                r.witness_index = IS_CONSTANT;
            } else {
                let denominator = other.get_value();
                let out = self.get_value()
                    * if denominator.is_zero() {
                        Fr::zero()
                    } else {
                        denominator.invert()
                    };
                let q_c = -self.get_value();
                let ctx = ctx.unwrap();
                let mut b = ctx.borrow_mut();
                r.witness_index = b.add_variable(out);
                b.create_arithmetic_gate(ArithmeticTriple {
                    a: r.witness_index,
                    b: other.witness_index,
                    c: r.witness_index,
                    q_m: other.multiplicative_constant,
                    q_l: other.additive_constant,
                    q_r: Fr::zero(),
                    q_o: Fr::zero(),
                    q_c,
                });
            }
        } else {
            let denominator = other.get_value();
            let out = self.get_value()
                * if denominator.is_zero() {
                    Fr::zero()
                } else {
                    denominator.invert()
                };
            let ctx = ctx.unwrap();
            let mut b = ctx.borrow_mut();
            r.witness_index = b.add_variable(out);
            b.create_arithmetic_gate(ArithmeticTriple {
                a: r.witness_index,
                b: other.witness_index,
                c: self.witness_index,
                q_m: other.multiplicative_constant,
                q_l: other.additive_constant,
                q_r: Fr::zero(),
                q_o: -self.multiplicative_constant,
                q_c: -self.additive_constant,
            });
        }
        r
    }

    /// bb `operator/`: asserts the divisor is non-zero, then divides.
    pub fn sqr(&self) -> Self {
        self.mul(self)
    }
    /// bb `field_t::is_zero`: a boolean witness with two polynomial identities binding it.
    pub fn is_zero(&self) -> BoolT {
        let value = self.get_value();
        if self.is_constant() {
            return BoolT::constant(value.is_zero());
        }
        let ctx = self.ctx.clone().unwrap();
        let is_zero = BoolT::from_witness(&ctx, value.is_zero());
        let inverse_native = if value.is_zero() { Fr::one() } else { value.invert() };
        let inverse = FieldT::from_witness(&ctx, inverse_native);
        FieldT::evaluate_polynomial_identity(self, &inverse, &is_zero.to_field(), &Self::constant(-Fr::one()));
        FieldT::evaluate_polynomial_identity(
            &is_zero.to_field(),
            &FieldT::neg(&inverse),
            &is_zero.to_field(),
            &Self::constant(Fr::zero()),
        );
        is_zero
    }
    pub fn eq(&self, other: &Self) -> BoolT {
        self.sub(other).is_zero()
    }
    /// bb `field_t::conditional_assign`: `predicate ? lhs : rhs`, normalized.
    pub fn conditional_assign(predicate: &BoolT, lhs: &Self, rhs: &Self) -> Self {
        Self::conditional_assign_internal(predicate, lhs, rhs).normalize()
    }
    /// bb `conditional_assign_internal`: `predicate ? lhs : rhs` left unnormalized.
    pub fn conditional_assign_internal(predicate: &BoolT, lhs: &Self, rhs: &Self) -> Self {
        if predicate.is_constant() {
            return if predicate.get_value() {
                lhs.clone()
            } else {
                rhs.clone()
            };
        }
        if lhs.witness_index == rhs.witness_index
            && lhs.additive_constant == rhs.additive_constant
            && lhs.multiplicative_constant == rhs.multiplicative_constant
        {
            return lhs.clone();
        }
        lhs.sub(rhs).madd(&predicate.to_field(), rhs)
    }
    pub fn div(&self, other: &Self) -> Self {
        other.assert_is_not_zero();
        self.divide_no_zero_check(other)
    }

    /// bb `invert`: `1 / self`; the division gate doubles as the non-zero check.
    pub fn inverse(&self) -> Self {
        if self.is_constant() {
            assert!(!self.get_value().is_zero(), "field_t::invert denominator is constant 0");
        } else if self.get_value().is_zero() {
            self.ctx().borrow_mut().failure("field_t::invert denominator is 0");
        }
        Self::constant(Fr::one()).divide_no_zero_check(self)
    }

    /// bb `pow(uint32_t)`: square-and-multiply, the accumulator initialised by the first set bit.
    pub fn pow_u32(&self, exponent: u32) -> Self {
        if self.is_constant() {
            return Self::constant(self.get_value().pow_u64(exponent as u64));
        }
        if exponent == 0 {
            return Self::constant(Fr::one());
        }
        let mut accumulator: Option<Self> = None;
        let mut running_power = self.clone();
        let mut shifted = exponent;
        while shifted != 0 {
            if shifted & 1 == 1 {
                accumulator = Some(match accumulator {
                    None => running_power.clone(),
                    Some(acc) => FieldT::mul(&acc, &running_power),
                });
            }
            if shifted >= 2 {
                running_power = FieldT::mul(&running_power, &running_power);
            }
            shifted >>= 1;
        }
        accumulator.unwrap()
    }

    pub fn assert_is_zero(&self) {
        if self.is_constant() {
            assert!(
                self.additive_constant.is_zero(),
                "assert_is_zero on a non-zero constant"
            );
            return;
        }
        let ctx = self.ctx();
        if !self.get_value().is_zero() {
            ctx.borrow_mut().failure("field_t::assert_is_zero");
        }
        let mut b = ctx.borrow_mut();
        let z = b.zero_idx();
        b.create_arithmetic_gate(ArithmeticTriple {
            a: self.witness_index,
            b: z,
            c: z,
            q_m: Fr::zero(),
            q_l: self.multiplicative_constant,
            q_r: Fr::zero(),
            q_o: Fr::zero(),
            q_c: self.additive_constant,
        });
    }

    pub fn assert_is_not_zero(&self) {
        if self.is_constant() {
            assert!(
                !self.additive_constant.is_zero(),
                "assert_is_not_zero on a zero constant"
            );
            return;
        }
        let ctx = self.ctx();
        let value = self.get_value();
        if value.is_zero() {
            ctx.borrow_mut().failure("field_t::assert_is_not_zero");
        }
        let inverse = Self::from_witness(&ctx, if value.is_zero() { Fr::zero() } else { value.invert() });
        let mut b = ctx.borrow_mut();
        let z = b.zero_idx();
        b.create_arithmetic_gate(ArithmeticTriple {
            a: self.witness_index,
            b: inverse.witness_index,
            c: z,
            q_m: self.multiplicative_constant,
            q_l: Fr::zero(),
            q_r: self.additive_constant,
            q_o: Fr::zero(),
            q_c: -Fr::one(),
        });
    }

    fn wire_or_zero(b: &Builder, f: &Self) -> u32 {
        if f.is_constant() {
            b.zero_idx()
        } else {
            f.witness_index
        }
    }

    /// bb `evaluate_linear_identity`: constrain `a + b + c + d == 0` with one big-add gate.
    pub fn evaluate_linear_identity(a: &Self, b: &Self, c: &Self, d: &Self) {
        let ctx = same_ctx(&same_ctx(&a.ctx, &b.ctx), &same_ctx(&c.ctx, &d.ctx));
        let sum = a.get_value() + b.get_value() + c.get_value() + d.get_value();
        if a.is_constant() && b.is_constant() && c.is_constant() && d.is_constant() {
            assert!(sum.is_zero(), "evaluate_linear_identity on constants");
            return;
        }
        let ctx = ctx.unwrap();
        if !sum.is_zero() {
            ctx.borrow_mut().failure("field_t::evaluate_linear_identity");
        }
        let mut bd = ctx.borrow_mut();
        let gate = AddQuad {
            a: Self::wire_or_zero(&bd, a),
            b: Self::wire_or_zero(&bd, b),
            c: Self::wire_or_zero(&bd, c),
            d: Self::wire_or_zero(&bd, d),
            a_scaling: a.multiplicative_constant,
            b_scaling: b.multiplicative_constant,
            c_scaling: c.multiplicative_constant,
            d_scaling: d.multiplicative_constant,
            const_scaling: a.additive_constant + b.additive_constant + c.additive_constant + d.additive_constant,
        };
        bd.create_big_add_gate(gate, false);
    }

    /// bb `evaluate_polynomial_identity`: constrain `a * b + c + d == 0` with one big-mul-add gate.
    pub fn evaluate_polynomial_identity(a: &Self, b: &Self, c: &Self, d: &Self) {
        let value = a.get_value() * b.get_value() + c.get_value() + d.get_value();
        if a.is_constant() && b.is_constant() && c.is_constant() && d.is_constant() {
            assert!(value.is_zero(), "evaluate_polynomial_identity on constants");
            return;
        }
        let ctx = same_ctx(&same_ctx(&a.ctx, &b.ctx), &same_ctx(&c.ctx, &d.ctx)).unwrap();
        if !value.is_zero() {
            ctx.borrow_mut().failure("field_t::evaluate_polynomial_identity");
        }
        let mut bd = ctx.borrow_mut();
        let gate = MulQuad {
            a: Self::wire_or_zero(&bd, a),
            b: Self::wire_or_zero(&bd, b),
            c: Self::wire_or_zero(&bd, c),
            d: Self::wire_or_zero(&bd, d),
            mul_scaling: a.multiplicative_constant * b.multiplicative_constant,
            a_scaling: a.multiplicative_constant * b.additive_constant,
            b_scaling: b.multiplicative_constant * a.additive_constant,
            c_scaling: c.multiplicative_constant,
            d_scaling: d.multiplicative_constant,
            const_scaling: a.additive_constant * b.additive_constant + c.additive_constant + d.additive_constant,
        };
        bd.create_big_mul_add_gate(&gate, false);
    }

    /// bb `accumulate`: the sum of many terms as a chain of big-add gates, three terms per gate,
    /// the running total carried in the next gate's fourth wire.
    pub fn accumulate(input: &[Self]) -> Self {
        if input.is_empty() {
            return Self::constant(Fr::zero());
        }
        if input.len() == 1 {
            return input[0].normalize();
        }
        let mut accumulator: Vec<Self> = Vec::new();
        let mut constant_term = Self::constant(Fr::zero());
        for element in input {
            if element.is_constant() {
                constant_term = FieldT::add(&constant_term, element);
            } else {
                accumulator.push(element.clone());
            }
        }
        if accumulator.is_empty() {
            return constant_term;
        }
        accumulator[0] = FieldT::add(&accumulator[0], &constant_term);
        let ctx = accumulator[0].ctx();
        let output: Fr = accumulator.iter().map(|a| a.get_value()).sum();
        let num_padding = (3 - accumulator.len() % 3) % 3;
        let zero_idx = ctx.borrow().zero_idx();
        for _ in 0..num_padding {
            accumulator.push(Self::from_witness_index(&ctx, zero_idx));
        }
        let num_gates = accumulator.len() / 3;
        let total = Self::from_witness(&ctx, output);
        let mut accumulating_total = total.clone();
        for i in 0..num_gates {
            let (x, y, z) = (&accumulator[3 * i], &accumulator[3 * i + 1], &accumulator[3 * i + 2]);
            let gate = AddQuad {
                a: x.witness_index,
                b: y.witness_index,
                c: z.witness_index,
                d: accumulating_total.witness_index,
                a_scaling: x.multiplicative_constant,
                b_scaling: y.multiplicative_constant,
                c_scaling: z.multiplicative_constant,
                d_scaling: -Fr::one(),
                const_scaling: x.additive_constant + y.additive_constant + z.additive_constant,
            };
            let last = i + 1 == num_gates;
            ctx.borrow_mut().create_big_add_gate(gate, !last);
            if !last {
                let new_total = accumulating_total.get_value() - x.get_value() - y.get_value() - z.get_value();
                accumulating_total = Self::from_witness(&ctx, new_total);
            }
        }
        total.normalize()
    }

    /// bb `create_range_constraint`: `self < 2^num_bits` by limb decomposition into 14-bit lookups.
    pub fn create_range_constraint(&self, num_bits: u64) {
        if num_bits == 0 {
            self.assert_is_zero();
        } else if self.is_constant() {
            assert!(
                (u256_num_bits(&u256(&self.get_value())) as u64) <= num_bits,
                "constant out of range"
            );
        } else {
            let w = self.normalize().witness_index;
            self.ctx()
                .borrow_mut()
                .create_limbed_range_constraint(w, num_bits, DEFAULT_PLOOKUP_RANGE_BITNUM);
        }
    }

    /// bb `convert_constant_to_fixed_witness`: a new witness holding the constant, fixed by a gate.
    pub fn convert_constant_to_fixed_witness(&mut self, ctx: &Ctx) {
        assert!(self.is_constant());
        let value = self.get_value();
        let idx = ctx.borrow_mut().add_variable(value);
        ctx.borrow_mut().fix_witness(idx, value);
        *self = Self::from_witness_index(ctx, idx);
    }

    pub fn fix_witness(&self) {
        assert!(!self.is_constant());
        let value = self.get_value();
        self.ctx().borrow_mut().fix_witness(self.witness_index, value);
    }
}

/// bb `split_unique`: `field = lo + hi * 2^lo_bits` with `lo < 2^lo_bits`, `hi < 2^(254 - lo_bits)`
/// and the pair validated to be the unique in-field decomposition.
/// bb `field_t::no_wrap_split_at`: split a value known to fit `num_bits` at `lsb_index` with range
/// constraints on both halves.
pub fn no_wrap_split_at(f: &FieldT, lsb_index: usize, num_bits: usize) -> (FieldT, FieldT) {
    assert!(lsb_index < num_bits);
    let value = u256(&f.get_value());
    let hi_val = u256_shr(value, lsb_index as u32);
    let lo_val = u256_low_bits(value, lsb_index as u32);
    if f.is_constant() {
        return (FieldT::constant(from_u256(lo_val)), FieldT::constant(from_u256(hi_val)));
    }
    if lsb_index == 0 {
        f.create_range_constraint(num_bits as u64);
        return (FieldT::constant(Fr::zero()), f.clone());
    }
    let ctx = f.ctx();
    let lo = FieldT::from_witness(&ctx, from_u256(lo_val));
    let hi = FieldT::from_witness(&ctx, from_u256(hi_val));
    lo.create_range_constraint(lsb_index as u64);
    hi.create_range_constraint((num_bits - lsb_index) as u64);
    let shift = FieldT::constant(from_u256(U256::from(1u64) << lsb_index as u32));
    let reconstructed = FieldT::add(&lo, &FieldT::mul(&hi, &shift));
    f.assert_equal(&reconstructed);
    (lo, hi)
}

pub fn split_unique(field: &FieldT, lo_bits: u32) -> (FieldT, FieldT) {
    const MAX_BITS: u32 = 254;
    let value = u256(&field.get_value());
    let lo_val: Fr = from_u256(u256_low_bits(value, lo_bits));
    let hi_val: Fr = from_u256(u256_shr(value, lo_bits));
    if field.is_constant() {
        return (FieldT::constant(lo_val), FieldT::constant(hi_val));
    }
    let ctx = field.ctx();
    let lo = FieldT::from_witness(&ctx, lo_val);
    let hi = FieldT::from_witness(&ctx, hi_val);
    let shift: Fr = from_u256(crate::base::field::U256::from(1u64) << lo_bits);
    let zero_idx = ctx.borrow().zero_idx();
    let zero = FieldT::from_witness_index(&ctx, zero_idx);
    FieldT::evaluate_linear_identity(
        &lo,
        &FieldT::mul(&hi, &FieldT::constant(shift)),
        &FieldT::neg(field),
        &zero,
    );
    validate_split_in_field_unsafe(&lo, &hi, lo_bits);
    lo.create_range_constraint(lo_bits as u64);
    hi.create_range_constraint((MAX_BITS - lo_bits) as u64);
    (lo, hi)
}

/// bb `validate_split_in_field_unsafe`: borrow-subtraction check that `lo + hi * 2^lo_bits < r`.
fn validate_split_in_field_unsafe(lo: &FieldT, hi: &FieldT, lo_bits: u32) {
    let modulus = Fr::MODULUS;
    let hi_bits = 254 - lo_bits;
    let r_lo = u256_low_bits(modulus, lo_bits);
    let r_hi = u256_shr(modulus, lo_bits);
    let need_borrow = u256(&lo.get_value()) >= r_lo;
    let ctx = lo.ctx();
    let borrow = FieldT::from_witness(&ctx, Fr::from(need_borrow as u64));
    ctx.borrow_mut().create_small_range_constraint(borrow.witness_index, 1);
    let hi_diff = &(&FieldT::neg(hi) + &FieldT::constant(from_u256(r_hi))) - &borrow;
    let shift = FieldT::constant(from_u256(crate::base::field::U256::from(1u64) << lo_bits));
    let lo_diff = &(&FieldT::neg(lo) + &FieldT::constant(from_u256::<Fr>(r_lo) - Fr::one())) + &(&borrow * &shift);
    hi_diff.create_range_constraint(hi_bits as u64);
    lo_diff.create_range_constraint(lo_bits as u64);
}

impl FieldT {
    /// bb `ranged_less_than<num_bits>` as a field (the predicate's value).
    pub fn ranged_less_than_bits(&self, other: &Self, num_bits: u32) -> Self {
        self.ranged_less_than(other, num_bits).to_field()
    }
    /// bb `ranged_less_than<num_bits>`: `self < other` for `num_bits`-bit values.
    pub fn ranged_less_than(&self, other: &Self, num_bits: u32) -> BoolT {
        if self.is_constant() && other.is_constant() {
            return BoolT::constant(u256(&self.get_value()) < u256(&other.get_value()));
        }
        let ctx = same_ctx(&self.ctx, &other.ctx).unwrap();
        let range_constant: Fr = from_u256(crate::base::field::U256::from(1u64) << num_bits);
        let predicate = BoolT::from_witness(&ctx, u256(&self.get_value()) < u256(&other.get_value()));
        let term_a = &(&FieldT::neg(self) + &Self::constant(range_constant)) - &Self::constant(Fr::one());
        let term_b = &FieldT::neg(&predicate.to_field()) * &Self::constant(range_constant);
        let predicate_valid = other.add_two(&term_a, &term_b);
        predicate_valid.create_range_constraint(num_bits as u64);
        predicate
    }

    /// bb `pow<num_bits>(const field_t& exponent)`: bit-decompose the exponent (bool witnesses, most
    /// significant first in the accumulator), then square-and-conditionally-multiply.
    pub fn pow_field_bits(&self, exponent: &Self, num_bits: u32) -> Self {
        let exponent_value = u256(&exponent.get_value());
        assert!(
            (u256_num_bits(&exponent_value) as u32) <= num_bits,
            "exponent too large in field_t::pow"
        );
        if self.is_constant() && exponent.is_constant() {
            return Self::constant(
                self.get_value()
                    .pow_u64(crate::base::field::u256_to_u64(&exponent_value)),
            );
        }
        if exponent.is_constant() {
            return self.pow_u32(crate::base::field::u256_to_u64(&exponent_value) as u32);
        }
        let ctx = same_ctx(&self.ctx, &exponent.ctx).unwrap();
        let mut bits: Vec<Option<BoolT>> = vec![None; num_bits as usize];
        let mut remaining = exponent_value;
        for i in 0..num_bits as usize {
            let bit = remaining.0[0] & 1 == 1;
            bits[num_bits as usize - 1 - i] = Some(BoolT::from_witness(&ctx, bit));
            remaining = u256_shr(remaining, 1);
        }
        let bits: Vec<BoolT> = bits.into_iter().map(Option::unwrap).collect();
        let mut exponent_accumulator = Self::constant(Fr::zero());
        for bit in &bits {
            exponent_accumulator = FieldT::add(&exponent_accumulator, &exponent_accumulator);
            exponent_accumulator = FieldT::add(&exponent_accumulator, &bit.to_field());
        }
        exponent.assert_equal(&exponent_accumulator);
        let mut accumulator = Self {
            ctx: Some(ctx.clone()),
            ..Self::constant(Fr::one())
        };
        let one = Self::constant(Fr::one());
        for bit in &bits {
            accumulator = FieldT::mul(&accumulator, &accumulator);
            // conditional_assign_internal(bit, self, one) = (self - one).madd(bit, one)
            let multiplier = FieldT::sub(self, &one).madd(&bit.to_field(), &one);
            accumulator = FieldT::mul(&accumulator, &multiplier);
        }
        accumulator.normalize()
    }
}

impl fmt::Debug for FieldT {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "FieldT({:?})", self.get_value())
    }
}

/// Structural equality (bb `witness_indices_match` plus the scaling constants); use `value()` to
/// compare represented values.
impl PartialEq for FieldT {
    fn eq(&self, other: &Self) -> bool {
        self.witness_index == other.witness_index
            && self.additive_constant == other.additive_constant
            && self.multiplicative_constant == other.multiplicative_constant
    }
}

impl FieldLike for FieldT {
    type Native = Fr;
    type Ctx = Ctx;
    fn ctx(&self) -> Option<Ctx> {
        self.ctx.clone()
    }
    fn constant(v: Fr) -> Self {
        FieldT::constant(v)
    }
    fn from_witness(ctx: &Ctx, v: Fr) -> Self {
        FieldT::from_witness(ctx, v)
    }
    fn value(&self) -> Fr {
        self.get_value()
    }
    fn invert(&self) -> Self {
        self.inverse()
    }
    fn assert_equal(&self, other: &Self) {
        FieldT::assert_equal(self, other)
    }
    fn pow_u64(&self, e: u64) -> Self {
        self.pow_u32(u32::try_from(e).expect("in-circuit exponents are 32-bit"))
    }
    fn fixed_witness(ctx: &Ctx, v: Fr) -> Self {
        let mut f = FieldT::constant(v);
        f.convert_constant_to_fixed_witness(ctx);
        f
    }
    fn div(&self, other: &Self) -> Self {
        FieldT::div(self, other)
    }
    fn ranged_less_than(&self, other: &Self, num_bits: u32) -> Self {
        self.ranged_less_than_bits(other, num_bits)
    }
    fn pow_field(&self, exponent: &Self, num_bits: u32) -> Self {
        self.pow_field_bits(exponent, num_bits)
    }
    fn madd(&self, to_mul: &Self, to_add: &[Self]) -> Self {
        assert_eq!(to_add.len(), 1, "field_t madd takes a single addend");
        FieldT::madd(self, to_mul, &to_add[0])
    }
    fn fix(&self) {
        self.fix_witness();
    }
}

impl Neg for FieldT {
    type Output = FieldT;
    fn neg(self) -> FieldT {
        FieldT::neg(&self)
    }
}
impl AddAssign<&FieldT> for FieldT {
    fn add_assign(&mut self, o: &FieldT) {
        *self = FieldT::add(self, o);
    }
}
impl SubAssign<&FieldT> for FieldT {
    fn sub_assign(&mut self, o: &FieldT) {
        *self = FieldT::sub(self, o);
    }
}
impl MulAssign<&FieldT> for FieldT {
    fn mul_assign(&mut self, o: &FieldT) {
        *self = FieldT::mul(self, o);
    }
}
impl AddAssign for FieldT {
    fn add_assign(&mut self, o: FieldT) {
        *self = FieldT::add(self, &o);
    }
}
impl SubAssign for FieldT {
    fn sub_assign(&mut self, o: FieldT) {
        *self = FieldT::sub(self, &o);
    }
}
impl MulAssign for FieldT {
    fn mul_assign(&mut self, o: FieldT) {
        *self = FieldT::mul(self, &o);
    }
}

impl Transcriptable<FieldT> for FieldT {
    fn num_fields() -> usize {
        1
    }
    fn to_fields(&self) -> Vec<FieldT> {
        vec![self.clone()]
    }
    fn from_fields(f: &[FieldT]) -> Self {
        f[0].clone()
    }
}

impl FromChallenge<FieldT> for FieldT {
    fn full(c: FieldT) -> Self {
        c
    }
    fn short(c: FieldT) -> Self {
        c
    }
}

/// bb `StdlibCodec::split_challenge`: the two 127-bit halves as range-constrained witnesses.
impl crate::base::codec::TranscriptData for FieldT {
    fn assert_equal(&self, other: &Self) {
        FieldT::assert_equal(self, other);
    }
}

impl ChallengeField for FieldT {
    fn split_challenge(&self) -> [Self; 2] {
        let (lo, hi) = split_unique(self, 127);
        [lo, hi]
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
