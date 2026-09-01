//! `BoolT`: a circuit boolean (bb `stdlib::bool_t`): a constant, or a witness constrained to
//! `{0, 1}` together with a lazily applied inversion flag. Gate shapes are bb's exactly. Like bb's
//! (whose members are `mutable`), `normalize` rewrites the value in place, so later uses of the
//! same variable see the normalized witness.

use super::field::{same_ctx, Ctx, FieldT};
use crate::base::field::FieldLike;
use crate::base::Fr;
use crate::circuit::builder::ArithmeticTriple;
use crate::circuit::IS_CONSTANT;
use std::cell::Cell;

#[derive(Clone)]
pub struct BoolT {
    pub ctx: Option<Ctx>,
    witness_index: Cell<u32>,
    witness_bool: Cell<bool>,
    witness_inverted: Cell<bool>,
}

fn fr(i: i64) -> Fr {
    if i < 0 {
        -Fr::from((-i) as u64)
    } else {
        Fr::from(i as u64)
    }
}

impl BoolT {
    fn build(ctx: Option<Ctx>, witness_index: u32, witness_bool: bool, witness_inverted: bool) -> Self {
        Self {
            ctx,
            witness_index: Cell::new(witness_index),
            witness_bool: Cell::new(witness_bool),
            witness_inverted: Cell::new(witness_inverted),
        }
    }
    pub fn witness_index(&self) -> u32 {
        self.witness_index.get()
    }
    pub fn witness_inverted(&self) -> bool {
        self.witness_inverted.get()
    }
    pub fn constant(value: bool) -> Self {
        Self::build(None, IS_CONSTANT, value, false)
    }
    /// A fresh boolean witness (one bool gate).
    pub fn from_witness(ctx: &Ctx, value: bool) -> Self {
        let idx = ctx.borrow_mut().add_variable(Fr::from(value as u64));
        ctx.borrow_mut().create_bool_gate(idx);
        Self::build(Some(ctx.clone()), idx, value, false)
    }
    /// bb `bool_t(witness, use_range_constraint = true)`: constrained through the `[0, 1]` range
    /// list instead of a bool gate (cheaper in bulk).
    pub fn from_witness_ranged(ctx: &Ctx, value: bool) -> Self {
        let idx = ctx.borrow_mut().add_variable(Fr::from(value as u64));
        ctx.borrow_mut().create_small_range_constraint(idx, 1);
        Self::build(Some(ctx.clone()), idx, value, false)
    }
    pub fn fix_witness(&self) {
        assert!(!self.is_constant());
        let value = Fr::from(self.get_value() as u64);
        self.ctx
            .as_ref()
            .unwrap()
            .borrow_mut()
            .fix_witness(self.witness_index(), value);
    }
    /// bb `field_t::operator bool_t`: reinterpret a field element as a boolean (bool gate on its witness).
    pub fn from_field(f: &FieldT) -> Self {
        if f.is_constant() {
            let v = f.get_value();
            assert!(
                v.is_zero() || v == Fr::one(),
                "bool_t from a constant that is not 0 or 1"
            );
            return Self::constant(v == Fr::one());
        }
        let ctx = f.ctx.clone().unwrap();
        let plain = f.additive_constant.is_zero() && f.multiplicative_constant == Fr::one();
        let inverted = f.additive_constant == Fr::one() && f.multiplicative_constant == -Fr::one();
        let witness_index = if plain || inverted {
            f.witness_index
        } else {
            f.normalize().witness_index
        };
        let witness = ctx.borrow().get_variable(witness_index);
        assert!(
            witness.is_zero() || witness == Fr::one(),
            "bool_t from a witness that is not 0 or 1"
        );
        ctx.borrow_mut().create_bool_gate(witness_index);
        Self::build(Some(ctx), witness_index, witness == Fr::one(), inverted)
    }
    pub fn is_constant(&self) -> bool {
        self.witness_index.get() == IS_CONSTANT
    }
    pub fn get_value(&self) -> bool {
        self.witness_bool.get() ^ self.witness_inverted.get()
    }
    /// bb `field_t(const bool_t&)`: the boolean as a field element (no gate).
    pub fn to_field(&self) -> FieldT {
        if self.is_constant() {
            return FieldT::constant(Fr::from(self.get_value() as u64));
        }
        FieldT {
            ctx: self.ctx.clone(),
            witness_index: self.witness_index.get(),
            additive_constant: Fr::from(self.witness_inverted.get() as u64),
            multiplicative_constant: if self.witness_inverted.get() {
                -Fr::one()
            } else {
                Fr::one()
            },
        }
    }

    fn gate(&self, other: &Self, value: bool, q: [i64; 5]) -> Self {
        let ctx = same_ctx(&self.ctx, &other.ctx).unwrap();
        let idx = ctx.borrow_mut().add_variable(Fr::from(value as u64));
        ctx.borrow_mut().create_arithmetic_gate(ArithmeticTriple {
            a: self.witness_index.get(),
            b: other.witness_index.get(),
            c: idx,
            q_m: fr(q[0]),
            q_l: fr(q[1]),
            q_r: fr(q[2]),
            q_o: fr(q[3]),
            q_c: fr(q[4]),
        });
        Self::build(Some(ctx), idx, value, false)
    }

    pub fn and(&self, other: &Self) -> Self {
        let value = self.get_value() && other.get_value();
        if !self.is_constant() && !other.is_constant() {
            let (a, b) = (self.witness_inverted.get() as i64, other.witness_inverted.get() as i64);
            self.gate(
                other,
                value,
                [
                    1 - 2 * b - 2 * a + 4 * a * b,
                    b * (1 - 2 * a),
                    a * (1 - 2 * b),
                    -1,
                    a * b,
                ],
            )
        } else if !self.is_constant() {
            if other.witness_bool.get() {
                self.clone()
            } else {
                other.clone()
            }
        } else if !other.is_constant() {
            if self.witness_bool.get() {
                other.clone()
            } else {
                self.clone()
            }
        } else {
            Self::constant(value)
        }
    }
    pub fn or(&self, other: &Self) -> Self {
        let value = self.get_value() || other.get_value();
        if !self.is_constant() && !other.is_constant() {
            let (a, b) = (self.witness_inverted.get() as i64, other.witness_inverted.get() as i64);
            self.gate(
                other,
                value,
                [
                    -(1 - 2 * b) * (1 - 2 * a),
                    (1 - 2 * a) * (1 - b),
                    (1 - a) * (1 - 2 * b),
                    -1,
                    b + a - b * a,
                ],
            )
        } else if !self.is_constant() {
            if other.witness_bool.get() {
                other.clone()
            } else {
                self.clone()
            }
        } else if !other.is_constant() {
            if self.witness_bool.get() {
                self.clone()
            } else {
                other.clone()
            }
        } else {
            Self::constant(value)
        }
    }
    pub fn xor(&self, other: &Self) -> Self {
        let value = self.get_value() ^ other.get_value();
        if !self.is_constant() && !other.is_constant() {
            let (a, b) = (self.witness_inverted.get() as i64, other.witness_inverted.get() as i64);
            let p = (1 - 2 * b) * (1 - 2 * a);
            self.gate(other, value, [-2 * p, p, p, -1, a + b - 2 * b * a])
        } else if !self.is_constant() {
            if other.witness_bool.get() {
                self.not()
            } else {
                self.clone()
            }
        } else if !other.is_constant() {
            if self.witness_bool.get() {
                other.not()
            } else {
                other.clone()
            }
        } else {
            Self::constant(value)
        }
    }
    pub fn not(&self) -> Self {
        let r = self.clone();
        if r.is_constant() {
            r.witness_bool.set(!r.witness_bool.get());
        } else {
            r.witness_inverted.set(!r.witness_inverted.get());
        }
        r
    }
    pub fn eq(&self, other: &Self) -> Self {
        let value = self.get_value() == other.get_value();
        if !self.is_constant() && !other.is_constant() {
            let (a, b) = (self.witness_inverted.get() as i64, other.witness_inverted.get() as i64);
            let p = (1 - 2 * b) * (1 - 2 * a);
            self.gate(other, value, [2 * p, -p, -p, -1, 1 - a - b + 2 * b * a])
        } else if !self.is_constant() {
            if other.witness_bool.get() {
                self.clone()
            } else {
                self.not()
            }
        } else if !other.is_constant() {
            if self.witness_bool.get() {
                other.clone()
            } else {
                other.not()
            }
        } else {
            Self::constant(value)
        }
    }
    pub fn assert_equal(&self, rhs: &Self) {
        if self.is_constant() && rhs.is_constant() {
            assert_eq!(
                self.get_value(),
                rhs.get_value(),
                "bool_t::assert_equal: constants differ"
            );
        } else if self.is_constant() {
            let v = self.witness_bool.get() ^ rhs.witness_inverted.get();
            rhs.ctx
                .as_ref()
                .unwrap()
                .borrow_mut()
                .assert_equal_constant(rhs.witness_index.get(), Fr::from(v as u64));
        } else if rhs.is_constant() {
            let v = rhs.witness_bool.get() ^ self.witness_inverted.get();
            self.ctx
                .as_ref()
                .unwrap()
                .borrow_mut()
                .assert_equal_constant(self.witness_index.get(), Fr::from(v as u64));
        } else {
            let ctx = same_ctx(&self.ctx, &rhs.ctx).unwrap();
            let (mut left, mut right) = (self.clone(), rhs.clone());
            if self.witness_inverted.get() ^ rhs.witness_inverted.get() {
                left = left.normalize();
                right = right.normalize();
            }
            ctx.borrow_mut()
                .assert_equal(left.witness_index.get(), right.witness_index.get());
        }
    }
    pub fn conditional_assign(predicate: &Self, lhs: &Self, rhs: &Self) -> Self {
        if predicate.is_constant() {
            return if predicate.get_value() {
                lhs.normalize()
            } else {
                rhs.normalize()
            };
        }
        let same = lhs.witness_index.get() == rhs.witness_index.get();
        let witness_same = same && !lhs.is_constant() && lhs.witness_inverted.get() == rhs.witness_inverted.get();
        let const_same = same && lhs.is_constant() && lhs.witness_bool.get() == rhs.witness_bool.get();
        if witness_same || const_same {
            return lhs.normalize();
        }
        predicate.and(lhs).or(&predicate.not().and(rhs)).normalize()
    }
    /// Resolve a pending inversion into a fresh witness (one arithmetic gate), in place.
    pub fn normalize(&self) -> Self {
        if self.is_constant() || !self.witness_inverted.get() {
            return self.clone();
        }
        let ctx = self.ctx.clone().unwrap();
        let value = self.get_value();
        let (new_witness, zero) = {
            let mut b = ctx.borrow_mut();
            (b.add_variable(Fr::from(value as u64)), b.zero_idx())
        };
        ctx.borrow_mut().create_arithmetic_gate(ArithmeticTriple {
            a: self.witness_index.get(),
            b: zero,
            c: new_witness,
            q_m: Fr::zero(),
            q_l: -Fr::one(),
            q_r: Fr::zero(),
            q_o: -Fr::one(),
            q_c: Fr::one(),
        });
        self.witness_index.set(new_witness);
        self.witness_bool.set(value);
        self.witness_inverted.set(false);
        self.clone()
    }
}
