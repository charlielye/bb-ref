//! Non-native field elements (bb `stdlib/primitives/bigfield`): a value of a foreign prime field
//! held as four 68-bit binary-basis limbs plus its native-field ("prime basis") image, with the
//! maximum possible value of every limb tracked so that reductions happen exactly where bb's do.
//! Every gate-emitting path is a line-by-line port of `bigfield_impl.hpp`.

use super::bool::BoolT;
use super::byte_array::ByteArray;
use super::field::{Ctx, FieldT};
use crate::base::field::{from_u256, u256, FieldLike, U256};
use crate::base::Fr;
use crate::circuit::nnf::{AddSimple, NonNativeMultiplicationWitnesses, DEFAULT_NON_NATIVE_FIELD_LIMB_BITS};
use crate::circuit::BlockId;
use ark_ff::PrimeField;
use num_bigint::BigUint;
use std::cell::RefCell;
use std::marker::PhantomData;

pub const NUM_LIMBS: usize = 4;
pub const NUM_LIMB_BITS: u64 = DEFAULT_NON_NATIVE_FIELD_LIMB_BITS;
pub const MAXIMUM_SUMMAND_COUNT: usize = 16;
const MAX_ADDITION_LOG: u64 = 10;
const MAX_UNREDUCED_LIMB_BITS: u64 = NUM_LIMB_BITS + MAX_ADDITION_LOG;
const PROHIBITED_LIMB_BITS: u64 = MAX_UNREDUCED_LIMB_BITS + 5;

fn big(f: &Fr) -> BigUint {
    f.into_bigint().into()
}
fn fr(b: &BigUint) -> Fr {
    Fr::from(b.clone())
}
fn pow2(bits: u64) -> BigUint {
    BigUint::from(1u64) << bits
}
fn msb(v: &BigUint) -> u64 {
    assert!(*v != BigUint::from(0u64));
    v.bits() - 1
}
/// `value.slice(start, end)` of bb's uint256/512: bits `start..end`.
fn slice(v: &BigUint, start: u64, end: u64) -> BigUint {
    (v >> start) & (pow2(end - start) - 1u64)
}
fn shift_k(k: u64) -> Fr {
    from_u256(U256::from(1u64) << (NUM_LIMB_BITS * k) as u32)
}

#[derive(Clone)]
pub struct Limb {
    pub element: FieldT,
    pub maximum_value: BigUint,
}

impl Limb {
    fn new(element: FieldT, max: BigUint) -> Self {
        let maximum_value = if element.is_constant() {
            let v = big(&element.additive_constant);
            assert!(v <= max, "constant limb above its maximum");
            v
        } else {
            max
        };
        Self { element, maximum_value }
    }
}

#[derive(Clone)]
struct State {
    limbs: [Limb; NUM_LIMBS],
    prime: FieldT,
}

/// A foreign-field element of `N`'s field (bb `bigfield<Builder, T>`).
pub struct BigField<N: PrimeField> {
    ctx: Option<Ctx>,
    // bb mutates a const bigfield in place when it reduces it (`mutable` limbs); clones are copies.
    state: RefCell<State>,
    _n: PhantomData<N>,
}

impl<N: PrimeField> Clone for BigField<N> {
    fn clone(&self) -> Self {
        Self { ctx: self.ctx.clone(), state: RefCell::new(self.state.borrow().clone()), _n: PhantomData }
    }
}

impl<N: PrimeField> BigField<N> {
    // ---- constants of the target field ----

    pub fn modulus() -> BigUint {
        N::MODULUS.into()
    }
    fn native(v: &BigUint) -> N {
        N::from(v.clone())
    }
    fn native_value(n: &N) -> BigUint {
        n.into_bigint().into()
    }
    pub fn num_last_limb_bits() -> u64 {
        msb(&Self::modulus()) + 1 - NUM_LIMB_BITS * 3
    }
    pub fn default_maximum_limb() -> BigUint {
        pow2(NUM_LIMB_BITS) - 1u64
    }
    pub fn default_maximum_most_significant_limb() -> BigUint {
        pow2(Self::num_last_limb_bits()) - 1u64
    }
    fn default_maximum_remainder() -> BigUint {
        pow2(NUM_LIMB_BITS * 3 + Self::num_last_limb_bits()) - 1u64
    }
    fn binary_basis_modulus() -> BigUint {
        pow2(NUM_LIMB_BITS * NUM_LIMBS as u64)
    }
    fn prime_basis_modulus() -> BigUint {
        Fr::MODULUS.into()
    }
    /// `-p mod r`.
    fn negative_prime_modulus_mod_native_basis() -> Fr {
        -fr(&Self::modulus())
    }
    fn neg_modulus_mod_binary_basis_limbs_big() -> [BigUint; NUM_LIMBS] {
        let neg = Self::binary_basis_modulus() - Self::modulus();
        std::array::from_fn(|i| slice(&neg, NUM_LIMB_BITS * i as u64, NUM_LIMB_BITS * (i as u64 + 1)))
    }
    fn neg_modulus_mod_binary_basis_limbs() -> [Fr; NUM_LIMBS] {
        Self::neg_modulus_mod_binary_basis_limbs_big().map(|l| fr(&l))
    }
    fn get_maximum_crt_product() -> BigUint {
        Self::binary_basis_modulus() * Self::prime_basis_modulus()
    }
    fn get_maximum_unreduced_value() -> BigUint {
        let maximum_product_bits = msb(&Self::get_maximum_crt_product()) - 1;
        pow2(maximum_product_bits >> 1) - 1u64
    }
    fn get_prohibited_value() -> BigUint {
        let maximum_product_bits = msb(&Self::get_maximum_crt_product()) - 1;
        pow2((maximum_product_bits >> 1) + 20) - 1u64
    }
    fn get_maximum_unreduced_limb_value() -> BigUint {
        pow2(MAX_UNREDUCED_LIMB_BITS) - 1u64
    }
    fn get_prohibited_limb_value() -> BigUint {
        pow2(PROHIBITED_LIMB_BITS)
    }
    fn get_quotient_max_bits(remainders_max: &[BigUint]) -> usize {
        let mut base = Self::get_maximum_crt_product();
        for r in remainders_max {
            base -= r;
        }
        base /= Self::modulus();
        (msb(&base) - 1) as usize
    }
    fn mul_product_overflows_crt_modulus(as_max: &[BigUint], bs_max: &[BigUint], to_add: &[Self]) -> bool {
        let mut product_sum = BigUint::from(0u64);
        for (a, b) in as_max.iter().zip(bs_max) {
            product_sum += a * b;
        }
        let add_term: BigUint = to_add.iter().map(|a| a.get_maximum_value()).sum();
        product_sum + add_term >= Self::get_maximum_crt_product()
    }

    // ---- state access ----

    fn limb(&self, i: usize) -> Limb {
        self.state.borrow().limbs[i].clone()
    }
    fn limb_element(&self, i: usize) -> FieldT {
        self.state.borrow().limbs[i].element.clone()
    }
    fn limb_max(&self, i: usize) -> BigUint {
        self.state.borrow().limbs[i].maximum_value.clone()
    }
    fn prime_limb(&self) -> FieldT {
        self.state.borrow().prime.clone()
    }
    fn set_limb(&self, i: usize, limb: Limb) {
        self.state.borrow_mut().limbs[i] = limb;
    }
    fn set_prime_limb(&self, p: FieldT) {
        self.state.borrow_mut().prime = p;
    }
    pub fn get_limb(&self, i: usize) -> Limb {
        self.limb(i)
    }
    pub fn get_prime_basis_limb(&self) -> FieldT {
        self.prime_limb()
    }
    pub fn set_limb_max(&self, i: usize, m: BigUint) {
        self.state.borrow_mut().limbs[i].maximum_value = m;
    }
    pub fn ctx(&self) -> Option<Ctx> {
        self.ctx.clone()
    }
    fn limb_maximums(&self) -> [BigUint; NUM_LIMBS] {
        std::array::from_fn(|i| self.limb_max(i))
    }
    fn limb_witness_indices(&self) -> [u32; NUM_LIMBS] {
        std::array::from_fn(|i| self.limb_element(i).get_witness_index())
    }
    pub fn is_constant(&self) -> bool {
        self.prime_limb().is_constant()
    }
    /// The integer the limbs encode (not reduced).
    pub fn get_value(&self) -> BigUint {
        let mut v = BigUint::from(0u64);
        for i in 0..NUM_LIMBS {
            v += big(&self.limb_element(i).get_value()) << (NUM_LIMB_BITS * i as u64);
        }
        v
    }
    pub fn get_maximum_value(&self) -> BigUint {
        let mut v = BigUint::from(0u64);
        for i in 0..NUM_LIMBS {
            v += self.limb_max(i) << (NUM_LIMB_BITS * i as u64);
        }
        v
    }
    /// The value reduced into the target field.
    pub fn get_native_value(&self) -> N {
        Self::native(&(self.get_value() % Self::modulus()))
    }

    // ---- constructors ----

    fn from_state(ctx: Option<Ctx>, limbs: [Limb; NUM_LIMBS], prime: FieldT) -> Self {
        Self { ctx, state: RefCell::new(State { limbs, prime }), _n: PhantomData }
    }
    /// A constant (bb `bigfield(ctx, uint256_t)`).
    pub fn constant(ctx: Option<Ctx>, value: &BigUint) -> Self {
        assert!(*value < Self::modulus(), "bigfield constant not reduced");
        let limbs = std::array::from_fn(|i| {
            let l = slice(value, NUM_LIMB_BITS * i as u64, NUM_LIMB_BITS * (i as u64 + 1));
            Limb::new(FieldT::constant(fr(&l)), Self::default_maximum_limb())
        });
        Self::from_state(ctx, limbs, FieldT::constant(fr(value)))
    }
    pub fn from_u64(v: u64) -> Self {
        Self::constant(None, &BigUint::from(v))
    }
    pub fn from_native(v: &N) -> Self {
        Self::constant(None, &Self::native_value(v))
    }
    pub fn zero() -> Self {
        Self::from_u64(0)
    }
    pub fn one() -> Self {
        Self::from_u64(1)
    }
    fn zero_with_ctx(ctx: Option<Ctx>) -> Self {
        Self::constant(ctx, &BigUint::from(0u64))
    }
    /// bb `unreduced_zero`: a multiple of the modulus above the reduction bound, as a constant.
    pub fn unreduced_zero() -> Self {
        let multiple = (Self::get_maximum_unreduced_value() / Self::modulus() + 1u64) * Self::modulus();
        let m = msb(&multiple);
        let l = |a: u64, b: u64| Limb::new(FieldT::constant(fr(&slice(&multiple, a, b))), Self::default_maximum_limb());
        let limbs = [
            l(0, NUM_LIMB_BITS),
            l(NUM_LIMB_BITS, 2 * NUM_LIMB_BITS),
            l(2 * NUM_LIMB_BITS, 3 * NUM_LIMB_BITS),
            Limb::new(FieldT::constant(fr(&slice(&multiple, 3 * NUM_LIMB_BITS, m + 1))), Self::default_maximum_limb()),
        ];
        Self::from_state(None, limbs, FieldT::constant(fr(&(multiple % Self::prime_basis_modulus()))))
    }

    /// bb `bigfield(low_bits, high_bits, can_overflow, maximum_bitlength)`: from two 136-bit halves.
    pub fn from_halves(low_bits: &FieldT, high_bits: &FieldT, can_overflow: bool, maximum_bitlength: u64) -> Self {
        assert_eq!(low_bits.is_constant(), high_bits.is_constant());
        let ctx = low_bits.ctx.clone().or_else(|| high_bits.ctx.clone());
        let (limb_0, limb_1) = if !low_bits.is_constant() {
            let w = Self::decompose_non_native_field_double_width_limb(ctx.as_ref().unwrap(), low_bits.get_witness_index(), 2 * NUM_LIMB_BITS);
            (FieldT::from_witness_index(ctx.as_ref().unwrap(), w[0]), FieldT::from_witness_index(ctx.as_ref().unwrap(), w[1]))
        } else {
            let v = big(&low_bits.additive_constant);
            (FieldT::constant(fr(&slice(&v, 0, NUM_LIMB_BITS))), FieldT::constant(fr(&slice(&v, NUM_LIMB_BITS, 2 * NUM_LIMB_BITS))))
        };
        let mut num_last_limb_bits = if can_overflow { NUM_LIMB_BITS } else { Self::num_last_limb_bits() };
        if maximum_bitlength > 0 {
            assert!(maximum_bitlength > 3 * NUM_LIMB_BITS && maximum_bitlength <= 4 * NUM_LIMB_BITS);
            num_last_limb_bits = maximum_bitlength - 3 * NUM_LIMB_BITS;
        }
        let num_high_limb_bits = NUM_LIMB_BITS + num_last_limb_bits;
        let (limb_2, limb_3) = if !high_bits.is_constant() {
            let w = Self::decompose_non_native_field_double_width_limb(ctx.as_ref().unwrap(), high_bits.get_witness_index(), num_high_limb_bits);
            (FieldT::from_witness_index(ctx.as_ref().unwrap(), w[0]), FieldT::from_witness_index(ctx.as_ref().unwrap(), w[1]))
        } else {
            let v = big(&high_bits.additive_constant);
            (FieldT::constant(fr(&slice(&v, 0, NUM_LIMB_BITS))), FieldT::constant(fr(&slice(&v, NUM_LIMB_BITS, num_high_limb_bits))))
        };
        let limb_3_max = if maximum_bitlength > 0 {
            pow2(maximum_bitlength - 3 * NUM_LIMB_BITS) - 1u64
        } else if can_overflow {
            Self::default_maximum_limb()
        } else {
            Self::default_maximum_most_significant_limb()
        };
        let limbs = [
            Limb::new(limb_0, Self::default_maximum_limb()),
            Limb::new(limb_1, Self::default_maximum_limb()),
            Limb::new(limb_2, Self::default_maximum_limb()),
            Limb::new(limb_3, limb_3_max),
        ];
        let prime = low_bits.add(&high_bits.mul(&FieldT::constant(shift_k(2))));
        Self::from_state(ctx, limbs, prime)
    }

    /// bb `bigfield(const byte_array&)`: 32 big-endian bytes as a 256-bit integer; the two bytes
    /// straddling limb boundaries are split into range-checked nibbles.
    pub fn from_bytes(bytes: &ByteArray) -> Self {
        assert_eq!(bytes.len(), 32);
        let ctx = bytes.ctx().expect("byte array without a builder");
        let split_byte_into_nibbles = |split_byte: &FieldT| {
            let byte_val = u256(&split_byte.get_value()).0[0];
            let lo_nibble = FieldT::from_witness(&ctx, Fr::from(byte_val & 15));
            let hi_nibble = FieldT::from_witness(&ctx, Fr::from(byte_val >> 4));
            lo_nibble.create_range_constraint(4);
            hi_nibble.create_range_constraint(4);
            let sum = lo_nibble.add(&hi_nibble.mul(&FieldT::constant(Fr::from(16u64))));
            sum.assert_equal(split_byte);
            (lo_nibble, hi_nibble)
        };
        let reconstruct_two_limbs = |hi_bytes: &FieldT, lo_bytes: &FieldT, split_byte: &FieldT| {
            let (lo_nibble, hi_nibble) = split_byte_into_nibbles(split_byte);
            let hi_limb = hi_nibble.add(&hi_bytes.mul(&FieldT::constant(Fr::from(16u64))));
            let lo_limb = lo_bytes.add(&lo_nibble.mul(&FieldT::constant(from_u256(U256::from(1u64) << 64))));
            (lo_limb, hi_limb)
        };
        let hi_8_bytes = bytes.slice(0, 6).to_field();
        let mid_split_byte = bytes.slice(6, 1).to_field();
        let mid_8_bytes = bytes.slice(7, 8).to_field();
        let lo_8_bytes = bytes.slice(15, 8).to_field();
        let lo_split_byte = bytes.slice(23, 1).to_field();
        let lolo_8_bytes = bytes.slice(24, 8).to_field();
        let (limb0, limb1) = reconstruct_two_limbs(&lo_8_bytes, &lolo_8_bytes, &lo_split_byte);
        let (limb2, limb3) = reconstruct_two_limbs(&hi_8_bytes, &mid_8_bytes, &mid_split_byte);
        let res = Self::unsafe_construct_from_limbs(&limb0, &limb1, &limb2, &limb3, true);
        res.set_limb_max(3, pow2(256 - NUM_LIMB_BITS * 3) - 1u64);
        res
    }

    /// bb `unsafe_construct_from_limbs` (4 limbs): the prime limb is recomputed, nothing is range-checked.
    pub fn unsafe_construct_from_limbs(a: &FieldT, b: &FieldT, c: &FieldT, d: &FieldT, can_overflow: bool) -> Self {
        assert!(a.is_constant() == b.is_constant() && b.is_constant() == c.is_constant() && c.is_constant() == d.is_constant());
        let ctx = a.ctx.clone();
        let limbs = [
            Limb::new(a.clone(), Self::default_maximum_limb()),
            Limb::new(b.clone(), Self::default_maximum_limb()),
            Limb::new(c.clone(), Self::default_maximum_limb()),
            Limb::new(d.clone(), if can_overflow { Self::default_maximum_limb() } else { Self::default_maximum_most_significant_limb() }),
        ];
        let mut prime = d.mul(&FieldT::constant(shift_k(3))).add_two(&c.mul(&FieldT::constant(shift_k(2))), &b.mul(&FieldT::constant(shift_k(1))));
        prime += a;
        Self::from_state(ctx, limbs, prime)
    }

    /// bb `unsafe_construct_from_limbs` with an explicit prime limb.
    pub fn unsafe_construct_from_limbs_with_prime(a: &FieldT, b: &FieldT, c: &FieldT, d: &FieldT, prime: &FieldT, can_overflow: bool) -> Self {
        let limbs = [
            Limb::new(a.clone(), Self::default_maximum_limb()),
            Limb::new(b.clone(), Self::default_maximum_limb()),
            Limb::new(c.clone(), Self::default_maximum_limb()),
            Limb::new(d.clone(), if can_overflow { Self::default_maximum_limb() } else { Self::default_maximum_most_significant_limb() }),
        ];
        Self::from_state(a.ctx.clone(), limbs, prime.clone())
    }

    /// bb `create_from_u512_as_witness`: fresh limb witnesses tied by one big-add gate, range-checked.
    pub fn create_from_u512_as_witness(ctx: &Ctx, value: &BigUint, can_overflow: bool, maximum_bitlength: u64) -> Self {
        assert!((can_overflow && maximum_bitlength == 0) || (!can_overflow && (maximum_bitlength == 0 || maximum_bitlength > 3 * NUM_LIMB_BITS)));
        let limbs: [BigUint; 4] = std::array::from_fn(|i| slice(value, NUM_LIMB_BITS * i as u64, NUM_LIMB_BITS * (i as u64 + 1)));
        let (w0, w1, w2, w3, wp) = {
            let mut b = ctx.borrow_mut();
            let w0 = b.add_variable(fr(&limbs[0]));
            let w1 = b.add_variable(fr(&limbs[1]));
            let w2 = b.add_variable(fr(&limbs[2]));
            let w3 = b.add_variable(fr(&limbs[3]));
            let wp = b.add_variable(fr(&limbs[0]) + fr(&limbs[1]) * shift_k(1) + fr(&limbs[2]) * shift_k(2) + fr(&limbs[3]) * shift_k(3));
            let zero = b.zero_idx();
            b.create_big_add_gate(
                crate::circuit::builder::AddQuad {
                    a: w1,
                    b: w2,
                    c: w3,
                    d: wp,
                    a_scaling: shift_k(1),
                    b_scaling: shift_k(2),
                    c_scaling: shift_k(3),
                    d_scaling: -Fr::one(),
                    const_scaling: Fr::zero(),
                },
                true,
            );
            b.create_unconstrained_gate(BlockId::Arithmetic, [zero, zero, zero, w0]);
            (w0, w1, w2, w3, wp)
        };
        let mut num_last_limb_bits = if can_overflow { NUM_LIMB_BITS } else { Self::num_last_limb_bits() };
        let el = |w| FieldT::from_witness_index(ctx, w);
        let mut limb_3 = Limb::new(el(w3), if can_overflow { Self::default_maximum_limb() } else { Self::default_maximum_most_significant_limb() });
        if maximum_bitlength > 0 {
            num_last_limb_bits = maximum_bitlength - 3 * NUM_LIMB_BITS;
            limb_3.maximum_value = pow2(num_last_limb_bits) - 1u64;
        }
        let result = Self::from_state(
            Some(ctx.clone()),
            [
                Limb::new(el(w0), Self::default_maximum_limb()),
                Limb::new(el(w1), Self::default_maximum_limb()),
                Limb::new(el(w2), Self::default_maximum_limb()),
                limb_3,
            ],
            el(wp),
        );
        let mut b = ctx.borrow_mut();
        b.range_constrain_two_limbs(w0, w1, NUM_LIMB_BITS as usize, NUM_LIMB_BITS as usize);
        b.range_constrain_two_limbs(w2, w3, NUM_LIMB_BITS as usize, num_last_limb_bits as usize);
        result
    }

    /// bb `from_witness`: a witness element from its native value (two 136-bit halves).
    pub fn from_witness(ctx: &Ctx, input: &N) -> Self {
        let v = Self::native_value(input);
        let low = FieldT::from_witness(ctx, fr(&slice(&v, 0, NUM_LIMB_BITS * 2)));
        let hi = FieldT::from_witness(ctx, fr(&slice(&v, NUM_LIMB_BITS * 2, NUM_LIMB_BITS * 4)));
        Self::from_halves(&low, &hi, false, 0)
    }

    /// bb `decompose_non_native_field_double_width_limb`: split a `num_limb_bits`-bit witness into
    /// a 68-bit low limb and the rest, range-checked and tied by a linear identity.
    fn decompose_non_native_field_double_width_limb(ctx: &Ctx, limb_idx: u32, num_limb_bits: u64) -> [u32; 2] {
        let value = big(&ctx.borrow().get_variable(limb_idx));
        assert!(value < pow2(num_limb_bits));
        let low = &value & (pow2(NUM_LIMB_BITS) - 1u64);
        let hi = &value >> NUM_LIMB_BITS;
        let (low_idx, hi_idx) = {
            let mut b = ctx.borrow_mut();
            let low_idx = b.add_variable(fr(&low));
            let hi_idx = b.add_variable(fr(&hi));
            b.range_constrain_two_limbs(low_idx, hi_idx, NUM_LIMB_BITS as usize, (num_limb_bits - NUM_LIMB_BITS) as usize);
            (low_idx, hi_idx)
        };
        let original = FieldT::from_witness_index(ctx, limb_idx);
        let lo_field = FieldT::from_witness_index(ctx, low_idx);
        let hi_field = FieldT::from_witness_index(ctx, hi_idx);
        FieldT::evaluate_linear_identity(&original, &lo_field.neg(), &hi_field.neg().mul(&FieldT::constant(shift_k(1))), &FieldT::constant(Fr::zero()));
        [low_idx, hi_idx]
    }

    fn ctx_of(&self, other: &Self) -> Option<Ctx> {
        self.ctx.clone().or_else(|| other.ctx.clone())
    }

    pub fn convert_constant_to_fixed_witness(&mut self, ctx: &Ctx) {
        self.ctx = Some(ctx.clone());
        let mut s = self.state.borrow_mut();
        for limb in s.limbs.iter_mut() {
            limb.element.convert_constant_to_fixed_witness(ctx);
        }
        s.prime.convert_constant_to_fixed_witness(ctx);
    }
    pub fn fix_witness(&self) {
        let s = self.state.borrow();
        for limb in &s.limbs {
            limb.element.fix_witness();
        }
        s.prime.fix_witness();
    }

    // ---- reductions ----

    /// bb `reduction_check`: reduce constants, and witnesses whose bounds exceed the unreduced limits.
    fn reduction_check(&self) {
        if self.is_constant() {
            let reduced = Self::constant(self.ctx.clone(), &(self.get_value() % Self::modulus()));
            *self.state.borrow_mut() = reduced.state.into_inner();
            return;
        }
        let max_limb = Self::get_maximum_unreduced_limb_value();
        let limb_overflow = (0..NUM_LIMBS).any(|i| self.limb_max(i) > max_limb);
        if self.get_maximum_value() > Self::get_maximum_unreduced_value() || limb_overflow {
            self.self_reduce();
        }
    }
    fn sanity_check(&self) {
        let prohibited = Self::get_prohibited_limb_value();
        let overflow = (0..NUM_LIMBS).any(|i| self.limb_max(i) > prohibited);
        assert!(!(self.get_maximum_value() > Self::get_prohibited_value() || overflow), "bigfield sanity check");
    }

    /// bb `self_reduce`: replace the limbs by `value mod p` (a fresh witness) with one multiply-add.
    pub fn self_reduce(&self) {
        if self.is_constant() {
            return;
        }
        let ctx = self.ctx.clone().unwrap();
        let value = self.get_value();
        let modulus = Self::modulus();
        let (quotient_value, remainder_value) = (&value / &modulus, &value % &modulus);
        let maximum_quotient_size = self.get_maximum_value() / &modulus;
        let mut maximum_quotient_bits = if maximum_quotient_size == BigUint::from(0u64) { 1 } else { msb(&maximum_quotient_size) + 1 };
        if maximum_quotient_bits & 1 == 1 {
            maximum_quotient_bits += 1;
        }
        assert!(maximum_quotient_bits <= NUM_LIMB_BITS);
        let quotient_limb_index = ctx.borrow_mut().add_variable(fr(&quotient_value));
        let quotient_limb = FieldT::from_witness_index(&ctx, quotient_limb_index);
        ctx.borrow_mut().create_limbed_range_constraint(quotient_limb_index, maximum_quotient_bits, crate::circuit::builder::DEFAULT_PLOOKUP_RANGE_BITNUM);
        let zero_idx = ctx.borrow().zero_idx();
        let zero_limb = || Limb { element: FieldT::from_witness_index(&ctx, zero_idx), maximum_value: BigUint::from(0u64) };
        let quotient = Self::from_state(
            Some(ctx.clone()),
            [Limb { element: quotient_limb.clone(), maximum_value: pow2(maximum_quotient_bits) - 1u64 }, zero_limb(), zero_limb(), zero_limb()],
            quotient_limb,
        );
        let remainder = Self::from_halves(
            &FieldT::from_witness(&ctx, fr(&slice(&remainder_value, 0, NUM_LIMB_BITS * 2))),
            &FieldT::from_witness(&ctx, fr(&slice(&remainder_value, NUM_LIMB_BITS * 2, NUM_LIMB_BITS * 3 + Self::num_last_limb_bits()))),
            false,
            0,
        );
        Self::unsafe_evaluate_multiply_add(self, &Self::one(), &[], &quotient, &[remainder.clone()]);
        *self.state.borrow_mut() = remainder.state.into_inner();
    }

    // ---- arithmetic ----

    /// bb `add_to_lower_limb`: add a small native-field term to limb 0 (and the prime limb).
    pub fn add_to_lower_limb(&self, other: &FieldT, other_maximum_value: &BigUint) -> Self {
        self.reduction_check();
        assert!(other_maximum_value + self.limb_max(0) <= Self::get_maximum_unreduced_limb_value());
        let ctx = self.ctx.clone().or_else(|| other.ctx.clone());
        if self.is_constant() && other.is_constant() {
            return Self::constant(ctx, &((self.get_value() + big(&other.get_value())) % Self::modulus()));
        }
        let result = if self.is_constant() {
            let context = other.ctx.clone().unwrap();
            let r = self.clone();
            for i in 1..NUM_LIMBS {
                let el = FieldT::from_witness(&context, self.limb_element(i).get_value());
                el.fix_witness();
                r.set_limb(i, Limb { element: el, maximum_value: self.limb_max(i) });
            }
            Self { ctx: ctx.clone(), state: r.state, _n: PhantomData }
        } else {
            self.clone()
        };
        let l0 = Limb { element: self.limb_element(0).add(other), maximum_value: self.limb_max(0) + other_maximum_value };
        result.set_limb(0, l0);
        result.set_prime_limb(self.prime_limb().add(other));
        result
    }

    fn witness_indices_match(a: &FieldT, b: &FieldT) -> bool {
        !a.is_constant() && !b.is_constant() && a.witness_index == b.witness_index
    }

    pub fn add(&self, other: &Self) -> Self {
        self.reduction_check();
        other.reduction_check();
        let ctx = self.ctx_of(other);
        if self.is_constant() && other.is_constant() {
            return Self::constant(ctx, &((self.get_value() + other.get_value()) % Self::modulus()));
        }
        let result = Self::zero_with_ctx(ctx.clone());
        for i in 0..NUM_LIMBS {
            result.set_limb_max(i, self.limb_max(i) + other.limb_max(i));
        }
        let both_witness = !self.is_constant() && !other.is_constant();
        let both_mul_one = self.prime_limb().multiplicative_constant == Fr::one() && other.prime_limb().multiplicative_constant == Fr::one();
        if both_mul_one && both_witness && !Self::witness_indices_match(&self.prime_limb(), &other.prime_limb()) {
            let ctx = ctx.unwrap();
            let limbs: [AddSimple; 4] = std::array::from_fn(|i| {
                let (x, y) = (self.limb_element(i), other.limb_element(i));
                ((x.witness_index, x.multiplicative_constant), (y.witness_index, y.multiplicative_constant), x.additive_constant + y.additive_constant)
            });
            let (xp, yp) = (self.prime_limb(), other.prime_limb());
            let out = ctx.borrow_mut().evaluate_non_native_field_addition(limbs, (xp.witness_index, yp.witness_index, xp.additive_constant + yp.additive_constant));
            for i in 0..NUM_LIMBS {
                result.state.borrow_mut().limbs[i].element = FieldT::from_witness_index(&ctx, out[i]);
            }
            result.set_prime_limb(FieldT::from_witness_index(&ctx, out[4]));
            return result;
        }
        for i in 0..NUM_LIMBS {
            result.state.borrow_mut().limbs[i].element = self.limb_element(i).add(&other.limb_element(i));
        }
        result.set_prime_limb(self.prime_limb().add(&other.prime_limb()));
        result
    }

    pub fn add_two(&self, add_a: &Self, add_b: &Self) -> Self {
        self.reduction_check();
        add_a.reduction_check();
        add_b.reduction_check();
        let ctx = self.ctx.clone().or_else(|| add_a.ctx.clone()).or_else(|| add_b.ctx.clone());
        if self.is_constant() && add_a.is_constant() && add_b.is_constant() {
            return Self::constant(ctx, &((self.get_value() + add_a.get_value() + add_b.get_value()) % Self::modulus()));
        }
        let result = Self::zero_with_ctx(ctx);
        for i in 0..NUM_LIMBS {
            let mut s = result.state.borrow_mut();
            s.limbs[i].maximum_value = self.limb_max(i) + add_a.limb_max(i) + add_b.limb_max(i);
            s.limbs[i].element = self.limb_element(i).add_two(&add_a.limb_element(i), &add_b.limb_element(i));
        }
        result.set_prime_limb(self.prime_limb().add_two(&add_a.prime_limb(), &add_b.prime_limb()));
        result
    }

    pub fn sub(&self, other: &Self) -> Self {
        let ctx = self.ctx_of(other);
        self.reduction_check();
        other.reduction_check();
        let modulus = Self::modulus();
        if self.is_constant() && other.is_constant() {
            let left = self.get_value() % &modulus;
            let right = other.get_value() % &modulus;
            return Self::constant(ctx, &((left + &modulus - right) % &modulus));
        }
        if other.is_constant() {
            let right = other.get_value() % &modulus;
            let neg_right = (&modulus - right) % &modulus;
            return self.add(&Self::constant(ctx, &neg_right));
        }
        let result = Self::zero_with_ctx(ctx.clone());
        let limb_0_maximum_value = other.limb_max(0);
        let limb_0_borrow_shift = (msb(&limb_0_maximum_value) + 1).max(NUM_LIMB_BITS);
        let limb_1_maximum_value = other.limb_max(1) + pow2(limb_0_borrow_shift - NUM_LIMB_BITS);
        let limb_1_borrow_shift = (msb(&limb_1_maximum_value) + 1).max(NUM_LIMB_BITS);
        let limb_2_maximum_value = other.limb_max(2) + pow2(limb_1_borrow_shift - NUM_LIMB_BITS);
        let limb_2_borrow_shift = (msb(&limb_2_maximum_value) + 1).max(NUM_LIMB_BITS);
        let limb_3_maximum_value = other.limb_max(3) + pow2(limb_2_borrow_shift - NUM_LIMB_BITS);
        let constant_to_add_factor = (limb_3_maximum_value << (NUM_LIMB_BITS * 3)) / &modulus + 1u64;
        let constant_to_add = constant_to_add_factor * &modulus;
        let t0 = pow2(limb_0_borrow_shift);
        let t1 = pow2(limb_1_borrow_shift) - pow2(limb_0_borrow_shift - NUM_LIMB_BITS);
        let t2 = pow2(limb_2_borrow_shift) - pow2(limb_1_borrow_shift - NUM_LIMB_BITS);
        let t3 = pow2(limb_2_borrow_shift - NUM_LIMB_BITS);
        let to_add = [
            slice(&constant_to_add, 0, NUM_LIMB_BITS) + t0,
            slice(&constant_to_add, NUM_LIMB_BITS, NUM_LIMB_BITS * 2) + t1,
            slice(&constant_to_add, NUM_LIMB_BITS * 2, NUM_LIMB_BITS * 3) + t2,
            slice(&constant_to_add, NUM_LIMB_BITS * 3, NUM_LIMB_BITS * 4) - t3,
        ];
        for i in 0..NUM_LIMBS {
            let mut s = result.state.borrow_mut();
            s.limbs[i].maximum_value = self.limb_max(i) + &to_add[i];
            s.limbs[i].element = self.limb_element(i).add(&FieldT::constant(fr(&to_add[i])));
        }
        let both_witness = !self.is_constant() && !other.is_constant();
        let both_mul_one = self.prime_limb().multiplicative_constant == Fr::one() && other.prime_limb().multiplicative_constant == Fr::one();
        let constant_to_add_mod_native = &constant_to_add % Self::prime_basis_modulus();
        if both_mul_one && both_witness && !Self::witness_indices_match(&self.prime_limb(), &other.prime_limb()) {
            let ctx = ctx.unwrap();
            let limbs: [AddSimple; 4] = std::array::from_fn(|i| {
                let (x, y) = (result.limb_element(i), other.limb_element(i));
                ((x.witness_index, x.multiplicative_constant), (y.witness_index, y.multiplicative_constant), x.additive_constant - y.additive_constant)
            });
            let (xp, yp) = (self.prime_limb(), other.prime_limb());
            let c_prime = xp.additive_constant - yp.additive_constant + fr(&constant_to_add_mod_native);
            let out = ctx.borrow_mut().evaluate_non_native_field_subtraction(limbs, (xp.witness_index, yp.witness_index, c_prime));
            for i in 0..NUM_LIMBS {
                result.state.borrow_mut().limbs[i].element = FieldT::from_witness_index(&ctx, out[i]);
            }
            result.set_prime_limb(FieldT::from_witness_index(&ctx, out[4]));
            return result;
        }
        for i in 0..NUM_LIMBS {
            let e = result.limb_element(i).sub(&other.limb_element(i));
            result.state.borrow_mut().limbs[i].element = e;
        }
        let prime = self.prime_limb().add(&FieldT::constant(fr(&constant_to_add_mod_native))).sub(&other.prime_limb());
        result.set_prime_limb(prime);
        result
    }

    pub fn neg(&self) -> Self {
        Self::zero_with_ctx(self.ctx.clone()).sub(self)
    }

    fn compute_quotient_remainder_values(a: &Self, b: &Self, to_add: &[Self]) -> (BigUint, BigUint) {
        let mut add_values = BigUint::from(0u64);
        for add in to_add {
            add.reduction_check();
            add_values += add.get_value();
        }
        let modulus = Self::modulus();
        let v = a.get_value() * b.get_value() + add_values;
        (&v / &modulus, &v % &modulus)
    }
    fn compute_maximum_quotient_value(as_max: &[BigUint], bs_max: &[BigUint], to_add: &[BigUint]) -> BigUint {
        let add_values: BigUint = to_add.iter().sum();
        let mut product_sum = BigUint::from(0u64);
        for (a, b) in as_max.iter().zip(bs_max) {
            product_sum += a * b;
        }
        (product_sum + add_values) / Self::modulus()
    }
    /// `(reduction required, quotient bits)` for a product with these bounds (bb `get_quotient_reduction_info`).
    fn get_quotient_reduction_info(as_max: &[BigUint], bs_max: &[BigUint], to_add: &[Self], remainders_max: &[BigUint]) -> (bool, u64) {
        if Self::mul_product_overflows_crt_modulus(as_max, bs_max, to_add) {
            return (true, 0);
        }
        let num_quotient_bits = Self::get_quotient_max_bits(remainders_max) as u64;
        let to_add_max: Vec<BigUint> = to_add.iter().map(|a| a.get_maximum_value()).collect();
        let maximum_quotient = Self::compute_maximum_quotient_value(as_max, bs_max, &to_add_max);
        if maximum_quotient >= pow2(num_quotient_bits) {
            return (true, 0);
        }
        (false, num_quotient_bits)
    }
    fn compute_partial_schoolbook_multiplication(a: &[BigUint; 4], b: &[BigUint; 4]) -> (BigUint, BigUint) {
        let r0 = &a[0] * &b[0];
        let r1 = &a[1] * &b[0] + &a[0] * &b[1];
        let r2 = &a[1] * &b[1] + &a[2] * &b[0] + &a[0] * &b[2];
        let r3 = &a[3] * &b[0] + &a[2] * &b[1] + &a[1] * &b[2] + &a[0] * &b[3];
        (r0 + (r1 << NUM_LIMB_BITS), r2 + (r3 << NUM_LIMB_BITS))
    }

    pub fn mul(&self, other: &Self) -> Self {
        self.reduction_check();
        other.reduction_check();
        let ctx = self.ctx_of(other);
        let (quotient_value, remainder_value) = Self::compute_quotient_remainder_values(self, other, &[]);
        if self.is_constant() && other.is_constant() {
            return Self::constant(ctx, &remainder_value);
        }
        let (reduction_required, num_quotient_bits) =
            Self::get_quotient_reduction_info(&[self.get_maximum_value()], &[other.get_maximum_value()], &[], &[Self::default_maximum_remainder()]);
        if reduction_required {
            if self.get_maximum_value() > other.get_maximum_value() {
                self.self_reduce();
            } else {
                other.self_reduce();
            }
            return self.mul(other);
        }
        let ctx = ctx.unwrap();
        let quotient = Self::create_from_u512_as_witness(&ctx, &quotient_value, false, num_quotient_bits);
        let remainder = Self::create_from_u512_as_witness(&ctx, &remainder_value, false, 0);
        Self::unsafe_evaluate_multiply_add(self, other, &[], &quotient, &[remainder.clone()]);
        remainder
    }

    pub fn div(&self, other: &Self) -> Self {
        Self::internal_div(&[self.clone()], other, true)
    }
    pub fn div_without_denominator_check(&self, denominator: &Self) -> Self {
        Self::internal_div(&[self.clone()], denominator, false)
    }
    pub fn div_check_denominator_nonzero(numerators: &[Self], denominator: &Self) -> Self {
        Self::internal_div(numerators, denominator, true)
    }
    /// bb static `div_without_denominator_check(numerators, denominator)`.
    pub fn div_check_denominator_nonzero_off(numerators: &[Self], denominator: &Self) -> Self {
        Self::internal_div(numerators, denominator, false)
    }
    pub fn invert(&self) -> Self {
        Self::one().div(self)
    }

    fn internal_div(numerators: &[Self], denominator: &Self, check_for_zero: bool) -> Self {
        assert!(numerators.len() < MAXIMUM_SUMMAND_COUNT);
        if numerators.is_empty() {
            if check_for_zero {
                denominator.assert_is_not_equal(&Self::zero());
            }
            return Self::zero_with_ctx(denominator.ctx.clone());
        }
        denominator.reduction_check();
        let mut ctx = denominator.ctx.clone();
        let mut numerator_values = BigUint::from(0u64);
        let mut numerator_constant = true;
        for n in numerators {
            if ctx.is_none() {
                ctx = n.ctx.clone();
            }
            n.reduction_check();
            numerator_values += n.get_value();
            numerator_constant = numerator_constant && n.is_constant();
        }
        let modulus = Self::modulus();
        let left = numerator_values;
        let right = denominator.get_value();
        let mut inverse_value = BigUint::from(0u64);
        let denominator_reduced = &right % &modulus;
        if denominator_reduced != BigUint::from(0u64) {
            let numerator_native = Self::native(&(&left % &modulus));
            let inv = numerator_native * Self::native(&denominator_reduced).inverse().unwrap();
            inverse_value = Self::native_value(&inv);
        }
        let quotient_value = (&inverse_value * &right + Self::unreduced_zero().get_value() - &left) / &modulus;
        if numerator_constant && denominator.is_constant() {
            if check_for_zero {
                assert!(denominator.get_value() != BigUint::from(0u64), "bigfield: division by zero");
            }
            return Self::constant(ctx, &inverse_value);
        }
        let numerator_max: Vec<BigUint> = numerators.iter().map(|n| n.get_maximum_value()).collect();
        let (reduction_required, num_quotient_bits) = Self::get_quotient_reduction_info(
            &[Self::default_maximum_remainder()],
            &[denominator.get_maximum_value()],
            &[Self::unreduced_zero()],
            &numerator_max,
        );
        if reduction_required {
            denominator.self_reduce();
            return Self::internal_div(numerators, denominator, check_for_zero);
        }
        if check_for_zero {
            denominator.assert_is_not_equal(&Self::zero());
        }
        let ctx = ctx.unwrap();
        let quotient = Self::create_from_u512_as_witness(&ctx, &quotient_value, false, num_quotient_bits);
        let inverse = Self::create_from_u512_as_witness(&ctx, &inverse_value, false, 0);
        Self::unsafe_evaluate_multiply_add(denominator, &inverse, &[Self::unreduced_zero()], &quotient, numerators);
        inverse
    }

    pub fn sqr(&self) -> Self {
        self.reduction_check();
        let (quotient_value, remainder_value) = Self::compute_quotient_remainder_values(self, self, &[]);
        if self.is_constant() {
            return Self::constant(self.ctx.clone(), &remainder_value);
        }
        let (reduction_required, num_quotient_bits) =
            Self::get_quotient_reduction_info(&[self.get_maximum_value()], &[self.get_maximum_value()], &[], &[Self::default_maximum_remainder()]);
        if reduction_required {
            self.self_reduce();
            return self.sqr();
        }
        let ctx = self.ctx.clone().unwrap();
        let quotient = Self::create_from_u512_as_witness(&ctx, &quotient_value, false, num_quotient_bits);
        let remainder = Self::create_from_u512_as_witness(&ctx, &remainder_value, false, 0);
        Self::unsafe_evaluate_multiply_add(self, self, &[], &quotient, &[remainder.clone()]);
        remainder
    }

    pub fn sqradd(&self, to_add: &[Self]) -> Self {
        assert!(to_add.len() <= MAXIMUM_SUMMAND_COUNT);
        self.reduction_check();
        let ctx = self.ctx.clone();
        let mut add_values = BigUint::from(0u64);
        let mut add_constant = true;
        for a in to_add {
            a.reduction_check();
            add_values += a.get_value();
            add_constant = add_constant && a.is_constant();
        }
        let modulus = Self::modulus();
        let (left, right) = (self.get_value(), self.get_value());
        if self.is_constant() {
            if add_constant {
                return Self::constant(ctx, &((&left * &right + &add_values) % &modulus));
            }
            let mut new_to_add: Vec<Self> = to_add.to_vec();
            new_to_add.push(Self::constant(ctx, &((&left * &right) % &modulus)));
            return Self::sum(&new_to_add);
        }
        let (reduction_required, num_quotient_bits) =
            Self::get_quotient_reduction_info(&[self.get_maximum_value()], &[self.get_maximum_value()], to_add, &[Self::default_maximum_remainder()]);
        if reduction_required {
            self.self_reduce();
            return self.sqradd(to_add);
        }
        let v = &left * &right + &add_values;
        let ctx = ctx.unwrap();
        let quotient = Self::create_from_u512_as_witness(&ctx, &(&v / &modulus), false, num_quotient_bits);
        let remainder = Self::create_from_u512_as_witness(&ctx, &(&v % &modulus), false, 0);
        Self::unsafe_evaluate_multiply_add(self, self, to_add, &quotient, &[remainder.clone()]);
        remainder
    }

    pub fn pow(&self, exponent: u32) -> Self {
        if exponent == 0 {
            return Self::one();
        }
        if self.is_constant() {
            let modulus = Self::modulus();
            let mut result_val = BigUint::from(1u64);
            let mut base = self.get_value() % &modulus;
            let mut e = exponent;
            while e > 0 {
                if e & 1 == 1 {
                    result_val = &result_val * &base % &modulus;
                }
                base = &base * &base % &modulus;
                e >>= 1;
            }
            return Self::constant(self.ctx.clone(), &result_val);
        }
        let mut accumulator: Option<Self> = None;
        let mut running_power = self.clone();
        let mut e = exponent;
        while e != 0 {
            if e & 1 == 1 {
                accumulator = Some(match accumulator {
                    None => running_power.clone(),
                    Some(acc) => acc.mul(&running_power),
                });
            }
            e >>= 1;
            if e != 0 {
                running_power = running_power.sqr();
            }
        }
        accumulator.unwrap()
    }

    pub fn madd(&self, to_mul: &Self, to_add: &[Self]) -> Self {
        assert!(to_add.len() <= MAXIMUM_SUMMAND_COUNT);
        let ctx = self.ctx_of(to_mul);
        self.reduction_check();
        to_mul.reduction_check();
        let mut add_values = BigUint::from(0u64);
        let mut add_constant = true;
        for a in to_add {
            a.reduction_check();
            add_values += a.get_value();
            add_constant = add_constant && a.is_constant();
        }
        let modulus = Self::modulus();
        let (left, mul_right) = (self.get_value(), to_mul.get_value());
        let v = &left * &mul_right + &add_values;
        let (quotient_value, remainder_value) = (&v / &modulus, &v % &modulus);
        if self.is_constant() && to_mul.is_constant() && add_constant {
            return Self::constant(ctx, &remainder_value);
        } else if self.is_constant() && to_mul.is_constant() {
            let mut to_add_copy: Vec<Self> = to_add.to_vec();
            to_add_copy.push(Self::constant(ctx, &((&left * &mul_right) % &modulus)));
            return Self::sum(&to_add_copy);
        }
        let (reduction_required, num_quotient_bits) =
            Self::get_quotient_reduction_info(&[self.get_maximum_value()], &[to_mul.get_maximum_value()], to_add, &[Self::default_maximum_remainder()]);
        if reduction_required {
            if self.get_maximum_value() > to_mul.get_maximum_value() {
                self.self_reduce();
            } else {
                to_mul.self_reduce();
            }
            return self.madd(to_mul, to_add);
        }
        let ctx = ctx.unwrap();
        let quotient = Self::create_from_u512_as_witness(&ctx, &quotient_value, false, num_quotient_bits);
        let remainder = Self::create_from_u512_as_witness(&ctx, &remainder_value, false, 0);
        Self::unsafe_evaluate_multiply_add(self, to_mul, to_add, &quotient, &[remainder.clone()]);
        remainder
    }

    /// bb `perform_reductions_for_mult_madd`: reduce the multiplicands, largest bound-saving first,
    /// until the products fit the CRT modulus.
    fn perform_reductions_for_mult_madd(mul_left: &mut [Self], mul_right: &mut [Self], to_add: &[Self]) {
        assert_eq!(mul_left.len(), mul_right.len());
        let n = mul_left.len();
        for l in mul_left.iter() {
            l.reduction_check();
        }
        for r in mul_right.iter() {
            r.reduction_check();
        }
        let maxes = |l: &[Self], r: &[Self]| -> (Vec<BigUint>, Vec<BigUint>) {
            (l.iter().map(|x| x.get_maximum_value()).collect(), r.iter().map(|x| x.get_maximum_value()).collect())
        };
        let (mut max_left, mut max_right) = maxes(mul_left, mul_right);
        let mut reduction_required = Self::get_quotient_reduction_info(&max_left, &max_right, to_add, &[Self::default_maximum_remainder()]).0;
        while reduction_required {
            let mut updates: Vec<(BigUint, usize, usize)> = Vec::with_capacity(2 * n);
            for i in 0..n {
                let original_left = mul_left[i].get_maximum_value();
                let original_right = mul_right[i].get_maximum_value();
                let original_product = &original_left * &original_right;
                if mul_left[i].is_constant() {
                    updates.push((BigUint::from(0u64), i, 0));
                } else {
                    let new_product = Self::default_maximum_remainder() * &original_right;
                    assert!(new_product <= original_product, "bigfield: This should never happen");
                    updates.push((&original_product - new_product, i, 0));
                }
                if mul_right[i].is_constant() {
                    updates.push((BigUint::from(0u64), i, 1));
                } else {
                    let new_product = Self::default_maximum_remainder() * &original_left;
                    assert!(new_product <= original_product, "bigfield: This should never happen");
                    updates.push((&original_product - new_product, i, 1));
                }
            }
            // bb std::sort by descending saving (ties keep no particular order; the pairs are
            // distinct in practice)
            updates.sort_by(|a, b| b.0.cmp(&a.0));
            let (update_size, idx, which) = &updates[0];
            assert!(*update_size != BigUint::from(0u64), "bigfield: Can't reduce further");
            if *which == 0 {
                mul_left[*idx].self_reduce();
            } else {
                mul_right[*idx].self_reduce();
            }
            (max_left, max_right) = maxes(mul_left, mul_right);
            reduction_required = Self::get_quotient_reduction_info(&max_left, &max_right, to_add, &[Self::default_maximum_remainder()]).0;
        }
    }

    /// bb `mult_madd`: `sum_i left_i * right_i + sum to_add` (mod p) in one multiplication check.
    pub fn mult_madd(mul_left: &[Self], mul_right: &[Self], to_add: &[Self], fix_remainder_to_zero: bool) -> Self {
        assert_eq!(mul_left.len(), mul_right.len());
        assert!(mul_left.len() <= MAXIMUM_SUMMAND_COUNT && to_add.len() <= MAXIMUM_SUMMAND_COUNT);
        let modulus = Self::modulus();
        let mut add_right_constant_sum = BigUint::from(0u64);
        let mut add_constant = true;
        let mut new_to_add: Vec<Self> = vec![];
        for a in to_add {
            a.reduction_check();
            if a.is_constant() {
                add_right_constant_sum += a.get_value();
            } else {
                add_constant = false;
                new_to_add.push(a.clone());
            }
        }
        let mut sum_of_constant_products = BigUint::from(0u64);
        let mut new_input_left: Vec<Self> = vec![];
        let mut new_input_right: Vec<Self> = vec![];
        let mut product_sum_constant = true;
        for (l, r) in mul_left.iter().zip(mul_right) {
            if l.is_constant() && r.is_constant() {
                sum_of_constant_products += l.get_value() * r.get_value();
            } else {
                new_input_left.push(l.clone());
                new_input_right.push(r.clone());
                product_sum_constant = false;
            }
        }
        let ctx = mul_left.iter().chain(mul_right).find_map(|e| e.ctx.clone());
        if product_sum_constant {
            let remainder_value = (&sum_of_constant_products + &add_right_constant_sum) % &modulus;
            if add_constant {
                assert!(!fix_remainder_to_zero || remainder_value == BigUint::from(0u64));
                return Self::constant(ctx, &remainder_value);
            }
            if remainder_value != BigUint::from(0u64) {
                new_to_add.push(Self::constant(ctx, &remainder_value));
            }
            let result = Self::sum(&new_to_add);
            if fix_remainder_to_zero {
                result.self_reduce();
                result.assert_equal(&Self::zero());
            }
            return result;
        }
        let ctx = ctx.expect("mult_madd without a builder");
        let constant_part_remainder = (&sum_of_constant_products + &add_right_constant_sum) % &modulus;
        if constant_part_remainder != BigUint::from(0u64) {
            new_to_add.push(Self::constant(Some(ctx.clone()), &constant_part_remainder));
        }
        let mut add_right_final_sum = BigUint::from(0u64);
        let mut add_right_maximum = BigUint::from(0u64);
        for a in &new_to_add {
            a.reduction_check();
            add_right_final_sum += a.get_value();
            add_right_maximum += a.get_maximum_value();
        }
        let final_number_of_products = new_input_left.len();
        let worst_case_product_sum = BigUint::from(final_number_of_products as u64) * Self::default_maximum_remainder() * Self::default_maximum_remainder();
        assert!(worst_case_product_sum + add_right_maximum < Self::get_maximum_crt_product());
        Self::perform_reductions_for_mult_madd(&mut new_input_left, &mut new_input_right, &new_to_add);
        let mut sum_of_products_final = BigUint::from(0u64);
        for (l, r) in new_input_left.iter().zip(&new_input_right) {
            sum_of_products_final += l.get_value() * r.get_value();
        }
        let num_quotient_bits = Self::get_quotient_max_bits(&[Self::default_maximum_remainder()]) as u64;
        let v = sum_of_products_final + add_right_final_sum;
        let (quotient_value, remainder_value) = (&v / &modulus, &v % &modulus);
        if fix_remainder_to_zero {
            assert!(remainder_value == BigUint::from(0u64));
        }
        let quotient = Self::create_from_u512_as_witness(&ctx, &quotient_value, false, num_quotient_bits);
        let remainder = if fix_remainder_to_zero {
            let mut r = Self::zero();
            r.convert_constant_to_fixed_witness(&ctx);
            r
        } else {
            Self::create_from_u512_as_witness(&ctx, &remainder_value, false, 0)
        };
        Self::unsafe_evaluate_multiple_multiply_add(&new_input_left, &new_input_right, &new_to_add, &quotient, &[remainder.clone()]);
        remainder
    }

    pub fn dual_madd(left_a: &Self, right_a: &Self, left_b: &Self, right_b: &Self, to_add: &[Self]) -> Self {
        for x in [left_a, right_a, left_b, right_b] {
            x.reduction_check();
        }
        Self::mult_madd(&[left_a.clone(), left_b.clone()], &[right_a.clone(), right_b.clone()], to_add, false)
    }

    /// bb `msub_div`: `(-sum_i left_i * right_i - sum to_sub) / divisor`.
    pub fn msub_div(mul_left: &[Self], mul_right: &[Self], divisor: &Self, to_sub: &[Self], enable_divisor_nz_check: bool) -> Self {
        assert_eq!(mul_left.len(), mul_right.len());
        let modulus = Self::modulus();
        assert!(divisor.get_value() % &modulus != BigUint::from(0u64), "bigfield: division by zero in msub_div");
        let ctx = divisor.ctx.clone().or_else(|| mul_left.iter().chain(mul_right).chain(to_sub).find_map(|e| e.ctx.clone()));
        if enable_divisor_nz_check {
            divisor.assert_is_not_equal(&Self::zero());
        }
        let mut product_native = N::zero();
        let mut products_constant = true;
        for (l, r) in mul_left.iter().zip(mul_right) {
            let ln = Self::native(&(l.get_value() % &modulus));
            let rn = Self::native(&(r.get_value() % &modulus));
            product_native += ln * -rn;
            products_constant = products_constant && l.is_constant() && r.is_constant();
        }
        let mut sub_native = N::zero();
        let mut sub_constant = true;
        for s in to_sub {
            sub_native += Self::native(&(s.get_value() % &modulus));
            sub_constant = sub_constant && s.is_constant();
        }
        let divisor_native = Self::native(&(divisor.get_value() % &modulus));
        let result_native = (product_native - sub_native) * divisor_native.inverse().unwrap();
        let result_value = Self::native_value(&result_native);
        if sub_constant && products_constant && divisor.is_constant() {
            return Self::constant(ctx, &result_value);
        }
        let ctx = ctx.expect("msub_div without a builder");
        let result = Self::create_from_u512_as_witness(&ctx, &result_value, false, 0);
        let mut eval_left = vec![result.clone()];
        let mut eval_right = vec![divisor.clone()];
        eval_left.extend(mul_left.iter().cloned());
        eval_right.extend(mul_right.iter().cloned());
        Self::mult_madd(&eval_left, &eval_right, to_sub, true);
        result
    }

    pub fn sum(terms: &[Self]) -> Self {
        assert!(!terms.is_empty());
        if terms.len() == 1 {
            return terms[0].clone();
        }
        let mut acc = terms[0].clone();
        for i in 1..(terms.len() + 1) / 2 {
            acc = acc.add_two(&terms[2 * i - 1], &terms[2 * i]);
        }
        if terms.len() % 2 == 0 {
            acc = acc.add(&terms[terms.len() - 1]);
        }
        acc
    }

    // ---- conditionals and comparisons ----

    pub fn conditional_negate(&self, predicate: &BoolT) -> Self {
        let ctx = self.ctx.clone().or_else(|| predicate.ctx.clone());
        if self.is_constant() && predicate.is_constant() {
            if predicate.get_value() {
                let modulus = Self::modulus();
                assert!(self.get_value() < modulus);
                return Self::constant(ctx, &((&modulus - self.get_value()) % &modulus));
            }
            return self.clone();
        }
        self.reduction_check();
        let negative_this = Self::zero().sub(self);
        Self::conditional_assign(predicate, &negative_this, self)
    }

    /// `predicate ? other : self` (bb `conditional_select`).
    pub fn conditional_select(&self, other: &Self, predicate: &BoolT) -> Self {
        if predicate.is_constant() {
            return if predicate.get_value() { other.clone() } else { self.clone() };
        }
        let same = |a: &FieldT, b: &FieldT| {
            Self::witness_indices_match(a, b) && a.additive_constant == b.additive_constant && a.multiplicative_constant == b.multiplicative_constant
        };
        if (0..NUM_LIMBS).all(|i| same(&self.limb_element(i), &other.limb_element(i))) && same(&self.prime_limb(), &other.prime_limb()) {
            return self.clone();
        }
        let ctx = self.ctx.clone().or_else(|| other.ctx.clone()).or_else(|| predicate.ctx.clone());
        let p = predicate.to_field();
        let limbs: [Limb; NUM_LIMBS] = std::array::from_fn(|i| {
            let (a, b) = (self.limb_element(i), other.limb_element(i));
            Limb::new(p.madd(&b.sub(&a), &a), self.limb_max(i).max(other.limb_max(i)))
        });
        let prime = p.madd(&other.prime_limb().sub(&self.prime_limb()), &self.prime_limb());
        Self::from_state(ctx, limbs, prime)
    }

    /// `predicate ? lhs : rhs`.
    pub fn conditional_assign(predicate: &BoolT, lhs: &Self, rhs: &Self) -> Self {
        rhs.conditional_select(lhs, predicate)
    }

    pub fn eq(&self, other: &Self) -> BoolT {
        let ctx = self.ctx_of(other);
        let modulus = Self::modulus();
        let is_equal_raw = self.get_value() % &modulus == other.get_value() % &modulus;
        if self.is_constant() && other.is_constant() {
            return BoolT::constant(is_equal_raw);
        }
        let ctx = ctx.unwrap();
        let is_equal = BoolT::from_witness(&ctx, is_equal_raw);
        let diff = self.sub(other);
        let diff_native = Self::native(&(diff.get_value() % &modulus));
        let inverse_native = if is_equal_raw { N::zero() } else { diff_native.inverse().unwrap() };
        let inverse = Self::from_witness(&ctx, &inverse_native);
        let multiplicand = Self::conditional_assign(&is_equal, &Self::one(), &inverse);
        let product = diff.mul(&multiplicand);
        let result = FieldT::conditional_assign_internal(&is_equal, &FieldT::constant(Fr::zero()), &FieldT::constant(Fr::one()));
        product.prime_limb().assert_equal(&result);
        product.limb_element(0).assert_equal(&result);
        product.limb_element(1).assert_equal(&FieldT::constant(Fr::zero()));
        product.limb_element(2).assert_equal(&FieldT::constant(Fr::zero()));
        product.limb_element(3).assert_equal(&FieldT::constant(Fr::zero()));
        is_equal
    }

    pub fn assert_zero_if(&self, predicate: &BoolT) {
        let p = predicate.to_field();
        for i in 0..NUM_LIMBS {
            self.limb_element(i).mul(&p).assert_is_zero();
        }
        self.prime_limb().mul(&p).assert_is_zero();
    }

    pub fn assert_is_in_field(&self) {
        self.assert_less_than(&Self::modulus());
    }

    pub fn assert_less_than(&self, upper_limit: &BigUint) {
        if self.is_constant() {
            assert!(self.get_value() % Self::modulus() < *upper_limit);
            return;
        }
        let ctx = self.ctx.clone().unwrap();
        let w = self.limb_witness_indices();
        ctx.borrow_mut().range_constrain_two_limbs(w[0], w[1], NUM_LIMB_BITS as usize, NUM_LIMB_BITS as usize);
        ctx.borrow_mut().range_constrain_two_limbs(w[2], w[3], NUM_LIMB_BITS as usize, Self::num_last_limb_bits() as usize);
        self.unsafe_assert_less_than(upper_limit);
    }

    pub fn is_less_than(&self, upper_limit: &BigUint) -> BoolT {
        let ctx = self.ctx.clone().unwrap();
        let w = self.limb_witness_indices();
        ctx.borrow_mut().range_constrain_two_limbs(w[0], w[1], NUM_LIMB_BITS as usize, NUM_LIMB_BITS as usize);
        ctx.borrow_mut().range_constrain_two_limbs(w[2], w[3], NUM_LIMB_BITS as usize, Self::num_last_limb_bits() as usize);
        let limit = |a: u64, b: u64| FieldT::constant(fr(&slice(upper_limit, a, b)));
        let u0 = limit(0, NUM_LIMB_BITS);
        let u1 = limit(NUM_LIMB_BITS, NUM_LIMB_BITS * 2);
        let u2 = limit(NUM_LIMB_BITS * 2, NUM_LIMB_BITS * 3);
        let u3 = limit(NUM_LIMB_BITS * 3, NUM_LIMB_BITS * 3 + Self::num_last_limb_bits());
        let less = |i: usize, u: &FieldT, bits: u64| self.limb_element(i).ranged_less_than(u, bits as u32);
        let third_limb_is_smaller = less(3, &u3, Self::num_last_limb_bits());
        let third_limb_is_equal = self.limb_element(3).eq(&u3);
        let second_limb_is_smaller = less(2, &u2, NUM_LIMB_BITS);
        let second_limb_is_equal = self.limb_element(2).eq(&u2);
        let first_limb_is_smaller = less(1, &u1, NUM_LIMB_BITS);
        let first_limb_is_equal = self.limb_element(1).eq(&u1);
        let zeroth_limb_is_smaller = less(0, &u0, NUM_LIMB_BITS);
        third_limb_is_smaller
            .or(&third_limb_is_equal.and(&second_limb_is_smaller))
            .or(&third_limb_is_equal.and(&second_limb_is_equal).and(&first_limb_is_smaller))
            .or(&third_limb_is_equal.and(&second_limb_is_equal).and(&first_limb_is_equal).and(&zeroth_limb_is_smaller))
    }

    pub fn reduce_mod_target_modulus(&self) {
        self.self_reduce();
        self.unsafe_assert_less_than(&Self::modulus());
    }

    fn unsafe_assert_less_than(&self, upper_limit: &BigUint) {
        if self.is_constant() {
            assert!(self.get_value() < *upper_limit);
            return;
        }
        assert!(*upper_limit != BigUint::from(0u64));
        let ctx = self.ctx.clone().unwrap();
        let strict_upper_limit = upper_limit - 1u64;
        let value = self.get_value();
        let ul: [BigUint; 4] = std::array::from_fn(|i| slice(&strict_upper_limit, NUM_LIMB_BITS * i as u64, NUM_LIMB_BITS * (i as u64 + 1)));
        let val: [BigUint; 3] = std::array::from_fn(|i| slice(&value, NUM_LIMB_BITS * i as u64, NUM_LIMB_BITS * (i as u64 + 1)));
        let borrow_0_value = val[0] > ul[0];
        let borrow_1_value = &val[1] + BigUint::from(borrow_0_value as u64) > ul[1];
        let borrow_2_value = &val[2] + BigUint::from(borrow_1_value as u64) > ul[2];
        let limit: [FieldT; 4] = std::array::from_fn(|i| FieldT::constant(fr(&ul[i])));
        let borrow_0 = BoolT::from_witness(&ctx, borrow_0_value).to_field();
        let borrow_1 = BoolT::from_witness(&ctx, borrow_1_value).to_field();
        let borrow_2 = BoolT::from_witness(&ctx, borrow_2_value).to_field();
        let shift_1 = FieldT::constant(shift_k(1));
        let r0 = limit[0].sub(&self.limb_element(0)).add(&borrow_0.mul(&shift_1));
        let r1 = limit[1].sub(&self.limb_element(1)).add(&borrow_1.mul(&shift_1)).sub(&borrow_0);
        let r2 = limit[2].sub(&self.limb_element(2)).add(&borrow_2.mul(&shift_1)).sub(&borrow_1);
        let r3 = limit[3].sub(&self.limb_element(3)).sub(&borrow_2);
        let (r0, r1) = (r0.get_witness_index(), r1.get_witness_index());
        ctx.borrow_mut().range_constrain_two_limbs(r0, r1, NUM_LIMB_BITS as usize, NUM_LIMB_BITS as usize);
        let (r2, r3) = (r2.get_witness_index(), r3.get_witness_index());
        ctx.borrow_mut().range_constrain_two_limbs(r2, r3, NUM_LIMB_BITS as usize, Self::num_last_limb_bits() as usize);
    }

    pub fn assert_equal(&self, other: &Self) {
        let ctx = self.ctx_of(other);
        let modulus = Self::modulus();
        if self.is_constant() && other.is_constant() {
            assert_eq!(self.get_value(), other.get_value(), "bigfield::assert_equal on constants");
            return;
        } else if other.is_constant() {
            assert!(self.get_value() < modulus, "bigfield::assert_equal: 'this' is not reduced");
            for i in 0..NUM_LIMBS {
                self.limb_element(i).sub(&other.limb_element(i)).assert_is_zero();
            }
            self.prime_limb().sub(&other.prime_limb()).assert_is_zero();
            return;
        } else if self.is_constant() {
            other.assert_equal(self);
            return;
        }
        let ctx = ctx.unwrap();
        if self.get_value() % &modulus != other.get_value() % &modulus {
            ctx.borrow_mut().failure("bigfield::assert_equal");
        }
        let diff = self.sub(other);
        let diff_val = diff.get_value();
        let quotient_512 = &diff_val / &modulus;
        let num_quotient_bits = Self::get_quotient_max_bits(&[BigUint::from(0u64)]) as u64;
        let quotient = Self::from_halves(
            &FieldT::from_witness(&ctx, fr(&slice(&quotient_512, 0, NUM_LIMB_BITS * 2))),
            &FieldT::from_witness(&ctx, fr(&slice(&quotient_512, NUM_LIMB_BITS * 2, NUM_LIMB_BITS * 4))),
            false,
            num_quotient_bits,
        );
        Self::unsafe_evaluate_multiply_add(&diff, &Self::one(), &[], &quotient, &[Self::zero()]);
    }

    pub fn assert_is_not_equal(&self, other: &Self) {
        let modulus = Self::modulus();
        let overload_count = |maximum_value: &BigUint| {
            let mut target = modulus.clone();
            let mut count = 0;
            while target <= *maximum_value {
                count += 1;
                target += &modulus;
            }
            count
        };
        let lhs_overload_count = overload_count(&self.get_maximum_value());
        let rhs_overload_count = overload_count(&other.get_maximum_value());
        let base_diff = self.prime_limb().sub(&other.prime_limb());
        let mut diff = base_diff.clone();
        let prime_basis = FieldT::constant(fr(&modulus));
        let mut acc = prime_basis.clone();
        for _ in 0..lhs_overload_count {
            diff = diff.mul(&base_diff.sub(&acc));
            acc += &prime_basis;
        }
        acc = prime_basis.clone();
        for _ in 0..rhs_overload_count {
            diff = diff.mul(&base_diff.add(&acc));
            acc += &prime_basis;
        }
        diff.assert_is_not_zero();
    }

    // ---- the multiplication identity ----

    fn constant_to_fixed_witness(input: &Self, ctx: &Ctx) -> Self {
        let mut b = ctx.borrow_mut();
        let fix = |b: &mut crate::circuit::Builder, f: &FieldT| FieldT::from_witness_index(ctx, b.put_constant_variable(f.get_value()));
        let prime = fix(&mut b, &input.prime_limb());
        let limbs: [Limb; NUM_LIMBS] = std::array::from_fn(|i| Limb { element: fix(&mut b, &input.limb_element(i)), maximum_value: input.limb_max(i) });
        drop(b);
        Self::from_state(Some(ctx.clone()), limbs, prime)
    }

    /// bb `unsafe_evaluate_multiply_add`: constrain `left * to_mul + sum(to_add) = quotient * p + sum(remainders)`.
    fn unsafe_evaluate_multiply_add(input_left: &Self, input_to_mul: &Self, to_add: &[Self], input_quotient: &Self, input_remainders: &[Self]) {
        assert!(to_add.len() <= MAXIMUM_SUMMAND_COUNT && input_remainders.len() <= MAXIMUM_SUMMAND_COUNT);
        for x in [input_left, input_to_mul, input_quotient].into_iter().chain(to_add).chain(input_remainders) {
            x.sanity_check();
        }
        assert!(!input_left.is_constant() || !input_to_mul.is_constant());
        let ctx = input_left.ctx_of(input_to_mul).unwrap();
        let (max_ab_lo, max_ab_hi) = Self::compute_partial_schoolbook_multiplication(&input_left.limb_maximums(), &input_to_mul.limb_maximums());
        let (max_q_neg_p_lo, max_q_neg_p_hi) = Self::compute_partial_schoolbook_multiplication(&Self::neg_modulus_mod_binary_basis_limbs_big(), &input_quotient.limb_maximums());
        let mut max_remainders_lo = BigUint::from(0u64);
        for r in input_remainders {
            max_remainders_lo += r.limb_max(0) + (r.limb_max(1) << NUM_LIMB_BITS);
        }
        let borrow_lo_value = (&max_remainders_lo + (pow2(2 * NUM_LIMB_BITS) - 1u64)) >> (2 * NUM_LIMB_BITS);
        let borrow_lo = FieldT::constant(fr(&borrow_lo_value));
        let (mut max_a0, mut max_a1) = (BigUint::from(0u64), BigUint::from(0u64));
        for a in to_add {
            max_a0 += a.limb_max(0) + (a.limb_max(1) << NUM_LIMB_BITS);
            max_a1 += a.limb_max(2) + (a.limb_max(3) << NUM_LIMB_BITS);
        }
        let max_lo = max_ab_lo + max_q_neg_p_lo + &max_remainders_lo + max_a0;
        let max_lo_carry = &max_lo >> (2 * NUM_LIMB_BITS);
        let max_hi = max_ab_hi + max_q_neg_p_hi + max_a1 + max_lo_carry;
        let max_lo_bits = msb(&max_lo) + 1;
        let max_hi_bits = msb(&max_hi) + 1;
        assert!(max_lo_bits > 2 * NUM_LIMB_BITS && max_hi_bits > 2 * NUM_LIMB_BITS);
        let carry_lo_msb = max_lo_bits - 2 * NUM_LIMB_BITS;
        let carry_hi_msb = max_hi_bits - 2 * NUM_LIMB_BITS;
        let fix = |x: &Self| if x.is_constant() { Self::constant_to_fixed_witness(x, &ctx) } else { x.clone() };
        let left = fix(input_left);
        let to_mul = fix(input_to_mul);
        let quotient = fix(input_quotient);
        let mut remainders: Vec<Self> = input_remainders.to_vec();
        remainders[0] = fix(&remainders[0]);
        let shift_1 = FieldT::constant(shift_k(1));
        let mut limb_0_accumulator = vec![remainders[0].limb_element(0)];
        let mut limb_2_accumulator = vec![remainders[0].limb_element(2)];
        let mut prime_limb_accumulator = vec![remainders[0].prime_limb()];
        for r in &remainders[1..] {
            limb_0_accumulator.push(r.limb_element(0));
            limb_0_accumulator.push(r.limb_element(1).mul(&shift_1));
            limb_2_accumulator.push(r.limb_element(2));
            limb_2_accumulator.push(r.limb_element(3).mul(&shift_1));
            prime_limb_accumulator.push(r.prime_limb());
        }
        for a in to_add {
            limb_0_accumulator.push(a.limb_element(0).neg());
            limb_0_accumulator.push(a.limb_element(1).neg().mul(&shift_1));
            limb_2_accumulator.push(a.limb_element(2).neg());
            limb_2_accumulator.push(a.limb_element(3).neg().mul(&shift_1));
            prime_limb_accumulator.push(a.prime_limb().neg());
        }
        let t0 = remainders[0].limb_element(1);
        let t1 = remainders[0].limb_element(3);
        let not_plain = |t: &FieldT| t.additive_constant != Fr::zero() || t.multiplicative_constant != Fr::one();
        let needs_normalize = not_plain(&t0) || not_plain(&t1);
        if needs_normalize {
            limb_0_accumulator.push(remainders[0].limb_element(1).mul(&shift_1));
            limb_2_accumulator.push(remainders[0].limb_element(3).mul(&shift_1));
        }
        let zero_idx = ctx.borrow().zero_idx();
        let remainder_limbs = [
            FieldT::accumulate(&limb_0_accumulator),
            if needs_normalize { FieldT::from_witness_index(&ctx, zero_idx) } else { remainders[0].limb_element(1) },
            FieldT::accumulate(&limb_2_accumulator),
            if needs_normalize { FieldT::from_witness_index(&ctx, zero_idx) } else { remainders[0].limb_element(3) },
        ];
        let remainder_prime_limb = FieldT::accumulate(&prime_limb_accumulator);
        let witnesses = NonNativeMultiplicationWitnesses {
            a: left.limb_witness_indices(),
            b: to_mul.limb_witness_indices(),
            q: quotient.limb_witness_indices(),
            r: std::array::from_fn(|i| remainder_limbs[i].get_witness_index()),
            neg_modulus: Self::neg_modulus_mod_binary_basis_limbs(),
        };
        let [lo_idx, hi_idx] = ctx.borrow_mut().evaluate_non_native_field_multiplication(&witnesses);
        FieldT::evaluate_polynomial_identity(
            &left.prime_limb(),
            &to_mul.prime_limb(),
            &quotient.prime_limb().mul(&FieldT::constant(Self::negative_prime_modulus_mod_native_basis())),
            &remainder_prime_limb.neg(),
        );
        let lo = FieldT::from_witness_index(&ctx, lo_idx).add(&borrow_lo);
        let hi = FieldT::from_witness_index(&ctx, hi_idx);
        if carry_lo_msb <= 70 && carry_hi_msb <= 70 {
            let (hi, lo) = (hi.get_witness_index(), lo.get_witness_index());
            ctx.borrow_mut().range_constrain_two_limbs(hi, lo, carry_hi_msb as usize, carry_lo_msb as usize);
        } else {
            hi.create_range_constraint(carry_hi_msb);
            lo.create_range_constraint(carry_lo_msb);
        }
    }

    /// bb `unsafe_evaluate_multiple_multiply_add`: several products, the first checked with the
    /// multiplication gate and the rest as queued partial products folded into its remainder.
    fn unsafe_evaluate_multiple_multiply_add(input_left: &[Self], input_right: &[Self], to_add: &[Self], input_quotient: &Self, input_remainders: &[Self]) {
        assert_eq!(input_left.len(), input_right.len());
        for x in input_left.iter().chain(input_right).chain(to_add).chain([input_quotient]).chain(input_remainders) {
            x.sanity_check();
        }
        assert!(!input_left.iter().all(|x| x.is_constant()) || !input_right.iter().all(|x| x.is_constant()));
        let ctx = input_left.iter().chain(input_right).find_map(|e| e.ctx.clone()).unwrap();
        let mut max_remainders_lo = BigUint::from(0u64);
        for r in input_remainders {
            max_remainders_lo += r.limb_max(0) + (r.limb_max(1) << NUM_LIMB_BITS);
        }
        let borrow_lo_value = (&max_remainders_lo + (pow2(2 * NUM_LIMB_BITS) - 1u64)) >> (2 * NUM_LIMB_BITS);
        let borrow_lo = FieldT::constant(fr(&borrow_lo_value));
        let (max_q_neg_p_lo, max_q_neg_p_hi) = Self::compute_partial_schoolbook_multiplication(&Self::neg_modulus_mod_binary_basis_limbs_big(), &input_quotient.limb_maximums());
        let mut max_lo = max_q_neg_p_lo + &max_remainders_lo;
        let mut max_hi = max_q_neg_p_hi;
        for a in to_add {
            max_lo += a.limb_max(0) + (a.limb_max(1) << NUM_LIMB_BITS);
            max_hi += a.limb_max(2) + (a.limb_max(3) << NUM_LIMB_BITS);
        }
        for (l, r) in input_left.iter().zip(input_right) {
            let (product_lo, product_hi) = Self::compute_partial_schoolbook_multiplication(&l.limb_maximums(), &r.limb_maximums());
            max_lo += product_lo;
            max_hi += product_hi;
        }
        let max_lo_carry = &max_lo >> (2 * NUM_LIMB_BITS);
        max_hi += max_lo_carry;
        let max_lo_bits = msb(&max_lo) + 1;
        let max_hi_bits = msb(&max_hi) + 1;
        let fix = |x: &Self| if x.is_constant() { Self::constant_to_fixed_witness(x, &ctx) } else { x.clone() };
        let shift_1 = FieldT::constant(shift_k(1));
        let mut limb_0_accumulator: Vec<FieldT> = vec![];
        let mut limb_2_accumulator: Vec<FieldT> = vec![];
        let mut prime_limb_accumulator: Vec<FieldT> = vec![];
        let mut left: Vec<Self> = Vec::with_capacity(input_left.len());
        let mut right: Vec<Self> = Vec::with_capacity(input_right.len());
        for i in 0..input_left.len() {
            left.push(fix(&input_left[i]));
            right.push(fix(&input_right[i]));
            if i > 0 {
                let (a_idx, b_idx) = (left[i].limb_witness_indices(), right[i].limb_witness_indices());
                let [lo_2_idx, hi_2_idx] = ctx.borrow_mut().queue_partial_non_native_field_multiplication(a_idx, b_idx);
                limb_0_accumulator.push(FieldT::from_witness_index(&ctx, lo_2_idx).neg());
                limb_2_accumulator.push(FieldT::from_witness_index(&ctx, hi_2_idx).neg());
                prime_limb_accumulator.push(left[i].prime_limb().mul(&right[i].prime_limb()).neg());
            }
        }
        let quotient = fix(input_quotient);
        let remainders: Vec<Self> = input_remainders.to_vec();
        if let Some(r0) = remainders.first() {
            limb_0_accumulator.push(r0.limb_element(0));
            limb_2_accumulator.push(r0.limb_element(2));
            prime_limb_accumulator.push(r0.prime_limb());
        }
        for r in remainders.iter().skip(1) {
            limb_0_accumulator.push(r.limb_element(0));
            limb_0_accumulator.push(r.limb_element(1).mul(&shift_1));
            limb_2_accumulator.push(r.limb_element(2));
            limb_2_accumulator.push(r.limb_element(3).mul(&shift_1));
            prime_limb_accumulator.push(r.prime_limb());
        }
        for a in to_add {
            limb_0_accumulator.push(a.limb_element(0).neg());
            limb_0_accumulator.push(a.limb_element(1).neg().mul(&shift_1));
            limb_2_accumulator.push(a.limb_element(2).neg());
            limb_2_accumulator.push(a.limb_element(3).neg().mul(&shift_1));
            prime_limb_accumulator.push(a.prime_limb().neg());
        }
        let fix_field = |f: FieldT| {
            if f.is_constant() {
                let idx = ctx.borrow_mut().put_constant_variable(f.get_value());
                FieldT::from_witness_index(&ctx, idx)
            } else {
                f
            }
        };
        let accumulated_lo = fix_field(FieldT::accumulate(&limb_0_accumulator));
        let accumulated_hi = fix_field(FieldT::accumulate(&limb_2_accumulator));
        let zero_idx = ctx.borrow().zero_idx();
        let remainder1 = fix_field(remainders.first().map_or_else(|| FieldT::from_witness_index(&ctx, zero_idx), |r| r.limb_element(1)));
        let remainder3 = fix_field(remainders.first().map_or_else(|| FieldT::from_witness_index(&ctx, zero_idx), |r| r.limb_element(3)));
        let remainder_limbs = [accumulated_lo, remainder1, accumulated_hi, remainder3];
        let remainder_prime_limb = FieldT::accumulate(&prime_limb_accumulator);
        let witnesses = NonNativeMultiplicationWitnesses {
            a: left[0].limb_witness_indices(),
            b: right[0].limb_witness_indices(),
            q: quotient.limb_witness_indices(),
            r: std::array::from_fn(|i| remainder_limbs[i].get_witness_index()),
            neg_modulus: Self::neg_modulus_mod_binary_basis_limbs(),
        };
        let [lo_1_idx, hi_1_idx] = ctx.borrow_mut().evaluate_non_native_field_multiplication(&witnesses);
        FieldT::evaluate_polynomial_identity(
            &left[0].prime_limb(),
            &right[0].prime_limb(),
            &quotient.prime_limb().mul(&FieldT::constant(Self::negative_prime_modulus_mod_native_basis())),
            &remainder_prime_limb.neg(),
        );
        let lo = FieldT::from_witness_index(&ctx, lo_1_idx).add(&borrow_lo);
        let hi = FieldT::from_witness_index(&ctx, hi_1_idx);
        assert!(max_lo_bits > 2 * NUM_LIMB_BITS && max_hi_bits > 2 * NUM_LIMB_BITS);
        let carry_lo_msb = max_lo_bits - 2 * NUM_LIMB_BITS;
        let carry_hi_msb = max_hi_bits - 2 * NUM_LIMB_BITS;
        if carry_lo_msb <= 70 && carry_hi_msb <= 70 {
            let (hi, lo) = (hi.get_witness_index(), lo.get_witness_index());
            ctx.borrow_mut().range_constrain_two_limbs(hi, lo, carry_hi_msb as usize, carry_lo_msb as usize);
        } else {
            hi.create_range_constraint(carry_hi_msb);
            lo.create_range_constraint(carry_lo_msb);
        }
    }
}
