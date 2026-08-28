//! Field abstraction: the `FieldLike` trait is implemented natively by arkworks prime fields and,
//! later, by the in-circuit `FieldT`, so verifier code is written once and runs in both settings.

use ark_ff::{BigInt, BigInteger, PrimeField};
use std::fmt::Debug;
use std::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

pub type Fr = ark_bn254::Fr;
pub type Fq = ark_bn254::Fq;

/// The native prime fields values can live in, with the conversions relation bodies need at no
/// per-call cost (`F::from(u64)` is a Montgomery multiplication).
pub trait NativeField: PrimeField<BigInt = U256> {
    /// `v` as a field element, from a table for small `v`.
    fn small(v: u64) -> Self;
    /// A bn254 `Fr` constant in this field (relation constants are written as `Fr`).
    fn from_fr(v: Fr) -> Self;
}

macro_rules! native_field {
    ($F:ty, $from_fr:expr) => {
        impl NativeField for $F {
            fn small(v: u64) -> Self {
                static SMALL: std::sync::LazyLock<[$F; 64]> =
                    std::sync::LazyLock::new(|| std::array::from_fn(|i| <$F>::from(i as u64)));
                match SMALL.get(v as usize) {
                    Some(x) => *x,
                    None => Self::from(v),
                }
            }
            fn from_fr(v: Fr) -> Self {
                $from_fr(v)
            }
        }
    };
}
native_field!(Fr, |v| v);
native_field!(Fq, |v: Fr| from_u256::<Fq>(u256(&v)));
/// 256-bit little-endian-limbed integer (canonical, non-Montgomery form).
pub type U256 = BigInt<4>;

pub trait FieldLike:
    Clone
    + Debug
    + PartialEq
    + Add<Output = Self>
    + Sub<Output = Self>
    + Mul<Output = Self>
    + Neg<Output = Self>
    + for<'a> Add<&'a Self, Output = Self>
    + for<'a> Sub<&'a Self, Output = Self>
    + for<'a> Mul<&'a Self, Output = Self>
    + AddAssign
    + SubAssign
    + MulAssign
    + for<'a> AddAssign<&'a Self>
    + for<'a> SubAssign<&'a Self>
    + for<'a> MulAssign<&'a Self>
{
    /// The underlying prime field of the values.
    type Native: NativeField;
    /// Builder context: `()` natively, a builder handle in-circuit.
    type Ctx: Clone;

    fn ctx(&self) -> Option<Self::Ctx>;
    /// A constant. In-circuit this never emits a gate.
    fn constant(v: Self::Native) -> Self;
    fn from_witness(ctx: &Self::Ctx, v: Self::Native) -> Self;
    fn value(&self) -> Self::Native;
    fn invert(&self) -> Self;
    /// In-circuit: a copy constraint (no gate). Natively: nothing.
    fn assert_equal(&self, other: &Self);

    fn from_u64(v: u64) -> Self {
        Self::constant(Self::Native::from(v))
    }
    /// `n` zeros. Native fields override this with a zeroed allocation, whose pages the OS only
    /// materializes when written, so sparse polynomials cost what they use (bb's virtual zeros).
    fn zeroed(n: usize) -> Vec<Self> {
        vec![Self::zero(); n]
    }
    fn zero() -> Self {
        Self::constant(<Self::Native as ark_ff::AdditiveGroup>::ZERO)
    }
    fn one() -> Self {
        Self::constant(<Self::Native as ark_ff::Field>::ONE)
    }
    fn sqr(&self) -> Self {
        self.clone() * self
    }
    /// bb bigfield `self_reduce`: native and circuit-native fields are always reduced.
    fn self_reduce(&self) {}
    /// bb `x + x` with both operands the same object (bigfield reduction aliasing).
    fn dbl(&self) -> Self {
        self.clone() + self
    }
    /// bb `x * x` with both operands the same object (NOT `sqr`, which is a different gate pattern).
    fn mul_self(&self) -> Self {
        self.clone() * self
    }
    /// Square-and-multiply; in-circuit implementations override to reproduce bb's gate pattern.
    fn pow_u64(&self, mut e: u64) -> Self {
        let mut base = self.clone();
        let mut acc = Self::one();
        while e > 0 {
            if e & 1 == 1 {
                acc *= &base;
            }
            base = base.sqr();
            e >>= 1;
        }
        acc
    }
    fn is_zero(&self) -> bool {
        ark_ff::Zero::is_zero(&self.value())
    }
    /// bb `convert_constant_to_fixed_witness` on a constant: natively just the constant; in-circuit a
    /// fresh witness fixed to `v` by a gate (an artifact bb's verifiers emit that must be mirrored).
    fn fixed_witness(_ctx: &Self::Ctx, v: Self::Native) -> Self {
        Self::constant(v)
    }
    /// bb `operator/`: in-circuit this also constrains the divisor to be non-zero (one extra gate),
    /// so it is used exactly where bb divides rather than inverts.
    fn div(&self, other: &Self) -> Self {
        self.clone() * &other.invert()
    }
    /// bb `ranged_less_than<num_bits>`: `self < other` as a field element; both are assumed to be
    /// below `2^num_bits` (in-circuit this costs a bool witness and a range gate).
    fn ranged_less_than(&self, other: &Self, _num_bits: u32) -> Self {
        Self::from_u64((u256(&self.value()) < u256(&other.value())) as u64)
    }
    /// bb `pow<num_bits>(exponent)` for an exponent below `2^num_bits` (in-circuit: bit decomposition).
    fn pow_field(&self, exponent: &Self, _num_bits: u32) -> Self {
        self.pow_u64(u256_to_u64(&u256(&exponent.value())))
    }
    /// bb `fix_witness` on a witness: a gate pinning it to its value. Natively nothing.
    fn fix(&self) {}
    /// bb `madd`: `self * to_mul + Σ to_add` (in-circuit implementations fuse the gates).
    fn madd(&self, to_mul: &Self, to_add: &[Self]) -> Self {
        let mut acc = self.clone() * to_mul;
        for a in to_add {
            acc += a;
        }
        acc
    }
    /// bb bigfield `mult_madd`: `Σ left_i * right_i + Σ to_add` (native: a plain dot product).
    fn mult_madd(left: &[Self], right: &[Self], to_add: &[Self]) -> Self {
        let mut acc = Self::zero();
        for (l, r) in left.iter().zip(right) {
            acc += l.clone() * r;
        }
        for a in to_add {
            acc += a;
        }
        acc
    }
}

impl<F: NativeField> FieldLike for F {
    type Native = F;
    type Ctx = ();
    fn ctx(&self) -> Option<()> {
        None
    }
    fn constant(v: F) -> Self {
        v
    }
    fn from_witness(_: &(), v: F) -> Self {
        v
    }
    fn value(&self) -> F {
        *self
    }
    fn invert(&self) -> Self {
        self.inverse().expect("inverse of zero")
    }
    fn assert_equal(&self, _other: &Self) {}
    fn zeroed(n: usize) -> Vec<Self> {
        if n == 0 {
            return Vec::new();
        }
        let layout = std::alloc::Layout::array::<F>(n).expect("polynomial size");
        // SAFETY: the Montgomery representation of zero is the all-zero bit pattern, so a zeroed
        // allocation of `n` elements is a valid `Vec<F>` of zeros; the allocation is owned by the
        // returned Vec with the same layout the global allocator will free it with.
        unsafe {
            let ptr = std::alloc::alloc_zeroed(layout) as *mut F;
            if ptr.is_null() {
                std::alloc::handle_alloc_error(layout);
            }
            Vec::from_raw_parts(ptr, n, n)
        }
    }
}

// ---- integer / byte helpers on the canonical representation ----

/// Invert every non-zero element with one field inversion (zeros stay zero), as bb's `batch_invert`.
pub fn batch_invert<F: PrimeField>(v: &mut [F]) {
    ark_ff::batch_inversion(v);
}

/// `z[0] = 1, z[i+1] = z[i] * num[i] / den[i]` with a single batched inversion (bb `compute_grand_product`).
pub fn grand_product<F: PrimeField>(num: &[F], den: &[F]) -> Vec<F> {
    let mut num_prefix = Vec::with_capacity(num.len() + 1);
    let mut den_prefix = Vec::with_capacity(num.len() + 1);
    let (mut n, mut d) = (F::one(), F::one());
    num_prefix.push(n);
    den_prefix.push(d);
    for (a, b) in num.iter().zip(den) {
        n *= a;
        d *= b;
        num_prefix.push(n);
        den_prefix.push(d);
    }
    batch_invert(&mut den_prefix);
    num_prefix.iter().zip(&den_prefix).map(|(n, d)| *n * d).collect()
}

pub fn u256<F: PrimeField<BigInt = U256>>(f: &F) -> U256 {
    f.into_bigint()
}

/// Panics if `v >= modulus` (bb asserts the same in its codecs).
pub fn from_u256<F: PrimeField<BigInt = U256>>(v: U256) -> F {
    F::from_bigint(v).expect("value >= field modulus")
}

pub fn u256_from_u64(v: u64) -> U256 {
    U256::from(v)
}

pub fn u256_shr(v: U256, bits: u32) -> U256 {
    v >> bits
}

/// The low `bits` bits of `v`.
pub fn u256_low_bits(v: U256, bits: u32) -> U256 {
    let mut limbs = v.0;
    for (i, limb) in limbs.iter_mut().enumerate() {
        let lo = i as u32 * 64;
        if bits <= lo {
            *limb = 0;
        } else if bits < lo + 64 {
            *limb &= (1u64 << (bits - lo)) - 1;
        }
    }
    BigInt(limbs)
}

pub fn u256_num_bits(v: &U256) -> u32 {
    v.num_bits()
}

pub fn u256_to_u64(v: &U256) -> u64 {
    assert!(v.0[1] == 0 && v.0[2] == 0 && v.0[3] == 0, "value does not fit in u64");
    v.0[0]
}

/// bb's byte encoding of a field element: 32 bytes, big-endian, canonical form.
pub fn to_bytes_be<F: PrimeField<BigInt = U256>>(f: &F) -> [u8; 32] {
    f.into_bigint().to_bytes_be().try_into().unwrap()
}

pub fn from_bytes_be<F: PrimeField<BigInt = U256>>(bytes: &[u8]) -> F {
    assert_eq!(bytes.len(), 32);
    F::from_be_bytes_mod_order(bytes)
}

pub fn from_hex<F: PrimeField<BigInt = U256>>(s: &str) -> F {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let padded = format!("{s:0>64}");
    let bytes = hex::decode(padded).expect("bad hex");
    F::from_be_bytes_mod_order(&bytes)
}

pub fn to_hex<F: PrimeField<BigInt = U256>>(f: &F) -> String {
    format!("0x{}", hex::encode(to_bytes_be(f)))
}
