//! Field abstraction: the `FieldLike` trait is implemented natively by arkworks prime fields and,
//! later, by the in-circuit `FieldT`, so verifier code is written once and runs in both settings.

use ark_ff::{BigInt, BigInteger, PrimeField};
use std::fmt::Debug;
use std::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

/// bn254 scalar field: arkworks' `Fp` container over bb-ref's `MontConfig` on wasm and x86-64
/// with ADX (`base/wasm`), arkworks' own type elsewhere.
pub type Fr = ark_ff::Fp256<ark_ff::MontBackend<crate::base::wasm::FrConfig, 4>>;
/// bn254 base field (Grumpkin's scalar field); as above.
pub type Fq = ark_ff::Fp256<ark_ff::MontBackend<crate::base::wasm::FqConfig, 4>>;

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
    /// True for prover-side representations (native fields, coefficient-basis univariates, SIMD
    /// lanes), false for circuit witnesses. Relation bodies may re-associate products on the
    /// prover side (bb's `IsProverAccumulator` branches); the circuit side must keep bb's gate
    /// order or the verification keys change.
    const IS_PROVER: bool = true;
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
    /// `x^5` (the Poseidon2 S-box) as `(x²)²·x`; coefficient-basis univariates override it.
    fn pow5(&self) -> Self {
        self.sqr().sqr() * self
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
    /// Prover-side probe: the value if it is constant over the whole sumcheck edge (a native
    /// value, or a degree-0 coefficient-basis univariate); `None` when unknown (circuit witnesses).
    fn as_const(&self) -> Option<Self::Native> {
        None
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
    fn as_const(&self) -> Option<F> {
        Some(*self)
    }
    fn zeroed(n: usize) -> Vec<Self> {
        if n == 0 {
            return Vec::new();
        }
        let layout = std::alloc::Layout::array::<F>(n).expect("polynomial size");
        // SAFETY: the Montgomery representation of zero is the all-zero bit pattern, so a zeroed
        // allocation of `n` elements is a valid `Vec<F>` of zeros; the allocation is owned by the
        // returned Vec with the same layout the global allocator will free it with.
        unsafe {
            let ptr = crate::base::wasm::alloc_zeroed(layout) as *mut F;
            if ptr.is_null() {
                std::alloc::handle_alloc_error(layout);
            }
            Vec::from_raw_parts(ptr, n, n)
        }
    }
}

// ---- integer / byte helpers on the canonical representation ----

/// Invert every non-zero element with one field inversion (zeros stay zero), as bb's `batch_invert`.
/// Small batches invert serially: ark's parallel `batch_inversion` splits even tiny inputs into
/// one chunk per thread, paying a real inversion and a rayon dispatch per chunk.
pub fn batch_invert<F: PrimeField>(v: &mut [F]) {
    if v.len() < 4096 {
        ark_ff::serial_batch_inversion_and_mul(v, &F::one());
    } else {
        ark_ff::batch_inversion(v);
    }
}

/// Element-wise inversion, so each chunk runs the Montgomery batch trick independently on the pool
/// (bb inverts its grand-product denominators in parallel). Bit-identical to `batch_invert`.
pub fn batch_invert_par<F: PrimeField + Send + Sync>(v: &mut [F]) {
    use rayon::prelude::*;
    if v.len() < 8192 {
        batch_invert(v);
        return;
    }
    let chunk = v.len().div_ceil(rayon::current_num_threads().max(1)).max(4096);
    v.par_chunks_mut(chunk).for_each(ark_ff::batch_inversion);
}

/// The grand product `out[i] = ∏_{j<=i} num_j / den_j` (bb `compute_grand_product`), where
/// `terms(lo, num, den)` fills rows `lo..lo + num.len()`. Each thread fills its chunk with `num`
/// in place, batch-inverts its `den`, and forms the running product of the ratios; a scan over
/// the chunk totals then scales every later chunk. A zero `den` zeroes every later entry.
pub fn grand_product_par<F: PrimeField + Send + Sync>(
    out: &mut [F],
    terms: impl Fn(usize, &mut [F], &mut [F]) + Sync,
) {
    use rayon::prelude::*;
    let chunk = out.len().div_ceil(rayon::current_num_threads()).max(1024);
    let totals: Vec<F> = out
        .par_chunks_mut(chunk)
        .enumerate()
        .map(|(b, o)| {
            let mut den = vec![F::zero(); o.len()];
            terms(b * chunk, o, &mut den);
            ark_ff::serial_batch_inversion_and_mul(&mut den, &F::one());
            let mut run = F::one();
            for (x, d) in o.iter_mut().zip(&den) {
                run *= *x * d;
                *x = run;
            }
            run
        })
        .collect();
    let mut scale = vec![F::one(); totals.len()];
    for b in 1..totals.len() {
        scale[b] = scale[b - 1] * totals[b - 1];
    }
    out.par_chunks_mut(chunk).zip(scale).skip(1).for_each(|(o, s)| o.iter_mut().for_each(|x| *x *= s));
}

/// `v mod p` for a little-endian integer of at most four limbs, reduced by subtracting the
/// modulus (a few times at most for 254-bit fields): ark's `from_le_bytes_mod_order` and
/// `From<BigUint>` go byte by byte through field multiplications.
pub fn from_limbs_mod_order<F: PrimeField>(v: impl IntoIterator<Item = u64>) -> F {
    let mut x = F::BigInt::default();
    for (l, d) in x.as_mut().iter_mut().zip(v) {
        *l = d;
    }
    while x >= F::MODULUS {
        x.sub_with_borrow(&F::MODULUS);
    }
    F::from_bigint(x).unwrap()
}

/// The field images of an ascending run of small integers (sorted range-constraint lists): each
/// is the previous plus a table constant when the step is small, instead of a Montgomery conversion.
pub fn ascending_to_fr(values: impl IntoIterator<Item = u64>) -> impl Iterator<Item = Fr> {
    values.into_iter().scan((0u64, Fr::zero()), |(prev, value), v| {
        *value = if v >= *prev && v - *prev < 64 { *value + Fr::small(v - *prev) } else { Fr::small(v) };
        *prev = v;
        Some(*value)
    })
}

pub fn u256<F: PrimeField<BigInt = U256>>(f: &F) -> U256 {
    f.into_bigint()
}

/// Panics if `v >= modulus` (bb asserts the same in its codecs).
pub fn from_u256<F: PrimeField<BigInt = U256>>(v: U256) -> F {
    F::from_bigint(v).expect("value >= field modulus")
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
    // Canonical encodings (every ACIR coefficient, every transcript element) convert with one
    // Montgomery multiplication; ark's mod-order path reduces a full-width input in several.
    let limb = |i: usize| u64::from_be_bytes(bytes[8 * i..8 * i + 8].try_into().unwrap());
    let bi = U256::new([limb(3), limb(2), limb(1), limb(0)]);
    F::from_bigint(bi).unwrap_or_else(|| F::from_be_bytes_mod_order(bytes))
}

pub fn from_hex<F: PrimeField<BigInt = U256>>(s: &str) -> F {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let padded = format!("{s:0>64}");
    let bytes = hex::decode(padded).expect("bad hex");
    F::from_be_bytes_mod_order(&bytes)
}
