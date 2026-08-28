//! Serialization of transcript objects into field elements (bb `FrCodec`) and conversion of raw
//! challenge hashes into typed challenges.

use super::field::FieldLike as FL;
use super::field::{from_u256, u256, u256_low_bits, u256_num_bits, u256_shr, u256_to_u64, Fq, Fr, U256};
use super::group::{G1Affine, GrumpkinAffine};
use ark_ec::AffineRepr;
use ark_ff::BigInteger;

/// Limb width of the in-circuit bigfield simulation; determines the 2-limb split of base-field values.
pub const NUM_LIMB_BITS: u32 = 68;
const LOWER_BITS: u32 = 2 * NUM_LIMB_BITS; // 136
const TOTAL_BITS: u32 = 254;

/// The transcript's word type: a field element natively (`Fr`, `FieldT`) or a raw 256-bit integer
/// for the Keccak transcript (bb `Codec::DataType`).
pub trait TranscriptData: Clone + PartialEq + std::fmt::Debug {
    /// In-circuit: a copy constraint binding two transcript words (bb `assert_equal`); native: no-op.
    fn assert_equal(&self, _other: &Self) {}
}
impl TranscriptData for Fr {}
impl TranscriptData for U256 {}

pub trait Transcriptable<TF: TranscriptData>: Sized {
    fn num_fields() -> usize;
    fn to_fields(&self) -> Vec<TF>;
    fn from_fields(fields: &[TF]) -> Self;
}

pub trait FromChallenge<TF: TranscriptData>: Sized {
    /// From a full-width (~254-bit) hash output.
    fn full(c: TF) -> Self;
    /// From a 127-bit limb of a split hash output.
    fn short(c: TF) -> Self;
}

/// Splitting a hash output into two 127-bit halves (natively arithmetic; in-circuit a range-gated
/// decomposition).
pub trait ChallengeField: TranscriptData {
    fn split_challenge(&self) -> [Self; 2];
}

impl ChallengeField for Fr {
    fn split_challenge(&self) -> [Self; 2] {
        let u = u256(self);
        let lo = u256_low_bits(u, 127);
        let hi = u256_shr(u, 127);
        [from_u256(lo), from_u256(hi)]
    }
}

impl Transcriptable<Fr> for Fr {
    fn num_fields() -> usize {
        1
    }
    fn to_fields(&self) -> Vec<Fr> {
        vec![*self]
    }
    fn from_fields(f: &[Fr]) -> Self {
        f[0]
    }
}

macro_rules! int_transcriptable {
    ($t:ty) => {
        impl Transcriptable<Fr> for $t {
            fn num_fields() -> usize {
                1
            }
            fn to_fields(&self) -> Vec<Fr> {
                vec![Fr::from(*self as u64)]
            }
            fn from_fields(f: &[Fr]) -> Self {
                u256_to_u64(&u256(&f[0])) as $t
            }
        }
    };
}
int_transcriptable!(u64);
int_transcriptable!(u32);

impl Transcriptable<Fr> for bool {
    fn num_fields() -> usize {
        1
    }
    fn to_fields(&self) -> Vec<Fr> {
        vec![Fr::from(*self as u64)]
    }
    fn from_fields(f: &[Fr]) -> Self {
        !<Fr as FL>::is_zero(&f[0])
    }
}

/// A base-field element is sent as `[v mod 2^136, v >> 136]`, mirroring the stdlib bigfield limbs.
impl Transcriptable<Fr> for Fq {
    fn num_fields() -> usize {
        2
    }
    fn to_fields(&self) -> Vec<Fr> {
        let v = u256(self);
        vec![
            from_u256(u256_low_bits(v, LOWER_BITS)),
            from_u256(u256_shr(v, LOWER_BITS)),
        ]
    }
    fn from_fields(f: &[Fr]) -> Self {
        let lo = u256(&f[0]);
        let hi = u256(&f[1]);
        assert!(u256_num_bits(&lo) <= LOWER_BITS, "fq limb 0 out of range");
        assert!(u256_num_bits(&hi) <= TOTAL_BITS - LOWER_BITS, "fq limb 1 out of range");
        let mut v: U256 = hi << LOWER_BITS;
        let overflow = v.add_with_carry(&lo);
        assert!(!overflow);
        from_u256(v) // panics if >= fq modulus (non-canonical), as bb does
    }
}

/// bn254 G1: `[x_lo, x_hi, y_lo, y_hi]`; the point at infinity is all zeros.
impl Transcriptable<Fr> for G1Affine {
    fn num_fields() -> usize {
        4
    }
    fn to_fields(&self) -> Vec<Fr> {
        match self.xy() {
            None => vec![<Fr as FL>::zero(); 4],
            Some((x, y)) => [x.to_fields(), y.to_fields()].concat(),
        }
    }
    fn from_fields(f: &[Fr]) -> Self {
        if f.iter().all(<Fr as FL>::is_zero) {
            return G1Affine::identity();
        }
        let p = G1Affine::new_unchecked(Fq::from_fields(&f[0..2]), Fq::from_fields(&f[2..4]));
        assert!(p.is_on_curve(), "deserialized point is not on the curve");
        p
    }
}

/// Grumpkin G1: coordinates are bn254 Fr, so `[x, y]`; infinity is `(0, 0)`.
impl Transcriptable<Fr> for GrumpkinAffine {
    fn num_fields() -> usize {
        2
    }
    fn to_fields(&self) -> Vec<Fr> {
        match self.xy() {
            None => vec![<Fr as FL>::zero(); 2],
            Some((x, y)) => vec![x, y],
        }
    }
    fn from_fields(f: &[Fr]) -> Self {
        if <Fr as FL>::is_zero(&f[0]) && <Fr as FL>::is_zero(&f[1]) {
            return GrumpkinAffine::identity();
        }
        let p = GrumpkinAffine::new_unchecked(f[0], f[1]);
        assert!(p.is_on_curve(), "deserialized point is not on the curve");
        p
    }
}

impl<TF: TranscriptData, T: Transcriptable<TF>, const N: usize> Transcriptable<TF> for [T; N] {
    fn num_fields() -> usize {
        N * T::num_fields()
    }
    fn to_fields(&self) -> Vec<TF> {
        self.iter().flat_map(|x| x.to_fields()).collect()
    }
    fn from_fields(f: &[TF]) -> Self {
        let n = T::num_fields();
        std::array::from_fn(|i| T::from_fields(&f[i * n..(i + 1) * n]))
    }
}

impl FromChallenge<Fr> for Fr {
    fn full(c: Fr) -> Self {
        c
    }
    fn short(c: Fr) -> Self {
        c
    }
}

/// bn254 Fr challenges reinterpret exactly as Fq (r < q).
impl FromChallenge<Fr> for Fq {
    fn full(c: Fr) -> Self {
        from_u256(u256(&c))
    }
    fn short(c: Fr) -> Self {
        assert!(u256_num_bits(&u256(&c)) <= LOWER_BITS);
        from_u256(u256(&c))
    }
}

/// Helper for values that are natively integers but travel as field elements.
pub fn fr_to_usize(f: &Fr) -> usize {
    u256_to_u64(&u256(f)) as usize
}

// ---- Keccak transcript (bb `U256Codec`): words are raw 256-bit integers ----

impl Transcriptable<U256> for U256 {
    fn num_fields() -> usize {
        1
    }
    fn to_fields(&self) -> Vec<U256> {
        vec![*self]
    }
    fn from_fields(f: &[U256]) -> Self {
        f[0]
    }
}

impl Transcriptable<U256> for Fr {
    fn num_fields() -> usize {
        1
    }
    fn to_fields(&self) -> Vec<U256> {
        vec![u256(self)]
    }
    fn from_fields(f: &[U256]) -> Self {
        // bb asserts canonicity: value < r.
        assert!(f[0] < <Fr as ark_ff::PrimeField>::MODULUS, "non-canonical scalar in keccak proof");
        from_u256(f[0])
    }
}

macro_rules! int_u256_transcriptable {
    ($t:ty) => {
        impl Transcriptable<U256> for $t {
            fn num_fields() -> usize {
                1
            }
            fn to_fields(&self) -> Vec<U256> {
                vec![U256::from(*self as u64)]
            }
            fn from_fields(f: &[U256]) -> Self {
                u256_to_u64(&f[0]) as $t
            }
        }
    };
}
int_u256_transcriptable!(u64);
int_u256_transcriptable!(u32);

impl Transcriptable<U256> for bool {
    fn num_fields() -> usize {
        1
    }
    fn to_fields(&self) -> Vec<U256> {
        vec![U256::from(*self as u64)]
    }
    fn from_fields(f: &[U256]) -> Self {
        f[0] != U256::from(0u64)
    }
}

/// bn254 G1 under `U256Codec`: `[x, y]` as full-width base-field values; infinity is `(0, 0)`.
impl Transcriptable<U256> for G1Affine {
    fn num_fields() -> usize {
        2
    }
    fn to_fields(&self) -> Vec<U256> {
        match self.xy() {
            None => vec![U256::from(0u64); 2],
            Some((x, y)) => vec![u256(&x), u256(&y)],
        }
    }
    fn from_fields(f: &[U256]) -> Self {
        if f[0] == U256::from(0u64) && f[1] == U256::from(0u64) {
            return G1Affine::identity();
        }
        assert!(
            f[0] < <Fq as ark_ff::PrimeField>::MODULUS && f[1] < <Fq as ark_ff::PrimeField>::MODULUS,
            "non-canonical base field element in keccak proof"
        );
        let p = G1Affine::new_unchecked(from_u256::<Fq>(f[0]), from_u256::<Fq>(f[1]));
        assert!(p.is_on_curve(), "deserialized point is not on the curve");
        p
    }
}

impl FromChallenge<U256> for Fr {
    fn full(c: U256) -> Self {
        // The keccak challenge is already reduced mod r.
        from_u256(c)
    }
    fn short(c: U256) -> Self {
        from_u256(c)
    }
}

impl ChallengeField for U256 {
    fn split_challenge(&self) -> [Self; 2] {
        [u256_low_bits(*self, 127), u256_shr(*self, 127)]
    }
}
