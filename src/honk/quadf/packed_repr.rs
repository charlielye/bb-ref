//! wasm+simd128 representation of [`QuadF`]: four lanes packed in the 29-bit-limb layout,
//! values kept in the 2^261 Montgomery domain, which is closed under the `quad261` kernel's
//! multiply (X·Y/2^261 stays ·2^261). Boundary crossings shift domains with one kernel multiply
//! by the plain integers 2^266 (in: ·2^256 → ·2^261 while packing stored ark values) and
//! 2^256 (out: back to stored form). Lanes are coarse [0, 2p); unpack canonicalizes.

use super::{FieldLike, NativeField};
use ark_ff::fields::models::fp::montgomery_backend::quad261;
use ark_ff::fields::models::fp::montgomery_backend::wasm_mont;
use std::marker::PhantomData;
use std::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use std::sync::LazyLock;

/// Prepared per-field kernel constants.
pub struct Kc {
    pub c: quad261::Consts,
    pub p29: [u64; 9],
    /// 2^266 mod p and 2^256 mod p, packed as plain integers (the domain-shift multipliers).
    pub c266: quad261::QuadFp,
    pub c256: quad261::QuadFp,
    pub modulus: [u64; 4],
}

unsafe impl Send for Kc {}
unsafe impl Sync for Kc {}

fn make_kc(modulus: [u64; 4], rinv29: [u32; 9], c266: [u64; 4], c256: [u64; 4]) -> Kc {
    let p29 = wasm_mont::to29(&modulus);
    let inv = wasm_mont::inv29(p29[0]);
    Kc {
        c: quad261::Consts::new(&rinv29, &p29, inv),
        p29,
        c266: quad261::QuadFp::pack(&[c266; 4]),
        c256: quad261::QuadFp::pack(&[c256; 4]),
        modulus,
    }
}

pub trait QuadConsts: NativeField {
    fn kc() -> &'static Kc;
}

impl QuadConsts for crate::base::Fr {
    fn kc() -> &'static Kc {
        static K: LazyLock<Kc> = LazyLock::new(|| {
            make_kc(
                [
                    0x43e1f593f0000001,
                    0x2833e84879b97091,
                    0xb85045b68181585d,
                    0x30644e72e131a029,
                ],
                wasm_mont::FR_RINV29,
                [
                    0x97aa889e8fffead7,
                    0x4da1da684b110e2a,
                    0xe56cdd25a60934c8,
                    0x5800320dce9ed32,
                ],
                [
                    0xac96341c4ffffffb,
                    0x36fc76959f60cd29,
                    0x666ea36f7879462e,
                    0xe0a77c19a07df2f,
                ],
            )
        });
        &K
    }
}

impl QuadConsts for ark_bn254::Fq {
    fn kc() -> &'static Kc {
        static K: LazyLock<Kc> = LazyLock::new(|| {
            make_kc(
                [
                    0x3c208c16d87cfd47,
                    0x97816a916871ca8d,
                    0xb85045b68181585d,
                    0x30644e72e131a029,
                ],
                wasm_mont::FQ_RINV29,
                [
                    0xb34bb09513349ca1,
                    0x1e880124f028f972,
                    0xe56cdd25a6092b95,
                    0x5800320dce9ed32,
                ],
                [
                    0xd35d438dc58f0d9d,
                    0xa78eb28f5c70b3d,
                    0x666ea36f7879462c,
                    0xe0a77c19a07df2f,
                ],
            )
        });
        &K
    }
}

pub struct QuadF<F>(pub quad261::QuadFp, PhantomData<F>);

impl<F> Clone for QuadF<F> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<F> Copy for QuadF<F> {}
impl<F> std::fmt::Debug for QuadF<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "QuadF(packed)")
    }
}

#[inline(always)]
fn stored<F: NativeField>(x: F) -> [u64; 4] {
    // Fp<_, 4> is repr-equivalent to its 4x64 Montgomery limbs.
    unsafe { core::mem::transmute_copy::<F, [u64; 4]>(&x) }
}
#[inline(always)]
fn unstored<F: NativeField>(limbs: [u64; 4]) -> F {
    unsafe { core::mem::transmute_copy::<[u64; 4], F>(&limbs) }
}

impl<F: QuadConsts> QuadF<F> {
    #[inline(always)]
    pub fn splat(v: F) -> Self {
        Self::lanes(v, v, v, v)
    }
    #[inline]
    pub fn lanes(a: F, b: F, c: F, d: F) -> Self {
        let kc = F::kc();
        let raw = quad261::QuadFp::pack(&[stored(a), stored(b), stored(c), stored(d)]);
        QuadF(quad261::mont_mul(&raw, &kc.c266, &kc.c), PhantomData)
    }
    #[inline]
    fn to_stored(&self) -> [[u64; 4]; 4] {
        let kc = F::kc();
        quad261::mont_mul(&self.0, &kc.c256, &kc.c).unpack(&kc.modulus)
    }
    #[inline]
    pub fn hsum(&self) -> F {
        let s = self.to_stored();
        unstored::<F>(s[0]) + unstored::<F>(s[1]) + unstored::<F>(s[2]) + unstored::<F>(s[3])
    }
}

impl<F: QuadConsts> PartialEq for QuadF<F> {
    fn eq(&self, other: &Self) -> bool {
        self.to_stored() == other.to_stored()
    }
}

impl<F: QuadConsts> Add<&QuadF<F>> for QuadF<F> {
    type Output = QuadF<F>;
    #[inline(always)]
    fn add(self, rhs: &QuadF<F>) -> QuadF<F> {
        let kc = F::kc();
        QuadF(quad261::add(&self.0, &rhs.0, &kc.c), PhantomData)
    }
}
impl<F: QuadConsts> Sub<&QuadF<F>> for QuadF<F> {
    type Output = QuadF<F>;
    #[inline(always)]
    fn sub(self, rhs: &QuadF<F>) -> QuadF<F> {
        let kc = F::kc();
        QuadF(quad261::sub(&self.0, &rhs.0, &kc.c), PhantomData)
    }
}
impl<F: QuadConsts> Mul<&QuadF<F>> for QuadF<F> {
    type Output = QuadF<F>;
    #[inline(always)]
    fn mul(self, rhs: &QuadF<F>) -> QuadF<F> {
        QuadF(quad261::mont_mul(&self.0, &rhs.0, &F::kc().c), PhantomData)
    }
}
macro_rules! byval {
    ($t:ident, $f:ident) => {
        impl<F: QuadConsts> $t for QuadF<F> {
            type Output = QuadF<F>;
            #[inline(always)]
            fn $f(self, rhs: QuadF<F>) -> QuadF<F> {
                $t::$f(self, &rhs)
            }
        }
    };
}
byval!(Add, add);
byval!(Sub, sub);
byval!(Mul, mul);

impl<F: QuadConsts> Neg for QuadF<F> {
    type Output = QuadF<F>;
    #[inline(always)]
    fn neg(self) -> QuadF<F> {
        let kc = F::kc();
        let zero = quad261::QuadFp::pack(&[[0u64; 4]; 4]);
        QuadF(quad261::sub(&zero, &self.0, &kc.c), PhantomData)
    }
}
macro_rules! opassign {
    ($t:ident, $f:ident, $base:ident, $bf:ident) => {
        impl<F: QuadConsts> $t<&QuadF<F>> for QuadF<F> {
            #[inline(always)]
            fn $f(&mut self, rhs: &QuadF<F>) {
                *self = $base::$bf(*self, rhs);
            }
        }
        impl<F: QuadConsts> $t for QuadF<F> {
            #[inline(always)]
            fn $f(&mut self, rhs: QuadF<F>) {
                *self = $base::$bf(*self, &rhs);
            }
        }
    };
}
opassign!(AddAssign, add_assign, Add, add);
opassign!(SubAssign, sub_assign, Sub, sub);
opassign!(MulAssign, mul_assign, Mul, mul);

impl<F: QuadConsts> FieldLike for QuadF<F> {
    type Native = F;
    type Ctx = ();

    fn ctx(&self) -> Option<()> {
        None
    }
    fn constant(v: F) -> Self {
        QuadF::splat(v)
    }
    fn from_witness(_ctx: &(), _v: F) -> Self {
        unreachable!("quad lanes are a native prover representation")
    }
    fn value(&self) -> F {
        unstored::<F>(self.to_stored()[0])
    }
    fn invert(&self) -> Self {
        let s = self.to_stored();
        let inv = |l: [u64; 4]| {
            let x: F = unstored(l);
            ark_ff::Field::inverse(&x).unwrap_or(F::ZERO)
        };
        Self::lanes(inv(s[0]), inv(s[1]), inv(s[2]), inv(s[3]))
    }
    fn assert_equal(&self, _other: &Self) {}
}
