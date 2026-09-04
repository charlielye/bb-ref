//! wasm+simd128 representation of [`QuadF`]: four lanes packed in the 29-bit-limb layout.
//! The wasm stored form is already the 2^261 Montgomery domain (see the vendored backend), which
//! is closed under the `quad261` kernel's multiply, so pack/unpack are pure SIMD transposes with
//! no domain shift. Lanes are canonical [0, p) on entry; kernel outputs are coarse [0, 2p) and
//! unpack canonicalizes.

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
    pub modulus: [u64; 4],
}

unsafe impl Send for Kc {}
unsafe impl Sync for Kc {}

fn make_kc(modulus: [u64; 4], rinv29: [u32; 9]) -> Kc {
    let p29 = wasm_mont::to29(&modulus);
    let inv = wasm_mont::inv29(p29[0]);
    Kc {
        c: quad261::Consts::new(&rinv29, &p29, inv),
        p29,
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
        QuadF(quad261::QuadFp::pack(&[stored(a), stored(b), stored(c), stored(d)]), PhantomData)
    }
    #[inline]
    fn to_stored(&self) -> [[u64; 4]; 4] {
        self.0.unpack(&F::kc().modulus)
    }
    #[inline]
    pub fn hsum(&self) -> F {
        let s = self.to_stored();
        unstored::<F>(s[0]) + unstored::<F>(s[1]) + unstored::<F>(s[2]) + unstored::<F>(s[3])
    }
    /// The four lane values, canonical.
    #[inline]
    pub fn to_lanes(&self) -> [F; 4] {
        let s = self.to_stored();
        [unstored(s[0]), unstored(s[1]), unstored(s[2]), unstored(s[3])]
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
