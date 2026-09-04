//! Four sumcheck edges per relation evaluation (bb PR06's `Element`-generic round, mapped onto
//! our `FieldLike` genericity): `QuadF<F>` is a 4-lane value, each lane an independent edge's
//! row entry. The relation sets are already generic over `FieldLike`, so `RelationSet<QuadF<F>>`
//! comes for free; the edge loop batches groups of four edges with identical skip patterns and
//! horizontally sums the lane accumulators afterwards — field addition is exact, so the round
//! univariates are bit-identical to the scalar path. This native `[F; 4]` representation is the
//! portable backend (and the byte-gate vehicle); wasm builds swap in the packed 29-bit SIMD
//! kernels behind the same type.

use super::relations::RelationParams;
use crate::base::field::{FieldLike, NativeField};

/// Marker carrying the packed-kernel constants on wasm; a blanket marker elsewhere, so generic
/// code can bound on it unconditionally.
#[cfg(not(all(target_family = "wasm", target_feature = "simd128")))]
pub trait QuadConsts: NativeField {}
#[cfg(not(all(target_family = "wasm", target_feature = "simd128")))]
impl<F: NativeField> QuadConsts for F {}
use std::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

#[cfg(not(all(target_family = "wasm", target_feature = "simd128")))]
mod native_repr {
    use super::*;
    #[derive(Clone, Copy, Debug, PartialEq)]
    pub struct QuadF<F>(pub [F; 4]);

    impl<F: NativeField> QuadF<F> {
        #[inline(always)]
        pub fn splat(v: F) -> Self {
            QuadF([v; 4])
        }
        #[inline(always)]
        pub fn lanes(a: F, b: F, c: F, d: F) -> Self {
            QuadF([a, b, c, d])
        }
        #[inline(always)]
        pub fn hsum(&self) -> F {
            self.0[0] + self.0[1] + self.0[2] + self.0[3]
        }
        /// The four lane values.
        #[inline(always)]
        pub fn to_lanes(&self) -> [F; 4] {
            self.0
        }
    }

    macro_rules! lanewise {
    ($trait:ident, $fn:ident, $op:tt) => {
        impl<F: NativeField> $trait<&QuadF<F>> for QuadF<F> {
            type Output = QuadF<F>;
            #[inline(always)]
            fn $fn(self, rhs: &QuadF<F>) -> QuadF<F> {
                QuadF([
                    self.0[0] $op rhs.0[0],
                    self.0[1] $op rhs.0[1],
                    self.0[2] $op rhs.0[2],
                    self.0[3] $op rhs.0[3],
                ])
            }
        }
        impl<F: NativeField> $trait for QuadF<F> {
            type Output = QuadF<F>;
            #[inline(always)]
            fn $fn(self, rhs: QuadF<F>) -> QuadF<F> {
                $trait::$fn(self, &rhs)
            }
        }
    };
}
    lanewise!(Add, add, +);
    lanewise!(Sub, sub, -);
    lanewise!(Mul, mul, *);

    impl<F: NativeField> Neg for QuadF<F> {
        type Output = QuadF<F>;
        #[inline(always)]
        fn neg(self) -> QuadF<F> {
            QuadF([-self.0[0], -self.0[1], -self.0[2], -self.0[3]])
        }
    }

    macro_rules! lanewise_assign {
    ($trait:ident, $fn:ident, $op:tt) => {
        impl<F: NativeField> $trait<&QuadF<F>> for QuadF<F> {
            #[inline(always)]
            fn $fn(&mut self, rhs: &QuadF<F>) {
                self.0[0] $op rhs.0[0];
                self.0[1] $op rhs.0[1];
                self.0[2] $op rhs.0[2];
                self.0[3] $op rhs.0[3];
            }
        }
        impl<F: NativeField> $trait for QuadF<F> {
            #[inline(always)]
            fn $fn(&mut self, rhs: QuadF<F>) {
                $trait::$fn(self, &rhs);
            }
        }
    };
}
    lanewise_assign!(AddAssign, add_assign, +=);
    lanewise_assign!(SubAssign, sub_assign, -=);
    lanewise_assign!(MulAssign, mul_assign, *=);

    impl<F: NativeField> FieldLike for QuadF<F> {
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
            debug_assert!(self.0[1] == self.0[0] && self.0[2] == self.0[0] && self.0[3] == self.0[0]);
            self.0[0]
        }
        fn invert(&self) -> Self {
            QuadF(core::array::from_fn(|i| {
                ark_ff::Field::inverse(&self.0[i]).unwrap_or(F::ZERO)
            }))
        }
        fn assert_equal(&self, _other: &Self) {}
    }
}
#[cfg(not(all(target_family = "wasm", target_feature = "simd128")))]
pub use native_repr::QuadF;

#[cfg(all(target_family = "wasm", target_feature = "simd128"))]
mod packed_repr;
#[cfg(all(target_family = "wasm", target_feature = "simd128"))]
pub use packed_repr::{QuadConsts, QuadF};

/// The relation parameters broadcast into quad lanes.
pub fn lift_params_quad<F: NativeField + QuadConsts>(p: &RelationParams<F>) -> RelationParams<QuadF<F>> {
    let c = |v: &F| QuadF::splat(*v);
    RelationParams {
        eta: c(&p.eta),
        eta_two: c(&p.eta_two),
        eta_three: c(&p.eta_three),
        rom_logup_gamma: c(&p.rom_logup_gamma),
        beta: c(&p.beta),
        gamma: c(&p.gamma),
        public_input_delta: c(&p.public_input_delta),
        beta_sqr: c(&p.beta_sqr),
        beta_cube: c(&p.beta_cube),
        beta_quartic: c(&p.beta_quartic),
        eccvm_set_permutation_delta: c(&p.eccvm_set_permutation_delta),
        evaluation_input_x: std::array::from_fn(|i| c(&p.evaluation_input_x[i])),
        batching_challenge_v: std::array::from_fn(|i| std::array::from_fn(|j| c(&p.batching_challenge_v[i][j]))),
        accumulated_result: std::array::from_fn(|i| c(&p.accumulated_result[i])),
    }
}
