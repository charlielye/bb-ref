//! Stand-ins for the simd128 kernels on every other target: the same names and signatures,
//! answering "no packed form" so the generic scalar paths run (the folds go to the AVX-512 IFMA
//! kernels, which answer the same way where the CPU lacks them).

use crate::base::field::NativeField;
use ark_ec::short_weierstrass::{Affine, SWCurveConfig};
use core::marker::PhantomData;

/// On simd128 wasm, the fields whose kernel constants exist (bn254 Fr/Fq); here, every field.
pub trait QuadConsts: NativeField {}
impl<F: NativeField> QuadConsts for F {}

#[inline(always)]
pub fn try_axpy<F: 'static>(_dst: &mut [F], _src: &[F], _s: &F) -> bool {
    false
}

pub use crate::base::ifma::{try_fold_from, try_fold_halve, try_fold_into};

/// The packed MSM tree drain; absent here, so `try_reduce` hands every level to the scalar tree.
pub struct PackedTree<P: SWCurveConfig>(PhantomData<P>);

impl<P: SWCurveConfig> PackedTree<P> {
    #[inline(always)]
    pub fn with_capacity(_cap: usize) -> Self {
        PackedTree(PhantomData)
    }

    #[inline(always)]
    pub fn try_reduce(
        &mut self,
        _run_id: &mut Vec<u32>,
        _run_len: &mut Vec<u32>,
        _ps: &mut Vec<Affine<P>>,
        _dens: &mut Vec<P::BaseField>,
        _prod: &mut Vec<P::BaseField>,
    ) -> bool {
        false
    }
}
