//! Every wasm-specific code path of the prover, behind one boundary. On wasm the bn254 fields are
//! bb-ref's own `MontConfig`s (`field.rs`: the 2^261 stored domain and bb's 9×29-bit multiply in
//! `mont29.rs`) and the curves bb-ref's own configs over them (`curves.rs`); with simd128, bb's
//! four-lane kernels (`quad261.rs`) drive the streaming polynomial ops (`packed.rs`) and the MSM
//! tree drain (`tree.rs`). On x86-64 with ADX the fields are `adx.rs`'s (arkworks' constants and
//! stored form, bb's multiply and square) and on aarch64 `arm64.rs`'s (the same, with an aarch64
//! multiply), both inverting with `safegcd.rs`, under the same curve configs; every other target
//! uses arkworks' own bn254/grumpkin configs. Callers stay `cfg`-free: the same names exist on every
//! target, and the native fallbacks answer `false`/`None` so the generic scalar paths run.
//! The wide-arithmetic build (`--cfg wasm_wide`, target feature `wide-arithmetic`) replaces the
//! 2^261 field and its four-lane kernels with `wide.rs`'s 4×64 field in arkworks' 2^256 domain
//! and raw-limb loops (`widepacked.rs`, `widetree.rs`) for the folds, axpy, MSM tree and bucket
//! reduction.

use crate::base::Fq;

#[cfg(all(target_arch = "x86_64", target_feature = "adx", target_feature = "bmi2"))]
mod adx;
#[cfg(all(target_arch = "wasm32", not(feature = "heap-profile")))]
mod alloc;
#[cfg(target_arch = "aarch64")]
mod arm64;
#[cfg(any(
    all(target_arch = "x86_64", target_feature = "adx", target_feature = "bmi2"),
    target_arch = "aarch64"
))]
mod safegcd;
#[cfg(not(all(target_arch = "wasm32", not(feature = "heap-profile"))))]
pub use crate::base::pool::alloc_zeroed;
#[cfg(all(target_arch = "wasm32", not(feature = "heap-profile")))]
pub use alloc::alloc_zeroed_par as alloc_zeroed;
#[cfg(target_family = "wasm")]
mod by29;
#[cfg(any(
    target_family = "wasm",
    all(target_arch = "x86_64", target_feature = "adx", target_feature = "bmi2"),
    target_arch = "aarch64"
))]
mod curves;
#[cfg(any(
    target_family = "wasm",
    all(target_arch = "x86_64", target_feature = "adx", target_feature = "bmi2"),
    target_arch = "aarch64"
))]
mod divsteps;
#[cfg(all(target_family = "wasm", wasm_wide))]
mod wide;
#[cfg(all(target_family = "wasm", wasm_wide))]
pub use wide::{FqConfig, FrConfig};
#[cfg(all(target_family = "wasm", not(wasm_wide)))]
mod field;
#[cfg(target_family = "wasm")]
#[cfg_attr(wasm_wide, allow(dead_code))]
mod mont29;
#[cfg(all(target_arch = "x86_64", target_feature = "adx", target_feature = "bmi2"))]
pub use adx::{FqConfig, FrConfig};
#[cfg(target_arch = "aarch64")]
pub use arm64::{FqConfig, FrConfig};
#[cfg(any(
    target_family = "wasm",
    all(target_arch = "x86_64", target_feature = "adx", target_feature = "bmi2"),
    target_arch = "aarch64"
))]
pub use curves::{G1Config, GrumpkinConfig};
#[cfg(all(target_family = "wasm", not(wasm_wide)))]
pub use field::{FqConfig, FrConfig};
#[cfg(not(any(
    target_family = "wasm",
    all(target_arch = "x86_64", target_feature = "adx", target_feature = "bmi2"),
    target_arch = "aarch64"
)))]
pub use {
    ark_bn254::{g1::Config as G1Config, FqConfig, FrConfig},
    ark_grumpkin::GrumpkinConfig,
};

/// Field elements are stored as `a·2^261 mod p` on wasm (`field.rs`) and as `a·2^256 mod p`
/// elsewhere (arkworks' configs).
pub const STORED_DOMAIN_261: bool = cfg!(all(target_family = "wasm", not(wasm_wide)));

/// The four-lane simd128 kernels exist (`packed.rs`, `ipafold.rs`, `tree.rs`).
pub const PACKED: bool = cfg!(all(target_family = "wasm", target_feature = "simd128", not(wasm_wide)));

/// The sumcheck's permutation relation runs on edge lanes: four on simd128 wasm (`perm4.rs`), eight
/// on x86-64 where the CPU has AVX-512 IFMA (`ifma.rs`; `PermLanes::new` checks at run time).
pub const PERM_LANES: bool = PACKED || cfg!(target_arch = "x86_64");

/// The GLV companion table `(β·x, −y)` per SRS point pays off where the per-entry multiply at
/// gather time is the visible cost: wasm only.
pub const GLV_PHI_TABLE: bool = cfg!(target_family = "wasm");

/// Default `log2` of the Pippenger chunk (`BBREF_GLV_LOG2` overrides).
pub const MSM_DEFAULT_LOG2: u32 = if cfg!(target_family = "wasm") { 16 } else { 12 };

/// Pippenger stage-6a sub-chunk (schedule entries tree-reduced together). Each tree level pays one
/// field inversion, ~130 muls on wasm, so wasm amortizes it over twice bb's 2048 (measured −1.5%
/// proving); natively 4096 measured −0.6% wall but +6% storage peak RSS, so it keeps bb's value.
pub const MSM_SUBCHUNK: usize = if cfg!(target_family = "wasm") { 4096 } else { 2048 };

/// The shared SRS cache holds 2^256-domain Montgomery limbs. The multiplier that takes such a limb
/// set, reinterpreted as a stored element, to the value it encodes: `Some(2^5)` where the stored
/// domain is 2^261, `None` where the domains coincide.
pub fn shared_to_stored() -> Option<Fq> {
    STORED_DOMAIN_261.then(|| Fq::from(32u64))
}

/// Inverse of [`shared_to_stored`], for writing the cache.
pub fn stored_to_shared() -> Option<Fq> {
    STORED_DOMAIN_261.then(|| ark_ff::Field::inverse(&Fq::from(32u64)).unwrap())
}

#[cfg(all(target_family = "wasm", target_feature = "simd128", not(wasm_wide)))]
mod ipafold;
#[cfg(all(target_family = "wasm", target_feature = "simd128", not(wasm_wide)))]
mod packed;
#[cfg(all(target_family = "wasm", target_feature = "simd128", not(wasm_wide)))]
mod perm4;
#[cfg(all(target_family = "wasm", target_feature = "simd128", not(wasm_wide)))]
mod quad261;
#[cfg(all(target_family = "wasm", target_feature = "simd128", not(wasm_wide)))]
mod tree;
#[cfg(all(target_family = "wasm", target_feature = "simd128", not(wasm_wide)))]
pub use {
    ipafold::try_fold_two_rounds,
    packed::{try_axpy, try_fold_from, try_fold_halve, try_fold_into, Kc, QuadConsts},
    perm4::{PermLanes, PERM_INPUTS, PERM_POINTS},
    tree::PackedTree,
};

#[cfg(not(all(target_family = "wasm", target_feature = "simd128", not(wasm_wide))))]
mod fallback;
#[cfg(not(any(all(target_family = "wasm", target_feature = "simd128"), wasm_wide)))]
pub use fallback::{try_axpy, try_fold_from, try_fold_halve, try_fold_into, PackedTree};
#[cfg(not(all(target_family = "wasm", target_feature = "simd128", not(wasm_wide))))]
pub use fallback::{try_fold_two_rounds, PermLanes, QuadConsts, PERM_INPUTS, PERM_POINTS};

// The wide-arithmetic build: raw-limb kernels in place of the 2^261 four-lane ones.
#[cfg(wasm_wide)]
mod widepacked;
#[cfg(wasm_wide)]
mod widetree;
#[cfg(wasm_wide)]
pub use {
    widepacked::{try_axpy, try_fold_from, try_fold_halve, try_fold_into},
    widetree::{try_batch_add_indexed, try_batch_double_indexed, PackedTree},
};

/// The bucket reduction's batched affine additions on raw limbs, where a kernel exists (`false`:
/// the generic loop runs).
#[cfg(not(wasm_wide))]
#[inline(always)]
pub fn try_batch_add_indexed<F>(_dx: &mut [F], _dy: &mut [F], _pairs: &[(u32, u32)]) -> bool {
    false
}

/// As `try_batch_add_indexed`, for the doublings.
#[cfg(not(wasm_wide))]
#[inline(always)]
pub fn try_batch_double_indexed<F>(_dx: &mut [F], _dy: &mut [F], _idx: &[u32]) -> bool {
    false
}

#[cfg(all(
    test,
    any(
        all(target_arch = "x86_64", target_feature = "adx", target_feature = "bmi2"),
        target_arch = "aarch64"
    )
))]
/// A native field config limb-for-limb against arkworks' on edge values (0, 1, p−1, p−2, values with all-ones and
/// top-heavy limbs) and random ones.
pub(crate) fn check_against_arkworks<C: ark_ff::MontConfig<4>, A: ark_ff::MontConfig<4>>() {
    use ark_ff::{AdditiveGroup, BigInt, Field, Fp, MontBackend, UniformRand};
    type F<C> = Fp<MontBackend<C, 4>, 4>;
    let m = A::MODULUS.0;
    let mut limbs = vec![
        [0; 4],
        [1, 0, 0, 0],
        [m[0] - 1, m[1], m[2], m[3]],
        [m[0] - 2, m[1], m[2], m[3]],
        [u64::MAX, u64::MAX, u64::MAX, m[3] - 1],
        [0, 0, 0, m[3]],
        [u64::MAX, 0, u64::MAX, 0],
    ];
    let mut rng = ark_std::test_rng();
    limbs.extend((0..2000).map(|_| F::<A>::rand(&mut rng).0 .0));
    for x in &limbs {
        let (ox, ax) = (F::<C>::new_unchecked(BigInt(*x)), F::<A>::new_unchecked(BigInt(*x)));
        assert_eq!(ox.square().0, ax.square().0, "square {x:?}");
        assert_eq!(ox.double().0, ax.double().0, "double {x:?}");
        assert_eq!(ox.inverse().map(|v| v.0), ax.inverse().map(|v| v.0), "inverse {x:?}");
        for y in limbs.iter().step_by(7).chain(&limbs[..7]) {
            let (oy, ay) = (F::<C>::new_unchecked(BigInt(*y)), F::<A>::new_unchecked(BigInt(*y)));
            assert_eq!((ox * oy).0, (ax * ay).0, "mul {x:?} {y:?}");
            assert_eq!((ox + oy).0, (ax + ay).0, "add {x:?} {y:?}");
            assert_eq!((ox - oy).0, (ax - ay).0, "sub {x:?} {y:?}");
        }
    }
}
