//! Every wasm-specific code path of the prover, behind one boundary. On wasm the bn254 fields are
//! bb-ref's own `MontConfig`s (`field.rs`: the 2^261 stored domain and bb's 9×29-bit multiply in
//! `mont29.rs`) and the curves bb-ref's own configs over them (`curves.rs`); with simd128, bb's
//! four-lane kernels (`quad261.rs`) drive the streaming polynomial ops (`packed.rs`) and the MSM
//! tree drain (`tree.rs`). On x86-64 with ADX the fields are `adx.rs`'s (arkworks' constants and
//! stored form, bb's multiply and square) under the same curve configs; every other target uses
//! arkworks' own bn254/grumpkin configs. Callers stay `cfg`-free: the same names exist on every
//! target, and the native fallbacks answer `false`/`None` so the generic scalar paths run.

use crate::base::Fq;

#[cfg(all(target_arch = "x86_64", target_feature = "adx", target_feature = "bmi2"))]
mod adx;
#[cfg(all(target_arch = "wasm32", not(feature = "heap-profile")))]
mod alloc;
#[cfg(all(target_arch = "wasm32", not(feature = "heap-profile")))]
pub use alloc::alloc_zeroed_par as alloc_zeroed;
#[cfg(not(all(target_arch = "wasm32", not(feature = "heap-profile"))))]
pub use std::alloc::alloc_zeroed;
#[cfg(any(
    target_family = "wasm",
    all(target_arch = "x86_64", target_feature = "adx", target_feature = "bmi2")
))]
mod curves;
#[cfg(target_family = "wasm")]
mod field;
#[cfg(target_family = "wasm")]
mod mont29;
#[cfg(all(target_arch = "x86_64", target_feature = "adx", target_feature = "bmi2"))]
pub use adx::{FqConfig, FrConfig};
#[cfg(any(
    target_family = "wasm",
    all(target_arch = "x86_64", target_feature = "adx", target_feature = "bmi2")
))]
pub use curves::{G1Config, GrumpkinConfig};
#[cfg(target_family = "wasm")]
pub use field::{FqConfig, FrConfig};
#[cfg(not(any(
    target_family = "wasm",
    all(target_arch = "x86_64", target_feature = "adx", target_feature = "bmi2")
)))]
pub use {
    ark_bn254::{g1::Config as G1Config, FqConfig, FrConfig},
    ark_grumpkin::GrumpkinConfig,
};

/// Field elements are stored as `a·2^261 mod p` on wasm (`field.rs`) and as `a·2^256 mod p`
/// elsewhere (arkworks' configs).
pub const STORED_DOMAIN_261: bool = cfg!(target_family = "wasm");

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

#[cfg(all(target_family = "wasm", target_feature = "simd128"))]
mod packed;
#[cfg(all(target_family = "wasm", target_feature = "simd128"))]
mod quad261;
#[cfg(all(target_family = "wasm", target_feature = "simd128"))]
mod tree;
#[cfg(all(target_family = "wasm", target_feature = "simd128"))]
pub use {
    packed::{try_axpy, try_fold_from, try_fold_halve, Kc, QuadConsts},
    tree::PackedTree,
};

#[cfg(not(all(target_family = "wasm", target_feature = "simd128")))]
mod fallback;
#[cfg(not(all(target_family = "wasm", target_feature = "simd128")))]
pub use fallback::{try_axpy, try_fold_from, try_fold_halve, PackedTree, QuadConsts};
