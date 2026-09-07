//! Every wasm-specific code path of the prover, behind one boundary. The wasm build stores field
//! elements in the 2^261 Montgomery domain (bb's wasm form; the vendored field kernel) and, with
//! simd128, runs bb's four-lane 29-bit kernels (`quad261`) for the streaming polynomial ops and the
//! MSM tree drain. Callers stay `cfg`-free: the same names exist on every target, and the native
//! fallbacks answer `false`/`None` so the generic scalar paths run.

use crate::base::Fq;

/// Field elements are stored as `a·2^261 mod p` on wasm and as `a·2^256 mod p` elsewhere.
pub const STORED_DOMAIN_261: bool = cfg!(target_family = "wasm");

/// The GLV companion table `(β·x, −y)` per SRS point pays off where the per-entry multiply at
/// gather time is the visible cost: wasm only.
pub const GLV_PHI_TABLE: bool = cfg!(target_family = "wasm");

/// Default `log2` of the Pippenger chunk (`BBREF_GLV_LOG2` overrides).
pub const MSM_DEFAULT_LOG2: u32 = if cfg!(target_family = "wasm") { 16 } else { 15 };

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
