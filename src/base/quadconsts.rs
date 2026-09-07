//! Marker for the fields whose wasm SIMD kernel constants are prepared: the packed 29-bit `axpy`
//! and fold kernels (`base/packed.rs`) and the MSM drain bound on it. On other targets it is a
//! blanket marker so generic code can require it unconditionally.
use crate::base::field::NativeField;

#[cfg(not(all(target_family = "wasm", target_feature = "simd128")))]
pub trait QuadConsts: NativeField {}
#[cfg(not(all(target_family = "wasm", target_feature = "simd128")))]
impl<F: NativeField> QuadConsts for F {}

#[cfg(all(target_family = "wasm", target_feature = "simd128"))]
pub use packed::{Kc, QuadConsts};

#[cfg(all(target_family = "wasm", target_feature = "simd128"))]
mod packed {
    use super::NativeField;
    use ark_ff::fields::models::fp::montgomery_backend::quad261;
    use ark_ff::fields::models::fp::montgomery_backend::wasm_mont;
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
                    [0x43e1f593f0000001, 0x2833e84879b97091, 0xb85045b68181585d, 0x30644e72e131a029],
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
                    [0x3c208c16d87cfd47, 0x97816a916871ca8d, 0xb85045b68181585d, 0x30644e72e131a029],
                    wasm_mont::FQ_RINV29,
                )
            });
            &K
        }
    }
}
