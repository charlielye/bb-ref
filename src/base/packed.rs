//! wasm+simd128 packed streaming kernels over stored field slices. The wasm stored form is the
//! 2^261 Montgomery domain, so packing is a pure SIMD transpose and the quad261 kernels apply
//! directly; callers in generic code dispatch by `TypeId` (only bn254 Fr/Fq have packed forms)
//! and fall back to scalar loops otherwise.

#![cfg(all(target_family = "wasm", target_feature = "simd128"))]

use crate::base::{Fq, Fr};
use crate::honk::quadf::QuadConsts;
use ark_ff::fields::models::fp::montgomery_backend::quad261::{self, QuadFp};
use core::any::TypeId;

#[inline(always)]
fn stored<F>(x: &F) -> [u64; 4] {
    // Fp<_, 4> is repr-equivalent to its 4x64 stored limbs.
    unsafe { core::mem::transmute_copy::<F, [u64; 4]>(x) }
}

#[inline(always)]
fn pack4<F>(v: &[F], at: usize) -> QuadFp {
    QuadFp::pack(unsafe { &*(v.as_ptr().add(at) as *const [[u64; 4]; 4]) })
}

#[inline(always)]
fn pack4_stride2<F>(v: &[F], at: usize) -> QuadFp {
    let g = [
        stored(&v[at]),
        stored(&v[at + 2]),
        stored(&v[at + 4]),
        stored(&v[at + 6]),
    ];
    QuadFp::pack(&g)
}

#[inline(always)]
fn unpack4<F: QuadConsts>(q: &QuadFp, v: &mut [F], at: usize) {
    let s = q.unpack(&F::kc().modulus);
    for l in 0..4 {
        v[at + l] = unsafe { core::mem::transmute_copy::<[u64; 4], F>(&s[l]) };
    }
}

#[inline(always)]
fn reslice<F: 'static, G: 'static>(v: &mut [F]) -> &mut [G] {
    debug_assert_eq!(TypeId::of::<F>(), TypeId::of::<G>());
    unsafe { &mut *(v as *mut [F] as *mut [G]) }
}
#[inline(always)]
fn reslice_ref<F: 'static, G: 'static>(v: &[F]) -> &[G] {
    debug_assert_eq!(TypeId::of::<F>(), TypeId::of::<G>());
    unsafe { &*(v as *const [F] as *const [G]) }
}

fn axpy<F: QuadConsts>(dst: &mut [F], src: &[F], s: &F) {
    let kc = F::kc();
    let splat = QuadFp::pack(&[stored(s); 4]);
    let n = dst.len().min(src.len());
    let groups = n / 4;
    for g in 0..groups {
        let acc = pack4(dst, 4 * g);
        let t = quad261::mont_mul(&pack4(src, 4 * g), &splat, &kc.c);
        unpack4(&quad261::add(&acc, &t, &kc.c), dst, 4 * g);
    }
    for i in 4 * groups..n {
        dst[i] += &(src[i] * s);
    }
}

/// `dst[i] += s * src[i]` over the overlap through the packed kernels; false if `F` has no
/// packed form (caller runs its scalar loop).
pub fn try_axpy<F: 'static>(dst: &mut [F], src: &[F], s: &F) -> bool {
    if TypeId::of::<F>() == TypeId::of::<Fr>() {
        axpy::<Fr>(reslice(dst), reslice_ref(src), &stored_as::<F, Fr>(s));
        return true;
    }
    if TypeId::of::<F>() == TypeId::of::<Fq>() {
        axpy::<Fq>(reslice(dst), reslice_ref(src), &stored_as::<F, Fq>(s));
        return true;
    }
    false
}

#[inline(always)]
fn stored_as<F: 'static, G: 'static>(x: &F) -> G {
    debug_assert_eq!(TypeId::of::<F>(), TypeId::of::<G>());
    unsafe { core::mem::transmute_copy::<F, G>(x) }
}

fn fold_halve<F: QuadConsts>(v: &mut Vec<F>, u: &F) {
    let kc = F::kc();
    let usplat = QuadFp::pack(&[stored(u); 4]);
    let len = v.len();
    let half = len.div_ceil(2);
    let full = if len % 2 == 0 {
        half / 4
    } else {
        half.saturating_sub(1) / 4
    };
    for g in 0..full {
        let base = 8 * g;
        let even = pack4_stride2(v, base);
        let odd = pack4_stride2(v, base + 1);
        let d = quad261::sub(&odd, &even, &kc.c);
        let r = quad261::add(&even, &quad261::mont_mul(&d, &usplat, &kc.c), &kc.c);
        unpack4(&r, v, 4 * g);
    }
    for k in 4 * full..half {
        let a = v[2 * k];
        let b = if 2 * k + 1 < len { v[2 * k + 1] } else { F::ZERO };
        v[k] = a + (b - a) * *u;
    }
    v.truncate(half);
}

fn fold_from<F: QuadConsts>(src: &[F], len: usize, u: &F) -> Vec<F> {
    let kc = F::kc();
    let usplat = QuadFp::pack(&[stored(u); 4]);
    let half = len.div_ceil(2);
    debug_assert!(len >= src.len());
    let mut out = Vec::with_capacity(half);
    // Packed over groups whose 8 source elements are all inside `src`; `len >= src.len()` makes
    // `4 * full <= half`.
    let full = src.len() / 8;
    unsafe { out.set_len(4 * full) };
    for g in 0..full {
        let base = 8 * g;
        let even = pack4_stride2(src, base);
        let odd = pack4_stride2(src, base + 1);
        let d = quad261::sub(&odd, &even, &kc.c);
        let r = quad261::add(&even, &quad261::mont_mul(&d, &usplat, &kc.c), &kc.c);
        unpack4(&r, &mut out, 4 * g);
    }
    let at = |i: usize| if i < src.len() { src[i] } else { F::ZERO };
    for k in out.len()..half {
        let a = at(2 * k);
        out.push(a + (at(2 * k + 1) - a) * *u);
    }
    out
}

/// One fold of a borrowed column (`src` plus virtual zeros up to logical length `len`):
/// `out[k] = a[2k] + u * (a[2k+1] - a[2k])`. None if `F` has no packed form.
pub fn try_fold_from<F: 'static>(src: &[F], len: usize, u: &F) -> Option<Vec<F>> {
    if TypeId::of::<F>() == TypeId::of::<Fr>() {
        let out = fold_from::<Fr>(reslice_ref(src), len, &stored_as::<F, Fr>(u));
        return Some(unsafe { core::mem::transmute::<Vec<Fr>, Vec<F>>(out) });
    }
    if TypeId::of::<F>() == TypeId::of::<Fq>() {
        let out = fold_from::<Fq>(reslice_ref(src), len, &stored_as::<F, Fq>(u));
        return Some(unsafe { core::mem::transmute::<Vec<Fq>, Vec<F>>(out) });
    }
    None
}

/// In-place sumcheck fold `v[k] = v[2k] + u * (v[2k+1] - v[2k])`, halving `v`; false if `F` has
/// no packed form.
pub fn try_fold_halve<F: 'static>(v: &mut Vec<F>, u: &F) -> bool {
    if TypeId::of::<F>() == TypeId::of::<Fr>() {
        let vv = unsafe { &mut *(v as *mut Vec<F> as *mut Vec<Fr>) };
        fold_halve::<Fr>(vv, &stored_as::<F, Fr>(u));
        return true;
    }
    if TypeId::of::<F>() == TypeId::of::<Fq>() {
        let vv = unsafe { &mut *(v as *mut Vec<F> as *mut Vec<Fq>) };
        fold_halve::<Fq>(vv, &stored_as::<F, Fq>(u));
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::{AdditiveGroup, UniformRand};

    #[test]
    fn axpy_and_fold_match_scalar() {
        let mut rng = ark_std::test_rng();
        for n in [1usize, 3, 8, 33, 257] {
            let mut a: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
            let b: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
            let s = Fr::rand(&mut rng);
            let mut expect = a.clone();
            for i in 0..n {
                expect[i] += b[i] * s;
            }
            assert!(try_axpy(&mut a, &b, &s));
            assert_eq!(a, expect, "axpy n={n}");

            let mut v: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
            let u = Fr::rand(&mut rng);
            let mut expect: Vec<Fr> = (0..n.div_ceil(2))
                .map(|k| {
                    let x = v[2 * k];
                    let y = if 2 * k + 1 < n { v[2 * k + 1] } else { Fr::ZERO };
                    x + (y - x) * u
                })
                .collect();
            assert!(try_fold_halve(&mut v, &u));
            assert_eq!(v, expect, "fold n={n}");
            expect.clear();
        }
    }
}
