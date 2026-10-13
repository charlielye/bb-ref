//! Packed streaming kernels over stored field slices (wasm+simd128). The stored form is the 2^261
//! Montgomery domain, so packing is a pure SIMD transpose and the `quad261` kernels apply
//! directly; callers in generic code dispatch by `TypeId` (only bn254 Fr/Fq have packed forms)
//! and fall back to their scalar loops otherwise.

use super::mont29;
use super::quad261::{self, QuadFp};
use crate::base::field::NativeField;
use crate::base::{Fq, Fr};
use core::any::TypeId;
use core::mem::MaybeUninit;
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
    let p29 = mont29::to29(&modulus);
    let inv = mont29::inv29(p29[0]);
    Kc {
        c: quad261::Consts::new(&rinv29, &p29, inv),
        p29,
        modulus,
    }
}

/// The fields whose kernel constants are prepared: bn254 Fr and Fq.
pub trait QuadConsts: NativeField {
    fn kc() -> &'static Kc;
}
impl QuadConsts for Fr {
    fn kc() -> &'static Kc {
        static K: LazyLock<Kc> = LazyLock::new(|| {
            make_kc(
                [
                    0x43e1f593f0000001,
                    0x2833e84879b97091,
                    0xb85045b68181585d,
                    0x30644e72e131a029,
                ],
                quad261::FR_RINV29,
            )
        });
        &K
    }
}
impl QuadConsts for Fq {
    fn kc() -> &'static Kc {
        static K: LazyLock<Kc> = LazyLock::new(|| {
            make_kc(
                [
                    0x3c208c16d87cfd47,
                    0x97816a916871ca8d,
                    0xb85045b68181585d,
                    0x30644e72e131a029,
                ],
                quad261::FQ_RINV29,
            )
        });
        &K
    }
}

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
        // Selector columns are mostly zero inside their backing range: skip all-zero groups.
        let w = unsafe { &*(src.as_ptr().add(4 * g) as *const [u64; 16]) };
        if w.iter().fold(0, |a, b| a | b) == 0 {
            continue;
        }
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

/// The fold of the 8 values at `base..base + 8` into 4: `a + u·(b − a)` per pair, or the evens
/// unchanged when every pair is bit-identical (constant selector runs, zero padding; golf 0053).
#[inline(always)]
fn fold4<F: QuadConsts>(v: &[F], base: usize, usplat: &QuadFp) -> [F; 4] {
    let w = unsafe { &*(v.as_ptr().add(base) as *const [[u64; 8]; 4]) };
    if w.iter().all(|p| p[..4] == p[4..]) {
        return core::array::from_fn(|l| v[base + 2 * l]);
    }
    let kc = F::kc();
    let even = pack4_stride2(v, base);
    let odd = pack4_stride2(v, base + 1);
    let d = quad261::sub(&odd, &even, &kc.c);
    let s = quad261::add(&even, &quad261::mont_mul(&d, usplat, &kc.c), &kc.c).unpack(&kc.modulus);
    s.map(|x| unsafe { core::mem::transmute_copy::<[u64; 4], F>(&x) })
}

fn fold_halve<F: QuadConsts>(v: &mut Vec<F>, u: &F) {
    let usplat = QuadFp::pack(&[stored(u); 4]);
    let len = v.len();
    let half = len.div_ceil(2);
    let full = if len % 2 == 0 {
        half / 4
    } else {
        half.saturating_sub(1) / 4
    };
    for g in 0..full {
        let r = fold4(v, 8 * g, &usplat);
        v[4 * g..4 * g + 4].copy_from_slice(&r);
    }
    for k in 4 * full..half {
        let a = v[2 * k];
        let b = if 2 * k + 1 < len { v[2 * k + 1] } else { F::ZERO };
        v[k] = a + (b - a) * *u;
    }
    v.truncate(half);
}

fn fold_from<F: QuadConsts>(src: &[F], len: usize, u: &F) -> Vec<F> {
    let usplat = QuadFp::pack(&[stored(u); 4]);
    let half = len.div_ceil(2);
    debug_assert!(len >= src.len());
    // Packed over groups whose 8 source elements are all inside `src`; `len >= src.len()` makes
    // `4 * full <= half`.
    let full = src.len() / 8;
    let mut out = Vec::with_capacity(half);
    for g in 0..full {
        out.extend_from_slice(&fold4(src, 8 * g, &usplat));
    }
    let at = |i: usize| if i < src.len() { src[i] } else { F::ZERO };
    for k in out.len()..half {
        let a = at(2 * k);
        out.push(a + (at(2 * k + 1) - a) * *u);
    }
    out
}

/// The fold of `src` (even length) into `dst` (half its length); false if `F` has no packed form.
pub fn try_fold_into<F: 'static>(src: &[F], dst: &mut [MaybeUninit<F>], u: &F) -> bool {
    fn go<G: QuadConsts>(src: &[G], dst: &mut [MaybeUninit<G>], u: &G) {
        let usplat = QuadFp::pack(&[stored(u); 4]);
        let full = dst.len() / 4;
        for g in 0..full {
            for (d, x) in dst[4 * g..4 * g + 4].iter_mut().zip(fold4(src, 8 * g, &usplat)) {
                d.write(x);
            }
        }
        for k in 4 * full..dst.len() {
            let a = src[2 * k];
            dst[k].write(a + (src[2 * k + 1] - a) * *u);
        }
    }
    assert_eq!(src.len(), 2 * dst.len());
    let dst = dst as *mut [MaybeUninit<F>];
    if TypeId::of::<F>() == TypeId::of::<Fr>() {
        go::<Fr>(reslice_ref(src), unsafe { &mut *(dst as *mut [MaybeUninit<Fr>]) }, &stored_as(u));
        return true;
    }
    if TypeId::of::<F>() == TypeId::of::<Fq>() {
        go::<Fq>(reslice_ref(src), unsafe { &mut *(dst as *mut [MaybeUninit<Fq>]) }, &stored_as(u));
        return true;
    }
    false
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
            // Zero groups and identical pairs in the first rows take the skips.
            let mut a: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
            let b: Vec<Fr> = (0..n).map(|i| if i < 8 { Fr::ZERO } else { Fr::rand(&mut rng) }).collect();
            let s = Fr::rand(&mut rng);
            let mut expect = a.clone();
            for i in 0..n {
                expect[i] += b[i] * s;
            }
            assert!(try_axpy(&mut a, &b, &s));
            assert_eq!(a, expect, "axpy n={n}");

            let mut v: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
            for k in 0..(n / 2).min(4) {
                v[2 * k + 1] = v[2 * k];
            }
            let u = Fr::rand(&mut rng);
            let at = |i: usize| if i < n { v[i] } else { Fr::ZERO };
            let expect: Vec<Fr> = (0..n.div_ceil(2)).map(|k| at(2 * k) + (at(2 * k + 1) - at(2 * k)) * u).collect();
            assert_eq!(try_fold_from(&v, n, &u).unwrap(), expect, "fold_from n={n}");
            if n % 2 == 0 {
                let mut out = Vec::with_capacity(n / 2);
                assert!(try_fold_into(&v, &mut out.spare_capacity_mut()[..n / 2], &u));
                unsafe { out.set_len(n / 2) };
                assert_eq!(out, expect, "fold_into n={n}");
            }
            assert!(try_fold_halve(&mut v, &u));
            assert_eq!(v, expect, "fold n={n}");
        }
    }
}
