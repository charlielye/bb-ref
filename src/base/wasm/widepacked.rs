//! The streaming polynomial kernels of `packed.rs` for the wide-arithmetic build (`wasm_wide`):
//! the same names and skips, one element at a time on raw stored limbs (`wide::raw`), so each
//! loop keeps its operands in locals instead of calling the out-of-line `Fp` multiply.

use super::wide::raw;
use crate::base::{Fq, Fr};
use core::any::TypeId;
use core::mem::MaybeUninit;

#[inline(always)]
fn limbs<F>(x: &F) -> [u64; 4] {
    // Fp<_, 4> is repr-equivalent to its 4x64 stored limbs.
    unsafe { core::mem::transmute_copy::<F, [u64; 4]>(x) }
}

/// `F`'s raw form and `mul` constants, if it is bn254 Fr or Fq.
#[inline(always)]
fn view<F: 'static>(v: &[F]) -> Option<(&[[u64; 4]], [u64; 6])> {
    let m = if TypeId::of::<F>() == TypeId::of::<Fr>() {
        <Fr as ark_ff::PrimeField>::MODULUS.0
    } else if TypeId::of::<F>() == TypeId::of::<Fq>() {
        <Fq as ark_ff::PrimeField>::MODULUS.0
    } else {
        return None;
    };
    Some((unsafe { core::slice::from_raw_parts(v.as_ptr().cast(), v.len()) }, raw::consts(m)))
}

#[inline(always)]
fn view_mut<F: 'static>(v: &mut [F]) -> Option<(&mut [[u64; 4]], [u64; 6])> {
    let p = view(&*v)?.1;
    Some((unsafe { core::slice::from_raw_parts_mut(v.as_mut_ptr().cast(), v.len()) }, p))
}

/// `a + u·(b − a)`, or `a` when the pair is bit-identical (constant runs, zero padding).
#[inline(always)]
fn fold(a: &[u64; 4], b: &[u64; 4], u: &[u64; 4], p: &[u64; 6]) -> [u64; 4] {
    if a == b { *a } else { raw::add(a, &raw::mul(&raw::sub(b, a, p), u, p), p) }
}

/// `dst[i] += s * src[i]` over the overlap; false if `F` has no raw form.
pub fn try_axpy<F: 'static>(dst: &mut [F], src: &[F], s: &F) -> bool {
    let Some((src, p)) = view(src) else { return false };
    let (dst, _) = view_mut(dst).unwrap();
    let s = limbs(s);
    for (d, x) in dst.iter_mut().zip(src) {
        // Selector columns are mostly zero inside their backing range.
        if *x != [0; 4] {
            *d = raw::add(d, &raw::mul(x, &s, &p), &p);
        }
    }
    true
}

/// The fold of `src` (even length) into `dst` (half its length); false if `F` has no raw form.
pub fn try_fold_into<F: 'static>(src: &[F], dst: &mut [MaybeUninit<F>], u: &F) -> bool {
    assert_eq!(src.len(), 2 * dst.len());
    let Some((src, p)) = view(src) else { return false };
    let u = limbs(u);
    for (k, d) in dst.iter_mut().enumerate() {
        let x = fold(&src[2 * k], &src[2 * k + 1], &u, &p);
        d.write(unsafe { core::mem::transmute_copy::<[u64; 4], F>(&x) });
    }
    true
}

/// One fold of a borrowed column (`src` plus virtual zeros up to logical length `len`):
/// `out[k] = a[2k] + u * (a[2k+1] - a[2k])`. None if `F` has no raw form.
pub fn try_fold_from<F: 'static>(src: &[F], len: usize, u: &F) -> Option<Vec<F>> {
    let (s, p) = view(src)?;
    let u = limbs(u);
    let at = |i: usize| s.get(i).copied().unwrap_or([0; 4]);
    let out: Vec<[u64; 4]> = (0..len.div_ceil(2)).map(|k| fold(&at(2 * k), &at(2 * k + 1), &u, &p)).collect();
    Some(unsafe { core::mem::transmute::<Vec<[u64; 4]>, Vec<F>>(out) })
}

/// In-place sumcheck fold `v[k] = v[2k] + u * (v[2k+1] - v[2k])`, halving `v`; false if `F` has
/// no raw form.
pub fn try_fold_halve<F: 'static>(v: &mut Vec<F>, u: &F) -> bool {
    let half = v.len().div_ceil(2);
    let Some((s, p)) = view_mut(v) else { return false };
    let u = limbs(u);
    let n = s.len();
    for k in 0..half {
        let b = if 2 * k + 1 < n { s[2 * k + 1] } else { [0; 4] };
        s[k] = fold(&s[2 * k], &b, &u, &p);
    }
    v.truncate(half);
    true
}
