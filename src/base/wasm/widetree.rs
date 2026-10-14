//! The MSM tree drain for the wide-arithmetic build (`wasm_wide`): the scalar tree level of
//! `base/msm.rs` (`tree_reduce_scalar`) with every field operation a raw kernel on stored limbs
//! (`wide::raw`), so the whole level keeps its operands in locals instead of calling the
//! out-of-line `Fp` operators.

use super::wide::raw;
use ark_ec::short_weierstrass::{Affine, SWCurveConfig};
use ark_ff::{Field, PrimeField};
use core::marker::PhantomData;

#[inline(always)]
fn limbs<F>(x: &F) -> [u64; 4] {
    // Fp<_, 4> is repr-equivalent to its 4x64 stored limbs.
    unsafe { core::mem::transmute_copy::<F, [u64; 4]>(x) }
}

#[inline(always)]
fn elt<F>(x: [u64; 4]) -> F {
    unsafe { core::mem::transmute_copy::<[u64; 4], F>(&x) }
}

/// `msm`'s `batch_affine_add_indexed` on raw limbs: `(x, y)[d] += (x, y)[s]` for every pair (d, s),
/// distinct x, one inversion.
pub fn try_batch_add_indexed<F: PrimeField>(dx: &mut [F], dy: &mut [F], pairs: &[(u32, u32)]) -> bool {
    let p = &raw::consts(limbs(&F::MODULUS));
    let (x, y): (&mut [[u64; 4]], &mut [[u64; 4]]) = unsafe {
        (
            core::slice::from_raw_parts_mut(dx.as_mut_ptr().cast(), dx.len()),
            core::slice::from_raw_parts_mut(dy.as_mut_ptr().cast(), dy.len()),
        )
    };
    // Forward: the slope numerators times the running product of the earlier denominators
    // (montgomery's batchAdd), so the backward pass yields each slope directly.
    let mut den: Vec<[u64; 4]> = Vec::with_capacity(pairs.len());
    let mut acc = limbs(&F::ONE);
    for &(d, s) in pairs {
        let (d, s) = (d as usize, s as usize);
        let dd = raw::sub(&x[d], &x[s], p);
        y[d] = raw::mul(&raw::sub(&y[d], &y[s], p), &acc, p);
        acc = raw::mul(&acc, &dd, p);
        den.push(dd);
    }
    let mut iv = limbs(&elt::<F>(acc).inverse().expect("batch_affine_add_indexed: zero denominator"));
    for (k, &(d, s)) in pairs.iter().enumerate().rev() {
        let (d, s) = (d as usize, s as usize);
        let lambda = raw::mul(&y[d], &iv, p);
        iv = raw::mul(&iv, &den[k], p);
        let x3 = raw::sub(&raw::sub(&raw::mul(&lambda, &lambda, p), &x[d], p), &x[s], p);
        y[d] = raw::sub(&raw::mul(&lambda, &raw::sub(&x[s], &x3, p), p), &y[s], p);
        x[d] = x3;
    }
    true
}

/// `msm`'s `batch_affine_double_indexed` on raw limbs: `(x, y)[k] = 2 (x, y)[k]`, one inversion.
pub fn try_batch_double_indexed<F: PrimeField>(dx: &mut [F], dy: &mut [F], idx: &[u32]) -> bool {
    let p = &raw::consts(limbs(&F::MODULUS));
    let (x, y): (&mut [[u64; 4]], &mut [[u64; 4]]) = unsafe {
        (
            core::slice::from_raw_parts_mut(dx.as_mut_ptr().cast(), dx.len()),
            core::slice::from_raw_parts_mut(dy.as_mut_ptr().cast(), dy.len()),
        )
    };
    let mut num: Vec<[u64; 4]> = Vec::with_capacity(idx.len());
    let mut acc = limbs(&F::ONE);
    for &k in idx {
        let k = k as usize;
        let xx = raw::mul(&x[k], &x[k], p);
        num.push(raw::mul(&raw::add(&raw::add(&xx, &xx, p), &xx, p), &acc, p));
        acc = raw::mul(&acc, &raw::add(&y[k], &y[k], p), p);
    }
    let mut iv = limbs(&elt::<F>(acc).inverse().expect("batch_affine_double_indexed: zero denominator"));
    for (i, &k) in idx.iter().enumerate().rev() {
        let k = k as usize;
        let lambda = raw::mul(&num[i], &iv, p);
        iv = raw::mul(&iv, &raw::add(&y[k], &y[k], p), p);
        let x3 = raw::sub(&raw::mul(&lambda, &lambda, p), &raw::add(&x[k], &x[k], p), p);
        y[k] = raw::sub(&raw::mul(&lambda, &raw::sub(&x[k], &x3, p), p), &y[k], p);
        x[k] = x3;
    }
    true
}

pub struct PackedTree<P: SWCurveConfig> {
    dens: Vec<[u64; 4]>,
    prod: Vec<[u64; 4]>,
    _p: PhantomData<P>,
}

impl<P: SWCurveConfig> PackedTree<P>
where
    P::BaseField: PrimeField,
{
    pub fn with_capacity(cap: usize) -> Self {
        PackedTree { dens: Vec::with_capacity(cap / 2 + 1), prod: Vec::with_capacity(cap / 2 + 1), _p: PhantomData }
    }

    /// `tree_reduce_scalar`'s levels (see there for the run bookkeeping). Always takes the level.
    pub fn try_reduce(
        &mut self,
        run_id: &mut Vec<u32>,
        run_len: &mut Vec<u32>,
        ps: &mut Vec<Affine<P>>,
        _dens: &mut Vec<P::BaseField>,
        _prod: &mut Vec<P::BaseField>,
    ) -> bool {
        let p = &raw::consts(limbs(&P::BaseField::MODULUS));
        let (dens, prod) = (&mut self.dens, &mut self.prod);
        loop {
            // Pass 1: the denominators of every adjacent same-bucket pair and their prefix products.
            dens.clear();
            prod.clear();
            let mut acc = [0u64; 4];
            let mut i = 0usize;
            let mut any = false;
            for &k in run_len.iter() {
                let k = k as usize;
                for j in 0..k / 2 {
                    let (a, b) = (&ps[i + 2 * j], &ps[i + 2 * j + 1]);
                    let d = if a.x != b.x {
                        raw::sub(&limbs(&b.x), &limbs(&a.x), p)
                    } else if a.y == b.y {
                        let y = limbs(&a.y);
                        raw::add(&y, &y, p)
                    } else {
                        continue; // inverse pair, sums to infinity — dropped in pass 2
                    };
                    acc = if dens.is_empty() { d } else { raw::mul(&acc, &d, p) };
                    dens.push(d);
                    prod.push(acc);
                }
                any |= k >= 2;
                i += k;
            }
            if !any {
                return true;
            }
            // Backward pass of the batched inversion: dens[t] becomes 1/dens[t].
            if let Some(&last) = prod.last() {
                let mut inv = limbs(&elt::<P::BaseField>(last).inverse().expect("zero denominator"));
                for t in (1..dens.len()).rev() {
                    let d = dens[t];
                    dens[t] = raw::mul(&inv, &prod[t - 1], p);
                    inv = raw::mul(&inv, &d, p);
                }
                dens[0] = inv;
            }
            // Pass 2: apply the additions, compacting points and runs in place.
            let mut inv = dens.iter();
            let (mut out, mut i, mut out_run) = (0usize, 0usize, 0usize);
            for r in 0..run_len.len() {
                let k = run_len[r] as usize;
                let mut new_k = 0u32;
                for j in 0..k / 2 {
                    let at = i + 2 * j;
                    let (ax, ay) = (limbs(&ps[at].x), limbs(&ps[at].y));
                    let (bx, by) = (limbs(&ps[at + 1].x), limbs(&ps[at + 1].y));
                    if ax == bx && ay != by {
                        continue;
                    }
                    let d = inv.next().unwrap();
                    let lambda = if ax == bx {
                        let xx = raw::mul(&ax, &ax, p);
                        raw::mul(&raw::add(&raw::add(&xx, &xx, p), &xx, p), d, p)
                    } else {
                        raw::mul(&raw::sub(&by, &ay, p), d, p)
                    };
                    let x3 = raw::sub(&raw::sub(&raw::mul(&lambda, &lambda, p), &ax, p), &bx, p);
                    let y3 = raw::sub(&raw::mul(&lambda, &raw::sub(&ax, &x3, p), p), &ay, p);
                    ps[out] = Affine::new_unchecked(elt(x3), elt(y3));
                    out += 1;
                    new_k += 1;
                }
                if k % 2 == 1 {
                    ps[out] = ps[i + k - 1];
                    out += 1;
                    new_k += 1;
                }
                i += k;
                if new_k > 0 {
                    run_id[out_run] = run_id[r];
                    run_len[out_run] = new_k;
                    out_run += 1;
                }
            }
            run_id.truncate(out_run);
            run_len.truncate(out_run);
            ps.truncate(out);
        }
    }
}
