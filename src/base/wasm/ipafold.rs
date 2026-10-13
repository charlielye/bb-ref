//! Packed replay of `base/fold.rs`'s two-round IPA SRS fold over one block of output points (golf
//! 0054's idea, bb-ref's schedule). Every coordinate column (the three multiplied bases' [1..8]·B
//! tables, φ(P0)'s x column, the accumulator) stays packed for the whole Horner chain, and each
//! batched-affine pass inverts lane-wise with one scalar inversion. The schedule is the same for
//! every point, so a non-generic operand pair (equal or opposite points, an infinite sum) can only
//! show up as a zero denominator: then the block answers None and the caller runs its exact scalar passes.

use super::packed::QuadConsts;
use super::quad261::{self, QuadFp};
use crate::base::{Fr, GrumpkinConfig};
use ark_ec::short_weierstrass::{Affine, SWCurveConfig};
use ark_ff::Field;
use core::any::TypeId;

#[inline(always)]
fn st<F>(x: &F) -> [u64; 4] {
    unsafe { core::mem::transmute_copy::<F, [u64; 4]>(x) }
}

struct Ctx {
    c: &'static quad261::Consts,
    modulus: &'static [u64; 4],
    zero: QuadFp,
    den: Vec<QuadFp>,
    prod: Vec<QuadFp>,
}

impl Ctx {
    #[inline(always)]
    fn mul(&self, a: &QuadFp, b: &QuadFp) -> QuadFp {
        quad261::mont_mul(a, b, self.c)
    }
    #[inline(always)]
    fn add(&self, a: &QuadFp, b: &QuadFp) -> QuadFp {
        quad261::add(a, b, self.c)
    }
    #[inline(always)]
    fn sub(&self, a: &QuadFp, b: &QuadFp) -> QuadFp {
        quad261::sub(a, b, self.c)
    }

    /// `den[g] ← 1/den[g]` lane-wise (prefix products, then the four lanes' totals by one scalar
    /// inversion); false on a zero lane.
    fn invert(&mut self) -> bool {
        self.prod.clear();
        let mut acc = self.den[0];
        self.prod.push(acc);
        for g in 1..self.den.len() {
            acc = self.mul(&acc, &self.den[g]);
            self.prod.push(acc);
        }
        let mut lanes: [Fr; 4] = acc.unpack(self.modulus).map(|l| unsafe { core::mem::transmute_copy(&l) });
        let mut pref = lanes;
        for l in 1..4 {
            pref[l] = pref[l - 1] * lanes[l];
        }
        let Some(mut inv) = pref[3].inverse() else {
            return false;
        };
        for l in (1..4).rev() {
            let prev = lanes[l];
            lanes[l] = inv * pref[l - 1];
            inv *= prev;
        }
        lanes[0] = inv;
        let mut inv = QuadFp::pack(&lanes.map(|l| st(&l)));
        for g in (1..self.den.len()).rev() {
            let d = self.mul(&inv, &self.prod[g - 1]);
            inv = self.mul(&inv, &self.den[g]);
            self.den[g] = d;
        }
        self.den[0] = inv;
        true
    }

    /// `(ax, ay) ← 2·(ax, ay)`.
    fn dbl(&mut self, ax: &mut [QuadFp], ay: &mut [QuadFp]) -> bool {
        self.den.clear();
        for y in ay.iter() {
            self.den.push(self.add(y, y));
        }
        if !self.invert() {
            return false;
        }
        for g in 0..ax.len() {
            let (x, y) = (ax[g], ay[g]);
            let xx = self.mul(&x, &x);
            let l = self.mul(&self.add(&self.add(&xx, &xx), &xx), &self.den[g]);
            let x3 = self.sub(&self.sub(&self.mul(&l, &l), &x), &x);
            ay[g] = self.sub(&self.mul(&l, &self.sub(&x, &x3)), &y);
            ax[g] = x3;
        }
        true
    }

    /// `(ax, ay) ← (ax, ay) + (bx, ±by)`.
    fn add_pts(&mut self, ax: &mut [QuadFp], ay: &mut [QuadFp], bx: &[QuadFp], by: &[QuadFp], neg: bool) -> bool {
        self.den.clear();
        for g in 0..ax.len() {
            self.den.push(self.sub(&bx[g], &ax[g]));
        }
        if !self.invert() {
            return false;
        }
        for g in 0..ax.len() {
            let (x, y) = (ax[g], ay[g]);
            let dy = if neg { self.sub(&self.zero, &self.add(&by[g], &y)) } else { self.sub(&by[g], &y) };
            let l = self.mul(&dy, &self.den[g]);
            let x3 = self.sub(&self.sub(&self.mul(&l, &l), &x), &bx[g]);
            ay[g] = self.sub(&self.mul(&l, &self.sub(&x, &x3)), &y);
            ax[g] = x3;
        }
        true
    }
}

fn pack_pts(pts: &[Affine<GrumpkinConfig>]) -> (Vec<QuadFp>, Vec<QuadFp>) {
    let pack = |c: &dyn Fn(&Affine<GrumpkinConfig>) -> [u64; 4]| -> Vec<QuadFp> {
        pts.chunks_exact(4).map(|a| QuadFp::pack(&core::array::from_fn(|l| c(&a[l])))).collect()
    };
    (pack(&|p| st(&p.x)), pack(&|p| st(&p.y)))
}

fn block(
    bases: [&[Affine<GrumpkinConfig>]; 4],
    digits: &[[i8; 33]; 4],
    top: usize,
    beta: &Fr,
) -> Option<Vec<Affine<GrumpkinConfig>>> {
    let kc = Fr::kc();
    let groups = bases[0].len() / 4;
    let mut cx = Ctx {
        c: &kc.c,
        modulus: &kc.modulus,
        zero: QuadFp::pack(&[[0u64; 4]; 4]),
        den: Vec::with_capacity(groups),
        prod: Vec::with_capacity(groups),
    };
    // tx[8b + k], ty[8b + k] = (k+1)·B_b; phix[k] = β·tx[k] (φ(P0) = (β·x, y)).
    let (mut tx, mut ty) = (Vec::with_capacity(24), Vec::with_capacity(24));
    for b in &bases[..3] {
        let (x0, y0) = pack_pts(b);
        let (mut x, mut y) = (x0.clone(), y0.clone());
        if !cx.dbl(&mut x, &mut y) {
            return None;
        }
        tx.push(x0.clone());
        ty.push(y0.clone());
        for _ in 2..8 {
            tx.push(x.clone());
            ty.push(y.clone());
            if !cx.add_pts(&mut x, &mut y, &x0, &y0, false) {
                return None;
            }
        }
        tx.push(x);
        ty.push(y);
    }
    let bsplat = QuadFp::pack(&[st(beta); 4]);
    let phix: Vec<Vec<QuadFp>> = tx[..8].iter().map(|t| t.iter().map(|v| cx.mul(v, &bsplat)).collect()).collect();

    let (mut ax, mut ay) = (vec![cx.zero; groups], vec![cx.zero; groups]);
    let mut started = false;
    for w in (0..=top).rev() {
        if started {
            for _ in 0..4 {
                if !cx.dbl(&mut ax, &mut ay) {
                    return None;
                }
            }
        }
        for (term, dset) in digits.iter().enumerate() {
            let d = dset[w];
            if d == 0 {
                continue;
            }
            let k = d.unsigned_abs() as usize - 1;
            let (bx, by) = match term {
                0 => (&tx[k], &ty[k]),
                1 => (&tx[8 + k], &ty[8 + k]),
                2 => (&phix[k], &ty[k]),
                _ => (&tx[16 + k], &ty[16 + k]),
            };
            if started {
                if !cx.add_pts(&mut ax, &mut ay, bx, by, d < 0) {
                    return None;
                }
            } else {
                ax.copy_from_slice(bx);
                for g in 0..groups {
                    ay[g] = if d < 0 { cx.sub(&cx.zero, &by[g]) } else { by[g] };
                }
                started = true;
            }
        }
    }
    let (x3, y3) = pack_pts(bases[3]);
    if !cx.add_pts(&mut ax, &mut ay, &x3, &y3, false) {
        return None;
    }
    let mut out = Vec::with_capacity(4 * groups);
    for (x, y) in ax.iter().zip(&ay) {
        let (xs, ys) = (x.unpack(&kc.modulus), y.unpack(&kc.modulus));
        for l in 0..4 {
            out.push(unsafe { Affine::new_unchecked(core::mem::transmute_copy(&xs[l]), core::mem::transmute_copy(&ys[l])) });
        }
    }
    Some(out)
}

/// One block of the two-round fold: `bases` are the block's slices of P0..P3 (equal lengths),
/// `digits` the four terms' signed Booth digits (term 2 is φ(P0) with its sign applied), `top` the
/// highest non-zero window; the bases are finite (SRS points). None unless the curve is Grumpkin
/// and the block a non-empty multiple of 4 points, or when a lane hits a non-generic pair.
pub fn try_fold_two_rounds<P: SWCurveConfig>(
    bases: [&[Affine<P>]; 4],
    digits: &[[i8; 33]; 4],
    top: usize,
    beta: &P::BaseField,
) -> Option<Vec<Affine<P>>> {
    type G = GrumpkinConfig;
    let m = bases[0].len();
    if TypeId::of::<P>() != TypeId::of::<G>() || m == 0 || m % 4 != 0 {
        return None;
    }
    let b: [&[Affine<G>]; 4] = unsafe { core::mem::transmute_copy(&bases) };
    let r = block(b, digits, top, unsafe { &*(beta as *const P::BaseField as *const Fr) })?;
    Some(unsafe { core::mem::transmute::<Vec<Affine<G>>, Vec<Affine<P>>>(r) })
}
