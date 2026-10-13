//! The packed MSM tree drain (wasm+simd128): each level's chord additions run four pairs per lane
//! group through the `quad261` kernels with one scalar batched inversion per level; chord
//! stragglers and doublings take the scalar tail. The run bookkeeping mirrors the scalar tree in
//! `base/msm.rs`.

use super::packed::QuadConsts;
use super::quad261::{self, QuadFp};
use crate::base::msm::batch_invert_nonzero;
use ark_ec::short_weierstrass::{Affine, SWCurveConfig};
use ark_ff::{AdditiveGroup, Field};

pub struct PackedTree<P: SWCurveConfig> {
    // Chord staging, coordinate-separated so groups of four pack straight from memory.
    ax: Vec<P::BaseField>,
    ay: Vec<P::BaseField>,
    bx: Vec<P::BaseField>,
    by: Vec<P::BaseField>,
    dest: Vec<u32>,
    dbl_dest: Vec<u32>,
    // Packed operands and batched-inversion chain, one entry per lane group.
    qax: Vec<QuadFp>,
    qbx: Vec<QuadFp>,
    qden: Vec<QuadFp>,
    qprod: Vec<QuadFp>,
}

impl<P: SWCurveConfig> PackedTree<P>
where
    P::BaseField: QuadConsts,
{
    pub fn with_capacity(cap: usize) -> Self {
        let half = cap / 2 + 1;
        PackedTree {
            ax: Vec::with_capacity(half),
            ay: Vec::with_capacity(half),
            bx: Vec::with_capacity(half),
            by: Vec::with_capacity(half),
            dest: Vec::with_capacity(half),
            dbl_dest: Vec::new(),
            qax: Vec::with_capacity(half / 4 + 1),
            qbx: Vec::with_capacity(half / 4 + 1),
            qden: Vec::with_capacity(half / 4 + 1),
            qprod: Vec::with_capacity(half / 4 + 1),
        }
    }

    /// Reduce a bucket-sorted point array to at most one point per bucket (see the scalar
    /// `tree_reduce` in `base/msm.rs` for the run bookkeeping): chord additions four pairs per
    /// lane group, one scalar batched inversion per level; `dens`/`prod` are the caller's
    /// scalar scratch for the tail. Always takes the level here, so returns true.
    pub fn try_reduce(
        &mut self,
        run_id: &mut Vec<u32>,
        run_len: &mut Vec<u32>,
        ps: &mut Vec<Affine<P>>,
        dens: &mut Vec<P::BaseField>,
        prod: &mut Vec<P::BaseField>,
    ) -> bool {
        loop {
            let p = &mut *self;
            p.ax.clear();
            p.ay.clear();
            p.bx.clear();
            p.by.clear();
            p.dest.clear();
            p.dbl_dest.clear();
            let mut any = false;
            // Classify and compact in one pass. The write cursor never passes the read cursor
            // (each read pair yields at most one output slot), so chord results scattered after
            // the walk land on slots already read this level.
            let (mut out, mut i, mut out_run) = (0usize, 0usize, 0usize);
            for r in 0..run_len.len() {
                let k = run_len[r] as usize;
                let mut new_k = 0u32;
                for j in 0..k / 2 {
                    let at = i + 2 * j;
                    let (a, b) = (ps[at], ps[at + 1]);
                    if a.x == b.x {
                        if a.y != b.y {
                            continue; // inverse pair, sums to infinity — dropped
                        }
                        ps[out] = a;
                        p.dbl_dest.push(out as u32);
                    } else {
                        p.ax.push(a.x);
                        p.ay.push(a.y);
                        p.bx.push(b.x);
                        p.by.push(b.y);
                        p.dest.push(out as u32);
                    }
                    out += 1;
                    new_k += 1;
                }
                if k % 2 == 1 {
                    ps[out] = ps[i + k - 1];
                    out += 1;
                    new_k += 1;
                }
                any |= k >= 2;
                i += k;
                if new_k > 0 {
                    run_id[out_run] = run_id[r];
                    run_len[out_run] = new_k;
                    out_run += 1;
                }
            }
            if !any {
                return true;
            }
            self.drain(ps, dens, prod);
            run_id.truncate(out_run);
            run_len.truncate(out_run);
            ps.truncate(out);
        }
    }

    /// Apply the level's queued additions: packed lane groups of four chords and the scalar tail
    /// (chord stragglers + doublings), all through one scalar batched inversion per level.
    fn drain(&mut self, ps: &mut [Affine<P>], dens: &mut Vec<P::BaseField>, prod: &mut Vec<P::BaseField>) {
        let p = self;
        let groups = p.ax.len() / 4;
        // The wasm stored form is the 2^261 Montgomery domain, which the quad261 multiply is
        // closed over — the packed groups are plain Montgomery arithmetic on packed stored bytes.
        let kc = <P::BaseField as QuadConsts>::kc();
        #[inline(always)]
        fn pack4<F>(v: &[F], g: usize) -> QuadFp {
            // Fp<_, 4> is repr-equivalent to its 4x64 stored limbs.
            QuadFp::pack(unsafe { &*(v.as_ptr().add(4 * g) as *const [[u64; 4]; 4]) })
        }
        if groups > 0 {
            p.qax.clear();
            p.qbx.clear();
            p.qden.clear();
            p.qprod.clear();
            for g in 0..groups {
                let (qax, qbx) = (pack4(&p.ax, g), pack4(&p.bx, g));
                let den = quad261::sub(&qbx, &qax, &kc.c);
                let acc = match p.qprod.last() {
                    Some(prev) => quad261::mont_mul(prev, &den, &kc.c),
                    None => den,
                };
                p.qprod.push(acc);
                p.qden.push(den);
                p.qax.push(qax);
                p.qbx.push(qbx);
            }
        }
        // One scalar batched inversion for the whole level (an inversion costs ~130 muls on
        // wasm): the tail's denominators followed by the four lanes of the packed total product.
        // The doubling slots are never packed destinations, so reading them here is unaffected
        // by the packed write-back below.
        dens.clear();
        for t in groups * 4..p.ax.len() {
            dens.push(p.bx[t] - p.ax[t]);
        }
        for &d in &p.dbl_dest {
            dens.push(ps[d as usize].y.double());
        }
        let tail = dens.len();
        if groups > 0 {
            let total = p.qprod[groups - 1].unpack(&kc.modulus);
            dens.extend((0..4).map(|l| unsafe { core::mem::transmute_copy::<_, P::BaseField>(&total[l]) }));
        }
        batch_invert_nonzero(dens, prod);
        if groups > 0 {
            let stored: [[u64; 4]; 4] = core::array::from_fn(|l| unsafe { core::mem::transmute_copy(&dens[tail + l]) });
            let mut inv = QuadFp::pack(&stored);
            for g in (1..groups).rev() {
                let d = quad261::mont_mul(&inv, &p.qprod[g - 1], &kc.c);
                inv = quad261::mont_mul(&inv, &p.qden[g], &kc.c);
                p.qden[g] = d;
            }
            p.qden[0] = inv;
            for g in 0..groups {
                let (qay, qby) = (pack4(&p.ay, g), pack4(&p.by, g));
                let (qax, qbx) = (p.qax[g], p.qbx[g]);
                let dy = quad261::sub(&qby, &qay, &kc.c);
                let l = quad261::mont_mul(&dy, &p.qden[g], &kc.c);
                let x3 = quad261::sub(
                    &quad261::sub(&quad261::mont_mul(&l, &l, &kc.c), &qax, &kc.c),
                    &qbx,
                    &kc.c,
                );
                let y3 = quad261::sub(
                    &quad261::mont_mul(&l, &quad261::sub(&qax, &x3, &kc.c), &kc.c),
                    &qay,
                    &kc.c,
                );
                let (xs, ys) = (x3.unpack(&kc.modulus), y3.unpack(&kc.modulus));
                for l in 0..4 {
                    let d = p.dest[4 * g + l] as usize;
                    let (x, y): (P::BaseField, P::BaseField) =
                        unsafe { (core::mem::transmute_copy(&xs[l]), core::mem::transmute_copy(&ys[l])) };
                    ps[d] = Affine::<P>::new_unchecked(x, y);
                }
            }
        }
        // Scalar tail: leftover chords and all doublings.
        let mut inv = dens.iter();
        for t in groups * 4..p.ax.len() {
            let d = *inv.next().unwrap();
            let lambda = (p.by[t] - p.ay[t]) * d;
            let x3 = lambda.square() - p.ax[t] - p.bx[t];
            let y3 = lambda * (p.ax[t] - x3) - p.ay[t];
            ps[p.dest[t] as usize] = Affine::<P>::new_unchecked(x3, y3);
        }
        for &dst in &p.dbl_dest {
            let d = *inv.next().unwrap();
            let (x, y) = (ps[dst as usize].x, ps[dst as usize].y);
            let xx = x.square();
            let lambda = (xx.double() + xx) * d;
            let x3 = lambda.square() - x.double();
            let y3 = lambda * (x - x3) - y;
            ps[dst as usize] = Affine::<P>::new_unchecked(x3, y3);
        }
    }
}
