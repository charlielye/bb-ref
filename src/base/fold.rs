//! The IPA SRS fold, two reduction rounds at a time on one shared doubling chain
//! (bb `element::batch_two_round_fold`, specified in bb's `ipa/ELEMENT_IMPL_FOLD.md`):
//!
//!   G''[i] = (u1·u2)·P0[i] + u1·P1[i] + u2·P2[i] + P3[i]
//!
//! over the four quarters `P0..P3` of the round's SRS. The full-width product `u1·u2` is
//! GLV-split into half-width `k1 − k2·λ` (with `λ·P = (β·x, y)`), so all four scalar terms are
//! ≤128 bits and share one ~128-doubling Horner chain per output point; every chain step is a
//! batched-affine pass over a per-thread chunk with one shared inversion. Unlike bb, the passes
//! handle equal, inverse, and infinity operands exactly, so no schedule simulation ("safe flags")
//! is needed.

use super::msm::extract_bits;
use ark_ec::short_weierstrass::{Affine, Projective, SWCurveConfig};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{AdditiveGroup, Field, One, PrimeField};
use rayon::prelude::*;

/// The curve's GLV endomorphism data plus the scalar-field lattice constants of bb's
/// `split_into_endomorphism_scalars` (for Grumpkin's scalar field these are bb's
/// `Bn254FqParams::endo_*`).
pub struct Endo<P: SWCurveConfig> {
    /// `λ` in the scalar field and `β` in the base field, matched so `λ·(x, y) = (β·x, y)`.
    pub lambda: P::ScalarField,
    pub beta: P::BaseField,
    pub g1: [u64; 4],
    pub g2: [u64; 4],
    pub minus_b1: [u64; 4],
    pub b2: [u64; 4],
}

/// The 512-bit product of two 4-limb integers (bb `field::mul_512`).
fn mul_512(a: &[u64; 4], b: &[u64; 4]) -> [u64; 8] {
    let mut out = [0u64; 8];
    for i in 0..4 {
        let mut carry = 0u128;
        for j in 0..4 {
            let t = a[i] as u128 * b[j] as u128 + out[i + j] as u128 + carry;
            out[i + j] = t as u64;
            carry = t >> 64;
        }
        let mut k = i + 4;
        while carry > 0 {
            let t = out[k] as u128 + carry;
            out[k] = t as u64;
            carry = t >> 64;
            k += 1;
        }
    }
    out
}

/// A 256-bit integer as a (reduced) scalar-field element.
fn field_from_limbs<F: PrimeField>(l: [u64; 4]) -> F {
    let s64 = F::from(1u128 << 64);
    let s128 = s64 * s64;
    F::from(l[0]) + F::from(l[1]) * s64 + F::from(l[2]) * s128 + F::from(l[3]) * s128 * s64
}

impl<P: SWCurveConfig> Endo<P> {
    /// `k ≡ k1 − k2·λ (mod r)` with `k1, k2 < 2^128` (bb `split_into_endomorphism_scalars`);
    /// the identity is asserted on every call — the split feeds proof data.
    pub fn split(&self, k: &P::ScalarField) -> ([u64; 2], [u64; 2]) {
        let raw: [u64; 4] = k.into_bigint().as_ref().try_into().unwrap();
        // c = high halves of g·k; q = low halves of c·(-b1), c·b2; k2 = q2 − q1 in the field.
        let c1: [u64; 4] = mul_512(&self.g2, &raw)[4..].try_into().unwrap();
        let c2: [u64; 4] = mul_512(&self.g1, &raw)[4..].try_into().unwrap();
        let q1: [u64; 4] = mul_512(&c1, &self.minus_b1)[..4].try_into().unwrap();
        let q2: [u64; 4] = mul_512(&c2, &self.b2)[..4].try_into().unwrap();
        let mut t1 = field_from_limbs::<P::ScalarField>(q2) - field_from_limbs::<P::ScalarField>(q1);
        // Negative-k2 fix: when t1's raw value exceeds 128 bits, shift it by |b1| (bb's comment:
        // ~2^-64 of inputs).
        if t1.into_bigint().as_ref()[2..].iter().any(|&l| l != 0) {
            t1 += field_from_limbs::<P::ScalarField>(self.minus_b1);
        }
        let t2 = t1 * self.lambda + k;
        let (k1r, k2r) = (t2.into_bigint(), t1.into_bigint());
        let (k1r, k2r) = (k1r.as_ref(), k2r.as_ref());
        assert!(
            k1r[2] == 0 && k1r[3] == 0 && k2r[2] == 0 && k2r[3] == 0,
            "endomorphism split exceeded 128 bits"
        );
        let (k1, k2) = ([k1r[0], k1r[1]], [k2r[0], k2r[1]]);
        let s64 = P::ScalarField::from(1u128 << 64);
        let val = |v: [u64; 2]| P::ScalarField::from(v[0]) + P::ScalarField::from(v[1]) * s64;
        assert_eq!(
            val(k1) - val(k2) * self.lambda,
            *k,
            "endomorphism split identity failed"
        );
        (k1, k2)
    }
}

/// Signed 4-bit Booth digits of a ≤128-bit value, lowest window first.
const NUM_WINDOWS: usize = 33;
fn booth_digits(v: [u64; 2], negate: bool) -> [i8; NUM_WINDOWS] {
    let limbs = [v[0], v[1], 0, 0];
    let mut out = [0i8; NUM_WINDOWS];
    let mut carry = 0u64;
    for (w, o) in out.iter_mut().enumerate() {
        let raw = extract_bits(&limbs, w * 4, 4) + carry;
        let d = if raw > 8 {
            carry = 1;
            raw as i8 - 16
        } else {
            carry = 0;
            raw as i8
        };
        *o = if negate { -d } else { d };
    }
    assert_eq!(carry, 0, "booth carry out of the window range");
    out
}

/// One batched-affine pass: `acc[i] = 2·acc[i]`.
pub(crate) fn pass_dbl<P: SWCurveConfig>(acc: &mut [Option<Affine<P>>], dens: &mut Vec<P::BaseField>) {
    dens.clear();
    for a in acc.iter().flatten() {
        dens.push(a.y.double());
    }
    ark_ff::serial_batch_inversion_and_mul(dens, &P::BaseField::one());
    let mut inv = dens.iter();
    for a in acc.iter_mut() {
        if let Some(p) = a {
            let xx = p.x.square();
            let lambda = (xx.double() + xx) * inv.next().unwrap();
            let x3 = lambda.square() - p.x.double();
            let y3 = lambda * (p.x - x3) - p.y;
            *a = Some(Affine::<P>::new_unchecked(x3, y3));
        }
    }
}

/// One batched-affine pass: `acc[i] += addend(i)`; equal, inverse, and infinity operands exact.
pub(crate) fn pass_add<P: SWCurveConfig>(
    acc: &mut [Option<Affine<P>>],
    addend: impl Fn(usize) -> Option<Affine<P>>,
    dens: &mut Vec<P::BaseField>,
    kinds: &mut Vec<u8>,
) {
    const SKIP: u8 = 0;
    const SET: u8 = 1;
    const ADD: u8 = 2;
    const DOUBLE: u8 = 3;
    const INF: u8 = 4;
    dens.clear();
    kinds.clear();
    for (i, a) in acc.iter().enumerate() {
        let kind = match (a, addend(i)) {
            (_, None) => SKIP,
            (None, Some(_)) => SET,
            (Some(p), Some(q)) => {
                if p.x == q.x {
                    if p.y == q.y {
                        dens.push(p.y.double());
                        DOUBLE
                    } else {
                        INF
                    }
                } else {
                    dens.push(q.x - p.x);
                    ADD
                }
            }
        };
        kinds.push(kind);
    }
    ark_ff::serial_batch_inversion_and_mul(dens, &P::BaseField::one());
    let mut inv = dens.iter();
    for (i, a) in acc.iter_mut().enumerate() {
        match kinds[i] {
            SKIP => {}
            SET => *a = addend(i),
            INF => *a = None,
            kind => {
                let p = a.unwrap();
                let q = addend(i).unwrap();
                let lambda = if kind == DOUBLE {
                    let xx = p.x.square();
                    (xx.double() + xx) * inv.next().unwrap()
                } else {
                    (q.y - p.y) * inv.next().unwrap()
                };
                let x3 = lambda.square() - p.x - q.x;
                let y3 = lambda * (p.x - x3) - p.y;
                *a = Some(Affine::<P>::new_unchecked(x3, y3));
            }
        }
    }
}

/// Scratch for the bb-kernel batched affine passes (feature `bbkernel`), reused across the
/// ~hundreds of passes a fold chunk performs.
#[cfg(all(feature = "bbkernel", target_family = "wasm", target_feature = "simd128"))]
pub(crate) struct BbkPassScratch<F> {
    ax: Vec<F>,
    ay: Vec<F>,
    bx: Vec<F>,
    by: Vec<F>,
    ox: Vec<F>,
    oy: Vec<F>,
    scratch: Vec<F>,
    dst: Vec<u32>,
}

#[cfg(all(feature = "bbkernel", target_family = "wasm", target_feature = "simd128"))]
impl<F: Copy> BbkPassScratch<F> {
    pub(crate) fn new() -> Self {
        BbkPassScratch {
            ax: Vec::new(),
            ay: Vec::new(),
            bx: Vec::new(),
            by: Vec::new(),
            ox: Vec::new(),
            oy: Vec::new(),
            scratch: Vec::new(),
            dst: Vec::new(),
        }
    }
}

/// `acc[i] += addend[i]` with the chord additions through bb's clang-compiled kernels: exact
/// (set/infinity/doubling lanes take the scalar path), one batched inversion per call. Fr/Fq
/// only — the fold call sites are bn254/grumpkin.
#[cfg(all(feature = "bbkernel", target_family = "wasm", target_feature = "simd128"))]
fn pass_add_bbk<P: SWCurveConfig>(
    acc: &mut [Option<Affine<P>>],
    addend: &[Option<Affine<P>>],
    s: &mut BbkPassScratch<P::BaseField>,
    dens: &mut Vec<P::BaseField>,
) -> bool
where
    P::BaseField: 'static,
{
    use crate::base::packed::bbk;
    use core::any::TypeId;
    type C1 = unsafe extern "C" fn(*const u64, *const u64, usize, *mut u64, *mut u64);
    type C2 = unsafe extern "C" fn(
        *const u64,
        *const u64,
        *const u64,
        *const u64,
        usize,
        *mut u64,
        *const u64,
        *const u64,
        *mut u64,
        *mut u64,
    );
    let (c1, c2): (C1, C2) = if TypeId::of::<P::BaseField>() == TypeId::of::<crate::base::Fr>() {
        (bbk::bbref_chord1_fr, bbk::bbref_chord2_fr)
    } else if TypeId::of::<P::BaseField>() == TypeId::of::<crate::base::Fq>() {
        (bbk::bbref_chord1_fq, bbk::bbref_chord2_fq)
    } else {
        return false;
    };
    s.ax.clear();
    s.ay.clear();
    s.bx.clear();
    s.by.clear();
    s.dst.clear();
    // Rare non-chord pairs (equal or inverse x): scalar, with individual inversions.
    for (i, a) in acc.iter_mut().enumerate() {
        match (&a, addend[i]) {
            (_, None) => {}
            (None, Some(q)) => *a = Some(q),
            (Some(p), Some(q)) => {
                if p.x == q.x {
                    if p.y == q.y {
                        let d = ark_ff::Field::inverse(&p.y.double()).expect("doubling a 2-torsion point");
                        let xx = p.x.square();
                        let lambda = (xx.double() + xx) * d;
                        let x3 = lambda.square() - p.x.double();
                        let y3 = lambda * (p.x - x3) - p.y;
                        *a = Some(Affine::<P>::new_unchecked(x3, y3));
                    } else {
                        *a = None;
                    }
                } else {
                    s.ax.push(p.x);
                    s.ay.push(p.y);
                    s.bx.push(q.x);
                    s.by.push(q.y);
                    s.dst.push(i as u32);
                }
            }
        }
    }
    if s.dst.is_empty() {
        return true;
    }
    let w = unsafe { bbk::bbref_chord_width() };
    while s.ax.len() % w != 0 {
        s.ax.push(s.ax[0]);
        s.ay.push(s.ay[0]);
        s.bx.push(s.bx[0]);
        s.by.push(s.by[0]);
    }
    let n = s.ax.len();
    s.ox.resize(n, s.ax[0]);
    s.oy.resize(n, s.ax[0]);
    s.scratch.resize(2 * n, s.ax[0]);
    let (dx, prod) = s.scratch.split_at_mut(n);
    unsafe {
        c1(
            s.ax.as_ptr() as *const u64,
            s.bx.as_ptr() as *const u64,
            n,
            dx.as_mut_ptr() as *mut u64,
            prod.as_mut_ptr() as *mut u64,
        )
    };
    dens.clear();
    dens.extend_from_slice(&prod[n - w..]);
    ark_ff::batch_inversion(dens);
    unsafe {
        c2(
            s.ax.as_ptr() as *const u64,
            s.ay.as_ptr() as *const u64,
            s.bx.as_ptr() as *const u64,
            s.by.as_ptr() as *const u64,
            n,
            dx.as_mut_ptr() as *mut u64,
            prod.as_ptr() as *const u64,
            dens.as_ptr() as *const u64,
            s.ox.as_mut_ptr() as *mut u64,
            s.oy.as_mut_ptr() as *mut u64,
        )
    };
    for (k, &i) in s.dst.iter().enumerate() {
        acc[i as usize] = Some(Affine::<P>::new_unchecked(s.ox[k], s.oy[k]));
    }
    true
}

/// `acc[i] = 2 acc[i]` through bb's kernels; `None` lanes skip.
#[cfg(all(feature = "bbkernel", target_family = "wasm", target_feature = "simd128"))]
fn pass_dbl_bbk<P: SWCurveConfig>(
    acc: &mut [Option<Affine<P>>],
    s: &mut BbkPassScratch<P::BaseField>,
    dens: &mut Vec<P::BaseField>,
) -> bool
where
    P::BaseField: 'static,
{
    use crate::base::packed::bbk;
    use core::any::TypeId;
    type D1 = unsafe extern "C" fn(*const u64, usize, *mut u64, *mut u64);
    type D2 = unsafe extern "C" fn(*const u64, *const u64, usize, *mut u64, *const u64, *const u64, *mut u64, *mut u64);
    let (d1, d2): (D1, D2) = if TypeId::of::<P::BaseField>() == TypeId::of::<crate::base::Fr>() {
        (bbk::bbref_dbl1_fr, bbk::bbref_dbl2_fr)
    } else if TypeId::of::<P::BaseField>() == TypeId::of::<crate::base::Fq>() {
        (bbk::bbref_dbl1_fq, bbk::bbref_dbl2_fq)
    } else {
        return false;
    };
    s.ax.clear();
    s.ay.clear();
    s.dst.clear();
    for (i, a) in acc.iter().enumerate() {
        if let Some(p) = a {
            s.ax.push(p.x);
            s.ay.push(p.y);
            s.dst.push(i as u32);
        }
    }
    if s.dst.is_empty() {
        return true;
    }
    let w = unsafe { bbk::bbref_chord_width() };
    while s.ax.len() % w != 0 {
        s.ax.push(s.ax[0]);
        s.ay.push(s.ay[0]);
    }
    let n = s.ax.len();
    s.ox.resize(n, s.ax[0]);
    s.oy.resize(n, s.ax[0]);
    s.scratch.resize(2 * n, s.ax[0]);
    let (den, prod) = s.scratch.split_at_mut(n);
    unsafe {
        d1(
            s.ay.as_ptr() as *const u64,
            n,
            den.as_mut_ptr() as *mut u64,
            prod.as_mut_ptr() as *mut u64,
        )
    };
    dens.clear();
    dens.extend_from_slice(&prod[n - w..]);
    ark_ff::batch_inversion(dens);
    unsafe {
        d2(
            s.ax.as_ptr() as *const u64,
            s.ay.as_ptr() as *const u64,
            n,
            den.as_mut_ptr() as *mut u64,
            prod.as_ptr() as *const u64,
            dens.as_ptr() as *const u64,
            s.ox.as_mut_ptr() as *mut u64,
            s.oy.as_mut_ptr() as *mut u64,
        )
    };
    for (k, &i) in s.dst.iter().enumerate() {
        acc[i as usize] = Some(Affine::<P>::new_unchecked(s.ox[k], s.oy[k]));
    }
    true
}

/// `out[i] = (u1·u2)·g[i] + u1·g[i+q] + u2·g[i+2q] + g[i+3q]` over the four quarters of `g`.
/// `u1`, `u2` must be short (≤128-bit) transcript challenges.
pub fn fold_points_two_rounds<P: SWCurveConfig>(
    g: &[Affine<P>],
    u1: &P::ScalarField,
    u2: &P::ScalarField,
    endo: &Endo<P>,
) -> Vec<Affine<P>> {
    let q = g.len() / 4;
    let (p0, rest) = g.split_at(q);
    let (p1, rest) = rest.split_at(q);
    let (p2, p3) = rest.split_at(q);
    let u12 = *u1 * u2;
    if q < 128 {
        return Projective::<P>::normalize_batch(
            &(0..q)
                .map(|i| p0[i] * u12 + p1[i] * u1 + p2[i] * u2 + p3[i])
                .collect::<Vec<_>>(),
        );
    }
    let (k1, k2) = endo.split(&u12);
    let low2 = |s: &P::ScalarField| {
        let b = s.into_bigint();
        let l = b.as_ref();
        assert!(l[2] == 0 && l[3] == 0, "IPA round challenge is not short");
        [l[0], l[1]]
    };
    // Term order: k1·P0 + u1·P1 + (−k2)·φ(P0) + u2·P2, then + P3 outside the chain.
    let digits = [
        booth_digits(k1, false),
        booth_digits(low2(u1), false),
        booth_digits(k2, true),
        booth_digits(low2(u2), false),
    ];
    let top = (0..NUM_WINDOWS)
        .rev()
        .find(|&w| digits.iter().any(|d| d[w] != 0))
        .expect("all fold scalars zero");

    let chunk = q.div_ceil(rayon::current_num_threads().max(1)).max(128);
    (0..q)
        .step_by(chunk)
        .collect::<Vec<_>>()
        .into_par_iter()
        .flat_map_iter(|s| {
            let m = chunk.min(q - s);
            let mut dens: Vec<P::BaseField> = Vec::with_capacity(m);
            let mut kinds: Vec<u8> = Vec::with_capacity(m);
            #[cfg(all(feature = "bbkernel", target_family = "wasm", target_feature = "simd128"))]
            let mut bbs = BbkPassScratch::<P::BaseField>::new();
            #[cfg(all(feature = "bbkernel", target_family = "wasm", target_feature = "simd128"))]
            let mut addend_buf: Vec<Option<Affine<P>>> = Vec::with_capacity(m);
            // Tables [B, 2B, .., 8B] per multiplied base; term 2 reads P0's table through φ.
            let bases = [&p0[s..s + m], &p1[s..s + m], &p2[s..s + m]];
            let mut tables: Vec<Vec<Option<Affine<P>>>> = Vec::with_capacity(24);
            for b in bases {
                let start = tables.len();
                tables.push(b.iter().map(|p| Some(*p)).collect());
                let mut dbld = tables[start].clone();
                #[cfg(all(feature = "bbkernel", target_family = "wasm", target_feature = "simd128"))]
                if !pass_dbl_bbk::<P>(&mut dbld, &mut bbs, &mut dens) {
                    pass_dbl(&mut dbld, &mut dens);
                }
                #[cfg(not(all(feature = "bbkernel", target_family = "wasm", target_feature = "simd128")))]
                pass_dbl(&mut dbld, &mut dens);
                tables.push(dbld);
                for _ in 2..8 {
                    let mut next = tables.last().unwrap().clone();
                    #[cfg(all(feature = "bbkernel", target_family = "wasm", target_feature = "simd128"))]
                    {
                        addend_buf.clear();
                        addend_buf.extend(b.iter().map(|p| Some(*p)));
                        if !pass_add_bbk::<P>(&mut next, &addend_buf, &mut bbs, &mut dens) {
                            pass_add(&mut next, |i| Some(b[i]), &mut dens, &mut kinds);
                        }
                    }
                    #[cfg(not(all(feature = "bbkernel", target_family = "wasm", target_feature = "simd128")))]
                    pass_add(&mut next, |i| Some(b[i]), &mut dens, &mut kinds);
                    tables.push(next);
                }
            }
            let entry = |term: usize, d: i8, i: usize| -> Option<Affine<P>> {
                let mag = d.unsigned_abs() as usize;
                if mag == 0 {
                    return None;
                }
                let raw = match term {
                    2 => tables[mag - 1][i].map(|p| Affine::<P>::new_unchecked(p.x * endo.beta, p.y)),
                    t => tables[8 * (t - t / 2) + mag - 1][i], // t=0 -> 0.., t=1 -> 8.., t=3 -> 16..
                };
                raw.map(|p| {
                    if d < 0 {
                        Affine::<P>::new_unchecked(p.x, -p.y)
                    } else {
                        p
                    }
                })
            };
            let mut acc: Vec<Option<Affine<P>>> = vec![None; m];
            let mut started = false;
            for w in (0..=top).rev() {
                if started {
                    for _ in 0..4 {
                        #[cfg(all(feature = "bbkernel", target_family = "wasm", target_feature = "simd128"))]
                        if pass_dbl_bbk::<P>(&mut acc, &mut bbs, &mut dens) {
                            continue;
                        }
                        pass_dbl(&mut acc, &mut dens);
                    }
                }
                for (term, dset) in digits.iter().enumerate() {
                    let d = dset[w];
                    if d == 0 {
                        continue;
                    }
                    if started {
                        #[cfg(all(feature = "bbkernel", target_family = "wasm", target_feature = "simd128"))]
                        {
                            addend_buf.clear();
                            addend_buf.extend((0..m).map(|i| entry(term, d, i)));
                            if !pass_add_bbk::<P>(&mut acc, &addend_buf, &mut bbs, &mut dens) {
                                pass_add(&mut acc, |i| entry(term, d, i), &mut dens, &mut kinds);
                            }
                            continue;
                        }
                        #[allow(unreachable_code)]
                        pass_add(&mut acc, |i| entry(term, d, i), &mut dens, &mut kinds);
                    } else {
                        for (i, a) in acc.iter_mut().enumerate() {
                            *a = entry(term, d, i);
                        }
                        started = true;
                    }
                }
            }
            #[cfg(all(feature = "bbkernel", target_family = "wasm", target_feature = "simd128"))]
            {
                addend_buf.clear();
                addend_buf.extend((0..m).map(|i| Some(p3[s + i])));
                if !pass_add_bbk::<P>(&mut acc, &addend_buf, &mut bbs, &mut dens) {
                    pass_add(&mut acc, |i| Some(p3[s + i]), &mut dens, &mut kinds);
                }
            }
            #[cfg(not(all(feature = "bbkernel", target_family = "wasm", target_feature = "simd128")))]
            pass_add(&mut acc, |i| Some(p3[s + i]), &mut dens, &mut kinds);
            acc.into_iter()
                .map(|a| a.unwrap_or(Affine::<P>::zero()))
                .collect::<Vec<_>>()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::grumpkin_endo;
    use ark_ec::VariableBaseMSM;
    use ark_ff::UniformRand;
    use ark_grumpkin::GrumpkinConfig;

    #[test]
    fn two_round_fold_matches_projective() {
        let mut rng = ark_std::test_rng();
        type G = Projective<GrumpkinConfig>;
        let n = 1024usize;
        let g = G::normalize_batch(&(0..n).map(|_| G::rand(&mut rng)).collect::<Vec<_>>());
        let endo = grumpkin_endo();
        for _ in 0..4 {
            // 127-bit challenges, like the transcript's.
            let mask = |v: ark_grumpkin::Fr| {
                let mut b = v.into_bigint();
                b.0[1] &= (1 << 63) - 1;
                b.0[2] = 0;
                b.0[3] = 0;
                ark_grumpkin::Fr::from_bigint(b).unwrap()
            };
            let u1 = mask(ark_grumpkin::Fr::rand(&mut rng));
            let u2 = mask(ark_grumpkin::Fr::rand(&mut rng));
            let folded = fold_points_two_rounds(&g, &u1, &u2, endo);
            let q = n / 4;
            let u12 = u1 * u2;
            for i in (0..q).step_by(29) {
                let direct: G = g[i] * u12 + g[i + q] * u1 + g[i + 2 * q] * u2 + G::from(g[i + 3 * q]);
                assert_eq!(G::from(folded[i]), direct, "output {i}");
            }
            let scalars = vec![u12, u1, u2, ark_grumpkin::Fr::one()];
            let pts = vec![g[5], g[5 + q], g[5 + 2 * q], g[5 + 3 * q]];
            assert_eq!(G::from(folded[5]), G::msm_unchecked(&pts, &scalars));
        }
    }
}
