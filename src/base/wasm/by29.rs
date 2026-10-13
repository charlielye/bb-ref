//! Bernstein–Yang safegcd inverse for wasm (golf's `Wasm9x29`): `adx.rs`'s algorithm on nine
//! signed 29-bit limbs, so every limb product is one `i64.mul` (no `__multi3`), with 58 divsteps
//! per matrix, so the exact /2^58 drops two limbs. 13 rounds cover the 735-divstep bound, and
//! (d, e) are brought back to [0, p) every 4 rounds. 3.8× arkworks' binary EEA on V8 (Fq
//! 6.5 → 1.7 µs per inverse).

use super::divsteps::divsteps;
use super::mont29::{from29, to29};

const N: usize = 9;
const MASK: i64 = (1 << 29) - 1;
const MASK58: u64 = (1 << 58) - 1;
type S = [i64; N];

/// The low 64 bits of a value whose limbs below the top are normalised.
fn low64(l: &S) -> u64 {
    (l[0] as u64) | ((l[1] as u64) << 29) | ((l[2] as u64) << 58)
}

/// Carries into 29-bit limbs below a signed top limb.
fn normalise(l: &mut S) {
    let mut c = 0;
    for x in &mut l[..N - 1] {
        let v = *x + c;
        *x = v & MASK;
        c = v >> 29;
    }
    l[N - 1] += c;
}

/// Into [0, p) by repeated ±p.
fn canon(x: &mut S, p: &S) {
    loop {
        normalise(x);
        if x[N - 1] < 0 {
            (0..N).for_each(|i| x[i] += p[i]);
        } else if x.iter().rev().ge(p.iter().rev()) {
            (0..N).for_each(|i| x[i] -= p[i]);
        } else {
            return;
        }
    }
}

/// [u v; q r]·(x, y)/2^58 with the matrix entries split into 29-bit halves (the high one signed),
/// plus k·p first on the (d, e) side, k = −(low 58 bits)·p⁻¹ mod 2^58 making the division exact.
/// Output limb i − 2 sums the low halves times limb i and the high halves times limb i − 1.
#[allow(clippy::many_single_char_names, clippy::similar_names)]
fn apply(m: [i64; 4], f: &mut S, g: &mut S, d: &mut S, e: &mut S, p: &S, pinv: u64) {
    let [u, v, q, r] = m;
    let (ul, uh, vl, vh) = (u & MASK, u >> 29, v & MASK, v >> 29);
    let (ql, qh, rl, rh) = (q & MASK, q >> 29, r & MASK, r >> 29);
    let (mut cf, mut cg, mut fp, mut gp) = (0, 0, 0, 0);
    for i in 0..N {
        let (fi, gi) = (f[i], g[i]);
        let nf = ul * fi + vl * gi + uh * fp + vh * gp + cf;
        let ng = ql * fi + rl * gi + qh * fp + rh * gp + cg;
        (cf, cg) = (nf >> 29, ng >> 29);
        if i >= 2 {
            (f[i - 2], g[i - 2]) = (nf & MASK, ng & MASK);
        }
        (fp, gp) = (fi, gi);
    }
    let (nf, ng) = (uh * fp + vh * gp + cf, qh * fp + rh * gp + cg);
    (f[N - 2], g[N - 2], f[N - 1], g[N - 1]) = (nf & MASK, ng & MASK, nf >> 29, ng >> 29);

    let (d0, e0, d1, e1) = (d[0], e[0], d[1], e[1]);
    let (nd0, ne0) = (ul * d0 + vl * e0, ql * d0 + rl * e0);
    let (nd1, ne1) = (ul * d1 + vl * e1 + uh * d0 + vh * e0, ql * d1 + rl * e1 + qh * d0 + rh * e0);
    let k = |t0: i64, t1: i64| {
        let low = (t0 & MASK) as u64 | ((((t1 + (t0 >> 29)) & MASK) as u64) << 29);
        let k = low.wrapping_neg().wrapping_mul(pinv) & MASK58;
        ((k & MASK as u64) as i64, (k >> 29) as i64)
    };
    let ((kdl, kdh), (kel, keh)) = (k(nd0, nd1), k(ne0, ne1));
    let mut cd = (nd1 + kdl * p[1] + kdh * p[0] + ((nd0 + kdl * p[0]) >> 29)) >> 29;
    let mut ce = (ne1 + kel * p[1] + keh * p[0] + ((ne0 + kel * p[0]) >> 29)) >> 29;
    let (mut dp, mut ep) = (d1, e1);
    for i in 2..N {
        let (di, ei) = (d[i], e[i]);
        let nd = ul * di + vl * ei + uh * dp + vh * ep + kdl * p[i] + kdh * p[i - 1] + cd;
        let ne = ql * di + rl * ei + qh * dp + rh * ep + kel * p[i] + keh * p[i - 1] + ce;
        (cd, ce) = (nd >> 29, ne >> 29);
        (d[i - 2], e[i - 2]) = (nd & MASK, ne & MASK);
        (dp, ep) = (di, ei);
    }
    let (nd, ne) = (uh * dp + vh * ep + kdh * p[N - 1] + cd, qh * dp + rh * ep + keh * p[N - 1] + ce);
    (d[N - 2], e[N - 2], d[N - 1], e[N - 1]) = (nd & MASK, ne & MASK, nd >> 29, ne >> 29);
}

/// p⁻¹ mod 2^58 (Newton).
pub const fn pinv58(p0: u64) -> u64 {
    let mut x: u64 = 1;
    let mut i = 0;
    while i < 6 {
        x = x.wrapping_mul(2u64.wrapping_sub(p0.wrapping_mul(x)));
        i += 1;
    }
    x & MASK58
}

/// a⁻¹ mod p for 0 < a < p (plain integers); `pinv` from [`pinv58`].
pub fn inverse(a: &[u64; 4], p4: &[u64; 4], pinv: u64) -> [u64; 4] {
    let s = |x: &[u64; 4]| to29(x).map(|l| l as i64);
    let p = s(p4);
    let (mut f, mut g, mut d, mut e) = (p, s(a), [0; N], [1, 0, 0, 0, 0, 0, 0, 0, 0]);
    let mut delta = 1;
    for i in 0..13 {
        let m = divsteps::<58>(&mut delta, low64(&f), low64(&g));
        apply(m, &mut f, &mut g, &mut d, &mut e, &p, pinv);
        if g == [0; N] {
            break;
        }
        if i % 4 == 3 {
            canon(&mut d, &p);
            canon(&mut e, &p);
        }
    }
    if f[N - 1] < 0 {
        d = d.map(|l| -l);
    }
    canon(&mut d, &p);
    from29(&d.map(|l| l as u64))
}
