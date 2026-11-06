//! Bernstein–Yang safegcd inverse over four 64-bit limbs (bb's `bernstein_yang_inverse.hpp`, with
//! golf 0007's batched variable-time divsteps), shared by the x86-64 (`adx.rs`) and aarch64
//! (`arm64.rs`) field configs, which take the result out of the Montgomery domain. (f, g) start at
//! (p, a) with Bézout coefficients (d, e), d·a ≡ f and e·a ≡ g (mod p). Each round runs 62
//! divsteps (`divsteps.rs`) on the low limbs of f and g alone, collecting them in a 2×2 matrix, and
//! then applies the matrix to the full state with an exact /2^62 (plus k·p on the (d, e) side to
//! make it exact); 12 rounds cover the 735-divstep bound for 254-bit inputs. When g reaches 0,
//! f = ±1 and a⁻¹ = ±d. Integers are 5 limbs, the top one signed.

use super::divsteps::divsteps;

type S = [u64; 5];
const MASK: u64 = (1 << 62) - 1;

/// a·x + b·y as a 6-limb signed integer.
fn lincomb(a: i64, x: &S, b: i64, y: &S) -> [u64; 6] {
    let (mut t, mut c) = ([0u64; 6], 0i128);
    for i in 0..4 {
        c += a as i128 * x[i] as i128 + b as i128 * y[i] as i128;
        t[i] = c as u64;
        c >>= 64;
    }
    c += a as i128 * x[4] as i64 as i128 + b as i128 * y[4] as i64 as i128;
    [t[0], t[1], t[2], t[3], c as u64, (c >> 64) as u64]
}

/// Exact arithmetic t / 2^62.
fn shift(t: &[u64; 6]) -> S {
    core::array::from_fn(|i| (t[i] >> 62) | (t[i + 1] << 2))
}

/// (a·x + b·y + k·p) / 2^62, with k making the division exact.
fn row(a: i64, x: &S, b: i64, y: &S, p: &S, pinv: u64) -> S {
    let mut t = lincomb(a, x, b, y);
    let k = t[0].wrapping_neg().wrapping_mul(pinv) & MASK;
    let mut c = 0u128;
    for i in 0..6 {
        c += t[i] as u128 + if i < 5 { k as u128 * p[i] as u128 } else { 0 };
        t[i] = c as u64;
        c >>= 64;
    }
    shift(&t)
}

fn add(x: &mut S, y: &S) {
    let mut c = false;
    for i in 0..5 {
        (x[i], c) = x[i].carrying_add(y[i], c);
    }
}

/// Into [0, p) by repeated ±p (|x| stays within a few dozen p between calls).
fn canon(x: &mut S, p: &S) {
    let minus_p = neg(*p);
    loop {
        if (x[4] as i64) < 0 {
            add(x, p);
        } else if x.iter().rev().ge(p.iter().rev()) {
            add(x, &minus_p);
        } else {
            break;
        }
    }
}

fn neg(mut x: S) -> S {
    x = x.map(|l| !l);
    add(&mut x, &[1, 0, 0, 0, 0]);
    x
}

/// a⁻¹ mod p for 0 < a < p; `p` is the modulus's limbs, then the Montgomery `INV`, then 0.
pub fn inverse(a: &[u64; 4], p: &[u64; 6]) -> [u64; 4] {
    let pinv = p[4].wrapping_neg() & MASK;
    let p: S = [p[0], p[1], p[2], p[3], 0];
    let (mut f, mut g, mut d, mut e) = (p, [a[0], a[1], a[2], a[3], 0], [0; 5], [1, 0, 0, 0, 0]);
    let mut delta = 1;
    for i in 0..12 {
        let [u, v, q, r] = divsteps::<62>(&mut delta, f[0], g[0]);
        (f, g) = (shift(&lincomb(u, &f, v, &g)), shift(&lincomb(q, &f, r, &g)));
        (d, e) = (row(u, &d, v, &e, &p, pinv), row(q, &d, r, &e, &p, pinv));
        if g == [0; 5] {
            break;
        }
        if i % 4 == 3 {
            canon(&mut d, &p);
            canon(&mut e, &p);
        }
    }
    if (f[4] as i64) < 0 {
        d = neg(d);
    }
    canon(&mut d, &p);
    [d[0], d[1], d[2], d[3]]
}
