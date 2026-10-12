//! bn254 Fr and Fq for x86-64 with ADX: arkworks' own constants and stored form (`a·2^256 mod p`,
//! so every limb matches `ark_bn254`), with the Montgomery multiply and square replaced by bb's
//! lower-latency ADX kernels (golf 0036). Against ark-ff-asm's, every CIOS row and reduction step
//! flushes both carry chains into its own top limb and the next restarts them with a zeroing `xor`,
//! so rounds depend on each other only through limb registers; `k` comes from `imul` (low half
//! only); squaring has its own schedule (cross products doubled, plus squares, then the low half
//! reduced and the high half added); and the final `≥ p` subtraction is a `cmov`, not a branch.
//! Montgomery reduction is unique once the output is canonical, so results equal arkworks'.
//! Zen 4, ns/op vs ark-ff-asm: mul 20.3 → 16.1 dependent, 19.6 → 15.0 independent; square
//! 19.5 → 18.0 and 18.7 → 14.5. Add, double and subtract are asm too, reducing through the same
//! `cmov`/borrow mask: on its own an add measures mixed (dependent 2.4 → 1.9 ns, streaming
//! 2.0 → 2.5 ns), but in place they took 5% off chonk proving. Negation measured neutral and stays
//! arkworks'.
//! Inversion is bb's Bernstein–Yang safegcd (`safegcd` below) in place of arkworks' binary EEA:
//! 4.2 → 1.2 µs, and 8% of chonk proving samples were in `inverse` (mostly the MSM's Fq tree).

use ark_ff::{BigInt, Fp, MontBackend, MontConfig};
use core::arch::asm;

/// One CIOS product row: (t0..t3) + a[off]·b into (t0..t4); t4 is fresh.
#[rustfmt::skip]
macro_rules! row {
    ($off:literal, $t0:literal, $t1:literal, $t2:literal, $t3:literal, $t4:literal) => {
        concat!(
            "xor {z:e}, {z:e}\n mov ", $off, "({a}), %rdx\n",
            "mulx 0({b}), {lo}, {hi}\n adcx {lo}, ", $t0, "\n adox {hi}, ", $t1, "\n",
            "mulx 8({b}), {lo}, {hi}\n adcx {lo}, ", $t1, "\n adox {hi}, ", $t2, "\n",
            "mulx 16({b}), {lo}, {hi}\n adcx {lo}, ", $t2, "\n adox {hi}, ", $t3, "\n",
            "mulx 24({b}), {lo}, ", $t4, "\n adcx {lo}, ", $t3, "\n adox {z}, ", $t4, "\n adcx {z}, ", $t4,
        )
    };
}

/// One CIOS reduction step: t += k·p with k = t0·inv, leaving t0 = 0 (dropped by the caller).
#[rustfmt::skip]
macro_rules! red {
    ($t0:literal, $t1:literal, $t2:literal, $t3:literal, $t4:literal) => {
        concat!(
            "mov ", $t0, ", %rdx\n imul 32({p}), %rdx\n xor {z:e}, {z:e}\n",
            "mulx 0({p}), {lo}, {hi}\n adcx {lo}, ", $t0, "\n adox {hi}, ", $t1, "\n",
            "mulx 8({p}), {lo}, {hi}\n adcx {lo}, ", $t1, "\n adox {hi}, ", $t2, "\n",
            "mulx 16({p}), {lo}, {hi}\n adcx {lo}, ", $t2, "\n adox {hi}, ", $t3, "\n",
            "mulx 24({p}), {lo}, {hi}\n adcx {lo}, ", $t3, "\n adox {hi}, ", $t4, "\n adcx {z}, ", $t4,
        )
    };
}

/// The squaring's reduction step on the low half (u0..u3): u = (u + k·p)/2^64, the new top limb
/// landing in u0's register.
#[rustfmt::skip]
macro_rules! sred {
    ($u0:literal, $u1:literal, $u2:literal, $u3:literal) => {
        concat!(
            "mov ", $u0, ", %rdx\n imul 32({p}), %rdx\n xor {x:e}, {x:e}\n",
            "mulx 0({p}), {x}, {y}\n adcx {x}, ", $u0, "\n adox {y}, ", $u1, "\n",
            "mulx 8({p}), {x}, {y}\n adcx {x}, ", $u1, "\n adox {y}, ", $u2, "\n",
            "mulx 16({p}), {x}, {y}\n adcx {x}, ", $u2, "\n adox {y}, ", $u3, "\n mov $0, {y}\n",
            "mulx 24({p}), {x}, ", $u0, "\n adcx {x}, ", $u3, "\n adox {y}, ", $u0, "\n adcx {y}, ", $u0,
        )
    };
}

/// (t0..t3) < 2p → t mod p, through scratch (s0..s3).
#[rustfmt::skip]
macro_rules! csub {
    ($t0:literal, $t1:literal, $t2:literal, $t3:literal, $s0:literal, $s1:literal, $s2:literal, $s3:literal) => {
        concat!(
            "mov ", $t0, ", ", $s0, "\n sub 0({p}), ", $s0, "\n mov ", $t1, ", ", $s1, "\n sbb 8({p}), ", $s1, "\n",
            "mov ", $t2, ", ", $s2, "\n sbb 16({p}), ", $s2, "\n mov ", $t3, ", ", $s3, "\n sbb 24({p}), ", $s3, "\n",
            "cmovae ", $s0, ", ", $t0, "\n cmovae ", $s1, ", ", $t1, "\n",
            "cmovae ", $s2, ", ", $t2, "\n cmovae ", $s3, ", ", $t3,
        )
    };
}

/// a·b/2^256 mod p for a, b < p; `p` is the modulus limbs then `-p⁻¹ mod 2^64`.
#[inline(always)]
fn mul(a: &[u64; 4], b: &[u64; 4], p: &[u64; 5]) -> [u64; 4] {
    let (t0, t1, t2, t4): (u64, u64, u64, u64);
    unsafe {
        asm!(
            "xor {z:e}, {z:e}",
            "mov 0({a}), %rdx",
            "mulx 0({b}), {t0}, {t1}",
            "mulx 8({b}), {lo}, {t2}",
            "adcx {lo}, {t1}",
            "mulx 16({b}), {lo}, {t3}",
            "adcx {lo}, {t2}",
            "mulx 24({b}), {lo}, {t4}",
            "adcx {lo}, {t3}",
            "adcx {z}, {t4}",
            red!("{t0}", "{t1}", "{t2}", "{t3}", "{t4}"),
            row!("8", "{t1}", "{t2}", "{t3}", "{t4}", "{t0}"),
            red!("{t1}", "{t2}", "{t3}", "{t4}", "{t0}"),
            row!("16", "{t2}", "{t3}", "{t4}", "{t0}", "{t1}"),
            red!("{t2}", "{t3}", "{t4}", "{t0}", "{t1}"),
            row!("24", "{t3}", "{t4}", "{t0}", "{t1}", "{t2}"),
            red!("{t3}", "{t4}", "{t0}", "{t1}", "{t2}"),
            csub!("{t4}", "{t0}", "{t1}", "{t2}", "{lo}", "{hi}", "{z}", "{t3}"),
            a = in(reg) a.as_ptr(),
            b = in(reg) b.as_ptr(),
            p = in(reg) p.as_ptr(),
            t0 = out(reg) t0, t1 = out(reg) t1, t2 = out(reg) t2, t3 = out(reg) _, t4 = out(reg) t4,
            lo = out(reg) _, hi = out(reg) _, z = out(reg) _, out("rdx") _,
            options(att_syntax, pure, readonly, nostack),
        );
    }
    [t4, t0, t1, t2]
}

/// a²/2^256 mod p for a < p.
#[inline(always)]
fn sqr(a: &[u64; 4], p: &[u64; 5]) -> [u64; 4] {
    let (r12, r13, r14, r15): (u64, u64, u64, u64);
    unsafe {
        asm!(
            // Cross products a[i]·a[j], i < j, into r1..r6.
            "mov 0({a}), %rdx",
            "xor {r8:e}, {r8:e}",
            "mulx 8({a}), {r9}, {r10}",
            "mulx 16({a}), {r8}, {r15}",
            "mulx 24({a}), {r11}, {r12}",
            "adox {r8}, {r10}",
            "adcx {r15}, {r11}",
            "mov 8({a}), %rdx",
            "mulx 16({a}), {r8}, {r15}",
            "mulx 24({a}), {x}, {y}",
            "mov 24({a}), %rdx",
            "mulx 16({a}), {r13}, {r14}",
            "adox {r8}, {r11}",
            "adcx {x}, {r12}",
            "adox {r15}, {r12}",
            "adcx {y}, {r13}",
            "mov $0, {r8}",
            "adox {r8}, {r13}",
            "adcx {r8}, {r14}",
            "adox {r8}, {r14}",
            // Doubled, on two chains.
            "adox {r9}, {r9}",
            "adcx {r12}, {r12}",
            "adox {r10}, {r10}",
            "adcx {r13}, {r13}",
            "adox {r11}, {r11}",
            "adcx {r14}, {r14}",
            // Plus the squares: T = a² in r8..r15.
            "mov 0({a}), %rdx",
            "mulx %rdx, {r8}, {y}",
            "mov 16({a}), %rdx",
            "mulx %rdx, %rdx, {x}",
            "adcx {y}, {r9}",
            "adox %rdx, {r12}",
            "adox {x}, {r13}",
            "mov 24({a}), %rdx",
            "mulx %rdx, {y}, {r15}",
            "mov 8({a}), %rdx",
            "mulx %rdx, {x}, %rdx",
            "adcx {x}, {r10}",
            "adcx %rdx, {r11}",
            "adox {y}, {r14}",
            "mov $0, {x}",
            "adox {x}, {r15}",
            "adcx {x}, {r12}",
            "adcx {x}, {r13}",
            "adcx {x}, {r14}",
            "adcx {x}, {r15}",
            // U = (T_lo + K·p)/2^256 ≤ p; the result is U + T_hi < 2p.
            sred!("{r8}", "{r9}", "{r10}", "{r11}"),
            sred!("{r9}", "{r10}", "{r11}", "{r8}"),
            sred!("{r10}", "{r11}", "{r8}", "{r9}"),
            sred!("{r11}", "{r8}", "{r9}", "{r10}"),
            "add {r8}, {r12}",
            "adc {r9}, {r13}",
            "adc {r10}, {r14}",
            "adc {r11}, {r15}",
            csub!("{r12}", "{r13}", "{r14}", "{r15}", "{r8}", "{r9}", "{r10}", "{r11}"),
            a = in(reg) a.as_ptr(),
            p = in(reg) p.as_ptr(),
            r8 = out(reg) _, r9 = out(reg) _, r10 = out(reg) _, r11 = out(reg) _,
            r12 = out(reg) r12, r13 = out(reg) r13, r14 = out(reg) r14, r15 = out(reg) r15,
            x = out(reg) _, y = out(reg) _, out("rdx") _,
            options(att_syntax, pure, readonly, nostack),
        );
    }
    [r12, r13, r14, r15]
}

/// a + b mod p (a, b < p), or 2a with `b = a`.
#[inline(always)]
fn add(a: [u64; 4], b: [u64; 4], p: &[u64; 5]) -> [u64; 4] {
    let [mut t0, mut t1, mut t2, mut t3] = a;
    unsafe {
        asm!(
            "add {b0}, {t0}",
            "adc {b1}, {t1}",
            "adc {b2}, {t2}",
            "adc {b3}, {t3}",
            csub!("{t0}", "{t1}", "{t2}", "{t3}", "{b0}", "{b1}", "{b2}", "{b3}"),
            p = in(reg) p.as_ptr(),
            t0 = inout(reg) t0, t1 = inout(reg) t1, t2 = inout(reg) t2, t3 = inout(reg) t3,
            b0 = inout(reg) b[0] => _, b1 = inout(reg) b[1] => _, b2 = inout(reg) b[2] => _, b3 = inout(reg) b[3] => _,
            options(att_syntax, pure, readonly, nostack),
        );
    }
    [t0, t1, t2, t3]
}

/// a − b mod p (a, b < p): p is added back under a borrow mask.
#[inline(always)]
fn sub(a: [u64; 4], b: [u64; 4], p: &[u64; 5]) -> [u64; 4] {
    let [mut t0, mut t1, mut t2, mut t3] = a;
    unsafe {
        asm!(
            "sub {b0}, {t0}",
            "sbb {b1}, {t1}",
            "sbb {b2}, {t2}",
            "sbb {b3}, {t3}",
            "sbb {m}, {m}",
            "mov 0({p}), {b0}",
            "mov 8({p}), {b1}",
            "mov 16({p}), {b2}",
            "mov 24({p}), {b3}",
            "and {m}, {b0}",
            "and {m}, {b1}",
            "and {m}, {b2}",
            "and {m}, {b3}",
            "add {b0}, {t0}",
            "adc {b1}, {t1}",
            "adc {b2}, {t2}",
            "adc {b3}, {t3}",
            p = in(reg) p.as_ptr(),
            t0 = inout(reg) t0, t1 = inout(reg) t1, t2 = inout(reg) t2, t3 = inout(reg) t3,
            b0 = inout(reg) b[0] => _, b1 = inout(reg) b[1] => _, b2 = inout(reg) b[2] => _, b3 = inout(reg) b[3] => _,
            m = out(reg) _,
            options(att_syntax, pure, readonly, nostack),
        );
    }
    [t0, t1, t2, t3]
}

/// Bernstein–Yang safegcd inverse (bb's `bernstein_yang_inverse.hpp`, with golf 0007's batched
/// variable-time divsteps): (f, g) start at (p, a) with Bézout coefficients (d, e), d·a ≡ f and
/// e·a ≡ g (mod p). Each round runs 62 divsteps on the low limbs of f and g alone, collecting them
/// in a 2×2 matrix, and then applies the matrix to the full state with an exact /2^62 (plus k·p on
/// the (d, e) side to make it exact); 12 rounds cover the 735-divstep bound for 254-bit inputs.
/// When g reaches 0, f = ±1 and a⁻¹ = ±d. Integers are 5 limbs, the top one signed.
mod safegcd {
    type S = [u64; 5];
    const MASK: u64 = (1 << 62) - 1;

    /// 62 divsteps on the low bits of (f, g): the matrix [u v; q r] (scaled by 2^62), δ updated.
    /// Runs of even g are taken at once (count trailing zeros), and consecutive g ← (g + f)/2
    /// steps collapse into g ← g + w·f with w = −g/f mod 2^4 (2^6 right after a swap).
    fn divsteps(delta: &mut i64, mut f: u64, mut g: u64) -> [i64; 4] {
        let (mut u, mut v, mut q, mut r) = (1u64, 0u64, 0u64, 1u64);
        let (mut eta, mut i) = (-*delta, 62u32);
        loop {
            // The sentinel bit at i caps the run at the divsteps left.
            let zeros = (g | (!0u64 << i)).trailing_zeros();
            (g, u, v) = (g >> zeros, u << zeros, v << zeros);
            eta -= zeros as i64;
            i -= zeros;
            if i == 0 {
                break;
            }
            let limit = (eta.unsigned_abs() + 1).min(i as u64) as u32;
            let w = if eta < 0 {
                // δ > 0: (f, g) ← (g, −f), (u, v, q, r) ← (q, r, −u, −v).
                eta = -eta;
                (f, g) = (g, f.wrapping_neg());
                (u, q) = (q, u.wrapping_neg());
                (v, r) = (r, v.wrapping_neg());
                f.wrapping_mul(g).wrapping_mul(f.wrapping_mul(f).wrapping_sub(2)) & (!0u64 >> (64 - limit)) & 63
            } else {
                let w = f.wrapping_add((f.wrapping_add(1) & 4) << 1);
                w.wrapping_mul(g).wrapping_neg() & (!0u64 >> (64 - limit)) & 15
            };
            g = g.wrapping_add(f.wrapping_mul(w));
            q = q.wrapping_add(u.wrapping_mul(w));
            r = r.wrapping_add(v.wrapping_mul(w));
        }
        *delta = -eta;
        [u as i64, v as i64, q as i64, r as i64]
    }

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

    /// a⁻¹ mod p for 0 < a < p; `p` is the modulus limbs then `−p⁻¹ mod 2^64`.
    pub(super) fn inverse(a: &[u64; 4], p: &[u64; 5]) -> [u64; 4] {
        let pinv = p[4].wrapping_neg() & MASK;
        let p: S = [p[0], p[1], p[2], p[3], 0];
        let (mut f, mut g, mut d, mut e) = (p, [a[0], a[1], a[2], a[3], 0], [0; 5], [1, 0, 0, 0, 0]);
        let mut delta = 1;
        for i in 0..12 {
            let [u, v, q, r] = divsteps(&mut delta, f[0], g[0]);
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
}

macro_rules! adx_config {
    ($name:ident, $ark:ty) => {
        #[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
        pub struct $name;

        impl $name {
            const P: [u64; 5] = {
                let m = <$ark as MontConfig<4>>::MODULUS.0;
                [m[0], m[1], m[2], m[3], <$ark as MontConfig<4>>::INV]
            };
            /// R³ mod p: the safegcd inverse of the stored a·R is a⁻¹·R⁻¹, and one multiply by R³
            /// takes it to the stored a⁻¹·R.
            const R3: [u64; 4] = Fp::<MontBackend<Self, 4>, 4>::new(<Self as MontConfig<4>>::R2)
                .0
                 .0;
        }

        impl MontConfig<4> for $name {
            const MODULUS: BigInt<4> = <$ark as MontConfig<4>>::MODULUS;
            const GENERATOR: Fp<MontBackend<Self, 4>, 4> = Fp::new_unchecked(<$ark as MontConfig<4>>::GENERATOR.0);
            const TWO_ADIC_ROOT_OF_UNITY: Fp<MontBackend<Self, 4>, 4> =
                Fp::new_unchecked(<$ark as MontConfig<4>>::TWO_ADIC_ROOT_OF_UNITY.0);
            const SMALL_SUBGROUP_BASE: Option<u32> = <$ark as MontConfig<4>>::SMALL_SUBGROUP_BASE;
            const SMALL_SUBGROUP_BASE_ADICITY: Option<u32> = <$ark as MontConfig<4>>::SMALL_SUBGROUP_BASE_ADICITY;
            const LARGE_SUBGROUP_ROOT_OF_UNITY: Option<Fp<MontBackend<Self, 4>, 4>> =
                match <$ark as MontConfig<4>>::LARGE_SUBGROUP_ROOT_OF_UNITY {
                    Some(x) => Some(Fp::new_unchecked(x.0)),
                    None => None,
                };

            #[inline(always)]
            fn mul_assign(a: &mut Fp<MontBackend<Self, 4>, 4>, b: &Fp<MontBackend<Self, 4>, 4>) {
                a.0 .0 = mul(&a.0 .0, &b.0 .0, &Self::P);
            }

            #[inline(always)]
            fn square_in_place(a: &mut Fp<MontBackend<Self, 4>, 4>) {
                a.0 .0 = sqr(&a.0 .0, &Self::P);
            }

            fn inverse(a: &Fp<MontBackend<Self, 4>, 4>) -> Option<Fp<MontBackend<Self, 4>, 4>> {
                let x = (a.0 .0 != [0; 4]).then(|| safegcd::inverse(&a.0 .0, &Self::P))?;
                Some(Fp::new_unchecked(BigInt(mul(&x, &Self::R3, &Self::P))))
            }

            #[inline(always)]
            fn add_assign(a: &mut Fp<MontBackend<Self, 4>, 4>, b: &Fp<MontBackend<Self, 4>, 4>) {
                a.0 .0 = add(a.0 .0, b.0 .0, &Self::P);
            }

            #[inline(always)]
            fn double_in_place(a: &mut Fp<MontBackend<Self, 4>, 4>) {
                a.0 .0 = add(a.0 .0, a.0 .0, &Self::P);
            }

            #[inline(always)]
            fn sub_assign(a: &mut Fp<MontBackend<Self, 4>, 4>, b: &Fp<MontBackend<Self, 4>, 4>) {
                a.0 .0 = sub(a.0 .0, b.0 .0, &Self::P);
            }
        }
    };
}

adx_config!(FrConfig, ark_bn254::FrConfig);
adx_config!(FqConfig, ark_bn254::FqConfig);

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::{AdditiveGroup, Field, UniformRand};

    /// Limb-for-limb against arkworks on edge values (0, 1, p−1, p−2, values with all-ones and
    /// top-heavy limbs) and random ones.
    fn check<C: MontConfig<4>, A: MontConfig<4>>() {
        type F<C> = Fp<MontBackend<C, 4>, 4>;
        let m = A::MODULUS.0;
        let mut limbs = vec![
            [0; 4],
            [1, 0, 0, 0],
            [m[0] - 1, m[1], m[2], m[3]],
            [m[0] - 2, m[1], m[2], m[3]],
            [u64::MAX, u64::MAX, u64::MAX, m[3] - 1],
            [0, 0, 0, m[3]],
            [u64::MAX, 0, u64::MAX, 0],
        ];
        let mut rng = ark_std::test_rng();
        limbs.extend((0..2000).map(|_| F::<A>::rand(&mut rng).0 .0));
        for x in &limbs {
            let (ox, ax) = (F::<C>::new_unchecked(BigInt(*x)), F::<A>::new_unchecked(BigInt(*x)));
            assert_eq!(ox.square().0, ax.square().0, "square {x:?}");
            assert_eq!(ox.double().0, ax.double().0, "double {x:?}");
            assert_eq!(ox.inverse().map(|v| v.0), ax.inverse().map(|v| v.0), "inverse {x:?}");
            for y in limbs.iter().step_by(7).chain(&limbs[..7]) {
                let (oy, ay) = (F::<C>::new_unchecked(BigInt(*y)), F::<A>::new_unchecked(BigInt(*y)));
                assert_eq!((ox * oy).0, (ax * ay).0, "mul {x:?} {y:?}");
                assert_eq!((ox + oy).0, (ax + ay).0, "add {x:?} {y:?}");
                assert_eq!((ox - oy).0, (ax - ay).0, "sub {x:?} {y:?}");
            }
        }
    }

    #[test]
    fn matches_arkworks() {
        check::<FrConfig, ark_bn254::FrConfig>();
        check::<FqConfig, ark_bn254::FqConfig>();
    }
}
