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

macro_rules! adx_config {
    ($name:ident, $ark:ty) => {
        #[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
        pub struct $name;

        impl $name {
            const P: [u64; 5] = {
                let m = <$ark as MontConfig<4>>::MODULUS.0;
                [m[0], m[1], m[2], m[3], <$ark as MontConfig<4>>::INV]
            };
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
