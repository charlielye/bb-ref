//! bn254 Fr and Fq for aarch64: arkworks' constants and stored form (`a·2^256 mod p`, so every limb
//! matches `ark_bn254`), with the Montgomery multiply in asm and the inverse bb's safegcd
//! (`safegcd.rs`), as `adx.rs` does for x86-64. The multiply is the no-carry CIOS arkworks also
//! runs (bn254's top limb leaves the spare bit it needs), scheduled by hand: each round's four
//! products and four reduction products issue as independent `mul`/`umulh` pairs, then fold in with
//! one `adds`/`adcs` chain each, and the final `≥ p` subtraction is a `csel`, not a branch. LLVM's
//! code for the same algorithm interleaves the chains through the carry flag. M3 Pro, ns/op against
//! arkworks: dependent 16.1 → 12.7–13.2, independent 11.4 → 10.2. Squaring is the multiply;
//! addition, doubling, subtraction and negation stay arkworks'.

use super::safegcd;
use ark_ff::{BigInt, Fp, MontBackend, MontConfig};

/// a·b·2^-256 mod p (the no-carry CIOS), for a, b < p; `p` is the modulus's limbs, then `INV`.
/// `b`'s limbs and the modulus are loaded inside the block as each round needs them: passed as
/// registers they took 27, and the callers' hot loops (the MSM's bucket tree) spilled and rebuilt
/// the constants around every multiply (Graviton4 chonk: 0.991 paired median).
#[inline(always)]
fn mul(a: &[u64; 4], b: &[u64; 4], p: &[u64; 6]) -> [u64; 4] {
    let (r0, r1, r2, r3): (u64, u64, u64, u64);
    // Round 0 sets t = a·b_0 from its products; later rounds add a·b_i into t (t4 fresh).
    macro_rules! first {
        () => {
            "mov {t0}, {l0}\n adds {t1}, {l1}, {h0}\n adcs {t2}, {l2}, {h1}\n adcs {t3}, {l3}, {h2}\n adc {t4}, {h3}, xzr\n"
        };
    }
    macro_rules! next {
        () => {
            concat!(
                "adds {t0}, {t0}, {l0}\n adcs {t1}, {t1}, {l1}\n adcs {t2}, {t2}, {l2}\n adcs {t3}, {t3}, {l3}\n adc {t4}, xzr, xzr\n",
                "adds {t1}, {t1}, {h0}\n adcs {t2}, {t2}, {h1}\n adcs {t3}, {t3}, {h2}\n adc {t4}, {t4}, {h3}\n"
            )
        };
    }
    // One round: the products a·b_i (b_i at byte offset `$off`), `$add` them into t, then
    // t = (t + m·p) / 2^64 with m = t0·INV.
    macro_rules! round {
        ($off:literal, $add:expr) => {
            concat!(
                "ldr {bi}, [{bp}, #", $off, "]\n",
                "mul {l0}, {a0}, {bi}\n umulh {h0}, {a0}, {bi}\n",
                "mul {l1}, {a1}, {bi}\n umulh {h1}, {a1}, {bi}\n",
                "mul {l2}, {a2}, {bi}\n umulh {h2}, {a2}, {bi}\n",
                "mul {l3}, {a3}, {bi}\n umulh {h3}, {a3}, {bi}\n",
                $add,
                "ldr {m}, [{pp}, #32]\n mul {m}, {t0}, {m}\n",
                "ldp {pa}, {pb}, [{pp}]\n",
                "mul {l0}, {m}, {pa}\n umulh {h0}, {m}, {pa}\n",
                "mul {l1}, {m}, {pb}\n umulh {h1}, {m}, {pb}\n",
                "ldp {pa}, {pb}, [{pp}, #16]\n",
                "mul {l2}, {m}, {pa}\n umulh {h2}, {m}, {pa}\n",
                "mul {l3}, {m}, {pb}\n umulh {h3}, {m}, {pb}\n",
                "adds {t0}, {t0}, {l0}\n adcs {t1}, {t1}, {l1}\n adcs {t2}, {t2}, {l2}\n adcs {t3}, {t3}, {l3}\n adc {t4}, {t4}, xzr\n",
                "adds {t0}, {t1}, {h0}\n adcs {t1}, {t2}, {h1}\n adcs {t2}, {t3}, {h2}\n adc {t3}, {t4}, {h3}\n",
            )
        };
    }
    // SAFETY: reads only `b` and `p`, both valid for their lengths.
    unsafe {
        core::arch::asm!(
            round!("0", first!()),
            round!("8", next!()),
            round!("16", next!()),
            round!("24", next!()),
            // t < 2p: subtract p unless that borrows.
            "ldp {pa}, {pb}, [{pp}]",
            "subs {l0}, {t0}, {pa}", "sbcs {l1}, {t1}, {pb}",
            "ldp {pa}, {pb}, [{pp}, #16]",
            "sbcs {l2}, {t2}, {pa}", "sbcs {l3}, {t3}, {pb}",
            "csel {t0}, {t0}, {l0}, lo", "csel {t1}, {t1}, {l1}, lo", "csel {t2}, {t2}, {l2}, lo", "csel {t3}, {t3}, {l3}, lo",
            a0 = in(reg) a[0], a1 = in(reg) a[1], a2 = in(reg) a[2], a3 = in(reg) a[3],
            bp = in(reg) b.as_ptr(), pp = in(reg) p.as_ptr(),
            t0 = out(reg) r0, t1 = out(reg) r1, t2 = out(reg) r2, t3 = out(reg) r3, t4 = out(reg) _,
            bi = out(reg) _, m = out(reg) _, pa = out(reg) _, pb = out(reg) _,
            l0 = out(reg) _, l1 = out(reg) _, l2 = out(reg) _, l3 = out(reg) _,
            h0 = out(reg) _, h1 = out(reg) _, h2 = out(reg) _, h3 = out(reg) _,
            options(pure, readonly, nostack),
        );
    }
    [r0, r1, r2, r3]
}

macro_rules! arm64_config {
    ($name:ident, $ark:ty) => {
        #[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
        pub struct $name;

        impl $name {
            const P: [u64; 6] = {
                let m = <$ark as MontConfig<4>>::MODULUS.0;
                [m[0], m[1], m[2], m[3], <$ark as MontConfig<4>>::INV, 0]
            };
            /// R³ mod p: the safegcd inverse of the stored a·R is a⁻¹·R⁻¹, and one multiply by R³
            /// (with its R⁻¹) brings it to a⁻¹·R.
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
                a.0 .0 = mul(&a.0 .0, &a.0 .0, &Self::P);
            }

            fn inverse(a: &Fp<MontBackend<Self, 4>, 4>) -> Option<Fp<MontBackend<Self, 4>, 4>> {
                let x = (a.0 .0 != [0; 4]).then(|| safegcd::inverse(&a.0 .0, &Self::P))?;
                Some(Fp::new_unchecked(BigInt(mul(&x, &Self::R3, &Self::P))))
            }
        }
    };
}

arm64_config!(FrConfig, ark_bn254::FrConfig);
arm64_config!(FqConfig, ark_bn254::FqConfig);

#[cfg(test)]
mod tests {
    #[test]
    fn matches_arkworks() {
        super::super::check_against_arkworks::<super::FrConfig, ark_bn254::FrConfig>();
        super::super::check_against_arkworks::<super::FqConfig, ark_bn254::FqConfig>();
    }
}
