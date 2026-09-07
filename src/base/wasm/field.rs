//! bn254 Fr and Fq for the wasm build: arkworks' `Fp` container over bb-ref's own `MontConfig`,
//! storing `a·2^261 mod p` (bb's wasm form) and multiplying through bb's 9×29-bit scheme
//! (`mont29`). Every other target uses arkworks' own bn254 configs (see `base/wasm/mod.rs`), so
//! the field type there is exactly `ark_bn254::Fr`.
//!
//! The 2^261 domain appears in exactly four constants, all here: `R` (the stored form of one),
//! `R2 = 2^517 mod p` — what arkworks' const-context constructor (`Fp::new`, hence every `MontFp!`)
//! multiplies by while dividing by 2^256, so constants land in the 2^261 form — the runtime
//! `R'^2 = 2^522 mod p` that `from_bigint` and `inverse` use through the /2^261 multiply, and the
//! 29-bit modulus image. Everything arkworks derives from `MODULUS` alone (`INV`, the no-carry
//! flags, the square-root precomputation) keeps its default.

use super::mont29;
use ark_ff::{BigInt, BigInteger, Fp, MontBackend, MontConfig, MontFp, Zero};

macro_rules! bn254_wasm_config {
    ($name:ident, $modulus:expr, $r:expr, $r2_const:expr, $r2_runtime:expr,
     $generator:literal, $two_adic_root:literal, $small_base:expr, $small_adicity:expr, $large_root:expr) => {
        #[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
        pub struct $name;

        impl $name {
            const P29: [u64; 9] = mont29::to29(&$modulus);
            const INV29: u64 = mont29::inv29(Self::P29[0]);
            /// `R'^2 = 2^522 mod p`: multiplying by it through the /2^261 kernel is the canonical
            /// → stored conversion.
            const R2_RUNTIME: [u64; 4] = $r2_runtime;
            #[inline(always)]
            fn mul(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
                mont29::mont_mul_261(a, b, &$modulus, &Self::P29, Self::INV29)
            }
        }

        impl MontConfig<4> for $name {
            const MODULUS: BigInt<4> = BigInt::new($modulus);
            const R: BigInt<4> = BigInt::new($r);
            const R2: BigInt<4> = BigInt::new($r2_const);
            const GENERATOR: Fp<MontBackend<Self, 4>, 4> = MontFp!($generator);
            const TWO_ADIC_ROOT_OF_UNITY: Fp<MontBackend<Self, 4>, 4> = MontFp!($two_adic_root);
            const SMALL_SUBGROUP_BASE: Option<u32> = $small_base;
            const SMALL_SUBGROUP_BASE_ADICITY: Option<u32> = $small_adicity;
            const LARGE_SUBGROUP_ROOT_OF_UNITY: Option<Fp<MontBackend<Self, 4>, 4>> = $large_root;

            #[inline(always)]
            fn mul_assign(a: &mut Fp<MontBackend<Self, 4>, 4>, b: &Fp<MontBackend<Self, 4>, 4>) {
                a.0 .0 = Self::mul(&a.0 .0, &b.0 .0);
            }

            #[inline(always)]
            fn square_in_place(a: &mut Fp<MontBackend<Self, 4>, 4>) {
                a.0 .0 = Self::mul(&a.0 .0, &a.0 .0);
            }

            fn sum_of_products<const M: usize>(
                a: &[Fp<MontBackend<Self, 4>, 4>; M],
                b: &[Fp<MontBackend<Self, 4>, 4>; M],
            ) -> Fp<MontBackend<Self, 4>, 4> {
                // The generic CIOS path divides by 2^256; stay on the domain's own multiply.
                let mut acc = Fp::<MontBackend<Self, 4>, 4>::zero();
                for i in 0..M {
                    acc += a[i] * b[i];
                }
                acc
            }

            fn inverse(a: &Fp<MontBackend<Self, 4>, 4>) -> Option<Fp<MontBackend<Self, 4>, 4>> {
                // Binary EEA (arkworks' own), R-agnostic except for the seed: R'^2 takes `a·R'` in
                // to `a^-1·R'` out.
                if a.is_zero() {
                    return None;
                }
                let one = BigInt::from(1u64);
                let mut u = a.0;
                let mut v = Self::MODULUS;
                let mut b = Fp::<MontBackend<Self, 4>, 4>::new_unchecked(BigInt::new(Self::R2_RUNTIME));
                let mut c = Fp::<MontBackend<Self, 4>, 4>::zero();
                while u != one && v != one {
                    while u.is_even() {
                        u.div2();
                        if b.0.is_even() {
                            b.0.div2();
                        } else {
                            let _ = b.0.add_with_carry(&Self::MODULUS);
                            b.0.div2();
                        }
                    }
                    while v.is_even() {
                        v.div2();
                        if c.0.is_even() {
                            c.0.div2();
                        } else {
                            let _ = c.0.add_with_carry(&Self::MODULUS);
                            c.0.div2();
                        }
                    }
                    if v < u {
                        u.sub_with_borrow(&v);
                        b -= &c;
                    } else {
                        v.sub_with_borrow(&u);
                        c -= &b;
                    }
                }
                Some(if u == one { b } else { c })
            }

            fn from_bigint(r: BigInt<4>) -> Option<Fp<MontBackend<Self, 4>, 4>> {
                if r.is_zero() {
                    return Some(Fp::zero());
                }
                if r >= Self::MODULUS {
                    return None;
                }
                Some(Fp::new_unchecked(BigInt::new(Self::mul(&r.0, &Self::R2_RUNTIME))))
            }

            #[inline]
            fn into_bigint(a: Fp<MontBackend<Self, 4>, 4>) -> BigInt<4> {
                // One multiply by 1 divides by 2^261 exactly.
                BigInt::new(Self::mul(&a.0 .0, &[1, 0, 0, 0]))
            }
        }
    };
}

bn254_wasm_config!(
    FrConfig,
    [
        0x43e1f593f0000001,
        0x2833e84879b97091,
        0xb85045b68181585d,
        0x30644e72e131a029
    ],
    [
        0x2fd4e1568fffff57,
        0x75bba827a494b01a,
        0x5301fa84819caa80,
        0x0dc83629563d4475
    ],
    [
        0x333ad321d42db4df,
        0x57936df3f1d1cbd2,
        0xd0e021f3f5eeb84d,
        0x1275c7bd0896f487
    ],
    [
        0x38c2e14b45b69bd4,
        0x0ffedb1885883377,
        0x7840f9f0abc6e54d,
        0x0a054a3e848b0f05
    ],
    "5",
    "19103219067921713944291392827692070036145651957329286315305642004821462161904",
    Some(3),
    Some(2),
    Some(MontFp!(
        "8001236115608269688640730372558895144313937963023562728862538587154079436142"
    ))
);

bn254_wasm_config!(
    FqConfig,
    [
        0x3c208c16d87cfd47,
        0x97816a916871ca8d,
        0xb85045b68181585d,
        0x30644e72e131a029
    ],
    [
        0x4e8384eb157ccc21,
        0xfb90a6020ce148c3,
        0x5301fa84819caa36,
        0x0dc83629563d4475
    ],
    [
        0x751d5b0f0f6b5c04,
        0x5edd77f4e6d91549,
        0x1422c907422a9d60,
        0x1982b46dd2402342
    ],
    [
        0xe1a2a074659bac10,
        0x639855865406005a,
        0xff54c5802d3e2632,
        0x2a11a68c34ea65a6
    ],
    "3",
    "21888242871839275222246405745257275088696311157297823662689037894645226208582",
    None,
    None,
    None
);

/// Every value and constant, checked against arkworks' own bn254 fields through canonical integers.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::{Fq, Fr};
    use ark_ff::{AdditiveGroup, Field, PrimeField, UniformRand};

    fn same<A: PrimeField<BigInt = BigInt<4>>, B: PrimeField<BigInt = BigInt<4>>>(a: A, b: B) -> bool {
        a.into_bigint() == b.into_bigint()
    }

    macro_rules! check_field {
        ($ours:ty, $theirs:ty, $config:ty, $their_config:ty) => {{
            let mut rng = ark_std::test_rng();
            assert_eq!(<$ours>::ONE.into_bigint(), BigInt::from(1u64));
            assert!(same(<$config>::GENERATOR, <$their_config>::GENERATOR));
            assert!(same(
                <$config>::TWO_ADIC_ROOT_OF_UNITY,
                <$their_config>::TWO_ADIC_ROOT_OF_UNITY
            ));
            assert_eq!(<$config>::SMALL_SUBGROUP_BASE, <$their_config>::SMALL_SUBGROUP_BASE);
            assert_eq!(
                <$config>::LARGE_SUBGROUP_ROOT_OF_UNITY.map(|x| x.into_bigint()),
                <$their_config>::LARGE_SUBGROUP_ROOT_OF_UNITY.map(|x| x.into_bigint())
            );
            assert!(<$ours>::from_bigint(<$config>::MODULUS).is_none());
            assert!(same(<$ours>::from(123456789u64), <$theirs>::from(123456789u64)));
            for _ in 0..200 {
                let (x, y) = (<$theirs>::rand(&mut rng), <$theirs>::rand(&mut rng));
                let (ox, oy) = (
                    <$ours>::from_bigint(x.into_bigint()).unwrap(),
                    <$ours>::from_bigint(y.into_bigint()).unwrap(),
                );
                assert_eq!(ox.into_bigint(), x.into_bigint(), "round trip");
                assert!(same(ox * oy, x * y), "mul");
                assert!(same(ox.square(), x.square()), "square");
                assert!(same(ox + oy, x + y), "add");
                assert!(same(ox - oy, x - y), "sub");
                assert!(same(-ox, -x), "neg");
                assert!(same(ox.double(), x.double()), "double");
                assert!(same(ox.inverse().unwrap(), x.inverse().unwrap()), "inverse");
                assert!(
                    same(
                        <$ours>::sum_of_products(&[ox, oy], &[oy, ox]),
                        <$theirs>::sum_of_products(&[x, y], &[y, x])
                    ),
                    "sum_of_products"
                );
                assert!(same(ox.pow([17u64]), x.pow([17u64])), "pow");
                let sq = ox.square();
                let root = sq.sqrt().expect("square has a root");
                assert!(root == ox || root == -ox, "sqrt");
                assert_eq!(ox.legendre(), x.legendre(), "legendre");
            }
        }};
    }

    #[test]
    fn fr_matches_arkworks() {
        check_field!(Fr, ark_bn254::Fr, FrConfig, ark_bn254::FrConfig);
    }

    #[test]
    fn fq_matches_arkworks() {
        check_field!(Fq, ark_bn254::Fq, FqConfig, ark_bn254::FqConfig);
    }

    #[test]
    fn stored_domain_is_2_pow_261() {
        // Stored limbs are `value · 2^261 mod p`: one is stored as `R`, the element 2^256 as `R2`
        // (2^517 mod p, what the const-context constructor multiplies by), the element 2^261 as
        // `R'^2` (2^522 mod p, what `from_bigint` multiplies by).
        assert_eq!(Fr::ONE.0, FrConfig::R);
        assert_eq!(Fr::from(2u64).pow([256u64]).0, FrConfig::R2);
        assert_eq!(Fr::from(2u64).pow([261u64]).0, BigInt::new(FrConfig::R2_RUNTIME));
        assert_eq!(Fq::ONE.0, FqConfig::R);
        assert_eq!(Fq::from(2u64).pow([256u64]).0, FqConfig::R2);
        assert_eq!(Fq::from(2u64).pow([261u64]).0, BigInt::new(FqConfig::R2_RUNTIME));
        // The const-context constructor (hence every `MontFp!`) lands in the runtime domain.
        assert_eq!(Fr::new(BigInt::from(7u64)), Fr::from(7u64));
        assert_eq!(Fq::new(BigInt::from(7u64)), Fq::from(7u64));
    }
}
