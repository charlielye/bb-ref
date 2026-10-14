//! bn254 Fr and Fq for wasm with the wide-arithmetic proposal (`--cfg wasm_wide`, target feature
//! `wide-arithmetic`): arkworks' constants and stored form (`a·2^256 mod p`, as natively), with a
//! 4×64 Montgomery multiply over `u128` products that LLVM lowers to `i64.mul_wide_u` and
//! `i64.add128`. The multiply is the no-carry CIOS (gnark's, also mitschabaude/montgomery's wide
//! kernel): each row runs the product and reduction chains interleaved, which p < 2^254 allows
//! without a carry limb. Inversion is the 29-bit Bernstein–Yang (`by29.rs`), faster on wasm than
//! a 64-bit one.

use ark_ff::{BigInt, Fp, MontBackend, MontConfig};

#[inline(always)]
fn mac(a: u64, b: u64, c: u64, d: u64) -> (u64, u64) {
    let x = a as u128 * b as u128 + c as u128 + d as u128;
    (x as u64, (x >> 64) as u64)
}

/// a·b/2^256 mod p for a, b < p; `p` is the modulus limbs, `-p⁻¹ mod 2^64`, then a zero.
#[inline(always)]
pub fn mul(x: &[u64; 4], y: &[u64; 4], p: &[u64; 6]) -> [u64; 4] {
    let mut t = [0u64; 4];
    for i in 0..4 {
        let (t0, mut a) = mac(x[0], y[i], t[0], 0);
        let m = t0.wrapping_mul(p[4]);
        let (_, mut c) = mac(m, p[0], t0, 0);
        for j in 1..4 {
            let (tj, a2) = mac(x[j], y[i], t[j], a);
            let (tj1, c2) = mac(m, p[j], tj, c);
            (a, c, t[j - 1]) = (a2, c2, tj1);
        }
        t[3] = a + c;
    }
    // t < 2p: one conditional subtraction, rarely taken, so a branch.
    let mut o = [0u64; 4];
    let mut borrow = false;
    for i in 0..4 {
        (o[i], borrow) = t[i].borrowing_sub(p[i], borrow);
    }
    if borrow { t } else { o }
}

macro_rules! wide_config {
    ($name:ident, $ark:ty) => {
        #[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
        pub struct $name;

        impl $name {
            const P: [u64; 6] = {
                let m = <$ark as MontConfig<4>>::MODULUS.0;
                [m[0], m[1], m[2], m[3], <$ark as MontConfig<4>>::INV, 0]
            };
            /// R³ mod p: the safegcd inverse of the stored a·R is a⁻¹·R⁻¹, and one multiply by R³
            /// takes it to the stored a⁻¹·R.
            const R3: [u64; 4] = Fp::<MontBackend<Self, 4>, 4>::new(<Self as MontConfig<4>>::R2).0 .0;
            const PINV58: u64 = super::by29::pinv58(<$ark as MontConfig<4>>::MODULUS.0[0]);
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
                let m = <Self as MontConfig<4>>::MODULUS.0;
                let x = (a.0 .0 != [0; 4]).then(|| super::by29::inverse(&a.0 .0, &m, Self::PINV58))?;
                Some(Fp::new_unchecked(BigInt(mul(&x, &Self::R3, &Self::P))))
            }
        }
    };
}

wide_config!(FrConfig, ark_bn254::FrConfig);
wide_config!(FqConfig, ark_bn254::FqConfig);

/// The raw kernels on stored limbs, for hot loops that keep their operands in locals (an
/// out-of-line `Fp` multiply passes both operands and the result through memory).
pub(super) mod raw {
    pub use super::mul;

    /// The `mul` constants for modulus `m`: its limbs, `-m⁻¹ mod 2^64`, then a zero.
    pub const fn consts(m: [u64; 4]) -> [u64; 6] {
        let mut x: u64 = 1;
        let mut i = 0;
        while i < 6 {
            x = x.wrapping_mul(2u64.wrapping_sub(m[0].wrapping_mul(x)));
            i += 1;
        }
        [m[0], m[1], m[2], m[3], x.wrapping_neg(), 0]
    }

    /// a − b mod p (a, b < p), branch-free: the reduction condition is data dependent.
    #[inline(always)]
    pub fn sub(a: &[u64; 4], b: &[u64; 4], p: &[u64; 6]) -> [u64; 4] {
        let mut o = [0u64; 4];
        let mut borrow = false;
        for i in 0..4 {
            (o[i], borrow) = a[i].borrowing_sub(b[i], borrow);
        }
        let mask = (borrow as u64).wrapping_neg();
        let mut carry = false;
        for i in 0..4 {
            (o[i], carry) = o[i].carrying_add(p[i] & mask, carry);
        }
        o
    }

    /// a + b mod p (a, b < p < 2^254, so the sum never carries out), branch-free.
    #[inline(always)]
    pub fn add(a: &[u64; 4], b: &[u64; 4], p: &[u64; 6]) -> [u64; 4] {
        let mut s = [0u64; 4];
        let mut carry = false;
        for i in 0..4 {
            (s[i], carry) = a[i].carrying_add(b[i], carry);
        }
        let mut o = [0u64; 4];
        let mut borrow = false;
        for i in 0..4 {
            (o[i], borrow) = s[i].borrowing_sub(p[i], borrow);
        }
        let keep = (borrow as u64).wrapping_neg();
        core::array::from_fn(|i| (s[i] & keep) | (o[i] & !keep))
    }
}
