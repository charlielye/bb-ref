use super::{Fp, FpConfig};
use crate::{biginteger::arithmetic as fa, BigInt, BigInteger, PrimeField, SqrtPrecomputation, Zero};
use ark_ff_macros::unroll_for_loops;
use ark_std::marker::PhantomData;

/// A trait that specifies the constants and arithmetic procedures
/// for Montgomery arithmetic over the prime field defined by `MODULUS`.
///
/// # Note
/// Manual implementation of this trait is not recommended unless one wishes
/// to specialize arithmetic methods. Instead, the
/// [`MontConfig`][`ark_ff_macros::MontConfig`] derive macro should be used.
pub trait MontConfig<const N: usize>: 'static + Sync + Send + Sized {
    /// The modulus of the field.
    const MODULUS: BigInt<N>;

    /// Let `M` be the power of 2^64 nearest to `Self::MODULUS_BITS`. Then
    /// `R = M % Self::MODULUS`.
    const R: BigInt<N> = Self::MODULUS.montgomery_r();

    /// R2 = R^2 % Self::MODULUS
    const R2: BigInt<N> = Self::MODULUS.montgomery_r2();

    /// INV = -MODULUS^{-1} mod 2^64
    const INV: u64 = inv::<Self, N>();

    /// A multiplicative generator of the field.
    /// `Self::GENERATOR` is an element having multiplicative order
    /// `Self::MODULUS - 1`.
    const GENERATOR: Fp<MontBackend<Self, N>, N>;

    /// Can we use the no-carry optimization for multiplication
    /// outlined [here](https://hackmd.io/@gnark/modular_multiplication)?
    ///
    /// This optimization applies if
    /// (a) `Self::MODULUS[N-1] < u64::MAX >> 1`, and
    /// (b) the bits of the modulus are not all 1.
    #[doc(hidden)]
    const CAN_USE_NO_CARRY_MUL_OPT: bool = can_use_no_carry_mul_optimization::<Self, N>();

    /// Can we use the no-carry optimization for squaring
    /// outlined [here](https://hackmd.io/@gnark/modular_multiplication)?
    ///
    /// This optimization applies if
    /// (a) `Self::MODULUS[N-1] < u64::MAX >> 2`, and
    /// (b) the bits of the modulus are not all 1.
    #[doc(hidden)]
    const CAN_USE_NO_CARRY_SQUARE_OPT: bool = can_use_no_carry_mul_optimization::<Self, N>();

    /// Does the modulus have a spare unused bit
    ///
    /// This condition applies if
    /// (a) `Self::MODULUS[N-1] >> 63 == 0`
    #[doc(hidden)]
    const MODULUS_HAS_SPARE_BIT: bool = modulus_has_spare_bit::<Self, N>();

    /// 2^s root of unity computed by GENERATOR^t
    const TWO_ADIC_ROOT_OF_UNITY: Fp<MontBackend<Self, N>, N>;

    /// An integer `b` such that there exists a multiplicative subgroup
    /// of size `b^k` for some integer `k`.
    const SMALL_SUBGROUP_BASE: Option<u32> = None;

    /// The integer `k` such that there exists a multiplicative subgroup
    /// of size `Self::SMALL_SUBGROUP_BASE^k`.
    const SMALL_SUBGROUP_BASE_ADICITY: Option<u32> = None;

    /// GENERATOR^((MODULUS-1) / (2^s *
    /// SMALL_SUBGROUP_BASE^SMALL_SUBGROUP_BASE_ADICITY)).
    /// Used for mixed-radix FFT.
    const LARGE_SUBGROUP_ROOT_OF_UNITY: Option<Fp<MontBackend<Self, N>, N>> = None;

    /// Precomputed material for use when computing square roots.
    /// The default is to use the standard Tonelli-Shanks algorithm.
    const SQRT_PRECOMP: Option<SqrtPrecomputation<Fp<MontBackend<Self, N>, N>>> = sqrt_precomputation();

    /// (MODULUS + 1) / 4 when MODULUS % 4 == 3. Used for square root precomputations.
    #[doc(hidden)]
    const MODULUS_PLUS_ONE_DIV_FOUR: Option<BigInt<N>> = {
        match Self::MODULUS.mod_4() == 3 {
            true => {
                let (modulus_plus_one, carry) = Self::MODULUS.const_add_with_carry(&BigInt::one());
                let mut result = modulus_plus_one.divide_by_2_round_down();
                // Since modulus_plus_one is even, dividing by 2 results in a MSB of 0.
                // Thus we can set MSB to `carry` to get the correct result of (MODULUS + 1) // 2:
                result.0[N - 1] |= (carry as u64) << 63;
                Some(result.divide_by_2_round_down())
            }
            false => None,
        }
    };

    /// (MODULUS + 3) / 8 when MODULUS % 8 == 5. Used for square root precomputations.
    #[doc(hidden)]
    const MODULUS_PLUS_THREE_DIV_EIGHT: Option<BigInt<N>> = {
        match Self::MODULUS.mod_8() == 5 {
            true => {
                let (modulus_plus_three, carry) = Self::MODULUS.const_add_with_carry(&BigInt!("3"));
                let mut result = modulus_plus_three.divide_by_2_round_down();
                // Since modulus_plus_one is even, dividing by 2 results in a MSB of 0.
                // Thus we can set MSB to `carry` to get the correct result of (MODULUS + 1) // 2:
                result.0[N - 1] |= (carry as u64) << 63;
                result = result.divide_by_2_round_down();

                Some(result.divide_by_2_round_down())
            }
            false => None,
        }
    };

    /// (MODULUS - 1) / 4 when MODULUS % 8 == 5. Used for square root precomputations.
    #[doc(hidden)]
    const MODULUS_MINUS_ONE_DIV_FOUR: Option<BigInt<N>> = {
        match Self::MODULUS.mod_8() == 5 {
            true => {
                let (modulus_plus_three, _) = Self::MODULUS.const_sub_with_borrow(&BigInt::one());
                let result = modulus_plus_three.divide_by_2_round_down();
                Some(result.divide_by_2_round_down())
            }
            false => None,
        }
    };

    /// Sets `a = a + b`.
    #[inline(always)]
    fn add_assign(a: &mut Fp<MontBackend<Self, N>, N>, b: &Fp<MontBackend<Self, N>, N>) {
        // This cannot exceed the backing capacity.
        let c = a.0.add_with_carry(&b.0);
        // However, it may need to be reduced
        if Self::MODULUS_HAS_SPARE_BIT {
            a.subtract_modulus()
        } else {
            a.subtract_modulus_with_carry(c)
        }
    }

    /// Sets `a = a - b`.
    #[inline(always)]
    fn sub_assign(a: &mut Fp<MontBackend<Self, N>, N>, b: &Fp<MontBackend<Self, N>, N>) {
        // If `other` is larger than `self`, add the modulus to self first.
        if b.0 > a.0 {
            a.0.add_with_carry(&Self::MODULUS);
        }
        a.0.sub_with_borrow(&b.0);
    }

    /// Sets `a = 2 * a`.
    #[inline(always)]
    fn double_in_place(a: &mut Fp<MontBackend<Self, N>, N>) {
        // This cannot exceed the backing capacity.
        let c = a.0.mul2();
        // However, it may need to be reduced.
        if Self::MODULUS_HAS_SPARE_BIT {
            a.subtract_modulus()
        } else {
            a.subtract_modulus_with_carry(c)
        }
    }

    /// Sets `a = -a`.
    #[inline(always)]
    fn neg_in_place(a: &mut Fp<MontBackend<Self, N>, N>) {
        if !a.is_zero() {
            let mut tmp = Self::MODULUS;
            tmp.sub_with_borrow(&a.0);
            a.0 = tmp;
        }
    }

    /// This modular multiplication algorithm uses Montgomery
    /// reduction for efficient implementation. It also additionally
    /// uses the "no-carry optimization" outlined
    /// [here](https://hackmd.io/@gnark/modular_multiplication) if
    /// `Self::MODULUS` has (a) a non-zero MSB, and (b) at least one
    /// zero bit in the rest of the modulus.
    #[unroll_for_loops(12)]
    #[inline(always)]
    fn mul_assign(a: &mut Fp<MontBackend<Self, N>, N>, b: &Fp<MontBackend<Self, N>, N>) {
        // No-carry optimisation applied to CIOS
        if Self::CAN_USE_NO_CARRY_MUL_OPT {
            if N <= 6
                && N > 1
                && cfg!(all(
                    feature = "asm",
                    target_feature = "bmi2",
                    target_feature = "adx",
                    target_arch = "x86_64"
                ))
            {
                #[cfg(
                    all(
                        feature = "asm",
                        target_feature = "bmi2",
                        target_feature = "adx",
                        target_arch = "x86_64"
                    )
                )]
                #[allow(unsafe_code)]
                #[rustfmt::skip]

                // Tentatively avoid using assembly for `N == 1`.
                match N {
                    2 => { ark_ff_asm::x86_64_asm_mul!(2, (a.0).0, (b.0).0); },
                    3 => { ark_ff_asm::x86_64_asm_mul!(3, (a.0).0, (b.0).0); },
                    4 => { ark_ff_asm::x86_64_asm_mul!(4, (a.0).0, (b.0).0); },
                    5 => { ark_ff_asm::x86_64_asm_mul!(5, (a.0).0, (b.0).0); },
                    6 => { ark_ff_asm::x86_64_asm_mul!(6, (a.0).0, (b.0).0); },
                    _ => unsafe { ark_std::hint::unreachable_unchecked() },
                };
            } else {
                let mut r = [0u64; N];

                for i in 0..N {
                    let mut carry1 = 0u64;
                    r[0] = fa::mac(r[0], (a.0).0[0], (b.0).0[i], &mut carry1);

                    let k = r[0].wrapping_mul(Self::INV);

                    let mut carry2 = 0u64;
                    fa::mac_discard(r[0], k, Self::MODULUS.0[0], &mut carry2);

                    for j in 1..N {
                        r[j] = fa::mac_with_carry(r[j], (a.0).0[j], (b.0).0[i], &mut carry1);
                        r[j - 1] = fa::mac_with_carry(r[j], k, Self::MODULUS.0[j], &mut carry2);
                    }
                    r[N - 1] = carry1 + carry2;
                }
                (a.0).0.copy_from_slice(&r);
            }
            a.subtract_modulus();
        } else {
            // Alternative implementation
            // Implements CIOS.
            let (carry, res) = a.mul_without_cond_subtract(b);
            *a = res;

            if Self::MODULUS_HAS_SPARE_BIT {
                a.subtract_modulus_with_carry(carry);
            } else {
                a.subtract_modulus();
            }
        }
    }

    #[inline(always)]
    #[unroll_for_loops(12)]
    fn square_in_place(a: &mut Fp<MontBackend<Self, N>, N>) {
        if N == 1 {
            // We default to multiplying with `a` using the `Mul` impl
            // for the N == 1 case
            *a *= *a;
            return;
        }
        #[cfg(all(
            feature = "asm",
            target_feature = "bmi2",
            target_feature = "adx",
            target_arch = "x86_64"
        ))]
        #[allow(unsafe_code)]
        if Self::CAN_USE_NO_CARRY_SQUARE_OPT && (2..=6).contains(&N) {
            use ark_ff_asm::x86_64_asm_square;
            #[rustfmt::skip]
            match N {
                2 => { x86_64_asm_square!(2, (a.0).0); },
                3 => { x86_64_asm_square!(3, (a.0).0); },
                4 => { x86_64_asm_square!(4, (a.0).0); },
                5 => { x86_64_asm_square!(5, (a.0).0); },
                6 => { x86_64_asm_square!(6, (a.0).0); },
                _ => unsafe { ark_std::hint::unreachable_unchecked() },
            };
            a.subtract_modulus();
            return;
        }

        let mut r = crate::const_helpers::MulBuffer::<N>::zeroed();

        let mut carry = 0;
        for i in 0..(N - 1) {
            for j in (i + 1)..N {
                r[i + j] = fa::mac_with_carry(r[i + j], (a.0).0[i], (a.0).0[j], &mut carry);
            }
            r.b1[i] = carry;
            carry = 0;
        }

        r.b1[N - 1] = r.b1[N - 2] >> 63;
        for i in 2..(2 * N - 1) {
            r[2 * N - i] = (r[2 * N - i] << 1) | (r[2 * N - (i + 1)] >> 63);
        }
        r.b0[1] <<= 1;

        for i in 0..N {
            r[2 * i] = fa::mac_with_carry(r[2 * i], (a.0).0[i], (a.0).0[i], &mut carry);
            carry = fa::adc(&mut r[2 * i + 1], 0, carry);
        }
        // Montgomery reduction
        let mut carry2 = 0;
        for i in 0..N {
            let k = r[i].wrapping_mul(Self::INV);
            carry = 0;
            fa::mac_discard(r[i], k, Self::MODULUS.0[0], &mut carry);
            for j in 1..N {
                r[j + i] = fa::mac_with_carry(r[j + i], k, Self::MODULUS.0[j], &mut carry);
            }
            carry2 = fa::adc(&mut r.b1[i], carry, carry2);
        }
        (a.0).0.copy_from_slice(&r.b1);
        if Self::MODULUS_HAS_SPARE_BIT {
            a.subtract_modulus();
        } else {
            a.subtract_modulus_with_carry(carry2 != 0);
        }
    }

    fn inverse(a: &Fp<MontBackend<Self, N>, N>) -> Option<Fp<MontBackend<Self, N>, N>> {
        if a.is_zero() {
            return None;
        }
        // Guajardo Kumar Paar Pelzl
        // Efficient Software-Implementation of Finite Fields with Applications to
        // Cryptography
        // Algorithm 16 (BEA for Inversion in Fp)

        let one = BigInt::from(1u64);

        let mut u = a.0;
        let mut v = Self::MODULUS;
        let mut b = Fp::new_unchecked(Self::R2); // Avoids unnecessary reduction step.
        let mut c = Fp::zero();

        while u != one && v != one {
            while u.is_even() {
                u.div2();

                if b.0.is_even() {
                    b.0.div2();
                } else {
                    let carry = b.0.add_with_carry(&Self::MODULUS);
                    b.0.div2();
                    if !Self::MODULUS_HAS_SPARE_BIT && carry {
                        (b.0).0[N - 1] |= 1 << 63;
                    }
                }
            }

            while v.is_even() {
                v.div2();

                if c.0.is_even() {
                    c.0.div2();
                } else {
                    let carry = c.0.add_with_carry(&Self::MODULUS);
                    c.0.div2();
                    if !Self::MODULUS_HAS_SPARE_BIT && carry {
                        (c.0).0[N - 1] |= 1 << 63;
                    }
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

        if u == one {
            Some(b)
        } else {
            Some(c)
        }
    }

    fn from_bigint(r: BigInt<N>) -> Option<Fp<MontBackend<Self, N>, N>> {
        let mut r = Fp::new_unchecked(r);
        if r.is_zero() {
            Some(r)
        } else if r.is_geq_modulus() {
            None
        } else {
            r *= &Fp::new_unchecked(Self::R2);
            Some(r)
        }
    }

    #[inline]
    #[cfg_attr(not(target_family = "wasm"), unroll_for_loops(12))]
    #[cfg_attr(target_family = "wasm", unroll_for_loops(6))]
    #[allow(clippy::modulo_one)]
    fn into_bigint(a: Fp<MontBackend<Self, N>, N>) -> BigInt<N> {
        let mut r = (a.0).0;
        // Montgomery Reduction
        for i in 0..N {
            let k = r[i].wrapping_mul(Self::INV);
            let mut carry = 0;

            fa::mac_with_carry(r[i], k, Self::MODULUS.0[0], &mut carry);
            for j in 1..N {
                r[(j + i) % N] = fa::mac_with_carry(r[(j + i) % N], k, Self::MODULUS.0[j], &mut carry);
            }
            r[i] = carry;
        }

        BigInt::new(r)
    }

    #[unroll_for_loops(12)]
    fn sum_of_products<const M: usize>(
        a: &[Fp<MontBackend<Self, N>, N>; M],
        b: &[Fp<MontBackend<Self, N>, N>; M],
    ) -> Fp<MontBackend<Self, N>, N> {
        // Adapted from https://github.com/zkcrypto/bls12_381/pull/84 by @str4d.

        // For a single `a x b` multiplication, operand scanning (schoolbook) takes each
        // limb of `a` in turn, and multiplies it by all of the limbs of `b` to compute
        // the result as a double-width intermediate representation, which is then fully
        // reduced at the carry. Here however we have pairs of multiplications (a_i, b_i),
        // the results of which are summed.
        //
        // The intuition for this algorithm is two-fold:
        // - We can interleave the operand scanning for each pair, by processing the jth
        //   limb of each `a_i` together. As these have the same offset within the overall
        //   operand scanning flow, their results can be summed directly.
        // - We can interleave the multiplication and reduction steps, resulting in a
        //   single bitshift by the limb size after each iteration. This means we only
        //   need to store a single extra limb overall, instead of keeping around all the
        //   intermediate results and eventually having twice as many limbs.

        let modulus_size = Self::MODULUS.const_num_bits() as usize;
        if modulus_size >= 64 * N - 1 {
            a.iter().zip(b).map(|(a, b)| *a * b).sum()
        } else if M == 2 {
            // Algorithm 2, line 2
            let result = (0..N).fold(BigInt::zero(), |mut result, j| {
                // Algorithm 2, line 3
                let mut carry_a = 0;
                let mut carry_b = 0;
                for (a, b) in a.iter().zip(b) {
                    let a = &a.0;
                    let b = &b.0;
                    let mut carry2 = 0;
                    result.0[0] = fa::mac(result.0[0], a.0[j], b.0[0], &mut carry2);
                    for k in 1..N {
                        result.0[k] = fa::mac_with_carry(result.0[k], a.0[j], b.0[k], &mut carry2);
                    }
                    carry_b = fa::adc(&mut carry_a, carry_b, carry2);
                }

                let k = result.0[0].wrapping_mul(Self::INV);
                let mut carry2 = 0;
                fa::mac_discard(result.0[0], k, Self::MODULUS.0[0], &mut carry2);
                for i in 1..N {
                    result.0[i - 1] = fa::mac_with_carry(result.0[i], k, Self::MODULUS.0[i], &mut carry2);
                }
                result.0[N - 1] = fa::adc_no_carry(carry_a, carry_b, &carry2);
                result
            });
            let mut result = Fp::new_unchecked(result);
            result.subtract_modulus();
            debug_assert_eq!(a.iter().zip(b).map(|(a, b)| *a * b).sum::<Fp<_, N>>(), result);
            result
        } else {
            let chunk_size = 2 * (N * 64 - modulus_size) - 1;
            // chunk_size is at least 1, since MODULUS_BIT_SIZE is at most N * 64 - 1.
            a.chunks(chunk_size)
                .zip(b.chunks(chunk_size))
                .map(|(a, b)| {
                    // Algorithm 2, line 2
                    let result = (0..N).fold(BigInt::zero(), |mut result, j| {
                        // Algorithm 2, line 3
                        let (temp, carry) =
                            a.iter()
                                .zip(b)
                                .fold((result, 0), |(mut temp, mut carry), (Fp(a, _), Fp(b, _))| {
                                    let mut carry2 = 0;
                                    temp.0[0] = fa::mac(temp.0[0], a.0[j], b.0[0], &mut carry2);
                                    for k in 1..N {
                                        temp.0[k] = fa::mac_with_carry(temp.0[k], a.0[j], b.0[k], &mut carry2);
                                    }
                                    carry = fa::adc_no_carry(carry, 0, &carry2);
                                    (temp, carry)
                                });

                        let k = temp.0[0].wrapping_mul(Self::INV);
                        let mut carry2 = 0;
                        fa::mac_discard(temp.0[0], k, Self::MODULUS.0[0], &mut carry2);
                        for i in 1..N {
                            result.0[i - 1] = fa::mac_with_carry(temp.0[i], k, Self::MODULUS.0[i], &mut carry2);
                        }
                        result.0[N - 1] = fa::adc_no_carry(carry, 0, &carry2);
                        result
                    });
                    let mut result = Fp::new_unchecked(result);
                    result.subtract_modulus();
                    debug_assert_eq!(a.iter().zip(b).map(|(a, b)| *a * b).sum::<Fp<_, N>>(), result);
                    result
                })
                .sum()
        }
    }
}

/// Compute -M^{-1} mod 2^64.
pub const fn inv<T: MontConfig<N>, const N: usize>() -> u64 {
    // We compute this as follows.
    // First, MODULUS mod 2^64 is just the lower 64 bits of MODULUS.
    // Hence MODULUS mod 2^64 = MODULUS.0[0] mod 2^64.
    //
    // Next, computing the inverse mod 2^64 involves exponentiating by
    // the multiplicative group order, which is euler_totient(2^64) - 1.
    // Now, euler_totient(2^64) = 1 << 63, and so
    // euler_totient(2^64) - 1 = (1 << 63) - 1 = 1111111... (63 digits).
    // We compute this powering via standard square and multiply.
    let mut inv = 1u64;
    crate::const_for!((_i in 0..63) {
        // Square
        inv = inv.wrapping_mul(inv);
        // Multiply
        inv = inv.wrapping_mul(T::MODULUS.0[0]);
    });
    inv.wrapping_neg()
}

#[inline]
pub const fn can_use_no_carry_mul_optimization<T: MontConfig<N>, const N: usize>() -> bool {
    // Checking the modulus at compile time
    let mut all_remaining_bits_are_one = T::MODULUS.0[N - 1] == u64::MAX >> 1;
    crate::const_for!((i in 1..N) {
        all_remaining_bits_are_one  &= T::MODULUS.0[N - i - 1] == u64::MAX;
    });
    modulus_has_spare_bit::<T, N>() && !all_remaining_bits_are_one
}

#[inline]
pub const fn modulus_has_spare_bit<T: MontConfig<N>, const N: usize>() -> bool {
    T::MODULUS.0[N - 1] >> 63 == 0
}

#[inline]
pub const fn can_use_no_carry_square_optimization<T: MontConfig<N>, const N: usize>() -> bool {
    // Checking the modulus at compile time
    let top_two_bits_are_zero = T::MODULUS.0[N - 1] >> 62 == 0;
    let mut all_remaining_bits_are_one = T::MODULUS.0[N - 1] == u64::MAX >> 2;
    crate::const_for!((i in 1..N) {
        all_remaining_bits_are_one  &= T::MODULUS.0[N - i - 1] == u64::MAX;
    });
    top_two_bits_are_zero && !all_remaining_bits_are_one
}

pub const fn sqrt_precomputation<const N: usize, T: MontConfig<N>>(
) -> Option<SqrtPrecomputation<Fp<MontBackend<T, N>, N>>> {
    match T::MODULUS.mod_4() {
        3 => match T::MODULUS_PLUS_ONE_DIV_FOUR.as_ref() {
            Some(BigInt(modulus_plus_one_div_four)) => Some(SqrtPrecomputation::Case3Mod4 {
                modulus_plus_one_div_four,
            }),
            None => None,
        },
        _ => match T::MODULUS.mod_8() {
            5 => match (
                T::MODULUS_PLUS_THREE_DIV_EIGHT.as_ref(),
                T::MODULUS_MINUS_ONE_DIV_FOUR.as_ref(),
            ) {
                (Some(BigInt(modulus_plus_three_div_eight)), Some(BigInt(modulus_minus_one_div_four))) => {
                    Some(SqrtPrecomputation::Case5Mod8 {
                        modulus_plus_three_div_eight,
                        modulus_minus_one_div_four,
                    })
                }
                _ => None,
            },
            _ => Some(SqrtPrecomputation::TonelliShanks {
                two_adicity: <MontBackend<T, N>>::TWO_ADICITY,
                quadratic_nonresidue_to_trace: T::TWO_ADIC_ROOT_OF_UNITY,
                trace_of_modulus_minus_one_div_two: &<Fp<MontBackend<T, N>, N>>::TRACE_MINUS_ONE_DIV_TWO.0,
            }),
        },
    }
}

/// Construct a [`Fp<MontBackend<T, N>, N>`] element from a literal string.
///
/// This should be used primarily for constructing constant field elements; in a
/// non-const context, [`Fp::from_str`](`ark_std::str::FromStr::from_str`) is
/// preferable.
///
/// # Panics
///
/// If the integer represented by the string cannot fit in the number
/// of limbs of the `Fp`, this macro results in a
/// * compile-time error if used in a const context
/// * run-time error otherwise.
///
/// # Usage
///
/// ```rust
/// # use ark_test_curves::MontFp;
/// # use ark_test_curves::bls12_381 as ark_bls12_381;
/// # use ark_std::{One, str::FromStr};
/// use ark_bls12_381::Fq;
/// const ONE: Fq = MontFp!("1");
/// const NEG_ONE: Fq = MontFp!("-1");
///
/// fn check_correctness() {
///     assert_eq!(ONE, Fq::one());
///     assert_eq!(Fq::from_str("1").unwrap(), ONE);
///     assert_eq!(NEG_ONE, -Fq::one());
/// }
/// ```
#[macro_export]
macro_rules! MontFp {
    ($c0:expr) => {{
        let (is_positive, limbs) = $crate::ark_ff_macros::to_sign_and_limbs!($c0);
        $crate::Fp::from_sign_and_limbs(is_positive, &limbs)
    }};
}

pub use ark_ff_macros::MontConfig;

pub use MontFp;

/// wasm Montgomery multiply in the standard 2^256 domain, bb's per-call 29-bit scheme
/// (`field_impl_generic.hpp`'s `__wasm__` branch): wasm has no widening 64x64 multiply, so the
/// 4x64 operands are split into nine 29-bit limbs whose products fit a single `i64.mul`;
/// 8 radix-2^29 Montgomery rounds plus one radix-2^24 round divide by exactly 2^256, so the
/// stored representation (and thus every proof byte) is unchanged from the native build.
/// First four modulus limbs as a fixed array (N == 4 is checked at the call sites).
#[cfg(target_family = "wasm")]
const fn first4<T: MontConfig<N>, const N: usize>() -> [u64; 4] {
    let m = T::MODULUS.0;
    [m[0], m[1], m[2], m[3]]
}

#[cfg(target_family = "wasm")]
pub mod wasm_mont {
    /// 2^-29 mod p, 29-bit limbs (the Yuval-reduction constant), for bn254 Fr and Fq.
    pub const FR_RINV29: [u32; 9] = [
        0x18f05361, 0x12bb1fe, 0xf5d8135, 0x1e6275f6, 0x7e7a880, 0x10c6bf1f, 0x11f74a6c, 0x6fdaecb, 0x183227,
    ];
    pub const FQ_RINV29: [u32; 9] = [
        0x17789a9f, 0x5ffc3dc, 0xd6bde42, 0x1cf152e3, 0x18eb055f, 0xed815e2, 0x16626d2, 0xb8bab0f, 0x6d7c4,
    ];

    pub const MASK29: u64 = (1 << 29) - 1;
    pub const MASK24: u64 = (1 << 24) - 1;

    #[allow(clippy::missing_const_for_fn)]
    pub const fn to29(a: &[u64; 4]) -> [u64; 9] {
        let mut out = [0u64; 9];
        let mut i = 0;
        while i < 9 {
            let bit = 29 * i;
            let (limb, sh) = (bit / 64, bit % 64);
            let mut v = a[limb] >> sh;
            if sh > 35 && limb + 1 < 4 {
                v |= a[limb + 1] << (64 - sh);
            }
            out[i] = v & MASK29;
            i += 1;
        }
        out
    }

    /// -p^-1 mod 2^29 (Newton lift from the 64-bit INV would also work; direct is clearer).
    pub const fn inv29(p0: u64) -> u64 {
        // Newton iteration for the inverse of p mod 2^29, then negate.
        let mut x: u64 = 1;
        let mut i = 0;
        while i < 5 {
            x = x.wrapping_mul(2u64.wrapping_sub(p0.wrapping_mul(x)));
            i += 1;
        }
        x.wrapping_neg() & MASK29
    }

    /// `a * b / 2^256 mod p`, canonical in and out; fully unrolled straight-line body.
    #[inline]
    #[allow(clippy::too_many_lines)]
    pub fn mont_mul_256(a: &[u64; 4], b: &[u64; 4], modulus: &[u64; 4], p: &[u64; 9], inv: u64) -> [u64; 4] {
        let l = to29(a);
        let r = to29(b);
        let l0 = l[0];
        let r0 = r[0];
        let l1 = l[1];
        let r1 = r[1];
        let l2 = l[2];
        let r2 = r[2];
        let l3 = l[3];
        let r3 = r[3];
        let l4 = l[4];
        let r4 = r[4];
        let l5 = l[5];
        let r5 = r[5];
        let l6 = l[6];
        let r6 = r[6];
        let l7 = l[7];
        let r7 = r[7];
        let l8 = l[8];
        let r8 = r[8];
        let p0 = p[0];
        let p1 = p[1];
        let p2 = p[2];
        let p3 = p[3];
        let p4 = p[4];
        let p5 = p[5];
        let p6 = p[6];
        let p7 = p[7];
        let p8 = p[8];
        let pl0 = l0 * r0;
        let pl1 = l0 * r1 + l1 * r0;
        let pl2 = l0 * r2 + l1 * r1 + l2 * r0;
        let pl3 = l0 * r3 + l1 * r2 + l2 * r1 + l3 * r0;
        let pl4 = l0 * r4 + l1 * r3 + l2 * r2 + l3 * r1 + l4 * r0;
        let pl5 = l1 * r4 + l2 * r3 + l3 * r2 + l4 * r1;
        let pl6 = l2 * r4 + l3 * r3 + l4 * r2;
        let pl7 = l3 * r4 + l4 * r3;
        let pl8 = l4 * r4;
        let ph0 = l5 * r5;
        let ph1 = l5 * r6 + l6 * r5;
        let ph2 = l5 * r7 + l6 * r6 + l7 * r5;
        let ph3 = l5 * r8 + l6 * r7 + l7 * r6 + l8 * r5;
        let ph4 = l6 * r8 + l7 * r7 + l8 * r6;
        let ph5 = l7 * r8 + l8 * r7;
        let ph6 = l8 * r8;
        let sl0 = l0 + l5;
        let sr0 = r0 + r5;
        let sl1 = l1 + l6;
        let sr1 = r1 + r6;
        let sl2 = l2 + l7;
        let sr2 = r2 + r7;
        let sl3 = l3 + l8;
        let sr3 = r3 + r8;
        let sl4 = l4;
        let sr4 = r4;
        let pc0 = sl0 * sr0;
        let pc1 = sl0 * sr1 + sl1 * sr0;
        let pc2 = sl0 * sr2 + sl1 * sr1 + sl2 * sr0;
        let pc3 = sl0 * sr3 + sl1 * sr2 + sl2 * sr1 + sl3 * sr0;
        let pc4 = sl0 * sr4 + sl1 * sr3 + sl2 * sr2 + sl3 * sr1 + sl4 * sr0;
        let pc5 = sl1 * sr4 + sl2 * sr3 + sl3 * sr2 + sl4 * sr1;
        let pc6 = sl2 * sr4 + sl3 * sr3 + sl4 * sr2;
        let pc7 = sl3 * sr4 + sl4 * sr3;
        let pc8 = sl4 * sr4;
        let mut t0 = pl0;
        let mut t1 = pl1;
        let mut t2 = pl2;
        let mut t3 = pl3;
        let mut t4 = pl4;
        let m0 = pc0.wrapping_sub(pl0).wrapping_sub(ph0);
        let m1 = pc1.wrapping_sub(pl1).wrapping_sub(ph1);
        let m2 = pc2.wrapping_sub(pl2).wrapping_sub(ph2);
        let m3 = pc3.wrapping_sub(pl3).wrapping_sub(ph3);
        let m4 = pc4.wrapping_sub(pl4).wrapping_sub(ph4);
        let m5 = pc5.wrapping_sub(pl5).wrapping_sub(ph5);
        let m6 = pc6.wrapping_sub(pl6).wrapping_sub(ph6);
        let m7 = pc7.wrapping_sub(pl7);
        let m8 = pc8.wrapping_sub(pl8);
        let mut t5 = pl5.wrapping_add(m0);
        let mut t6 = pl6.wrapping_add(m1);
        let mut t7 = pl7.wrapping_add(m2);
        let mut t8 = pl8.wrapping_add(m3);
        let mut t9 = m4;
        let mut t10 = m5.wrapping_add(ph0);
        let mut t11 = m6.wrapping_add(ph1);
        let mut t12 = m7.wrapping_add(ph2);
        let mut t13 = m8.wrapping_add(ph3);
        let mut t14 = ph4;
        let mut t15 = ph5;
        let mut t16 = ph6;
        let mut t17: u64 = 0;
        let k0 = t0.wrapping_mul(inv) & MASK29;
        t0 = t0.wrapping_add(k0 * p0);
        t1 = t1.wrapping_add(k0 * p1);
        t2 = t2.wrapping_add(k0 * p2);
        t3 = t3.wrapping_add(k0 * p3);
        t4 = t4.wrapping_add(k0 * p4);
        t5 = t5.wrapping_add(k0 * p5);
        t6 = t6.wrapping_add(k0 * p6);
        t7 = t7.wrapping_add(k0 * p7);
        t8 = t8.wrapping_add(k0 * p8);
        t1 = t1.wrapping_add(t0 >> 29);
        let k1 = t1.wrapping_mul(inv) & MASK29;
        t1 = t1.wrapping_add(k1 * p0);
        t2 = t2.wrapping_add(k1 * p1);
        t3 = t3.wrapping_add(k1 * p2);
        t4 = t4.wrapping_add(k1 * p3);
        t5 = t5.wrapping_add(k1 * p4);
        t6 = t6.wrapping_add(k1 * p5);
        t7 = t7.wrapping_add(k1 * p6);
        t8 = t8.wrapping_add(k1 * p7);
        t9 = t9.wrapping_add(k1 * p8);
        t2 = t2.wrapping_add(t1 >> 29);
        let k2 = t2.wrapping_mul(inv) & MASK29;
        t2 = t2.wrapping_add(k2 * p0);
        t3 = t3.wrapping_add(k2 * p1);
        t4 = t4.wrapping_add(k2 * p2);
        t5 = t5.wrapping_add(k2 * p3);
        t6 = t6.wrapping_add(k2 * p4);
        t7 = t7.wrapping_add(k2 * p5);
        t8 = t8.wrapping_add(k2 * p6);
        t9 = t9.wrapping_add(k2 * p7);
        t10 = t10.wrapping_add(k2 * p8);
        t3 = t3.wrapping_add(t2 >> 29);
        let k3 = t3.wrapping_mul(inv) & MASK29;
        t3 = t3.wrapping_add(k3 * p0);
        t4 = t4.wrapping_add(k3 * p1);
        t5 = t5.wrapping_add(k3 * p2);
        t6 = t6.wrapping_add(k3 * p3);
        t7 = t7.wrapping_add(k3 * p4);
        t8 = t8.wrapping_add(k3 * p5);
        t9 = t9.wrapping_add(k3 * p6);
        t10 = t10.wrapping_add(k3 * p7);
        t11 = t11.wrapping_add(k3 * p8);
        t4 = t4.wrapping_add(t3 >> 29);
        let k4 = t4.wrapping_mul(inv) & MASK29;
        t4 = t4.wrapping_add(k4 * p0);
        t5 = t5.wrapping_add(k4 * p1);
        t6 = t6.wrapping_add(k4 * p2);
        t7 = t7.wrapping_add(k4 * p3);
        t8 = t8.wrapping_add(k4 * p4);
        t9 = t9.wrapping_add(k4 * p5);
        t10 = t10.wrapping_add(k4 * p6);
        t11 = t11.wrapping_add(k4 * p7);
        t12 = t12.wrapping_add(k4 * p8);
        t5 = t5.wrapping_add(t4 >> 29);
        let k5 = t5.wrapping_mul(inv) & MASK29;
        t5 = t5.wrapping_add(k5 * p0);
        t6 = t6.wrapping_add(k5 * p1);
        t7 = t7.wrapping_add(k5 * p2);
        t8 = t8.wrapping_add(k5 * p3);
        t9 = t9.wrapping_add(k5 * p4);
        t10 = t10.wrapping_add(k5 * p5);
        t11 = t11.wrapping_add(k5 * p6);
        t12 = t12.wrapping_add(k5 * p7);
        t13 = t13.wrapping_add(k5 * p8);
        t6 = t6.wrapping_add(t5 >> 29);
        let k6 = t6.wrapping_mul(inv) & MASK29;
        t6 = t6.wrapping_add(k6 * p0);
        t7 = t7.wrapping_add(k6 * p1);
        t8 = t8.wrapping_add(k6 * p2);
        t9 = t9.wrapping_add(k6 * p3);
        t10 = t10.wrapping_add(k6 * p4);
        t11 = t11.wrapping_add(k6 * p5);
        t12 = t12.wrapping_add(k6 * p6);
        t13 = t13.wrapping_add(k6 * p7);
        t14 = t14.wrapping_add(k6 * p8);
        t7 = t7.wrapping_add(t6 >> 29);
        let k7 = t7.wrapping_mul(inv) & MASK29;
        t7 = t7.wrapping_add(k7 * p0);
        t8 = t8.wrapping_add(k7 * p1);
        t9 = t9.wrapping_add(k7 * p2);
        t10 = t10.wrapping_add(k7 * p3);
        t11 = t11.wrapping_add(k7 * p4);
        t12 = t12.wrapping_add(k7 * p5);
        t13 = t13.wrapping_add(k7 * p6);
        t14 = t14.wrapping_add(k7 * p7);
        t15 = t15.wrapping_add(k7 * p8);
        t8 = t8.wrapping_add(t7 >> 29);
        let k8 = t8.wrapping_mul(inv) & MASK24;
        t8 = t8.wrapping_add(k8 * p0);
        t9 = t9.wrapping_add(k8 * p1);
        t10 = t10.wrapping_add(k8 * p2);
        t11 = t11.wrapping_add(k8 * p3);
        t12 = t12.wrapping_add(k8 * p4);
        t13 = t13.wrapping_add(k8 * p5);
        t14 = t14.wrapping_add(k8 * p6);
        t15 = t15.wrapping_add(k8 * p7);
        t16 = t16.wrapping_add(k8 * p8);
        t9 = t9.wrapping_add(t8 >> 29);
        t8 &= MASK29;
        t10 = t10.wrapping_add(t9 >> 29);
        t9 &= MASK29;
        t11 = t11.wrapping_add(t10 >> 29);
        t10 &= MASK29;
        t12 = t12.wrapping_add(t11 >> 29);
        t11 &= MASK29;
        t13 = t13.wrapping_add(t12 >> 29);
        t12 &= MASK29;
        t14 = t14.wrapping_add(t13 >> 29);
        t13 &= MASK29;
        t15 = t15.wrapping_add(t14 >> 29);
        t14 &= MASK29;
        t16 = t16.wrapping_add(t15 >> 29);
        t15 &= MASK29;
        t17 = t17.wrapping_add(t16 >> 29);
        t16 &= MASK29;
        let w0 = (t8 >> 24) | (t9 << 5) | (t10 << 34) | (t11 << 63);
        let w1 = (t11 >> 1) | (t12 << 28) | (t13 << 57);
        let w2 = (t13 >> 7) | (t14 << 22) | (t15 << 51);
        let w3 = (t15 >> 13) | (t16 << 16) | (t17 << 45);
        let wide = [w0, w1, w2, w3];
        let mut borrow = 0u64;
        let mut d = [0u64; 4];
        let mut i = 0;
        while i < 4 {
            let (v1, b1) = wide[i].overflowing_sub(modulus[i]);
            let (v2, b2) = v1.overflowing_sub(borrow);
            d[i] = v2;
            borrow = (b1 as u64) | (b2 as u64);
            i += 1;
        }
        if borrow == 1 {
            wide
        } else {
            d
        }
    }
}
/// Four-lane SIMD Montgomery multiply in the standard 2^256 domain, for batched loops:
/// operands and result stay in the transposed 29-bit-limb layout (`QuadFp`), so packing is
/// paid once per loop, not per multiply — bb's VectorField pattern, whose in-loop throughput
/// on V8 measures ~4x the scalar path (dependency-chain microbenches wildly understate it).
/// Karatsuba 5+4, then 8 radix-2^29 + 1 radix-2^24 Montgomery rounds (÷2^256 exactly), then
/// realignment to 29-bit limbs. Lanes are independent; values are coarse [0, 2p).
#[cfg(all(target_family = "wasm", target_feature = "simd128"))]
pub mod quad256 {
    use super::wasm_mont::{to29, MASK24, MASK29};
    use core::arch::wasm32::*;

    /// 4 field elements, transposed into u32x4 lanes per limb.
    #[derive(Clone, Copy)]
    pub struct QuadFp {
        pub limbs: [v128; 9],
    }

    /// 4x4 i32 lane transpose in 8 shuffles (bb `transpose_4x4_i32x4`).
    #[inline(always)]
    fn transpose4(r0: v128, r1: v128, r2: v128, r3: v128) -> (v128, v128, v128, v128) {
        let t0 = i32x4_shuffle::<0, 4, 1, 5>(r0, r1);
        let t1 = i32x4_shuffle::<2, 6, 3, 7>(r0, r1);
        let t2 = i32x4_shuffle::<0, 4, 1, 5>(r2, r3);
        let t3 = i32x4_shuffle::<2, 6, 3, 7>(r2, r3);
        (
            i32x4_shuffle::<0, 1, 4, 5>(t0, t2),
            i32x4_shuffle::<2, 3, 6, 7>(t0, t2),
            i32x4_shuffle::<0, 1, 4, 5>(t1, t3),
            i32x4_shuffle::<2, 3, 6, 7>(t1, t3),
        )
    }

    impl QuadFp {
        /// Pack four 4x64 values (the stored ark form, < 2^255) via bb VectorField's SIMD
        /// transpose: 8 loads, two 4x4 transposes, then each 29-bit limb assembled from the
        /// two straddling u32 chunks — no per-lane scalar radix conversion.
        #[allow(unsafe_code)]
        pub fn pack(e: &[[u64; 4]; 4]) -> QuadFp {
            let m = u32x4_splat(MASK29 as u32);
            unsafe {
                let p = e.as_ptr() as *const v128;
                let (i0, i1, i2, i3) = transpose4(
                    v128_load(p),
                    v128_load(p.add(2)),
                    v128_load(p.add(4)),
                    v128_load(p.add(6)),
                );
                let (i4, i5, i6, i7) = transpose4(
                    v128_load(p.add(1)),
                    v128_load(p.add(3)),
                    v128_load(p.add(5)),
                    v128_load(p.add(7)),
                );
                QuadFp {
                    limbs: [
                        v128_and(i0, m),
                        v128_and(v128_or(u32x4_shr(i0, 29), i32x4_shl(i1, 3)), m),
                        v128_and(v128_or(u32x4_shr(i1, 26), i32x4_shl(i2, 6)), m),
                        v128_and(v128_or(u32x4_shr(i2, 23), i32x4_shl(i3, 9)), m),
                        v128_and(v128_or(u32x4_shr(i3, 20), i32x4_shl(i4, 12)), m),
                        v128_and(v128_or(u32x4_shr(i4, 17), i32x4_shl(i5, 15)), m),
                        v128_and(v128_or(u32x4_shr(i5, 14), i32x4_shl(i6, 18)), m),
                        v128_and(v128_or(u32x4_shr(i6, 11), i32x4_shl(i7, 21)), m),
                        u32x4_shr(i7, 8),
                    ],
                }
            }
        }
        /// Unpack to canonical 4x64: one packed conditional `- p` (borrow chain + blend)
        /// canonicalizes all four coarse lanes, then u32 chunks reassemble and transpose back.
        #[allow(unsafe_code)]
        pub fn unpack(&self, modulus: &[u64; 4]) -> [[u64; 4]; 4] {
            let p29 = to29(modulus);
            let mask = u32x4_splat(MASK29 as u32);
            let mut d = [u32x4_splat(0); 9];
            let mut v = i32x4_sub(self.limbs[0], u32x4_splat(p29[0] as u32));
            let mut borrow = u32x4_shr(v, 31);
            d[0] = v128_and(v, mask);
            for k in 1..9 {
                v = i32x4_sub(i32x4_sub(self.limbs[k], u32x4_splat(p29[k] as u32)), borrow);
                borrow = u32x4_shr(v, 31);
                d[k] = v128_and(v, mask);
            }
            let keep_a = i32x4_eq(borrow, u32x4_splat(1));
            let l: [v128; 9] = core::array::from_fn(|k| v128_bitselect(self.limbs[k], d[k], keep_a));
            let o0 = v128_or(l[0], i32x4_shl(l[1], 29));
            let o1 = v128_or(u32x4_shr(l[1], 3), i32x4_shl(l[2], 26));
            let o2 = v128_or(u32x4_shr(l[2], 6), i32x4_shl(l[3], 23));
            let o3 = v128_or(u32x4_shr(l[3], 9), i32x4_shl(l[4], 20));
            let o4 = v128_or(u32x4_shr(l[4], 12), i32x4_shl(l[5], 17));
            let o5 = v128_or(u32x4_shr(l[5], 15), i32x4_shl(l[6], 14));
            let o6 = v128_or(u32x4_shr(l[6], 18), i32x4_shl(l[7], 11));
            let o7 = v128_or(u32x4_shr(l[7], 21), i32x4_shl(l[8], 8));
            let (f1l, f2l, f3l, f4l) = transpose4(o0, o1, o2, o3);
            let (f1h, f2h, f3h, f4h) = transpose4(o4, o5, o6, o7);
            let mut out = [[0u64; 4]; 4];
            unsafe {
                let p = out.as_mut_ptr() as *mut v128;
                v128_store(p, f1l);
                v128_store(p.add(1), f1h);
                v128_store(p.add(2), f2l);
                v128_store(p.add(3), f2h);
                v128_store(p.add(4), f3l);
                v128_store(p.add(5), f3h);
                v128_store(p.add(6), f4l);
                v128_store(p.add(7), f4h);
            }
            out
        }
    }

    /// Per-lane `a * b / 2^256 mod p`, coarse in/out; fully unrolled.
    #[allow(clippy::too_many_lines)]
    pub fn mont_mul(a: &QuadFp, b: &QuadFp, p29: &[u64; 9], inv: u64) -> QuadFp {
        let invv = u32x4_splat(inv as u32);
        let mask64 = u64x2_splat(MASK29);
        let mask24 = u64x2_splat(MASK24);
        let p0 = u32x4_splat(p29[0] as u32);
        let p1 = u32x4_splat(p29[1] as u32);
        let p2 = u32x4_splat(p29[2] as u32);
        let p3 = u32x4_splat(p29[3] as u32);
        let p4 = u32x4_splat(p29[4] as u32);
        let p5 = u32x4_splat(p29[5] as u32);
        let p6 = u32x4_splat(p29[6] as u32);
        let p7 = u32x4_splat(p29[7] as u32);
        let p8 = u32x4_splat(p29[8] as u32);
        let a0 = a.limbs[0];
        let b0 = b.limbs[0];
        let a1 = a.limbs[1];
        let b1 = b.limbs[1];
        let a2 = a.limbs[2];
        let b2 = b.limbs[2];
        let a3 = a.limbs[3];
        let b3 = b.limbs[3];
        let a4 = a.limbs[4];
        let b4 = b.limbs[4];
        let a5 = a.limbs[5];
        let b5 = b.limbs[5];
        let a6 = a.limbs[6];
        let b6 = b.limbs[6];
        let a7 = a.limbs[7];
        let b7 = b.limbs[7];
        let a8 = a.limbs[8];
        let b8 = b.limbs[8];
        let sl0 = u32x4_add(a0, a5);
        let sr0 = u32x4_add(b0, b5);
        let sl1 = u32x4_add(a1, a6);
        let sr1 = u32x4_add(b1, b6);
        let sl2 = u32x4_add(a2, a7);
        let sr2 = u32x4_add(b2, b7);
        let sl3 = u32x4_add(a3, a8);
        let sr3 = u32x4_add(b3, b8);
        let sl4 = a4;
        let sr4 = b4;
        let pl0_l = u64x2_extmul_low_u32x4(a0, b0);
        let pl0_h = u64x2_extmul_high_u32x4(a0, b0);
        let pl1_l = u64x2_add(u64x2_extmul_low_u32x4(a0, b1), u64x2_extmul_low_u32x4(a1, b0));
        let pl1_h = u64x2_add(u64x2_extmul_high_u32x4(a0, b1), u64x2_extmul_high_u32x4(a1, b0));
        let pl2_l = u64x2_add(
            u64x2_add(u64x2_extmul_low_u32x4(a0, b2), u64x2_extmul_low_u32x4(a1, b1)),
            u64x2_extmul_low_u32x4(a2, b0),
        );
        let pl2_h = u64x2_add(
            u64x2_add(u64x2_extmul_high_u32x4(a0, b2), u64x2_extmul_high_u32x4(a1, b1)),
            u64x2_extmul_high_u32x4(a2, b0),
        );
        let pl3_l = u64x2_add(
            u64x2_add(
                u64x2_add(u64x2_extmul_low_u32x4(a0, b3), u64x2_extmul_low_u32x4(a1, b2)),
                u64x2_extmul_low_u32x4(a2, b1),
            ),
            u64x2_extmul_low_u32x4(a3, b0),
        );
        let pl3_h = u64x2_add(
            u64x2_add(
                u64x2_add(u64x2_extmul_high_u32x4(a0, b3), u64x2_extmul_high_u32x4(a1, b2)),
                u64x2_extmul_high_u32x4(a2, b1),
            ),
            u64x2_extmul_high_u32x4(a3, b0),
        );
        let pl4_l = u64x2_add(
            u64x2_add(
                u64x2_add(
                    u64x2_add(u64x2_extmul_low_u32x4(a0, b4), u64x2_extmul_low_u32x4(a1, b3)),
                    u64x2_extmul_low_u32x4(a2, b2),
                ),
                u64x2_extmul_low_u32x4(a3, b1),
            ),
            u64x2_extmul_low_u32x4(a4, b0),
        );
        let pl4_h = u64x2_add(
            u64x2_add(
                u64x2_add(
                    u64x2_add(u64x2_extmul_high_u32x4(a0, b4), u64x2_extmul_high_u32x4(a1, b3)),
                    u64x2_extmul_high_u32x4(a2, b2),
                ),
                u64x2_extmul_high_u32x4(a3, b1),
            ),
            u64x2_extmul_high_u32x4(a4, b0),
        );
        let pl5_l = u64x2_add(
            u64x2_add(
                u64x2_add(u64x2_extmul_low_u32x4(a1, b4), u64x2_extmul_low_u32x4(a2, b3)),
                u64x2_extmul_low_u32x4(a3, b2),
            ),
            u64x2_extmul_low_u32x4(a4, b1),
        );
        let pl5_h = u64x2_add(
            u64x2_add(
                u64x2_add(u64x2_extmul_high_u32x4(a1, b4), u64x2_extmul_high_u32x4(a2, b3)),
                u64x2_extmul_high_u32x4(a3, b2),
            ),
            u64x2_extmul_high_u32x4(a4, b1),
        );
        let pl6_l = u64x2_add(
            u64x2_add(u64x2_extmul_low_u32x4(a2, b4), u64x2_extmul_low_u32x4(a3, b3)),
            u64x2_extmul_low_u32x4(a4, b2),
        );
        let pl6_h = u64x2_add(
            u64x2_add(u64x2_extmul_high_u32x4(a2, b4), u64x2_extmul_high_u32x4(a3, b3)),
            u64x2_extmul_high_u32x4(a4, b2),
        );
        let pl7_l = u64x2_add(u64x2_extmul_low_u32x4(a3, b4), u64x2_extmul_low_u32x4(a4, b3));
        let pl7_h = u64x2_add(u64x2_extmul_high_u32x4(a3, b4), u64x2_extmul_high_u32x4(a4, b3));
        let pl8_l = u64x2_extmul_low_u32x4(a4, b4);
        let pl8_h = u64x2_extmul_high_u32x4(a4, b4);
        let ph0_l = u64x2_extmul_low_u32x4(a5, b5);
        let ph0_h = u64x2_extmul_high_u32x4(a5, b5);
        let ph1_l = u64x2_add(u64x2_extmul_low_u32x4(a5, b6), u64x2_extmul_low_u32x4(a6, b5));
        let ph1_h = u64x2_add(u64x2_extmul_high_u32x4(a5, b6), u64x2_extmul_high_u32x4(a6, b5));
        let ph2_l = u64x2_add(
            u64x2_add(u64x2_extmul_low_u32x4(a5, b7), u64x2_extmul_low_u32x4(a6, b6)),
            u64x2_extmul_low_u32x4(a7, b5),
        );
        let ph2_h = u64x2_add(
            u64x2_add(u64x2_extmul_high_u32x4(a5, b7), u64x2_extmul_high_u32x4(a6, b6)),
            u64x2_extmul_high_u32x4(a7, b5),
        );
        let ph3_l = u64x2_add(
            u64x2_add(
                u64x2_add(u64x2_extmul_low_u32x4(a5, b8), u64x2_extmul_low_u32x4(a6, b7)),
                u64x2_extmul_low_u32x4(a7, b6),
            ),
            u64x2_extmul_low_u32x4(a8, b5),
        );
        let ph3_h = u64x2_add(
            u64x2_add(
                u64x2_add(u64x2_extmul_high_u32x4(a5, b8), u64x2_extmul_high_u32x4(a6, b7)),
                u64x2_extmul_high_u32x4(a7, b6),
            ),
            u64x2_extmul_high_u32x4(a8, b5),
        );
        let ph4_l = u64x2_add(
            u64x2_add(u64x2_extmul_low_u32x4(a6, b8), u64x2_extmul_low_u32x4(a7, b7)),
            u64x2_extmul_low_u32x4(a8, b6),
        );
        let ph4_h = u64x2_add(
            u64x2_add(u64x2_extmul_high_u32x4(a6, b8), u64x2_extmul_high_u32x4(a7, b7)),
            u64x2_extmul_high_u32x4(a8, b6),
        );
        let ph5_l = u64x2_add(u64x2_extmul_low_u32x4(a7, b8), u64x2_extmul_low_u32x4(a8, b7));
        let ph5_h = u64x2_add(u64x2_extmul_high_u32x4(a7, b8), u64x2_extmul_high_u32x4(a8, b7));
        let ph6_l = u64x2_extmul_low_u32x4(a8, b8);
        let ph6_h = u64x2_extmul_high_u32x4(a8, b8);
        let pc0_l = u64x2_extmul_low_u32x4(sl0, sr0);
        let pc0_h = u64x2_extmul_high_u32x4(sl0, sr0);
        let pc1_l = u64x2_add(u64x2_extmul_low_u32x4(sl0, sr1), u64x2_extmul_low_u32x4(sl1, sr0));
        let pc1_h = u64x2_add(u64x2_extmul_high_u32x4(sl0, sr1), u64x2_extmul_high_u32x4(sl1, sr0));
        let pc2_l = u64x2_add(
            u64x2_add(u64x2_extmul_low_u32x4(sl0, sr2), u64x2_extmul_low_u32x4(sl1, sr1)),
            u64x2_extmul_low_u32x4(sl2, sr0),
        );
        let pc2_h = u64x2_add(
            u64x2_add(u64x2_extmul_high_u32x4(sl0, sr2), u64x2_extmul_high_u32x4(sl1, sr1)),
            u64x2_extmul_high_u32x4(sl2, sr0),
        );
        let pc3_l = u64x2_add(
            u64x2_add(
                u64x2_add(u64x2_extmul_low_u32x4(sl0, sr3), u64x2_extmul_low_u32x4(sl1, sr2)),
                u64x2_extmul_low_u32x4(sl2, sr1),
            ),
            u64x2_extmul_low_u32x4(sl3, sr0),
        );
        let pc3_h = u64x2_add(
            u64x2_add(
                u64x2_add(u64x2_extmul_high_u32x4(sl0, sr3), u64x2_extmul_high_u32x4(sl1, sr2)),
                u64x2_extmul_high_u32x4(sl2, sr1),
            ),
            u64x2_extmul_high_u32x4(sl3, sr0),
        );
        let pc4_l = u64x2_add(
            u64x2_add(
                u64x2_add(
                    u64x2_add(u64x2_extmul_low_u32x4(sl0, sr4), u64x2_extmul_low_u32x4(sl1, sr3)),
                    u64x2_extmul_low_u32x4(sl2, sr2),
                ),
                u64x2_extmul_low_u32x4(sl3, sr1),
            ),
            u64x2_extmul_low_u32x4(sl4, sr0),
        );
        let pc4_h = u64x2_add(
            u64x2_add(
                u64x2_add(
                    u64x2_add(u64x2_extmul_high_u32x4(sl0, sr4), u64x2_extmul_high_u32x4(sl1, sr3)),
                    u64x2_extmul_high_u32x4(sl2, sr2),
                ),
                u64x2_extmul_high_u32x4(sl3, sr1),
            ),
            u64x2_extmul_high_u32x4(sl4, sr0),
        );
        let pc5_l = u64x2_add(
            u64x2_add(
                u64x2_add(u64x2_extmul_low_u32x4(sl1, sr4), u64x2_extmul_low_u32x4(sl2, sr3)),
                u64x2_extmul_low_u32x4(sl3, sr2),
            ),
            u64x2_extmul_low_u32x4(sl4, sr1),
        );
        let pc5_h = u64x2_add(
            u64x2_add(
                u64x2_add(u64x2_extmul_high_u32x4(sl1, sr4), u64x2_extmul_high_u32x4(sl2, sr3)),
                u64x2_extmul_high_u32x4(sl3, sr2),
            ),
            u64x2_extmul_high_u32x4(sl4, sr1),
        );
        let pc6_l = u64x2_add(
            u64x2_add(u64x2_extmul_low_u32x4(sl2, sr4), u64x2_extmul_low_u32x4(sl3, sr3)),
            u64x2_extmul_low_u32x4(sl4, sr2),
        );
        let pc6_h = u64x2_add(
            u64x2_add(u64x2_extmul_high_u32x4(sl2, sr4), u64x2_extmul_high_u32x4(sl3, sr3)),
            u64x2_extmul_high_u32x4(sl4, sr2),
        );
        let pc7_l = u64x2_add(u64x2_extmul_low_u32x4(sl3, sr4), u64x2_extmul_low_u32x4(sl4, sr3));
        let pc7_h = u64x2_add(u64x2_extmul_high_u32x4(sl3, sr4), u64x2_extmul_high_u32x4(sl4, sr3));
        let pc8_l = u64x2_extmul_low_u32x4(sl4, sr4);
        let pc8_h = u64x2_extmul_high_u32x4(sl4, sr4);
        let mut t0_l = pl0_l;
        let mut t1_l = pl1_l;
        let mut t2_l = pl2_l;
        let mut t3_l = pl3_l;
        let mut t4_l = pl4_l;
        let m0_l = u64x2_sub(u64x2_sub(pc0_l, pl0_l), ph0_l);
        let m1_l = u64x2_sub(u64x2_sub(pc1_l, pl1_l), ph1_l);
        let m2_l = u64x2_sub(u64x2_sub(pc2_l, pl2_l), ph2_l);
        let m3_l = u64x2_sub(u64x2_sub(pc3_l, pl3_l), ph3_l);
        let m4_l = u64x2_sub(u64x2_sub(pc4_l, pl4_l), ph4_l);
        let m5_l = u64x2_sub(u64x2_sub(pc5_l, pl5_l), ph5_l);
        let m6_l = u64x2_sub(u64x2_sub(pc6_l, pl6_l), ph6_l);
        let m7_l = u64x2_sub(pc7_l, pl7_l);
        let m8_l = u64x2_sub(pc8_l, pl8_l);
        let mut t5_l = u64x2_add(pl5_l, m0_l);
        let mut t6_l = u64x2_add(pl6_l, m1_l);
        let mut t7_l = u64x2_add(pl7_l, m2_l);
        let mut t8_l = u64x2_add(pl8_l, m3_l);
        let mut t9_l = m4_l;
        let mut t10_l = u64x2_add(m5_l, ph0_l);
        let mut t11_l = u64x2_add(m6_l, ph1_l);
        let mut t12_l = u64x2_add(m7_l, ph2_l);
        let mut t13_l = u64x2_add(m8_l, ph3_l);
        let mut t14_l = ph4_l;
        let mut t15_l = ph5_l;
        let mut t16_l = ph6_l;
        let mut t17_l = u64x2(0, 0);
        let mut t0_h = pl0_h;
        let mut t1_h = pl1_h;
        let mut t2_h = pl2_h;
        let mut t3_h = pl3_h;
        let mut t4_h = pl4_h;
        let m0_h = u64x2_sub(u64x2_sub(pc0_h, pl0_h), ph0_h);
        let m1_h = u64x2_sub(u64x2_sub(pc1_h, pl1_h), ph1_h);
        let m2_h = u64x2_sub(u64x2_sub(pc2_h, pl2_h), ph2_h);
        let m3_h = u64x2_sub(u64x2_sub(pc3_h, pl3_h), ph3_h);
        let m4_h = u64x2_sub(u64x2_sub(pc4_h, pl4_h), ph4_h);
        let m5_h = u64x2_sub(u64x2_sub(pc5_h, pl5_h), ph5_h);
        let m6_h = u64x2_sub(u64x2_sub(pc6_h, pl6_h), ph6_h);
        let m7_h = u64x2_sub(pc7_h, pl7_h);
        let m8_h = u64x2_sub(pc8_h, pl8_h);
        let mut t5_h = u64x2_add(pl5_h, m0_h);
        let mut t6_h = u64x2_add(pl6_h, m1_h);
        let mut t7_h = u64x2_add(pl7_h, m2_h);
        let mut t8_h = u64x2_add(pl8_h, m3_h);
        let mut t9_h = m4_h;
        let mut t10_h = u64x2_add(m5_h, ph0_h);
        let mut t11_h = u64x2_add(m6_h, ph1_h);
        let mut t12_h = u64x2_add(m7_h, ph2_h);
        let mut t13_h = u64x2_add(m8_h, ph3_h);
        let mut t14_h = ph4_h;
        let mut t15_h = ph5_h;
        let mut t16_h = ph6_h;
        let mut t17_h = u64x2(0, 0);
        let k4_of = |tl: v128, th: v128, maskk: v128| -> v128 {
            let kt = u32x4_shuffle::<0, 2, 4, 6>(v128_and(tl, mask64), v128_and(th, mask64));
            let ml = v128_and(u64x2_extmul_low_u32x4(kt, invv), maskk);
            let mh = v128_and(u64x2_extmul_high_u32x4(kt, invv), maskk);
            u32x4_shuffle::<0, 2, 4, 6>(ml, mh)
        };
        let k0 = k4_of(t0_l, t0_h, mask64);
        t0_l = u64x2_add(t0_l, u64x2_extmul_low_u32x4(k0, p0));
        t0_h = u64x2_add(t0_h, u64x2_extmul_high_u32x4(k0, p0));
        t1_l = u64x2_add(t1_l, u64x2_extmul_low_u32x4(k0, p1));
        t1_h = u64x2_add(t1_h, u64x2_extmul_high_u32x4(k0, p1));
        t2_l = u64x2_add(t2_l, u64x2_extmul_low_u32x4(k0, p2));
        t2_h = u64x2_add(t2_h, u64x2_extmul_high_u32x4(k0, p2));
        t3_l = u64x2_add(t3_l, u64x2_extmul_low_u32x4(k0, p3));
        t3_h = u64x2_add(t3_h, u64x2_extmul_high_u32x4(k0, p3));
        t4_l = u64x2_add(t4_l, u64x2_extmul_low_u32x4(k0, p4));
        t4_h = u64x2_add(t4_h, u64x2_extmul_high_u32x4(k0, p4));
        t5_l = u64x2_add(t5_l, u64x2_extmul_low_u32x4(k0, p5));
        t5_h = u64x2_add(t5_h, u64x2_extmul_high_u32x4(k0, p5));
        t6_l = u64x2_add(t6_l, u64x2_extmul_low_u32x4(k0, p6));
        t6_h = u64x2_add(t6_h, u64x2_extmul_high_u32x4(k0, p6));
        t7_l = u64x2_add(t7_l, u64x2_extmul_low_u32x4(k0, p7));
        t7_h = u64x2_add(t7_h, u64x2_extmul_high_u32x4(k0, p7));
        t8_l = u64x2_add(t8_l, u64x2_extmul_low_u32x4(k0, p8));
        t8_h = u64x2_add(t8_h, u64x2_extmul_high_u32x4(k0, p8));
        t1_l = u64x2_add(t1_l, u64x2_shr(t0_l, 29));
        t1_h = u64x2_add(t1_h, u64x2_shr(t0_h, 29));
        let k1 = k4_of(t1_l, t1_h, mask64);
        t1_l = u64x2_add(t1_l, u64x2_extmul_low_u32x4(k1, p0));
        t1_h = u64x2_add(t1_h, u64x2_extmul_high_u32x4(k1, p0));
        t2_l = u64x2_add(t2_l, u64x2_extmul_low_u32x4(k1, p1));
        t2_h = u64x2_add(t2_h, u64x2_extmul_high_u32x4(k1, p1));
        t3_l = u64x2_add(t3_l, u64x2_extmul_low_u32x4(k1, p2));
        t3_h = u64x2_add(t3_h, u64x2_extmul_high_u32x4(k1, p2));
        t4_l = u64x2_add(t4_l, u64x2_extmul_low_u32x4(k1, p3));
        t4_h = u64x2_add(t4_h, u64x2_extmul_high_u32x4(k1, p3));
        t5_l = u64x2_add(t5_l, u64x2_extmul_low_u32x4(k1, p4));
        t5_h = u64x2_add(t5_h, u64x2_extmul_high_u32x4(k1, p4));
        t6_l = u64x2_add(t6_l, u64x2_extmul_low_u32x4(k1, p5));
        t6_h = u64x2_add(t6_h, u64x2_extmul_high_u32x4(k1, p5));
        t7_l = u64x2_add(t7_l, u64x2_extmul_low_u32x4(k1, p6));
        t7_h = u64x2_add(t7_h, u64x2_extmul_high_u32x4(k1, p6));
        t8_l = u64x2_add(t8_l, u64x2_extmul_low_u32x4(k1, p7));
        t8_h = u64x2_add(t8_h, u64x2_extmul_high_u32x4(k1, p7));
        t9_l = u64x2_add(t9_l, u64x2_extmul_low_u32x4(k1, p8));
        t9_h = u64x2_add(t9_h, u64x2_extmul_high_u32x4(k1, p8));
        t2_l = u64x2_add(t2_l, u64x2_shr(t1_l, 29));
        t2_h = u64x2_add(t2_h, u64x2_shr(t1_h, 29));
        let k2 = k4_of(t2_l, t2_h, mask64);
        t2_l = u64x2_add(t2_l, u64x2_extmul_low_u32x4(k2, p0));
        t2_h = u64x2_add(t2_h, u64x2_extmul_high_u32x4(k2, p0));
        t3_l = u64x2_add(t3_l, u64x2_extmul_low_u32x4(k2, p1));
        t3_h = u64x2_add(t3_h, u64x2_extmul_high_u32x4(k2, p1));
        t4_l = u64x2_add(t4_l, u64x2_extmul_low_u32x4(k2, p2));
        t4_h = u64x2_add(t4_h, u64x2_extmul_high_u32x4(k2, p2));
        t5_l = u64x2_add(t5_l, u64x2_extmul_low_u32x4(k2, p3));
        t5_h = u64x2_add(t5_h, u64x2_extmul_high_u32x4(k2, p3));
        t6_l = u64x2_add(t6_l, u64x2_extmul_low_u32x4(k2, p4));
        t6_h = u64x2_add(t6_h, u64x2_extmul_high_u32x4(k2, p4));
        t7_l = u64x2_add(t7_l, u64x2_extmul_low_u32x4(k2, p5));
        t7_h = u64x2_add(t7_h, u64x2_extmul_high_u32x4(k2, p5));
        t8_l = u64x2_add(t8_l, u64x2_extmul_low_u32x4(k2, p6));
        t8_h = u64x2_add(t8_h, u64x2_extmul_high_u32x4(k2, p6));
        t9_l = u64x2_add(t9_l, u64x2_extmul_low_u32x4(k2, p7));
        t9_h = u64x2_add(t9_h, u64x2_extmul_high_u32x4(k2, p7));
        t10_l = u64x2_add(t10_l, u64x2_extmul_low_u32x4(k2, p8));
        t10_h = u64x2_add(t10_h, u64x2_extmul_high_u32x4(k2, p8));
        t3_l = u64x2_add(t3_l, u64x2_shr(t2_l, 29));
        t3_h = u64x2_add(t3_h, u64x2_shr(t2_h, 29));
        let k3 = k4_of(t3_l, t3_h, mask64);
        t3_l = u64x2_add(t3_l, u64x2_extmul_low_u32x4(k3, p0));
        t3_h = u64x2_add(t3_h, u64x2_extmul_high_u32x4(k3, p0));
        t4_l = u64x2_add(t4_l, u64x2_extmul_low_u32x4(k3, p1));
        t4_h = u64x2_add(t4_h, u64x2_extmul_high_u32x4(k3, p1));
        t5_l = u64x2_add(t5_l, u64x2_extmul_low_u32x4(k3, p2));
        t5_h = u64x2_add(t5_h, u64x2_extmul_high_u32x4(k3, p2));
        t6_l = u64x2_add(t6_l, u64x2_extmul_low_u32x4(k3, p3));
        t6_h = u64x2_add(t6_h, u64x2_extmul_high_u32x4(k3, p3));
        t7_l = u64x2_add(t7_l, u64x2_extmul_low_u32x4(k3, p4));
        t7_h = u64x2_add(t7_h, u64x2_extmul_high_u32x4(k3, p4));
        t8_l = u64x2_add(t8_l, u64x2_extmul_low_u32x4(k3, p5));
        t8_h = u64x2_add(t8_h, u64x2_extmul_high_u32x4(k3, p5));
        t9_l = u64x2_add(t9_l, u64x2_extmul_low_u32x4(k3, p6));
        t9_h = u64x2_add(t9_h, u64x2_extmul_high_u32x4(k3, p6));
        t10_l = u64x2_add(t10_l, u64x2_extmul_low_u32x4(k3, p7));
        t10_h = u64x2_add(t10_h, u64x2_extmul_high_u32x4(k3, p7));
        t11_l = u64x2_add(t11_l, u64x2_extmul_low_u32x4(k3, p8));
        t11_h = u64x2_add(t11_h, u64x2_extmul_high_u32x4(k3, p8));
        t4_l = u64x2_add(t4_l, u64x2_shr(t3_l, 29));
        t4_h = u64x2_add(t4_h, u64x2_shr(t3_h, 29));
        let k4 = k4_of(t4_l, t4_h, mask64);
        t4_l = u64x2_add(t4_l, u64x2_extmul_low_u32x4(k4, p0));
        t4_h = u64x2_add(t4_h, u64x2_extmul_high_u32x4(k4, p0));
        t5_l = u64x2_add(t5_l, u64x2_extmul_low_u32x4(k4, p1));
        t5_h = u64x2_add(t5_h, u64x2_extmul_high_u32x4(k4, p1));
        t6_l = u64x2_add(t6_l, u64x2_extmul_low_u32x4(k4, p2));
        t6_h = u64x2_add(t6_h, u64x2_extmul_high_u32x4(k4, p2));
        t7_l = u64x2_add(t7_l, u64x2_extmul_low_u32x4(k4, p3));
        t7_h = u64x2_add(t7_h, u64x2_extmul_high_u32x4(k4, p3));
        t8_l = u64x2_add(t8_l, u64x2_extmul_low_u32x4(k4, p4));
        t8_h = u64x2_add(t8_h, u64x2_extmul_high_u32x4(k4, p4));
        t9_l = u64x2_add(t9_l, u64x2_extmul_low_u32x4(k4, p5));
        t9_h = u64x2_add(t9_h, u64x2_extmul_high_u32x4(k4, p5));
        t10_l = u64x2_add(t10_l, u64x2_extmul_low_u32x4(k4, p6));
        t10_h = u64x2_add(t10_h, u64x2_extmul_high_u32x4(k4, p6));
        t11_l = u64x2_add(t11_l, u64x2_extmul_low_u32x4(k4, p7));
        t11_h = u64x2_add(t11_h, u64x2_extmul_high_u32x4(k4, p7));
        t12_l = u64x2_add(t12_l, u64x2_extmul_low_u32x4(k4, p8));
        t12_h = u64x2_add(t12_h, u64x2_extmul_high_u32x4(k4, p8));
        t5_l = u64x2_add(t5_l, u64x2_shr(t4_l, 29));
        t5_h = u64x2_add(t5_h, u64x2_shr(t4_h, 29));
        let k5 = k4_of(t5_l, t5_h, mask64);
        t5_l = u64x2_add(t5_l, u64x2_extmul_low_u32x4(k5, p0));
        t5_h = u64x2_add(t5_h, u64x2_extmul_high_u32x4(k5, p0));
        t6_l = u64x2_add(t6_l, u64x2_extmul_low_u32x4(k5, p1));
        t6_h = u64x2_add(t6_h, u64x2_extmul_high_u32x4(k5, p1));
        t7_l = u64x2_add(t7_l, u64x2_extmul_low_u32x4(k5, p2));
        t7_h = u64x2_add(t7_h, u64x2_extmul_high_u32x4(k5, p2));
        t8_l = u64x2_add(t8_l, u64x2_extmul_low_u32x4(k5, p3));
        t8_h = u64x2_add(t8_h, u64x2_extmul_high_u32x4(k5, p3));
        t9_l = u64x2_add(t9_l, u64x2_extmul_low_u32x4(k5, p4));
        t9_h = u64x2_add(t9_h, u64x2_extmul_high_u32x4(k5, p4));
        t10_l = u64x2_add(t10_l, u64x2_extmul_low_u32x4(k5, p5));
        t10_h = u64x2_add(t10_h, u64x2_extmul_high_u32x4(k5, p5));
        t11_l = u64x2_add(t11_l, u64x2_extmul_low_u32x4(k5, p6));
        t11_h = u64x2_add(t11_h, u64x2_extmul_high_u32x4(k5, p6));
        t12_l = u64x2_add(t12_l, u64x2_extmul_low_u32x4(k5, p7));
        t12_h = u64x2_add(t12_h, u64x2_extmul_high_u32x4(k5, p7));
        t13_l = u64x2_add(t13_l, u64x2_extmul_low_u32x4(k5, p8));
        t13_h = u64x2_add(t13_h, u64x2_extmul_high_u32x4(k5, p8));
        t6_l = u64x2_add(t6_l, u64x2_shr(t5_l, 29));
        t6_h = u64x2_add(t6_h, u64x2_shr(t5_h, 29));
        let k6 = k4_of(t6_l, t6_h, mask64);
        t6_l = u64x2_add(t6_l, u64x2_extmul_low_u32x4(k6, p0));
        t6_h = u64x2_add(t6_h, u64x2_extmul_high_u32x4(k6, p0));
        t7_l = u64x2_add(t7_l, u64x2_extmul_low_u32x4(k6, p1));
        t7_h = u64x2_add(t7_h, u64x2_extmul_high_u32x4(k6, p1));
        t8_l = u64x2_add(t8_l, u64x2_extmul_low_u32x4(k6, p2));
        t8_h = u64x2_add(t8_h, u64x2_extmul_high_u32x4(k6, p2));
        t9_l = u64x2_add(t9_l, u64x2_extmul_low_u32x4(k6, p3));
        t9_h = u64x2_add(t9_h, u64x2_extmul_high_u32x4(k6, p3));
        t10_l = u64x2_add(t10_l, u64x2_extmul_low_u32x4(k6, p4));
        t10_h = u64x2_add(t10_h, u64x2_extmul_high_u32x4(k6, p4));
        t11_l = u64x2_add(t11_l, u64x2_extmul_low_u32x4(k6, p5));
        t11_h = u64x2_add(t11_h, u64x2_extmul_high_u32x4(k6, p5));
        t12_l = u64x2_add(t12_l, u64x2_extmul_low_u32x4(k6, p6));
        t12_h = u64x2_add(t12_h, u64x2_extmul_high_u32x4(k6, p6));
        t13_l = u64x2_add(t13_l, u64x2_extmul_low_u32x4(k6, p7));
        t13_h = u64x2_add(t13_h, u64x2_extmul_high_u32x4(k6, p7));
        t14_l = u64x2_add(t14_l, u64x2_extmul_low_u32x4(k6, p8));
        t14_h = u64x2_add(t14_h, u64x2_extmul_high_u32x4(k6, p8));
        t7_l = u64x2_add(t7_l, u64x2_shr(t6_l, 29));
        t7_h = u64x2_add(t7_h, u64x2_shr(t6_h, 29));
        let k7 = k4_of(t7_l, t7_h, mask64);
        t7_l = u64x2_add(t7_l, u64x2_extmul_low_u32x4(k7, p0));
        t7_h = u64x2_add(t7_h, u64x2_extmul_high_u32x4(k7, p0));
        t8_l = u64x2_add(t8_l, u64x2_extmul_low_u32x4(k7, p1));
        t8_h = u64x2_add(t8_h, u64x2_extmul_high_u32x4(k7, p1));
        t9_l = u64x2_add(t9_l, u64x2_extmul_low_u32x4(k7, p2));
        t9_h = u64x2_add(t9_h, u64x2_extmul_high_u32x4(k7, p2));
        t10_l = u64x2_add(t10_l, u64x2_extmul_low_u32x4(k7, p3));
        t10_h = u64x2_add(t10_h, u64x2_extmul_high_u32x4(k7, p3));
        t11_l = u64x2_add(t11_l, u64x2_extmul_low_u32x4(k7, p4));
        t11_h = u64x2_add(t11_h, u64x2_extmul_high_u32x4(k7, p4));
        t12_l = u64x2_add(t12_l, u64x2_extmul_low_u32x4(k7, p5));
        t12_h = u64x2_add(t12_h, u64x2_extmul_high_u32x4(k7, p5));
        t13_l = u64x2_add(t13_l, u64x2_extmul_low_u32x4(k7, p6));
        t13_h = u64x2_add(t13_h, u64x2_extmul_high_u32x4(k7, p6));
        t14_l = u64x2_add(t14_l, u64x2_extmul_low_u32x4(k7, p7));
        t14_h = u64x2_add(t14_h, u64x2_extmul_high_u32x4(k7, p7));
        t15_l = u64x2_add(t15_l, u64x2_extmul_low_u32x4(k7, p8));
        t15_h = u64x2_add(t15_h, u64x2_extmul_high_u32x4(k7, p8));
        t8_l = u64x2_add(t8_l, u64x2_shr(t7_l, 29));
        t8_h = u64x2_add(t8_h, u64x2_shr(t7_h, 29));
        let k8 = k4_of(t8_l, t8_h, mask24);
        t8_l = u64x2_add(t8_l, u64x2_extmul_low_u32x4(k8, p0));
        t8_h = u64x2_add(t8_h, u64x2_extmul_high_u32x4(k8, p0));
        t9_l = u64x2_add(t9_l, u64x2_extmul_low_u32x4(k8, p1));
        t9_h = u64x2_add(t9_h, u64x2_extmul_high_u32x4(k8, p1));
        t10_l = u64x2_add(t10_l, u64x2_extmul_low_u32x4(k8, p2));
        t10_h = u64x2_add(t10_h, u64x2_extmul_high_u32x4(k8, p2));
        t11_l = u64x2_add(t11_l, u64x2_extmul_low_u32x4(k8, p3));
        t11_h = u64x2_add(t11_h, u64x2_extmul_high_u32x4(k8, p3));
        t12_l = u64x2_add(t12_l, u64x2_extmul_low_u32x4(k8, p4));
        t12_h = u64x2_add(t12_h, u64x2_extmul_high_u32x4(k8, p4));
        t13_l = u64x2_add(t13_l, u64x2_extmul_low_u32x4(k8, p5));
        t13_h = u64x2_add(t13_h, u64x2_extmul_high_u32x4(k8, p5));
        t14_l = u64x2_add(t14_l, u64x2_extmul_low_u32x4(k8, p6));
        t14_h = u64x2_add(t14_h, u64x2_extmul_high_u32x4(k8, p6));
        t15_l = u64x2_add(t15_l, u64x2_extmul_low_u32x4(k8, p7));
        t15_h = u64x2_add(t15_h, u64x2_extmul_high_u32x4(k8, p7));
        t16_l = u64x2_add(t16_l, u64x2_extmul_low_u32x4(k8, p8));
        t16_h = u64x2_add(t16_h, u64x2_extmul_high_u32x4(k8, p8));
        t9_l = u64x2_add(t9_l, u64x2_shr(t8_l, 29));
        t8_l = v128_and(t8_l, mask64);
        t9_h = u64x2_add(t9_h, u64x2_shr(t8_h, 29));
        t8_h = v128_and(t8_h, mask64);
        t10_l = u64x2_add(t10_l, u64x2_shr(t9_l, 29));
        t9_l = v128_and(t9_l, mask64);
        t10_h = u64x2_add(t10_h, u64x2_shr(t9_h, 29));
        t9_h = v128_and(t9_h, mask64);
        t11_l = u64x2_add(t11_l, u64x2_shr(t10_l, 29));
        t10_l = v128_and(t10_l, mask64);
        t11_h = u64x2_add(t11_h, u64x2_shr(t10_h, 29));
        t10_h = v128_and(t10_h, mask64);
        t12_l = u64x2_add(t12_l, u64x2_shr(t11_l, 29));
        t11_l = v128_and(t11_l, mask64);
        t12_h = u64x2_add(t12_h, u64x2_shr(t11_h, 29));
        t11_h = v128_and(t11_h, mask64);
        t13_l = u64x2_add(t13_l, u64x2_shr(t12_l, 29));
        t12_l = v128_and(t12_l, mask64);
        t13_h = u64x2_add(t13_h, u64x2_shr(t12_h, 29));
        t12_h = v128_and(t12_h, mask64);
        t14_l = u64x2_add(t14_l, u64x2_shr(t13_l, 29));
        t13_l = v128_and(t13_l, mask64);
        t14_h = u64x2_add(t14_h, u64x2_shr(t13_h, 29));
        t13_h = v128_and(t13_h, mask64);
        t15_l = u64x2_add(t15_l, u64x2_shr(t14_l, 29));
        t14_l = v128_and(t14_l, mask64);
        t15_h = u64x2_add(t15_h, u64x2_shr(t14_h, 29));
        t14_h = v128_and(t14_h, mask64);
        t16_l = u64x2_add(t16_l, u64x2_shr(t15_l, 29));
        t15_l = v128_and(t15_l, mask64);
        t16_h = u64x2_add(t16_h, u64x2_shr(t15_h, 29));
        t15_h = v128_and(t15_h, mask64);
        t17_l = u64x2_add(t17_l, u64x2_shr(t16_l, 29));
        t16_l = v128_and(t16_l, mask64);
        t17_h = u64x2_add(t17_h, u64x2_shr(t16_h, 29));
        t16_h = v128_and(t16_h, mask64);
        let o0_l = v128_and(v128_or(u64x2_shr(t8_l, 24), u64x2_shl(t9_l, 5)), mask64);
        let o0_h = v128_and(v128_or(u64x2_shr(t8_h, 24), u64x2_shl(t9_h, 5)), mask64);
        let o1_l = v128_and(v128_or(u64x2_shr(t9_l, 24), u64x2_shl(t10_l, 5)), mask64);
        let o1_h = v128_and(v128_or(u64x2_shr(t9_h, 24), u64x2_shl(t10_h, 5)), mask64);
        let o2_l = v128_and(v128_or(u64x2_shr(t10_l, 24), u64x2_shl(t11_l, 5)), mask64);
        let o2_h = v128_and(v128_or(u64x2_shr(t10_h, 24), u64x2_shl(t11_h, 5)), mask64);
        let o3_l = v128_and(v128_or(u64x2_shr(t11_l, 24), u64x2_shl(t12_l, 5)), mask64);
        let o3_h = v128_and(v128_or(u64x2_shr(t11_h, 24), u64x2_shl(t12_h, 5)), mask64);
        let o4_l = v128_and(v128_or(u64x2_shr(t12_l, 24), u64x2_shl(t13_l, 5)), mask64);
        let o4_h = v128_and(v128_or(u64x2_shr(t12_h, 24), u64x2_shl(t13_h, 5)), mask64);
        let o5_l = v128_and(v128_or(u64x2_shr(t13_l, 24), u64x2_shl(t14_l, 5)), mask64);
        let o5_h = v128_and(v128_or(u64x2_shr(t13_h, 24), u64x2_shl(t14_h, 5)), mask64);
        let o6_l = v128_and(v128_or(u64x2_shr(t14_l, 24), u64x2_shl(t15_l, 5)), mask64);
        let o6_h = v128_and(v128_or(u64x2_shr(t14_h, 24), u64x2_shl(t15_h, 5)), mask64);
        let o7_l = v128_and(v128_or(u64x2_shr(t15_l, 24), u64x2_shl(t16_l, 5)), mask64);
        let o7_h = v128_and(v128_or(u64x2_shr(t15_h, 24), u64x2_shl(t16_h, 5)), mask64);
        let o8_l = v128_and(v128_or(u64x2_shr(t16_l, 24), u64x2_shl(t17_l, 5)), mask64);
        let o8_h = v128_and(v128_or(u64x2_shr(t16_h, 24), u64x2_shl(t17_h, 5)), mask64);
        QuadFp {
            limbs: [
                u32x4_shuffle::<0, 2, 4, 6>(o0_l, o0_h),
                u32x4_shuffle::<0, 2, 4, 6>(o1_l, o1_h),
                u32x4_shuffle::<0, 2, 4, 6>(o2_l, o2_h),
                u32x4_shuffle::<0, 2, 4, 6>(o3_l, o3_h),
                u32x4_shuffle::<0, 2, 4, 6>(o4_l, o4_h),
                u32x4_shuffle::<0, 2, 4, 6>(o5_l, o5_h),
                u32x4_shuffle::<0, 2, 4, 6>(o6_l, o6_h),
                u32x4_shuffle::<0, 2, 4, 6>(o7_l, o7_h),
                u32x4_shuffle::<0, 2, 4, 6>(o8_l, o8_h),
            ],
        }
    }
}

/// bb's exact wasm multiply as a 4-lane SIMD kernel: Karatsuba 5+4, eight Yuval reductions
/// (the round multiplier is the masked low limb — no inverse multiply) and one standard
/// Montgomery round, dividing by 2^261. Batched loops absorb the 2^-5 domain drift into a
/// pre-scaled constant operand (`scale32`), keeping stored values in ark's 2^256 domain.
#[cfg(all(target_family = "wasm", target_feature = "simd128"))]
pub mod quad261 {
    pub use super::quad256::QuadFp;
    use super::wasm_mont::MASK29;
    use core::arch::wasm32::*;

    /// Lanewise `a + b` on coarse [0, 2p) values, entirely in u32x4 (bb VectorField's TNM
    /// trick, no 64-bit widening): raw carry-propagated add `r = a + b`, an independent chain
    /// `t = r + (2^261 - 2p)` whose top-limb carry fires exactly when `a + b >= 2p`, and a
    /// per-lane blend. Output back in [0, 2p).
    pub fn add(a: &QuadFp, b: &QuadFp, c: &Consts) -> QuadFp {
        let mask = c.mask32;
        let mut r = [u32x4_splat(0); 9];
        let mut v = u32x4_add(a.limbs[0], b.limbs[0]);
        let mut carry = u32x4_shr(v, 29);
        r[0] = v128_and(v, mask);
        for k in 1..9 {
            // 29-bit limb + 29-bit limb + carry <= 2^30: fits u32, carry is bit 29.
            v = u32x4_add(u32x4_add(a.limbs[k], b.limbs[k]), carry);
            carry = u32x4_shr(v, 29);
            r[k] = v128_and(v, mask);
        }
        let mut t = [u32x4_splat(0); 9];
        v = u32x4_add(r[0], c.tnm[0]);
        carry = u32x4_shr(v, 29);
        t[0] = v128_and(v, mask);
        for k in 1..9 {
            v = u32x4_add(u32x4_add(r[k], c.tnm[k]), carry);
            carry = u32x4_shr(v, 29);
            t[k] = v128_and(v, mask);
        }
        // Top-limb carry set (per lane) => a + b >= 2p => t (= r - 2p mod 2^261) is the value.
        let pick_t = i32x4_eq(carry, u32x4_splat(1));
        let mut out = [u32x4_splat(0); 9];
        for k in 0..9 {
            out[k] = v128_bitselect(t[k], r[k], pick_t);
        }
        QuadFp { limbs: out }
    }

    /// Lanewise `a - b` on coarse values, entirely in u32x4: borrow-propagated raw subtract
    /// (29-bit limbs keep bits 29..31 clear, so underflow shows in bit 31), a `+2p` chain, and
    /// a per-lane blend on the final borrow. Output in [0, 2p).
    pub fn sub(a: &QuadFp, b: &QuadFp, c: &Consts) -> QuadFp {
        let mask = c.mask32;
        let mut r = [u32x4_splat(0); 9];
        let mut v = i32x4_sub(a.limbs[0], b.limbs[0]);
        let mut borrow = u32x4_shr(v, 31);
        r[0] = v128_and(v, mask);
        for k in 1..9 {
            v = i32x4_sub(i32x4_sub(a.limbs[k], b.limbs[k]), borrow);
            borrow = u32x4_shr(v, 31);
            r[k] = v128_and(v, mask);
        }
        let pick_s = i32x4_eq(borrow, u32x4_splat(1));
        let mut s = [u32x4_splat(0); 9];
        v = u32x4_add(r[0], c.twop[0]);
        let mut carry = u32x4_shr(v, 29);
        s[0] = v128_and(v, mask);
        for k in 1..9 {
            v = u32x4_add(u32x4_add(r[k], c.twop[k]), carry);
            carry = u32x4_shr(v, 29);
            s[k] = v128_and(v, mask);
        }
        let mut out = [u32x4_splat(0); 9];
        for k in 0..9 {
            out[k] = v128_bitselect(s[k], r[k], pick_s);
        }
        QuadFp { limbs: out }
    }

    /// Splatted per-field constants, prepared once per loop instead of per multiply.
    #[derive(Clone, Copy)]
    pub struct Consts {
        pub ri: [v128; 9],
        pub p: [v128; 9],
        /// 2p as splatted 29-bit limbs (sub's blend chain).
        pub twop: [v128; 9],
        /// 2^261 - 2p as splatted 29-bit limbs (add's TNM chain).
        pub tnm: [v128; 9],
        pub invv: v128,
        pub mask64: v128,
        pub mask32: v128,
    }

    impl Consts {
        pub fn new(rinv29: &[u32; 9], p29: &[u64; 9], inv: u64) -> Self {
            let mut twop = [0u32; 9];
            let mut carry = 0u64;
            for k in 0..9 {
                let v = 2 * p29[k] + carry;
                twop[k] = (v & MASK29) as u32;
                carry = v >> 29;
            }
            let mut tnm = [0u32; 9];
            carry = 1;
            for k in 0..9 {
                let v = ((!(twop[k] as u64)) & MASK29) + carry;
                tnm[k] = (v & MASK29) as u32;
                carry = v >> 29;
            }
            Consts {
                ri: core::array::from_fn(|k| u32x4_splat(rinv29[k])),
                p: core::array::from_fn(|k| u32x4_splat(p29[k] as u32)),
                twop: core::array::from_fn(|k| u32x4_splat(twop[k])),
                tnm: core::array::from_fn(|k| u32x4_splat(tnm[k])),
                invv: u32x4_splat(inv as u32),
                mask64: u64x2_splat(MASK29),
                mask32: u32x4_splat(MASK29 as u32),
            }
        }
    }

    /// Per-lane `a * b / 2^261 mod p`, coarse in/out.
    #[allow(clippy::too_many_lines)]
    pub fn mont_mul(a: &QuadFp, b: &QuadFp, c: &Consts) -> QuadFp {
        let mask64 = c.mask64;
        let invv = c.invv;
        let ri0 = c.ri[0];
        let p0 = c.p[0];
        let ri1 = c.ri[1];
        let p1 = c.p[1];
        let ri2 = c.ri[2];
        let p2 = c.p[2];
        let ri3 = c.ri[3];
        let p3 = c.p[3];
        let ri4 = c.ri[4];
        let p4 = c.p[4];
        let ri5 = c.ri[5];
        let p5 = c.p[5];
        let ri6 = c.ri[6];
        let p6 = c.p[6];
        let ri7 = c.ri[7];
        let p7 = c.p[7];
        let ri8 = c.ri[8];
        let p8 = c.p[8];
        let a0 = a.limbs[0];
        let b0 = b.limbs[0];
        let a1 = a.limbs[1];
        let b1 = b.limbs[1];
        let a2 = a.limbs[2];
        let b2 = b.limbs[2];
        let a3 = a.limbs[3];
        let b3 = b.limbs[3];
        let a4 = a.limbs[4];
        let b4 = b.limbs[4];
        let a5 = a.limbs[5];
        let b5 = b.limbs[5];
        let a6 = a.limbs[6];
        let b6 = b.limbs[6];
        let a7 = a.limbs[7];
        let b7 = b.limbs[7];
        let a8 = a.limbs[8];
        let b8 = b.limbs[8];
        let sl0 = u32x4_add(a0, a5);
        let sr0 = u32x4_add(b0, b5);
        let sl1 = u32x4_add(a1, a6);
        let sr1 = u32x4_add(b1, b6);
        let sl2 = u32x4_add(a2, a7);
        let sr2 = u32x4_add(b2, b7);
        let sl3 = u32x4_add(a3, a8);
        let sr3 = u32x4_add(b3, b8);
        let sl4 = a4;
        let sr4 = b4;
        let pl0_l = u64x2_extmul_low_u32x4(a0, b0);
        let pl0_h = u64x2_extmul_high_u32x4(a0, b0);
        let pl1_l = u64x2_add(u64x2_extmul_low_u32x4(a0, b1), u64x2_extmul_low_u32x4(a1, b0));
        let pl1_h = u64x2_add(u64x2_extmul_high_u32x4(a0, b1), u64x2_extmul_high_u32x4(a1, b0));
        let pl2_l = u64x2_add(
            u64x2_add(u64x2_extmul_low_u32x4(a0, b2), u64x2_extmul_low_u32x4(a1, b1)),
            u64x2_extmul_low_u32x4(a2, b0),
        );
        let pl2_h = u64x2_add(
            u64x2_add(u64x2_extmul_high_u32x4(a0, b2), u64x2_extmul_high_u32x4(a1, b1)),
            u64x2_extmul_high_u32x4(a2, b0),
        );
        let pl3_l = u64x2_add(
            u64x2_add(
                u64x2_add(u64x2_extmul_low_u32x4(a0, b3), u64x2_extmul_low_u32x4(a1, b2)),
                u64x2_extmul_low_u32x4(a2, b1),
            ),
            u64x2_extmul_low_u32x4(a3, b0),
        );
        let pl3_h = u64x2_add(
            u64x2_add(
                u64x2_add(u64x2_extmul_high_u32x4(a0, b3), u64x2_extmul_high_u32x4(a1, b2)),
                u64x2_extmul_high_u32x4(a2, b1),
            ),
            u64x2_extmul_high_u32x4(a3, b0),
        );
        let pl4_l = u64x2_add(
            u64x2_add(
                u64x2_add(
                    u64x2_add(u64x2_extmul_low_u32x4(a0, b4), u64x2_extmul_low_u32x4(a1, b3)),
                    u64x2_extmul_low_u32x4(a2, b2),
                ),
                u64x2_extmul_low_u32x4(a3, b1),
            ),
            u64x2_extmul_low_u32x4(a4, b0),
        );
        let pl4_h = u64x2_add(
            u64x2_add(
                u64x2_add(
                    u64x2_add(u64x2_extmul_high_u32x4(a0, b4), u64x2_extmul_high_u32x4(a1, b3)),
                    u64x2_extmul_high_u32x4(a2, b2),
                ),
                u64x2_extmul_high_u32x4(a3, b1),
            ),
            u64x2_extmul_high_u32x4(a4, b0),
        );
        let pl5_l = u64x2_add(
            u64x2_add(
                u64x2_add(u64x2_extmul_low_u32x4(a1, b4), u64x2_extmul_low_u32x4(a2, b3)),
                u64x2_extmul_low_u32x4(a3, b2),
            ),
            u64x2_extmul_low_u32x4(a4, b1),
        );
        let pl5_h = u64x2_add(
            u64x2_add(
                u64x2_add(u64x2_extmul_high_u32x4(a1, b4), u64x2_extmul_high_u32x4(a2, b3)),
                u64x2_extmul_high_u32x4(a3, b2),
            ),
            u64x2_extmul_high_u32x4(a4, b1),
        );
        let pl6_l = u64x2_add(
            u64x2_add(u64x2_extmul_low_u32x4(a2, b4), u64x2_extmul_low_u32x4(a3, b3)),
            u64x2_extmul_low_u32x4(a4, b2),
        );
        let pl6_h = u64x2_add(
            u64x2_add(u64x2_extmul_high_u32x4(a2, b4), u64x2_extmul_high_u32x4(a3, b3)),
            u64x2_extmul_high_u32x4(a4, b2),
        );
        let pl7_l = u64x2_add(u64x2_extmul_low_u32x4(a3, b4), u64x2_extmul_low_u32x4(a4, b3));
        let pl7_h = u64x2_add(u64x2_extmul_high_u32x4(a3, b4), u64x2_extmul_high_u32x4(a4, b3));
        let pl8_l = u64x2_extmul_low_u32x4(a4, b4);
        let pl8_h = u64x2_extmul_high_u32x4(a4, b4);
        let ph0_l = u64x2_extmul_low_u32x4(a5, b5);
        let ph0_h = u64x2_extmul_high_u32x4(a5, b5);
        let ph1_l = u64x2_add(u64x2_extmul_low_u32x4(a5, b6), u64x2_extmul_low_u32x4(a6, b5));
        let ph1_h = u64x2_add(u64x2_extmul_high_u32x4(a5, b6), u64x2_extmul_high_u32x4(a6, b5));
        let ph2_l = u64x2_add(
            u64x2_add(u64x2_extmul_low_u32x4(a5, b7), u64x2_extmul_low_u32x4(a6, b6)),
            u64x2_extmul_low_u32x4(a7, b5),
        );
        let ph2_h = u64x2_add(
            u64x2_add(u64x2_extmul_high_u32x4(a5, b7), u64x2_extmul_high_u32x4(a6, b6)),
            u64x2_extmul_high_u32x4(a7, b5),
        );
        let ph3_l = u64x2_add(
            u64x2_add(
                u64x2_add(u64x2_extmul_low_u32x4(a5, b8), u64x2_extmul_low_u32x4(a6, b7)),
                u64x2_extmul_low_u32x4(a7, b6),
            ),
            u64x2_extmul_low_u32x4(a8, b5),
        );
        let ph3_h = u64x2_add(
            u64x2_add(
                u64x2_add(u64x2_extmul_high_u32x4(a5, b8), u64x2_extmul_high_u32x4(a6, b7)),
                u64x2_extmul_high_u32x4(a7, b6),
            ),
            u64x2_extmul_high_u32x4(a8, b5),
        );
        let ph4_l = u64x2_add(
            u64x2_add(u64x2_extmul_low_u32x4(a6, b8), u64x2_extmul_low_u32x4(a7, b7)),
            u64x2_extmul_low_u32x4(a8, b6),
        );
        let ph4_h = u64x2_add(
            u64x2_add(u64x2_extmul_high_u32x4(a6, b8), u64x2_extmul_high_u32x4(a7, b7)),
            u64x2_extmul_high_u32x4(a8, b6),
        );
        let ph5_l = u64x2_add(u64x2_extmul_low_u32x4(a7, b8), u64x2_extmul_low_u32x4(a8, b7));
        let ph5_h = u64x2_add(u64x2_extmul_high_u32x4(a7, b8), u64x2_extmul_high_u32x4(a8, b7));
        let ph6_l = u64x2_extmul_low_u32x4(a8, b8);
        let ph6_h = u64x2_extmul_high_u32x4(a8, b8);
        let pc0_l = u64x2_extmul_low_u32x4(sl0, sr0);
        let pc0_h = u64x2_extmul_high_u32x4(sl0, sr0);
        let pc1_l = u64x2_add(u64x2_extmul_low_u32x4(sl0, sr1), u64x2_extmul_low_u32x4(sl1, sr0));
        let pc1_h = u64x2_add(u64x2_extmul_high_u32x4(sl0, sr1), u64x2_extmul_high_u32x4(sl1, sr0));
        let pc2_l = u64x2_add(
            u64x2_add(u64x2_extmul_low_u32x4(sl0, sr2), u64x2_extmul_low_u32x4(sl1, sr1)),
            u64x2_extmul_low_u32x4(sl2, sr0),
        );
        let pc2_h = u64x2_add(
            u64x2_add(u64x2_extmul_high_u32x4(sl0, sr2), u64x2_extmul_high_u32x4(sl1, sr1)),
            u64x2_extmul_high_u32x4(sl2, sr0),
        );
        let pc3_l = u64x2_add(
            u64x2_add(
                u64x2_add(u64x2_extmul_low_u32x4(sl0, sr3), u64x2_extmul_low_u32x4(sl1, sr2)),
                u64x2_extmul_low_u32x4(sl2, sr1),
            ),
            u64x2_extmul_low_u32x4(sl3, sr0),
        );
        let pc3_h = u64x2_add(
            u64x2_add(
                u64x2_add(u64x2_extmul_high_u32x4(sl0, sr3), u64x2_extmul_high_u32x4(sl1, sr2)),
                u64x2_extmul_high_u32x4(sl2, sr1),
            ),
            u64x2_extmul_high_u32x4(sl3, sr0),
        );
        let pc4_l = u64x2_add(
            u64x2_add(
                u64x2_add(
                    u64x2_add(u64x2_extmul_low_u32x4(sl0, sr4), u64x2_extmul_low_u32x4(sl1, sr3)),
                    u64x2_extmul_low_u32x4(sl2, sr2),
                ),
                u64x2_extmul_low_u32x4(sl3, sr1),
            ),
            u64x2_extmul_low_u32x4(sl4, sr0),
        );
        let pc4_h = u64x2_add(
            u64x2_add(
                u64x2_add(
                    u64x2_add(u64x2_extmul_high_u32x4(sl0, sr4), u64x2_extmul_high_u32x4(sl1, sr3)),
                    u64x2_extmul_high_u32x4(sl2, sr2),
                ),
                u64x2_extmul_high_u32x4(sl3, sr1),
            ),
            u64x2_extmul_high_u32x4(sl4, sr0),
        );
        let pc5_l = u64x2_add(
            u64x2_add(
                u64x2_add(u64x2_extmul_low_u32x4(sl1, sr4), u64x2_extmul_low_u32x4(sl2, sr3)),
                u64x2_extmul_low_u32x4(sl3, sr2),
            ),
            u64x2_extmul_low_u32x4(sl4, sr1),
        );
        let pc5_h = u64x2_add(
            u64x2_add(
                u64x2_add(u64x2_extmul_high_u32x4(sl1, sr4), u64x2_extmul_high_u32x4(sl2, sr3)),
                u64x2_extmul_high_u32x4(sl3, sr2),
            ),
            u64x2_extmul_high_u32x4(sl4, sr1),
        );
        let pc6_l = u64x2_add(
            u64x2_add(u64x2_extmul_low_u32x4(sl2, sr4), u64x2_extmul_low_u32x4(sl3, sr3)),
            u64x2_extmul_low_u32x4(sl4, sr2),
        );
        let pc6_h = u64x2_add(
            u64x2_add(u64x2_extmul_high_u32x4(sl2, sr4), u64x2_extmul_high_u32x4(sl3, sr3)),
            u64x2_extmul_high_u32x4(sl4, sr2),
        );
        let pc7_l = u64x2_add(u64x2_extmul_low_u32x4(sl3, sr4), u64x2_extmul_low_u32x4(sl4, sr3));
        let pc7_h = u64x2_add(u64x2_extmul_high_u32x4(sl3, sr4), u64x2_extmul_high_u32x4(sl4, sr3));
        let pc8_l = u64x2_extmul_low_u32x4(sl4, sr4);
        let pc8_h = u64x2_extmul_high_u32x4(sl4, sr4);
        let mut t0_l = pl0_l;
        let mut t1_l = pl1_l;
        let mut t2_l = pl2_l;
        let mut t3_l = pl3_l;
        let mut t4_l = pl4_l;
        let m0_l = u64x2_sub(u64x2_sub(pc0_l, pl0_l), ph0_l);
        let m1_l = u64x2_sub(u64x2_sub(pc1_l, pl1_l), ph1_l);
        let m2_l = u64x2_sub(u64x2_sub(pc2_l, pl2_l), ph2_l);
        let m3_l = u64x2_sub(u64x2_sub(pc3_l, pl3_l), ph3_l);
        let m4_l = u64x2_sub(u64x2_sub(pc4_l, pl4_l), ph4_l);
        let m5_l = u64x2_sub(u64x2_sub(pc5_l, pl5_l), ph5_l);
        let m6_l = u64x2_sub(u64x2_sub(pc6_l, pl6_l), ph6_l);
        let m7_l = u64x2_sub(pc7_l, pl7_l);
        let m8_l = u64x2_sub(pc8_l, pl8_l);
        let mut t5_l = u64x2_add(pl5_l, m0_l);
        let mut t6_l = u64x2_add(pl6_l, m1_l);
        let mut t7_l = u64x2_add(pl7_l, m2_l);
        let mut t8_l = u64x2_add(pl8_l, m3_l);
        let mut t9_l = m4_l;
        let mut t10_l = u64x2_add(m5_l, ph0_l);
        let mut t11_l = u64x2_add(m6_l, ph1_l);
        let mut t12_l = u64x2_add(m7_l, ph2_l);
        let mut t13_l = u64x2_add(m8_l, ph3_l);
        let mut t14_l = ph4_l;
        let mut t15_l = ph5_l;
        let mut t16_l = ph6_l;
        let mut t0_h = pl0_h;
        let mut t1_h = pl1_h;
        let mut t2_h = pl2_h;
        let mut t3_h = pl3_h;
        let mut t4_h = pl4_h;
        let m0_h = u64x2_sub(u64x2_sub(pc0_h, pl0_h), ph0_h);
        let m1_h = u64x2_sub(u64x2_sub(pc1_h, pl1_h), ph1_h);
        let m2_h = u64x2_sub(u64x2_sub(pc2_h, pl2_h), ph2_h);
        let m3_h = u64x2_sub(u64x2_sub(pc3_h, pl3_h), ph3_h);
        let m4_h = u64x2_sub(u64x2_sub(pc4_h, pl4_h), ph4_h);
        let m5_h = u64x2_sub(u64x2_sub(pc5_h, pl5_h), ph5_h);
        let m6_h = u64x2_sub(u64x2_sub(pc6_h, pl6_h), ph6_h);
        let m7_h = u64x2_sub(pc7_h, pl7_h);
        let m8_h = u64x2_sub(pc8_h, pl8_h);
        let mut t5_h = u64x2_add(pl5_h, m0_h);
        let mut t6_h = u64x2_add(pl6_h, m1_h);
        let mut t7_h = u64x2_add(pl7_h, m2_h);
        let mut t8_h = u64x2_add(pl8_h, m3_h);
        let mut t9_h = m4_h;
        let mut t10_h = u64x2_add(m5_h, ph0_h);
        let mut t11_h = u64x2_add(m6_h, ph1_h);
        let mut t12_h = u64x2_add(m7_h, ph2_h);
        let mut t13_h = u64x2_add(m8_h, ph3_h);
        let mut t14_h = ph4_h;
        let mut t15_h = ph5_h;
        let mut t16_h = ph6_h;
        let kml = v128_and(t0_l, mask64);
        let kmh = v128_and(t0_h, mask64);
        let k0 = u32x4_shuffle::<0, 2, 4, 6>(kml, kmh);
        t1_l = u64x2_add(t1_l, u64x2_shr(t0_l, 29));
        t1_h = u64x2_add(t1_h, u64x2_shr(t0_h, 29));
        t1_l = u64x2_add(t1_l, u64x2_extmul_low_u32x4(k0, ri0));
        t1_h = u64x2_add(t1_h, u64x2_extmul_high_u32x4(k0, ri0));
        t2_l = u64x2_add(t2_l, u64x2_extmul_low_u32x4(k0, ri1));
        t2_h = u64x2_add(t2_h, u64x2_extmul_high_u32x4(k0, ri1));
        t3_l = u64x2_add(t3_l, u64x2_extmul_low_u32x4(k0, ri2));
        t3_h = u64x2_add(t3_h, u64x2_extmul_high_u32x4(k0, ri2));
        t4_l = u64x2_add(t4_l, u64x2_extmul_low_u32x4(k0, ri3));
        t4_h = u64x2_add(t4_h, u64x2_extmul_high_u32x4(k0, ri3));
        t5_l = u64x2_add(t5_l, u64x2_extmul_low_u32x4(k0, ri4));
        t5_h = u64x2_add(t5_h, u64x2_extmul_high_u32x4(k0, ri4));
        t6_l = u64x2_add(t6_l, u64x2_extmul_low_u32x4(k0, ri5));
        t6_h = u64x2_add(t6_h, u64x2_extmul_high_u32x4(k0, ri5));
        t7_l = u64x2_add(t7_l, u64x2_extmul_low_u32x4(k0, ri6));
        t7_h = u64x2_add(t7_h, u64x2_extmul_high_u32x4(k0, ri6));
        t8_l = u64x2_add(t8_l, u64x2_extmul_low_u32x4(k0, ri7));
        t8_h = u64x2_add(t8_h, u64x2_extmul_high_u32x4(k0, ri7));
        t9_l = u64x2_add(t9_l, u64x2_extmul_low_u32x4(k0, ri8));
        t9_h = u64x2_add(t9_h, u64x2_extmul_high_u32x4(k0, ri8));
        let kml = v128_and(t1_l, mask64);
        let kmh = v128_and(t1_h, mask64);
        let k1 = u32x4_shuffle::<0, 2, 4, 6>(kml, kmh);
        t2_l = u64x2_add(t2_l, u64x2_shr(t1_l, 29));
        t2_h = u64x2_add(t2_h, u64x2_shr(t1_h, 29));
        t2_l = u64x2_add(t2_l, u64x2_extmul_low_u32x4(k1, ri0));
        t2_h = u64x2_add(t2_h, u64x2_extmul_high_u32x4(k1, ri0));
        t3_l = u64x2_add(t3_l, u64x2_extmul_low_u32x4(k1, ri1));
        t3_h = u64x2_add(t3_h, u64x2_extmul_high_u32x4(k1, ri1));
        t4_l = u64x2_add(t4_l, u64x2_extmul_low_u32x4(k1, ri2));
        t4_h = u64x2_add(t4_h, u64x2_extmul_high_u32x4(k1, ri2));
        t5_l = u64x2_add(t5_l, u64x2_extmul_low_u32x4(k1, ri3));
        t5_h = u64x2_add(t5_h, u64x2_extmul_high_u32x4(k1, ri3));
        t6_l = u64x2_add(t6_l, u64x2_extmul_low_u32x4(k1, ri4));
        t6_h = u64x2_add(t6_h, u64x2_extmul_high_u32x4(k1, ri4));
        t7_l = u64x2_add(t7_l, u64x2_extmul_low_u32x4(k1, ri5));
        t7_h = u64x2_add(t7_h, u64x2_extmul_high_u32x4(k1, ri5));
        t8_l = u64x2_add(t8_l, u64x2_extmul_low_u32x4(k1, ri6));
        t8_h = u64x2_add(t8_h, u64x2_extmul_high_u32x4(k1, ri6));
        t9_l = u64x2_add(t9_l, u64x2_extmul_low_u32x4(k1, ri7));
        t9_h = u64x2_add(t9_h, u64x2_extmul_high_u32x4(k1, ri7));
        t10_l = u64x2_add(t10_l, u64x2_extmul_low_u32x4(k1, ri8));
        t10_h = u64x2_add(t10_h, u64x2_extmul_high_u32x4(k1, ri8));
        let kml = v128_and(t2_l, mask64);
        let kmh = v128_and(t2_h, mask64);
        let k2 = u32x4_shuffle::<0, 2, 4, 6>(kml, kmh);
        t3_l = u64x2_add(t3_l, u64x2_shr(t2_l, 29));
        t3_h = u64x2_add(t3_h, u64x2_shr(t2_h, 29));
        t3_l = u64x2_add(t3_l, u64x2_extmul_low_u32x4(k2, ri0));
        t3_h = u64x2_add(t3_h, u64x2_extmul_high_u32x4(k2, ri0));
        t4_l = u64x2_add(t4_l, u64x2_extmul_low_u32x4(k2, ri1));
        t4_h = u64x2_add(t4_h, u64x2_extmul_high_u32x4(k2, ri1));
        t5_l = u64x2_add(t5_l, u64x2_extmul_low_u32x4(k2, ri2));
        t5_h = u64x2_add(t5_h, u64x2_extmul_high_u32x4(k2, ri2));
        t6_l = u64x2_add(t6_l, u64x2_extmul_low_u32x4(k2, ri3));
        t6_h = u64x2_add(t6_h, u64x2_extmul_high_u32x4(k2, ri3));
        t7_l = u64x2_add(t7_l, u64x2_extmul_low_u32x4(k2, ri4));
        t7_h = u64x2_add(t7_h, u64x2_extmul_high_u32x4(k2, ri4));
        t8_l = u64x2_add(t8_l, u64x2_extmul_low_u32x4(k2, ri5));
        t8_h = u64x2_add(t8_h, u64x2_extmul_high_u32x4(k2, ri5));
        t9_l = u64x2_add(t9_l, u64x2_extmul_low_u32x4(k2, ri6));
        t9_h = u64x2_add(t9_h, u64x2_extmul_high_u32x4(k2, ri6));
        t10_l = u64x2_add(t10_l, u64x2_extmul_low_u32x4(k2, ri7));
        t10_h = u64x2_add(t10_h, u64x2_extmul_high_u32x4(k2, ri7));
        t11_l = u64x2_add(t11_l, u64x2_extmul_low_u32x4(k2, ri8));
        t11_h = u64x2_add(t11_h, u64x2_extmul_high_u32x4(k2, ri8));
        let kml = v128_and(t3_l, mask64);
        let kmh = v128_and(t3_h, mask64);
        let k3 = u32x4_shuffle::<0, 2, 4, 6>(kml, kmh);
        t4_l = u64x2_add(t4_l, u64x2_shr(t3_l, 29));
        t4_h = u64x2_add(t4_h, u64x2_shr(t3_h, 29));
        t4_l = u64x2_add(t4_l, u64x2_extmul_low_u32x4(k3, ri0));
        t4_h = u64x2_add(t4_h, u64x2_extmul_high_u32x4(k3, ri0));
        t5_l = u64x2_add(t5_l, u64x2_extmul_low_u32x4(k3, ri1));
        t5_h = u64x2_add(t5_h, u64x2_extmul_high_u32x4(k3, ri1));
        t6_l = u64x2_add(t6_l, u64x2_extmul_low_u32x4(k3, ri2));
        t6_h = u64x2_add(t6_h, u64x2_extmul_high_u32x4(k3, ri2));
        t7_l = u64x2_add(t7_l, u64x2_extmul_low_u32x4(k3, ri3));
        t7_h = u64x2_add(t7_h, u64x2_extmul_high_u32x4(k3, ri3));
        t8_l = u64x2_add(t8_l, u64x2_extmul_low_u32x4(k3, ri4));
        t8_h = u64x2_add(t8_h, u64x2_extmul_high_u32x4(k3, ri4));
        t9_l = u64x2_add(t9_l, u64x2_extmul_low_u32x4(k3, ri5));
        t9_h = u64x2_add(t9_h, u64x2_extmul_high_u32x4(k3, ri5));
        t10_l = u64x2_add(t10_l, u64x2_extmul_low_u32x4(k3, ri6));
        t10_h = u64x2_add(t10_h, u64x2_extmul_high_u32x4(k3, ri6));
        t11_l = u64x2_add(t11_l, u64x2_extmul_low_u32x4(k3, ri7));
        t11_h = u64x2_add(t11_h, u64x2_extmul_high_u32x4(k3, ri7));
        t12_l = u64x2_add(t12_l, u64x2_extmul_low_u32x4(k3, ri8));
        t12_h = u64x2_add(t12_h, u64x2_extmul_high_u32x4(k3, ri8));
        let kml = v128_and(t4_l, mask64);
        let kmh = v128_and(t4_h, mask64);
        let k4 = u32x4_shuffle::<0, 2, 4, 6>(kml, kmh);
        t5_l = u64x2_add(t5_l, u64x2_shr(t4_l, 29));
        t5_h = u64x2_add(t5_h, u64x2_shr(t4_h, 29));
        t5_l = u64x2_add(t5_l, u64x2_extmul_low_u32x4(k4, ri0));
        t5_h = u64x2_add(t5_h, u64x2_extmul_high_u32x4(k4, ri0));
        t6_l = u64x2_add(t6_l, u64x2_extmul_low_u32x4(k4, ri1));
        t6_h = u64x2_add(t6_h, u64x2_extmul_high_u32x4(k4, ri1));
        t7_l = u64x2_add(t7_l, u64x2_extmul_low_u32x4(k4, ri2));
        t7_h = u64x2_add(t7_h, u64x2_extmul_high_u32x4(k4, ri2));
        t8_l = u64x2_add(t8_l, u64x2_extmul_low_u32x4(k4, ri3));
        t8_h = u64x2_add(t8_h, u64x2_extmul_high_u32x4(k4, ri3));
        t9_l = u64x2_add(t9_l, u64x2_extmul_low_u32x4(k4, ri4));
        t9_h = u64x2_add(t9_h, u64x2_extmul_high_u32x4(k4, ri4));
        t10_l = u64x2_add(t10_l, u64x2_extmul_low_u32x4(k4, ri5));
        t10_h = u64x2_add(t10_h, u64x2_extmul_high_u32x4(k4, ri5));
        t11_l = u64x2_add(t11_l, u64x2_extmul_low_u32x4(k4, ri6));
        t11_h = u64x2_add(t11_h, u64x2_extmul_high_u32x4(k4, ri6));
        t12_l = u64x2_add(t12_l, u64x2_extmul_low_u32x4(k4, ri7));
        t12_h = u64x2_add(t12_h, u64x2_extmul_high_u32x4(k4, ri7));
        t13_l = u64x2_add(t13_l, u64x2_extmul_low_u32x4(k4, ri8));
        t13_h = u64x2_add(t13_h, u64x2_extmul_high_u32x4(k4, ri8));
        let kml = v128_and(t5_l, mask64);
        let kmh = v128_and(t5_h, mask64);
        let k5 = u32x4_shuffle::<0, 2, 4, 6>(kml, kmh);
        t6_l = u64x2_add(t6_l, u64x2_shr(t5_l, 29));
        t6_h = u64x2_add(t6_h, u64x2_shr(t5_h, 29));
        t6_l = u64x2_add(t6_l, u64x2_extmul_low_u32x4(k5, ri0));
        t6_h = u64x2_add(t6_h, u64x2_extmul_high_u32x4(k5, ri0));
        t7_l = u64x2_add(t7_l, u64x2_extmul_low_u32x4(k5, ri1));
        t7_h = u64x2_add(t7_h, u64x2_extmul_high_u32x4(k5, ri1));
        t8_l = u64x2_add(t8_l, u64x2_extmul_low_u32x4(k5, ri2));
        t8_h = u64x2_add(t8_h, u64x2_extmul_high_u32x4(k5, ri2));
        t9_l = u64x2_add(t9_l, u64x2_extmul_low_u32x4(k5, ri3));
        t9_h = u64x2_add(t9_h, u64x2_extmul_high_u32x4(k5, ri3));
        t10_l = u64x2_add(t10_l, u64x2_extmul_low_u32x4(k5, ri4));
        t10_h = u64x2_add(t10_h, u64x2_extmul_high_u32x4(k5, ri4));
        t11_l = u64x2_add(t11_l, u64x2_extmul_low_u32x4(k5, ri5));
        t11_h = u64x2_add(t11_h, u64x2_extmul_high_u32x4(k5, ri5));
        t12_l = u64x2_add(t12_l, u64x2_extmul_low_u32x4(k5, ri6));
        t12_h = u64x2_add(t12_h, u64x2_extmul_high_u32x4(k5, ri6));
        t13_l = u64x2_add(t13_l, u64x2_extmul_low_u32x4(k5, ri7));
        t13_h = u64x2_add(t13_h, u64x2_extmul_high_u32x4(k5, ri7));
        t14_l = u64x2_add(t14_l, u64x2_extmul_low_u32x4(k5, ri8));
        t14_h = u64x2_add(t14_h, u64x2_extmul_high_u32x4(k5, ri8));
        let kml = v128_and(t6_l, mask64);
        let kmh = v128_and(t6_h, mask64);
        let k6 = u32x4_shuffle::<0, 2, 4, 6>(kml, kmh);
        t7_l = u64x2_add(t7_l, u64x2_shr(t6_l, 29));
        t7_h = u64x2_add(t7_h, u64x2_shr(t6_h, 29));
        t7_l = u64x2_add(t7_l, u64x2_extmul_low_u32x4(k6, ri0));
        t7_h = u64x2_add(t7_h, u64x2_extmul_high_u32x4(k6, ri0));
        t8_l = u64x2_add(t8_l, u64x2_extmul_low_u32x4(k6, ri1));
        t8_h = u64x2_add(t8_h, u64x2_extmul_high_u32x4(k6, ri1));
        t9_l = u64x2_add(t9_l, u64x2_extmul_low_u32x4(k6, ri2));
        t9_h = u64x2_add(t9_h, u64x2_extmul_high_u32x4(k6, ri2));
        t10_l = u64x2_add(t10_l, u64x2_extmul_low_u32x4(k6, ri3));
        t10_h = u64x2_add(t10_h, u64x2_extmul_high_u32x4(k6, ri3));
        t11_l = u64x2_add(t11_l, u64x2_extmul_low_u32x4(k6, ri4));
        t11_h = u64x2_add(t11_h, u64x2_extmul_high_u32x4(k6, ri4));
        t12_l = u64x2_add(t12_l, u64x2_extmul_low_u32x4(k6, ri5));
        t12_h = u64x2_add(t12_h, u64x2_extmul_high_u32x4(k6, ri5));
        t13_l = u64x2_add(t13_l, u64x2_extmul_low_u32x4(k6, ri6));
        t13_h = u64x2_add(t13_h, u64x2_extmul_high_u32x4(k6, ri6));
        t14_l = u64x2_add(t14_l, u64x2_extmul_low_u32x4(k6, ri7));
        t14_h = u64x2_add(t14_h, u64x2_extmul_high_u32x4(k6, ri7));
        t15_l = u64x2_add(t15_l, u64x2_extmul_low_u32x4(k6, ri8));
        t15_h = u64x2_add(t15_h, u64x2_extmul_high_u32x4(k6, ri8));
        let kml = v128_and(t7_l, mask64);
        let kmh = v128_and(t7_h, mask64);
        let k7 = u32x4_shuffle::<0, 2, 4, 6>(kml, kmh);
        t8_l = u64x2_add(t8_l, u64x2_shr(t7_l, 29));
        t8_h = u64x2_add(t8_h, u64x2_shr(t7_h, 29));
        t8_l = u64x2_add(t8_l, u64x2_extmul_low_u32x4(k7, ri0));
        t8_h = u64x2_add(t8_h, u64x2_extmul_high_u32x4(k7, ri0));
        t9_l = u64x2_add(t9_l, u64x2_extmul_low_u32x4(k7, ri1));
        t9_h = u64x2_add(t9_h, u64x2_extmul_high_u32x4(k7, ri1));
        t10_l = u64x2_add(t10_l, u64x2_extmul_low_u32x4(k7, ri2));
        t10_h = u64x2_add(t10_h, u64x2_extmul_high_u32x4(k7, ri2));
        t11_l = u64x2_add(t11_l, u64x2_extmul_low_u32x4(k7, ri3));
        t11_h = u64x2_add(t11_h, u64x2_extmul_high_u32x4(k7, ri3));
        t12_l = u64x2_add(t12_l, u64x2_extmul_low_u32x4(k7, ri4));
        t12_h = u64x2_add(t12_h, u64x2_extmul_high_u32x4(k7, ri4));
        t13_l = u64x2_add(t13_l, u64x2_extmul_low_u32x4(k7, ri5));
        t13_h = u64x2_add(t13_h, u64x2_extmul_high_u32x4(k7, ri5));
        t14_l = u64x2_add(t14_l, u64x2_extmul_low_u32x4(k7, ri6));
        t14_h = u64x2_add(t14_h, u64x2_extmul_high_u32x4(k7, ri6));
        t15_l = u64x2_add(t15_l, u64x2_extmul_low_u32x4(k7, ri7));
        t15_h = u64x2_add(t15_h, u64x2_extmul_high_u32x4(k7, ri7));
        t16_l = u64x2_add(t16_l, u64x2_extmul_low_u32x4(k7, ri8));
        t16_h = u64x2_add(t16_h, u64x2_extmul_high_u32x4(k7, ri8));
        let kt = u32x4_shuffle::<0, 2, 4, 6>(v128_and(t8_l, mask64), v128_and(t8_h, mask64));
        let kl = v128_and(u64x2_extmul_low_u32x4(kt, invv), mask64);
        let kh = v128_and(u64x2_extmul_high_u32x4(kt, invv), mask64);
        let k8 = u32x4_shuffle::<0, 2, 4, 6>(kl, kh);
        t8_l = u64x2_add(t8_l, u64x2_extmul_low_u32x4(k8, p0));
        t8_h = u64x2_add(t8_h, u64x2_extmul_high_u32x4(k8, p0));
        t9_l = u64x2_add(t9_l, u64x2_extmul_low_u32x4(k8, p1));
        t9_h = u64x2_add(t9_h, u64x2_extmul_high_u32x4(k8, p1));
        t10_l = u64x2_add(t10_l, u64x2_extmul_low_u32x4(k8, p2));
        t10_h = u64x2_add(t10_h, u64x2_extmul_high_u32x4(k8, p2));
        t11_l = u64x2_add(t11_l, u64x2_extmul_low_u32x4(k8, p3));
        t11_h = u64x2_add(t11_h, u64x2_extmul_high_u32x4(k8, p3));
        t12_l = u64x2_add(t12_l, u64x2_extmul_low_u32x4(k8, p4));
        t12_h = u64x2_add(t12_h, u64x2_extmul_high_u32x4(k8, p4));
        t13_l = u64x2_add(t13_l, u64x2_extmul_low_u32x4(k8, p5));
        t13_h = u64x2_add(t13_h, u64x2_extmul_high_u32x4(k8, p5));
        t14_l = u64x2_add(t14_l, u64x2_extmul_low_u32x4(k8, p6));
        t14_h = u64x2_add(t14_h, u64x2_extmul_high_u32x4(k8, p6));
        t15_l = u64x2_add(t15_l, u64x2_extmul_low_u32x4(k8, p7));
        t15_h = u64x2_add(t15_h, u64x2_extmul_high_u32x4(k8, p7));
        t16_l = u64x2_add(t16_l, u64x2_extmul_low_u32x4(k8, p8));
        t16_h = u64x2_add(t16_h, u64x2_extmul_high_u32x4(k8, p8));
        t9_l = u64x2_add(t9_l, u64x2_shr(t8_l, 29));
        t9_h = u64x2_add(t9_h, u64x2_shr(t8_h, 29));
        let mut t17_l = u64x2(0, 0);
        let mut t17_h = u64x2(0, 0);
        t10_l = u64x2_add(t10_l, u64x2_shr(t9_l, 29));
        t9_l = v128_and(t9_l, mask64);
        t10_h = u64x2_add(t10_h, u64x2_shr(t9_h, 29));
        t9_h = v128_and(t9_h, mask64);
        t11_l = u64x2_add(t11_l, u64x2_shr(t10_l, 29));
        t10_l = v128_and(t10_l, mask64);
        t11_h = u64x2_add(t11_h, u64x2_shr(t10_h, 29));
        t10_h = v128_and(t10_h, mask64);
        t12_l = u64x2_add(t12_l, u64x2_shr(t11_l, 29));
        t11_l = v128_and(t11_l, mask64);
        t12_h = u64x2_add(t12_h, u64x2_shr(t11_h, 29));
        t11_h = v128_and(t11_h, mask64);
        t13_l = u64x2_add(t13_l, u64x2_shr(t12_l, 29));
        t12_l = v128_and(t12_l, mask64);
        t13_h = u64x2_add(t13_h, u64x2_shr(t12_h, 29));
        t12_h = v128_and(t12_h, mask64);
        t14_l = u64x2_add(t14_l, u64x2_shr(t13_l, 29));
        t13_l = v128_and(t13_l, mask64);
        t14_h = u64x2_add(t14_h, u64x2_shr(t13_h, 29));
        t13_h = v128_and(t13_h, mask64);
        t15_l = u64x2_add(t15_l, u64x2_shr(t14_l, 29));
        t14_l = v128_and(t14_l, mask64);
        t15_h = u64x2_add(t15_h, u64x2_shr(t14_h, 29));
        t14_h = v128_and(t14_h, mask64);
        t16_l = u64x2_add(t16_l, u64x2_shr(t15_l, 29));
        t15_l = v128_and(t15_l, mask64);
        t16_h = u64x2_add(t16_h, u64x2_shr(t15_h, 29));
        t15_h = v128_and(t15_h, mask64);
        t17_l = u64x2_add(t17_l, u64x2_shr(t16_l, 29));
        t16_l = v128_and(t16_l, mask64);
        t17_h = u64x2_add(t17_h, u64x2_shr(t16_h, 29));
        t16_h = v128_and(t16_h, mask64);
        QuadFp {
            limbs: [
                u32x4_shuffle::<0, 2, 4, 6>(t9_l, t9_h),
                u32x4_shuffle::<0, 2, 4, 6>(t10_l, t10_h),
                u32x4_shuffle::<0, 2, 4, 6>(t11_l, t11_h),
                u32x4_shuffle::<0, 2, 4, 6>(t12_l, t12_h),
                u32x4_shuffle::<0, 2, 4, 6>(t13_l, t13_h),
                u32x4_shuffle::<0, 2, 4, 6>(t14_l, t14_h),
                u32x4_shuffle::<0, 2, 4, 6>(t15_l, t15_h),
                u32x4_shuffle::<0, 2, 4, 6>(t16_l, t16_h),
                u32x4_shuffle::<0, 2, 4, 6>(t17_l, t17_h),
            ],
        }
    }
}

pub struct MontBackend<T: MontConfig<N>, const N: usize>(PhantomData<T>);

impl<T: MontConfig<N>, const N: usize> FpConfig<N> for MontBackend<T, N> {
    /// The modulus of the field.
    const MODULUS: crate::BigInt<N> = T::MODULUS;

    /// A multiplicative generator of the field.
    /// `Self::GENERATOR` is an element having multiplicative order
    /// `Self::MODULUS - 1`.
    const GENERATOR: Fp<Self, N> = T::GENERATOR;

    /// Additive identity of the field, i.e. the element `e`
    /// such that, for all elements `f` of the field, `e + f = f`.
    const ZERO: Fp<Self, N> = Fp::new_unchecked(BigInt([0u64; N]));

    /// Multiplicative identity of the field, i.e. the element `e`
    /// such that, for all elements `f` of the field, `e * f = f`.
    const ONE: Fp<Self, N> = Fp::new_unchecked(T::R);

    /// Negation of `Self::ONE`.
    const NEG_ONE: Fp<Self, N> = Fp::new_unchecked(Self::MODULUS.const_sub_with_borrow(&T::R).0);

    const TWO_ADICITY: u32 = Self::MODULUS.two_adic_valuation();
    const TWO_ADIC_ROOT_OF_UNITY: Fp<Self, N> = T::TWO_ADIC_ROOT_OF_UNITY;
    const SMALL_SUBGROUP_BASE: Option<u32> = T::SMALL_SUBGROUP_BASE;
    const SMALL_SUBGROUP_BASE_ADICITY: Option<u32> = T::SMALL_SUBGROUP_BASE_ADICITY;
    const LARGE_SUBGROUP_ROOT_OF_UNITY: Option<Fp<Self, N>> = T::LARGE_SUBGROUP_ROOT_OF_UNITY;
    const SQRT_PRECOMP: Option<crate::SqrtPrecomputation<Fp<Self, N>>> = T::SQRT_PRECOMP;

    #[inline(always)]
    fn add_assign(a: &mut Fp<Self, N>, b: &Fp<Self, N>) {
        T::add_assign(a, b)
    }

    #[inline(always)]
    fn sub_assign(a: &mut Fp<Self, N>, b: &Fp<Self, N>) {
        T::sub_assign(a, b)
    }

    fn double_in_place(a: &mut Fp<Self, N>) {
        T::double_in_place(a)
    }

    fn neg_in_place(a: &mut Fp<Self, N>) {
        T::neg_in_place(a)
    }

    /// This modular multiplication algorithm uses Montgomery
    /// reduction for efficient implementation. It also additionally
    /// uses the "no-carry optimization" outlined
    /// [here](https://hackmd.io/@zkteam/modular_multiplication) if
    /// `P::MODULUS` has (a) a non-zero MSB, and (b) at least one
    /// zero bit in the rest of the modulus.
    #[inline(always)]
    fn mul_assign(a: &mut Fp<Self, N>, b: &Fp<Self, N>) {
        // wasm: bb-style per-call 29-bit-limb Montgomery in the unchanged 2^256 domain — the
        // derive-generated T::mul_assign compiles to carry-heavy 32-bit pieces on wasm.
        #[cfg(target_family = "wasm")]
        if N == 4 && T::MODULUS_HAS_SPARE_BIT {
            let av: [u64; 4] = a.0 .0[..4].try_into().unwrap();
            let bv: [u64; 4] = b.0 .0[..4].try_into().unwrap();
            let m: [u64; 4] = const { first4::<T, N>() };
            let p29: [u64; 9] = const { wasm_mont::to29(&first4::<T, N>()) };
            let inv: u64 = const { wasm_mont::inv29(wasm_mont::to29(&first4::<T, N>())[0]) };
            let r = wasm_mont::mont_mul_256(&av, &bv, &m, &p29, inv);
            a.0 .0[..4].copy_from_slice(&r);
            return;
        }
        T::mul_assign(a, b)
    }

    fn sum_of_products<const M: usize>(a: &[Fp<Self, N>; M], b: &[Fp<Self, N>; M]) -> Fp<Self, N> {
        T::sum_of_products(a, b)
    }

    #[inline(always)]
    fn square_in_place(a: &mut Fp<Self, N>) {
        #[cfg(target_family = "wasm")]
        if N == 4 && T::MODULUS_HAS_SPARE_BIT {
            let av: [u64; 4] = a.0 .0[..4].try_into().unwrap();
            let m: [u64; 4] = const { first4::<T, N>() };
            let p29: [u64; 9] = const { wasm_mont::to29(&first4::<T, N>()) };
            let inv: u64 = const { wasm_mont::inv29(wasm_mont::to29(&first4::<T, N>())[0]) };
            let r = wasm_mont::mont_mul_256(&av, &av, &m, &p29, inv);
            a.0 .0[..4].copy_from_slice(&r);
            return;
        }
        T::square_in_place(a)
    }

    fn inverse(a: &Fp<Self, N>) -> Option<Fp<Self, N>> {
        T::inverse(a)
    }

    fn from_bigint(r: BigInt<N>) -> Option<Fp<Self, N>> {
        T::from_bigint(r)
    }

    #[inline]
    fn into_bigint(a: Fp<Self, N>) -> BigInt<N> {
        T::into_bigint(a)
    }
}

impl<T: MontConfig<N>, const N: usize> Fp<MontBackend<T, N>, N> {
    #[doc(hidden)]
    pub const R: BigInt<N> = T::R;
    #[doc(hidden)]
    pub const R2: BigInt<N> = T::R2;
    #[doc(hidden)]
    pub const INV: u64 = T::INV;

    /// Construct a new field element from its underlying
    /// [`struct@BigInt`] data type.
    #[inline]
    pub const fn new(element: BigInt<N>) -> Self {
        let mut r = Self(element, PhantomData);
        if r.const_is_zero() {
            r
        } else {
            r = r.mul(&Fp(T::R2, PhantomData));
            r
        }
    }

    /// Construct a new field element from its underlying
    /// [`struct@BigInt`] data type.
    ///
    /// Unlike [`Self::new`], this method does not perform Montgomery reduction.
    /// Thus, this method should be used only when constructing
    /// an element from an integer that has already been put in
    /// Montgomery form.
    #[inline]
    pub const fn new_unchecked(element: BigInt<N>) -> Self {
        Self(element, PhantomData)
    }

    const fn const_is_zero(&self) -> bool {
        self.0.const_is_zero()
    }

    #[doc(hidden)]
    const fn const_neg(self) -> Self {
        if !self.const_is_zero() {
            Self::new_unchecked(Self::sub_with_borrow(&T::MODULUS, &self.0))
        } else {
            self
        }
    }

    /// Interpret a set of limbs (along with a sign) as a field element.
    /// For *internal* use only; please use the `ark_ff::MontFp` macro instead
    /// of this method
    #[doc(hidden)]
    pub const fn from_sign_and_limbs(is_positive: bool, limbs: &[u64]) -> Self {
        let mut repr = BigInt([0; N]);
        assert!(limbs.len() <= N);
        crate::const_for!((i in 0..(limbs.len())) {
            repr.0[i] = limbs[i];
        });
        let res = Self::new(repr);
        if is_positive {
            res
        } else {
            res.const_neg()
        }
    }

    const fn mul_without_cond_subtract(mut self, other: &Self) -> (bool, Self) {
        let (mut lo, mut hi) = ([0u64; N], [0u64; N]);
        crate::const_for!((i in 0..N) {
            let mut carry = 0;
            crate::const_for!((j in 0..N) {
                let k = i + j;
                if k >= N {
                    hi[k - N] = fa::mac_with_carry(hi[k - N], (self.0).0[i], (other.0).0[j], &mut carry);
                } else {
                    lo[k] = fa::mac_with_carry(lo[k], (self.0).0[i], (other.0).0[j], &mut carry);
                }
            });
            hi[i] = carry;
        });
        // Montgomery reduction
        let mut carry2 = 0;
        crate::const_for!((i in 0..N) {
            let tmp = lo[i].wrapping_mul(T::INV);
            let mut carry = 0;
            fa::mac(lo[i], tmp, T::MODULUS.0[0], &mut carry);
            crate::const_for!((j in 1..N) {
                let k = i + j;
                if k >= N {
                    hi[k - N] = fa::mac_with_carry(hi[k - N], tmp, T::MODULUS.0[j], &mut carry);
                }  else {
                    lo[k] = fa::mac_with_carry(lo[k], tmp, T::MODULUS.0[j], &mut carry);
                }
            });
            carry2 = fa::adc(&mut hi[i], carry, carry2);
        });

        crate::const_for!((i in 0..N) {
            (self.0).0[i] = hi[i];
        });
        (carry2 != 0, self)
    }

    const fn mul(self, other: &Self) -> Self {
        let (carry, res) = self.mul_without_cond_subtract(other);
        if T::MODULUS_HAS_SPARE_BIT {
            res.const_subtract_modulus()
        } else {
            res.const_subtract_modulus_with_carry(carry)
        }
    }

    const fn const_is_valid(&self) -> bool {
        crate::const_for!((i in 0..N) {
            if (self.0).0[N - i - 1] < T::MODULUS.0[N - i - 1] {
                return true
            } else if (self.0).0[N - i - 1] > T::MODULUS.0[N - i - 1] {
                return false
            }
        });
        false
    }

    #[inline]
    const fn const_subtract_modulus(mut self) -> Self {
        if !self.const_is_valid() {
            self.0 = Self::sub_with_borrow(&self.0, &T::MODULUS);
        }
        self
    }

    #[inline]
    const fn const_subtract_modulus_with_carry(mut self, carry: bool) -> Self {
        if carry || !self.const_is_valid() {
            self.0 = Self::sub_with_borrow(&self.0, &T::MODULUS);
        }
        self
    }

    const fn sub_with_borrow(a: &BigInt<N>, b: &BigInt<N>) -> BigInt<N> {
        a.const_sub_with_borrow(b).0
    }
}

#[cfg(test)]
mod test {
    use ark_std::{str::FromStr, vec::*};
    use ark_test_curves::secp256k1::Fr;
    use num_bigint::{BigInt, BigUint, Sign};

    #[test]
    fn test_mont_macro_correctness() {
        let (is_positive, limbs) =
            str_to_limbs_u64("111192936301596926984056301862066282284536849596023571352007112326586892541694");
        let t = Fr::from_sign_and_limbs(is_positive, &limbs);

        let result: BigUint = t.into();
        let expected =
            BigUint::from_str("111192936301596926984056301862066282284536849596023571352007112326586892541694")
                .unwrap();

        assert_eq!(result, expected);
    }

    fn str_to_limbs_u64(num: &str) -> (bool, Vec<u64>) {
        let (sign, digits) = BigInt::from_str(num)
            .expect("could not parse to bigint")
            .to_radix_le(16);
        let limbs = digits
            .chunks(16)
            .map(|chunk| {
                let mut this = 0u64;
                for (i, hexit) in chunk.iter().enumerate() {
                    this += (*hexit as u64) << (4 * i);
                }
                this
            })
            .collect::<Vec<_>>();

        let sign_is_positive = sign != Sign::Minus;
        (sign_is_positive, limbs)
    }
}
