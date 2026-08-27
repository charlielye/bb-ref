//! The two secp256r1-specific scalar multiplications of the ECDSA circuit (bb
//! `biggroup_secp256r1.hpp`): `u₁·G` through the fixed-base plookup tables and `u₂·Q` through a
//! prover-supplied hint checked by a "fake GLV" two-point MSM.

use super::bigfield::NUM_LIMB_BITS;
use super::biggroup::{Element, Scalar};
use super::bool::BoolT;
use super::field::FieldT;
use super::plookup::read_accumulators;
use crate::base::field::{from_u256, U256};
use crate::base::Fr;
use crate::circuit::plookup::{MultiTableId, ReadData};
use crate::circuit::secp256r1_fixed_base as tables;
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_secp256r1::Config;
use num_bigint::BigUint;

type Fq = super::biggroup::Fq<Config>;
type P256 = Element<Config>;

/// bb `compute_secp256r1_fake_glv_decomposition`: extended Euclid on `(n, s)` until the remainder
/// drops below 2¹²⁸, giving `(α, |β|, β < 0)` with `β·s ≡ α (mod n)`.
fn fake_glv_decomposition(s: &BigUint) -> (BigUint, BigUint, bool) {
    let n: BigUint = ark_secp256r1::Fr::MODULUS.into();
    let half_n = &n >> 1;
    let bound = BigUint::from(1u64) << 128;
    let (mut u_prev, mut u_curr) = (n.clone(), s.clone());
    let (mut v_prev, mut v_curr) = (BigUint::from(0u64), BigUint::from(1u64));
    while u_curr >= bound && u_curr != BigUint::from(0u64) {
        let q = &u_prev / &u_curr;
        let u_next = &u_prev - &q * &u_curr;
        let v_next = (&v_prev + &n - (&q % &n) * &v_curr % &n) % &n;
        u_prev = u_curr;
        v_prev = v_curr;
        u_curr = u_next;
        v_curr = v_next;
    }
    if v_curr <= half_n {
        (u_curr, v_curr, false)
    } else {
        (u_curr, &n - v_curr, true)
    }
}

impl P256 {
    /// bb `secp256r1_fixed_base_mul`: `u·G` as a chain-add of 38 table reads minus the constant
    /// table offset.
    pub fn secp256r1_fixed_base_mul(u: &Scalar<Config>) -> Self {
        let limb_shift = FieldT::constant(from_u256(U256::from(1u64) << NUM_LIMB_BITS as u32));
        let u_low = u.get_limb(0).element.add(&u.get_limb(1).element.mul(&limb_shift));
        let u_high = u.get_limb(2).element.add(&u.get_limb(3).element.mul(&limb_shift));
        let read = |axis: u8, is_lo: bool| {
            read_accumulators(
                MultiTableId::Secp256r1FixedBase { axis, is_lo },
                if is_lo { &u_low } else { &u_high },
            )
        };
        let xlo_lo = read(0, true);
        let xlo_hi = read(0, false);
        let xhi_lo = read(1, true);
        let xhi_hi = read(1, false);
        let ylo_lo = read(2, true);
        let ylo_hi = read(2, false);
        let yhi_lo = read(3, true);
        let yhi_hi = read(3, false);
        let build_element = |xlo: &ReadData<FieldT>,
                             xhi: &ReadData<FieldT>,
                             ylo: &ReadData<FieldT>,
                             yhi: &ReadData<FieldT>,
                             j: usize| {
            let x = Fq::unsafe_construct_from_limbs(
                &xlo.columns[1][j],
                &xlo.columns[2][j],
                &xhi.columns[1][j],
                &xhi.columns[2][j],
                false,
            );
            let y = Fq::unsafe_construct_from_limbs(
                &ylo.columns[1][j],
                &ylo.columns[2][j],
                &yhi.columns[1][j],
                &yhi.columns[2][j],
                false,
            );
            Self::new(x, y, false)
        };
        let mut looked_up = Vec::with_capacity(tables::NUM_WINDOWS);
        for j in 0..tables::NUM_WINDOWS_LO {
            looked_up.push(build_element(&xlo_lo, &xhi_lo, &ylo_lo, &yhi_lo, j));
        }
        for j in 0..tables::NUM_WINDOWS_HI {
            looked_up.push(build_element(&xlo_hi, &xhi_hi, &ylo_hi, &yhi_hi, j));
        }
        let mut chain = Self::chain_add_start(&looked_up[0], &looked_up[1]);
        for point in &looked_up[2..] {
            chain = Self::chain_add(point, &chain);
        }
        let raw_result = Self::chain_add_end(&chain);
        let offset_correction = Self::constant_point(None, &tables::total_offset());
        raw_result.sub(&offset_correction)
    }

    /// bb `secp256r1_ecdsa_mul`: `u₁·G + u₂·Q` with the second term proven by fake GLV; the flag is
    /// false when `u₂ ∈ {0, ±1}`, where the substituted scalar makes the result wrong.
    pub fn secp256r1_ecdsa_mul(pubkey: &Self, u1: &Scalar<Config>, u2: &Scalar<Config>) -> (Self, BoolT) {
        let ctx = pubkey.ctx().expect("secp256r1_ecdsa_mul: constant public key");
        let t1 = Self::secp256r1_fixed_base_mul(u1);
        let neg_one = Scalar::<Config>::one().neg();
        let u2_is_degenerate = u2
            .eq(&Scalar::<Config>::zero())
            .or(&u2.eq(&Scalar::<Config>::one()))
            .or(&u2.eq(&neg_one));
        let u2_safe = Scalar::<Config>::conditional_assign(&u2_is_degenerate, &Scalar::<Config>::from_u64(2), u2);

        let n: BigUint = ark_secp256r1::Fr::MODULUS.into();
        let u2_n = u2_safe.get_value() % &n;
        let t2_native = (pubkey.get_value() * ark_secp256r1::Fr::from(u2_n.clone())).into_affine();
        let (alpha, beta_abs, beta_is_negative) = fake_glv_decomposition(&u2_n);

        let alpha2_field = FieldT::from_witness(&ctx, Fr::from(alpha));
        let beta2_abs_field = FieldT::from_witness(&ctx, Fr::from(beta_abs));
        alpha2_field.create_range_constraint(128);
        beta2_abs_field.create_range_constraint(128);
        beta2_abs_field.assert_is_not_zero();
        let beta2_neg = BoolT::from_witness(&ctx, beta_is_negative);
        let zero_idx = ctx.borrow().zero_idx();
        let zero_witness = FieldT::from_witness_index(&ctx, zero_idx);
        let alpha2_fr = Scalar::<Config>::from_halves(&alpha2_field, &zero_witness, false, 0);
        let beta2_abs_fr = Scalar::<Config>::from_halves(&beta2_abs_field, &zero_witness, false, 0);
        let neg_beta2_fr = beta2_abs_fr.neg();
        let beta2_signed_fr = Scalar::<Config>::conditional_assign(&beta2_neg, &neg_beta2_fr, &beta2_abs_fr);
        beta2_signed_fr.mul(&u2_safe).assert_equal(&alpha2_fr);

        let t2 = Self::from_witness(&ctx, &t2_native);
        t2.is_point_at_infinity().assert_equal(&BoolT::constant(false));
        let t2_neg = t2.neg();
        let t2_msm = t2_neg.conditional_select(&t2, &beta2_neg);
        let msm = Self::batch_mul(&[pubkey.clone(), t2_msm], &[alpha2_fr, beta2_abs_fr], 128, false);
        msm.is_point_at_infinity().assert_equal(&BoolT::constant(true));
        (t1.add(&t2), u2_is_degenerate.not())
    }
}
