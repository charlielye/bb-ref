//! In-circuit ECDSA verification over secp256r1 and secp256k1 (bb
//! `stdlib/encryption/ecdsa/ecdsa_impl.hpp`): every input-validity condition becomes a bool folded
//! into the result instead of a constraint, and invalid inputs are swapped for valid ones so
//! witness generation never fails.

use super::biggroup::{BigGroupCurve, Element, Fq, Scalar};
use super::biggroup_secp256k1::secp256k1_ecdsa_mul;
use super::bool::BoolT;
use super::byte_array::ByteArray;
use ark_ec::short_weierstrass::Affine;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use num_bigint::BigUint;

/// bb `ecdsa_verify_signature<secp256r1>`: `r`, `s` and the hashed message are 32-byte big-endian
/// strings; returns whether the signature is valid under `public_key`.
pub fn ecdsa_verify_signature(
    hashed_message: &ByteArray,
    public_key: &Element<ark_secp256r1::Config>,
    r: &ByteArray,
    s: &ByteArray,
) -> BoolT {
    verify(hashed_message, public_key, r, s, |key, on_curve, double_generator, u1, u2| {
        let fake_glv_pubkey = Element::conditional_assign(&on_curve.not(), double_generator, key);
        let (result, is_u2_acceptable) = Element::secp256r1_ecdsa_mul(&fake_glv_pubkey, u1, u2);
        (result, Some(is_u2_acceptable))
    })
}

/// bb `ecdsa_verify_signature<secp256k1>`: the k1 endomorphism multiplication (no fake-GLV
/// substitution, no u2 restriction).
pub fn ecdsa_verify_signature_secp256k1(
    hashed_message: &ByteArray,
    public_key: &Element<ark_secp256k1::Config>,
    r: &ByteArray,
    s: &ByteArray,
) -> BoolT {
    verify(hashed_message, public_key, r, s, |key, _, _, u1, u2| (secp256k1_ecdsa_mul(key, u1, u2), None))
}

/// The shared body; `mul(corrected key, is on curve, 2·G, u1, u2)` computes `u1·G + u2·key` and
/// any extra validity bit of its own.
fn verify<C: BigGroupCurve>(
    hashed_message: &ByteArray,
    public_key: &Element<C>,
    r: &ByteArray,
    s: &ByteArray,
    mul: impl FnOnce(&Element<C>, &BoolT, &Element<C>, &Scalar<C>, &Scalar<C>) -> (Element<C>, Option<BoolT>),
) -> BoolT {
    let fq_modulus: BigUint = C::BaseField::MODULUS.into();
    let fr_modulus: BigUint = C::ScalarField::MODULUS.into();
    let z = Scalar::<C>::from_bytes(hashed_message);
    let is_x_less_than_modulus = public_key.x().is_less_than(&fq_modulus);
    let is_y_less_than_modulus = public_key.y().is_less_than(&fq_modulus);
    let is_point_at_infinity = public_key.is_point_at_infinity();
    // `2·G` as a constant point: bb's stand-in for invalid public keys.
    let g = Affine::<C>::generator();
    let double_generator = Element::constant_point(None, &(g + g).into_affine());
    let corrected_public_key = Element::conditional_assign(
        &is_point_at_infinity
            .or(&is_x_less_than_modulus.not())
            .or(&is_y_less_than_modulus.not()),
        &double_generator,
        public_key,
    );
    let is_point_on_curve = corrected_public_key.validate_on_curve(false).eq(&Fq::<C>::zero());
    let r = Scalar::<C>::from_bytes(r);
    let is_r_in_range = r.is_less_than(&fr_modulus);
    let is_r_zero = r.eq(&Scalar::<C>::zero());
    let s = Scalar::<C>::from_bytes(s);
    let is_s_in_range = s.is_less_than(&((&fr_modulus + 1u64) / 2u64));
    let is_s_zero = s.eq(&Scalar::<C>::zero());
    let corrected_s = Scalar::<C>::conditional_assign(&is_s_zero, &Scalar::<C>::one(), &s);
    let u1 = z.div_without_denominator_check(&corrected_s);
    let u2 = r.div_without_denominator_check(&corrected_s);
    let (result, mul_ok) = mul(&corrected_public_key, &is_point_on_curve, &double_generator, &u1, &u2);
    let result_is_infinity = result.is_point_at_infinity();
    result.x().reduce_mod_target_modulus();
    let x = result.x();
    let result_x_mod_r = Scalar::<C>::unsafe_construct_from_limbs(
        &x.get_limb(0).element,
        &x.get_limb(1).element,
        &x.get_limb(2).element,
        &x.get_limb(3).element,
        false,
    );
    for idx in 0..4 {
        result_x_mod_r.set_limb_max(idx, x.get_limb(idx).maximum_value);
    }
    let valid = result_x_mod_r
        .eq(&r)
        .and(&is_point_at_infinity.not())
        .and(&result_is_infinity.not())
        .and(&is_r_in_range)
        .and(&is_r_zero.not())
        .and(&is_s_in_range)
        .and(&is_s_zero.not())
        .and(&is_point_on_curve)
        .and(&is_x_less_than_modulus)
        .and(&is_y_less_than_modulus);
    match mul_ok {
        Some(ok) => valid.and(&ok),
        None => valid,
    }
}
