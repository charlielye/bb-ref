//! In-circuit ECDSA verification over secp256r1 (bb `stdlib/encryption/ecdsa/ecdsa_impl.hpp`):
//! every input-validity condition becomes a bool folded into the result instead of a constraint,
//! and invalid inputs are swapped for valid ones so witness generation never fails.

use super::biggroup::{Element, Scalar};
use super::bool::BoolT;
use super::byte_array::ByteArray;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use ark_secp256r1::Config;
use num_bigint::BigUint;

type Fq = super::biggroup::Fq<Config>;
type Fr = Scalar<Config>;
type P256 = Element<Config>;

/// `2·G` as a constant point (bb's stand-in for invalid public keys).
fn double_generator() -> P256 {
    let two_g = (ark_secp256r1::Affine::generator() + ark_secp256r1::Affine::generator()).into_affine();
    P256::constant_point(None, &two_g)
}

/// bb `ecdsa_verify_signature<secp256r1>`: `r`, `s` and the hashed message are 32-byte big-endian
/// strings; returns whether the signature is valid under `public_key`.
pub fn ecdsa_verify_signature(hashed_message: &ByteArray, public_key: &P256, r: &ByteArray, s: &ByteArray) -> BoolT {
    let fq_modulus: BigUint = ark_secp256r1::Fq::MODULUS.into();
    let fr_modulus: BigUint = ark_secp256r1::Fr::MODULUS.into();
    let z = Fr::from_bytes(hashed_message);
    let is_x_less_than_modulus = public_key.x().is_less_than(&fq_modulus);
    let is_y_less_than_modulus = public_key.y().is_less_than(&fq_modulus);
    let is_point_at_infinity = public_key.is_point_at_infinity();
    let double_generator = double_generator();
    let corrected_public_key = P256::conditional_assign(
        &is_point_at_infinity
            .or(&is_x_less_than_modulus.not())
            .or(&is_y_less_than_modulus.not()),
        &double_generator,
        public_key,
    );
    let is_point_on_curve = corrected_public_key.validate_on_curve(false).eq(&Fq::zero());
    let r = Fr::from_bytes(r);
    let is_r_in_range = r.is_less_than(&fr_modulus);
    let is_r_zero = r.eq(&Fr::zero());
    let s = Fr::from_bytes(s);
    let is_s_in_range = s.is_less_than(&((&fr_modulus + 1u64) / 2u64));
    let is_s_zero = s.eq(&Fr::zero());
    let corrected_s = Fr::conditional_assign(&is_s_zero, &Fr::one(), &s);
    let u1 = z.div_without_denominator_check(&corrected_s);
    let u2 = r.div_without_denominator_check(&corrected_s);
    let fake_glv_pubkey = P256::conditional_assign(&is_point_on_curve.not(), &double_generator, &corrected_public_key);
    let (result, is_u2_acceptable) = P256::secp256r1_ecdsa_mul(&fake_glv_pubkey, &u1, &u2);
    let result_is_infinity = result.is_point_at_infinity();
    result.x().reduce_mod_target_modulus();
    let x = result.x();
    let result_x_mod_r = Fr::unsafe_construct_from_limbs(
        &x.get_limb(0).element,
        &x.get_limb(1).element,
        &x.get_limb(2).element,
        &x.get_limb(3).element,
        false,
    );
    for idx in 0..4 {
        result_x_mod_r.set_limb_max(idx, x.get_limb(idx).maximum_value);
    }
    let x_matches = result_x_mod_r.eq(&r);
    x_matches
        .and(&is_point_at_infinity.not())
        .and(&result_is_infinity.not())
        .and(&is_r_in_range)
        .and(&is_r_zero.not())
        .and(&is_s_in_range)
        .and(&is_s_zero.not())
        .and(&is_point_on_curve)
        .and(&is_x_less_than_modulus)
        .and(&is_y_less_than_modulus)
        .and(&is_u2_acceptable)
}

mod k1 {
    use super::super::biggroup::{Element, Fq as FqOf, Scalar};
    use super::super::biggroup_secp256k1::secp256k1_ecdsa_mul;
    use super::super::bool::BoolT;
    use super::super::byte_array::ByteArray;
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_ff::PrimeField;
    use ark_secp256k1::Config;
    use num_bigint::BigUint;

    type Fq = FqOf<Config>;
    type Fr = Scalar<Config>;
    type K1 = Element<Config>;

    fn double_generator() -> K1 {
        let two_g = (ark_secp256k1::Affine::generator() + ark_secp256k1::Affine::generator()).into_affine();
        K1::constant_point(None, &two_g)
    }

    /// bb `ecdsa_verify_signature<secp256k1>`: the shared verification body with the k1
    /// endomorphism multiplication (no fake-GLV substitution, no u2 restriction).
    pub fn ecdsa_verify_signature_secp256k1(
        hashed_message: &ByteArray,
        public_key: &K1,
        r: &ByteArray,
        s: &ByteArray,
    ) -> BoolT {
        let fq_modulus: BigUint = ark_secp256k1::Fq::MODULUS.into();
        let fr_modulus: BigUint = ark_secp256k1::Fr::MODULUS.into();
        let z = Fr::from_bytes(hashed_message);
        let is_x_less_than_modulus = public_key.x().is_less_than(&fq_modulus);
        let is_y_less_than_modulus = public_key.y().is_less_than(&fq_modulus);
        let is_point_at_infinity = public_key.is_point_at_infinity();
        let double_generator = double_generator();
        let corrected_public_key = K1::conditional_assign(
            &is_point_at_infinity
                .or(&is_x_less_than_modulus.not())
                .or(&is_y_less_than_modulus.not()),
            &double_generator,
            public_key,
        );
        let is_point_on_curve = corrected_public_key.validate_on_curve(false).eq(&Fq::zero());
        let r = Fr::from_bytes(r);
        let is_r_in_range = r.is_less_than(&fr_modulus);
        let is_r_zero = r.eq(&Fr::zero());
        let s = Fr::from_bytes(s);
        let is_s_in_range = s.is_less_than(&((&fr_modulus + 1u64) / 2u64));
        let is_s_zero = s.eq(&Fr::zero());
        let corrected_s = Fr::conditional_assign(&is_s_zero, &Fr::one(), &s);
        let u1 = z.div_without_denominator_check(&corrected_s);
        let u2 = r.div_without_denominator_check(&corrected_s);
        let result = secp256k1_ecdsa_mul(&corrected_public_key, &u1, &u2);
        let result_is_infinity = result.is_point_at_infinity();
        result.x().reduce_mod_target_modulus();
        let x = result.x();
        let result_x_mod_r = Fr::unsafe_construct_from_limbs(
            &x.get_limb(0).element,
            &x.get_limb(1).element,
            &x.get_limb(2).element,
            &x.get_limb(3).element,
            false,
        );
        for idx in 0..4 {
            result_x_mod_r.set_limb_max(idx, x.get_limb(idx).maximum_value);
        }
        let x_matches = result_x_mod_r.eq(&r);
        x_matches
            .and(&is_point_at_infinity.not())
            .and(&result_is_infinity.not())
            .and(&is_r_in_range)
            .and(&is_r_zero.not())
            .and(&is_s_in_range)
            .and(&is_s_zero.not())
            .and(&is_point_on_curve)
            .and(&is_x_less_than_modulus)
            .and(&is_y_less_than_modulus)
    }
}
pub use k1::ecdsa_verify_signature_secp256k1;
