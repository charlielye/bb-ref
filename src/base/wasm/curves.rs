//! BN254 G1 and Grumpkin over bb-ref's own field types (`field.rs` on wasm, `adx.rs` on x86-64).
//! The constants are arkworks' (`ark-bn254`/`ark-grumpkin` 0.6); every other target uses those
//! crates' configs directly (see `base/wasm/mod.rs`), so the point types there are exactly arkworks'.

use crate::base::{Fq, Fr};
use ark_ec::models::CurveConfig;
use ark_ec::scalar_mul::glv::GLVConfig;
use ark_ec::short_weierstrass::{Affine, Projective, SWCurveConfig};
use ark_ff::{AdditiveGroup, BigInt, Field, MontFp, PrimeField, Zero};

#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct G1Config;

impl CurveConfig for G1Config {
    type BaseField = Fq;
    type ScalarField = Fr;
    const COFACTOR: &'static [u64] = &[0x1];
    const COFACTOR_INV: Fr = Fr::ONE;
}

impl SWCurveConfig for G1Config {
    const COEFF_A: Fq = Fq::ZERO;
    const COEFF_B: Fq = MontFp!("3");
    const GENERATOR: Affine<Self> = Affine::new_unchecked(Fq::ONE, MontFp!("2"));
    type ZeroFlag = ();

    #[inline(always)]
    fn mul_by_a(_: Fq) -> Fq {
        Fq::zero()
    }

    #[inline]
    fn mul_projective(p: &Projective<Self>, scalar: &[u64]) -> Projective<Self> {
        let s = Fr::from_sign_and_limbs(true, scalar);
        GLVConfig::glv_mul_projective(*p, s)
    }

    #[inline]
    fn is_in_correct_subgroup_assuming_on_curve(_: &Affine<Self>) -> bool {
        true
    }
}

impl GLVConfig for G1Config {
    const ENDO_COEFFS: &'static [Fq] = &[MontFp!(
        "21888242871839275220042445260109153167277707414472061641714758635765020556616"
    )];
    const LAMBDA: Fr = MontFp!("21888242871839275217838484774961031246154997185409878258781734729429964517155");
    const SCALAR_DECOMP_COEFFS: [(bool, <Fr as PrimeField>::BigInt); 4] = [
        (false, BigInt!("147946756881789319000765030803803410728")),
        (true, BigInt!("9931322734385697763")),
        (false, BigInt!("9931322734385697763")),
        (false, BigInt!("147946756881789319010696353538189108491")),
    ];

    fn endomorphism(p: &Projective<Self>) -> Projective<Self> {
        let mut res = *p;
        res.x *= Self::ENDO_COEFFS[0];
        res
    }

    fn endomorphism_affine(p: &Affine<Self>) -> Affine<Self> {
        let mut res = *p;
        res.x *= Self::ENDO_COEFFS[0];
        res
    }
}

#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct GrumpkinConfig;

impl CurveConfig for GrumpkinConfig {
    type BaseField = Fr;
    type ScalarField = Fq;
    const COFACTOR: &'static [u64] = &[0x1];
    const COFACTOR_INV: Fq = Fq::ONE;
}

impl SWCurveConfig for GrumpkinConfig {
    const COEFF_A: Fr = Fr::ZERO;
    const COEFF_B: Fr = MontFp!("-17");
    const GENERATOR: Affine<Self> = Affine::new_unchecked(
        MontFp!("1"),
        MontFp!("17631683881184975370165255887551781615748388533673675138860"),
    );
    type ZeroFlag = ();

    #[inline(always)]
    fn mul_by_a(_: Fr) -> Fr {
        Fr::zero()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_ff::UniformRand;

    fn canon<F: PrimeField<BigInt = BigInt<4>>>(f: F) -> BigInt<4> {
        f.into_bigint()
    }

    #[test]
    fn generators_match_arkworks_and_lie_on_curve() {
        let g = Affine::<G1Config>::generator();
        let a = ark_bn254::G1Affine::generator();
        assert_eq!(canon(g.x), canon(a.x));
        assert_eq!(canon(g.y), canon(a.y));
        assert!(g.is_on_curve());
        let g = Affine::<GrumpkinConfig>::generator();
        let a = ark_grumpkin::Affine::generator();
        assert_eq!(canon(g.x), canon(a.x));
        assert_eq!(canon(g.y), canon(a.y));
        assert!(g.is_on_curve());
        assert_eq!(
            canon(<G1Config as SWCurveConfig>::COEFF_B),
            canon(<ark_bn254::g1::Config as SWCurveConfig>::COEFF_B)
        );
        assert_eq!(
            canon(<GrumpkinConfig as SWCurveConfig>::COEFF_B),
            canon(<ark_grumpkin::GrumpkinConfig as SWCurveConfig>::COEFF_B)
        );
    }

    #[test]
    fn scalar_multiplication_matches_arkworks() {
        let mut rng = ark_std::test_rng();
        for _ in 0..20 {
            let s = ark_bn254::Fr::rand(&mut rng);
            let ours = (Affine::<G1Config>::generator() * Fr::from_bigint(s.into_bigint()).unwrap()).into_affine();
            let theirs = (ark_bn254::G1Affine::generator() * s).into_affine();
            assert_eq!(canon(ours.x), canon(theirs.x));
            assert_eq!(canon(ours.y), canon(theirs.y));
            let s = ark_grumpkin::Fr::rand(&mut rng);
            let ours =
                (Affine::<GrumpkinConfig>::generator() * Fq::from_bigint(s.into_bigint()).unwrap()).into_affine();
            let theirs = (ark_grumpkin::Affine::generator() * s).into_affine();
            assert_eq!(canon(ours.x), canon(theirs.x));
            assert_eq!(canon(ours.y), canon(theirs.y));
        }
    }
}
