//! Group abstraction (`GroupLike`), the `Curve` bundle that generic verifiers are written against,
//! and the native BN254 instantiation including the final pairing check.

use super::codec::{FromChallenge, Transcriptable};
use super::field::{FieldLike, Fr};
use super::poseidon2::{Hasher, Poseidon2};
use ark_ec::pairing::Pairing;
use ark_ec::short_weierstrass::{Affine, Projective, SWCurveConfig};
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{One, PrimeField};
use std::fmt::Debug;

/// Spelled via the concrete curve config (not ark's projected alias) so coherence can tell it apart
/// from other `Affine<_>` instantiations.
pub type G1Affine = Affine<ark_bn254::g1::Config>;
pub type G2Affine = ark_bn254::G2Affine;
pub type GrumpkinAffine = Affine<ark_grumpkin::GrumpkinConfig>;

pub trait GroupLike<F: FieldLike>: Clone + Debug + PartialEq {
    type Native: AffineRepr;
    /// The generator. In-circuit this needs a builder context (bb: `Commitment::one(ctx)`).
    fn one(ctx: &F::Ctx) -> Self;
    fn constant(ctx: &F::Ctx, p: Self::Native) -> Self;
    fn from_witness(ctx: &F::Ctx, p: Self::Native) -> Self;
    fn value(&self) -> Self::Native;
    fn neg(&self) -> Self;
    fn add(&self, other: &Self) -> Self;
    fn scalar_mul(&self, s: &F) -> Self;
    /// One multi-scalar multiplication. Natively an MSM; in goblin circuits an op-queue sequence.
    fn batch_mul(points: &[Self], scalars: &[F]) -> Self;
    fn assert_equal(&self, other: &Self);
}

impl<P: SWCurveConfig> GroupLike<P::ScalarField> for Affine<P>
where
    P::ScalarField: PrimeField<BigInt = super::field::U256>,
{
    type Native = Affine<P>;
    fn one(_: &()) -> Self {
        Affine::<P>::generator()
    }
    fn constant(_: &(), p: Self) -> Self {
        p
    }
    fn from_witness(_: &(), p: Self) -> Self {
        p
    }
    fn value(&self) -> Self {
        *self
    }
    fn neg(&self) -> Self {
        -*self
    }
    fn add(&self, other: &Self) -> Self {
        (self.into_group() + other).into_affine()
    }
    fn scalar_mul(&self, s: &P::ScalarField) -> Self {
        self.mul_bigint(s.into_bigint()).into_affine()
    }
    fn batch_mul(points: &[Self], scalars: &[P::ScalarField]) -> Self {
        assert_eq!(points.len(), scalars.len());
        Projective::<P>::msm_unchecked(points, scalars).into_affine()
    }
    fn assert_equal(&self, _other: &Self) {}
}

/// Everything a generic prover/verifier needs to know about the curve it runs over.
/// `TF` is the transcript field (bn254 Fr natively, `FieldT` in-circuit); it differs from the
/// scalar field `Fr` for Grumpkin, whose transcript is still over bn254 Fr.
pub trait Curve: 'static {
    type TF: FieldLike + Transcriptable<Self::TF>;
    type Fr: FieldLike + Transcriptable<Self::TF> + FromChallenge<Self::TF>;
    type G: GroupLike<Self::Fr> + Transcriptable<Self::TF>;
    type Hash: Hasher<Self::TF>;
    /// Size of the multiplicative subgroup used by SmallSubgroupIPA, and its fixed generator.
    const SUBGROUP_SIZE: usize;
    fn subgroup_generator() -> <Self::Fr as FieldLike>::Native;
    fn subgroup_generator_inverse() -> <Self::Fr as FieldLike>::Native;
    /// Length of the Libra univariates masking the sumcheck round univariates.
    const LIBRA_UNIVARIATES_LENGTH: usize;
}

pub struct Bn254;
impl Curve for Bn254 {
    type TF = Fr;
    type Fr = Fr;
    type G = G1Affine;
    type Hash = Poseidon2;
    const SUBGROUP_SIZE: usize = 256;
    // 5^((r-1)/2^8), of order 256 (ecc/curves/bn254/bn254.hpp).
    fn subgroup_generator() -> Fr {
        super::field::from_hex("0x07b0c561a6148404f086204a9f36ffb0617942546750f230c893619174a57a76")
    }
    fn subgroup_generator_inverse() -> Fr {
        super::field::from_hex("0x204bd3277422fad364751ad938e2b5e6a54cf8c68712848a692c553d0329f5d6")
    }
    const LIBRA_UNIVARIATES_LENGTH: usize = 9;
}

/// The two points `{P0, P1}` of a deferred pairing check `e(P0, [1]_2) * e(P1, [x]_2) == 1`
/// (bb `PairingPoints`, native and in-circuit).
#[derive(Clone, Debug, PartialEq)]
pub struct PairingPoints<C: Curve> {
    pub p0: C::G,
    pub p1: C::G,
}

impl<C: Curve> PairingPoints<C> {
    pub fn num_fields() -> usize {
        2 * C::G::num_fields()
    }
    pub fn to_fields(&self) -> Vec<C::TF> {
        [self.p0.to_fields(), self.p1.to_fields()].concat()
    }
    pub fn from_fields(f: &[C::TF]) -> Self {
        let n = C::G::num_fields();
        Self { p0: C::G::from_fields(&f[..n]), p1: C::G::from_fields(&f[n..2 * n]) }
    }
}

impl PairingPoints<Bn254> {
    pub fn check(&self, g2: &G2Points) -> bool {
        pairing_check(self.p0, self.p1, g2)
    }
}

/// The two BN254 G2 points of the trusted setup: `[1]_2` and `[x]_2`.
pub type G2Points = [G2Affine; 2];

/// `e(p0, [1]_2) * e(p1, [x]_2) == 1`.
pub fn pairing_check(p0: G1Affine, p1: G1Affine, g2: &G2Points) -> bool {
    ark_bn254::Bn254::multi_pairing([p0, p1], [g2[0], g2[1]]).0.is_one()
}
