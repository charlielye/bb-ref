//! Foundations: field/curve traits over arkworks, serialization, Poseidon2, transcript, SRS.
pub mod bench;
pub mod codec;
pub mod endo;
pub mod field;
pub mod fold;
pub mod generators;
pub mod ifma;
pub mod group;
pub mod io;
pub mod keccak;
pub mod msm;
pub mod poly;
pub mod pool;
pub mod poseidon2;
pub mod poseidon2_params;
pub mod rng;
pub mod srs;
pub mod timing;
pub mod transcript;
pub mod vk;
pub mod wasm;

pub use codec::{ChallengeField, FromChallenge, Transcriptable};
pub use field::{FieldLike, Fq, Fr, U256};
pub use group::KeccakBn254;
pub use group::{
    Bn254, Curve, G1Affine, G1Config, G1Projective, G2Affine, GroupLike, Grumpkin, GrumpkinAffine, GrumpkinConfig,
    GrumpkinProjective, PairingPoints,
};
pub use poly::Poly;
pub use poseidon2::{Hasher, Poseidon2};
pub use rng::{OsRng, Rng};
pub use srs::{CommitmentKey, GrumpkinKey};
pub use transcript::{NativeTranscript, Transcript};
pub use vk::Vk;

/// The Grumpkin GLV endomorphism (`λ·(x, y) = (β·x, y)`), the cube roots of `endo::EndoField`.
/// Verified on first use: the (λ, β) pairing is checked on the generator.
pub fn grumpkin_endo() -> &'static fold::Endo<GrumpkinConfig> {
    use ark_ec::{AffineRepr, CurveGroup};
    static ENDO: std::sync::LazyLock<fold::Endo<GrumpkinConfig>> = std::sync::LazyLock::new(|| {
        // λ in Grumpkin's scalar field (bn254 Fq), β in its base field (bn254 Fr).
        use crate::base::endo::EndoField;
        let lambda = <Fq as EndoField>::cube_root();
        let beta = <Fr as EndoField>::cube_root();
        use crate::base::field::FieldLike;
        assert!(lambda.sqr() * lambda == Fq::one() && lambda != Fq::one(), "bad λ");
        assert!(beta.sqr() * beta == Fr::one() && beta != Fr::one(), "bad β");
        let g = GrumpkinAffine::generator();
        let lg = (g * lambda).into_affine();
        assert_eq!(
            lg,
            GrumpkinAffine::new_unchecked(g.x * beta, g.y),
            "λ and β do not pair"
        );
        fold::Endo { lambda, beta }
    });
    &ENDO
}
