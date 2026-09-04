//! Foundations: field/curve traits over arkworks, serialization, Poseidon2, transcript, SRS.
pub mod codec;
pub mod endo;
pub mod field;
pub mod fold;
pub mod generators;
pub mod group;
pub mod io;
pub mod keccak;
pub mod msm;
pub mod mont29;
pub mod poly;
pub mod poseidon2;
pub mod poseidon2_params;
pub mod rng;
pub mod srs;
pub mod timing;
pub mod transcript;
pub mod vk;

pub use codec::{ChallengeField, FromChallenge, Transcriptable};
pub use field::{FieldLike, Fq, Fr, U256};
pub use group::KeccakBn254;
pub use group::{Bn254, Curve, G1Affine, G2Affine, GroupLike, Grumpkin, GrumpkinAffine, PairingPoints};
pub use poly::Poly;
pub use poseidon2::{Hasher, Poseidon2};
pub use rng::{OsRng, Rng};
pub use srs::{CommitmentKey, GrumpkinKey};
pub use transcript::{NativeTranscript, Transcript};
pub use vk::Vk;

/// The Grumpkin GLV endomorphism (`λ·(x, y) = (β·x, y)`) with bb's lattice constants for the
/// scalar-field split (`Bn254FqParams::endo_*`; the cube roots are bb's Montgomery limbs, which
/// arkworks shares). Verified on first use: the split's field identity is asserted per call, and
/// the (λ, β) pairing is checked on the generator here.
pub fn grumpkin_endo() -> &'static fold::Endo<ark_grumpkin::GrumpkinConfig> {
    use ark_ec::{AffineRepr, CurveGroup};
    static ENDO: std::sync::LazyLock<fold::Endo<ark_grumpkin::GrumpkinConfig>> = std::sync::LazyLock::new(|| {
        // λ in Grumpkin's scalar field (bn254 Fq), β in its base field (bn254 Fr).
        let lambda = unsafe {
            std::mem::transmute::<[u64; 4], Fq>([
                0x71930c11d782e155,
                0xa6bb947cffbe3323,
                0xaa303344d4741444,
                0x2c3b3f0d26594943,
            ])
        };
        let beta = unsafe {
            std::mem::transmute::<[u64; 4], Fr>([
                0x93e7cede4a0329b3,
                0x7d4fdca77a96c167,
                0x8be4ba08b19a750a,
                0x1cbd5653a5661c25,
            ])
        };
        use crate::base::field::FieldLike;
        assert!(lambda.sqr() * lambda == Fq::one() && lambda != Fq::one(), "bad λ");
        assert!(beta.sqr() * beta == Fr::one() && beta != Fr::one(), "bad β");
        let g = GrumpkinAffine::generator();
        let lg = (g * lambda).into_affine();
        assert_eq!(lg, GrumpkinAffine::new_unchecked(g.x * beta, g.y), "λ and β do not pair");
        fold::Endo {
            lambda,
            beta,
            g1: [0x7a7bd9d4391eb18d, 0x4ccef014a773d2cf, 0x2, 0],
            g2: [0xd91d232ec7e0b3d2, 0x2, 0, 0],
            minus_b1: [0x8211bbeb7d4f1129, 0x6f4d8248eeb859fc, 0, 0],
            b2: [0x89d3256894d213e2, 0, 0, 0],
        }
    });
    &ENDO
}
