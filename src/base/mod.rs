//! Foundations: field/curve traits over arkworks, serialization, Poseidon2, transcript, SRS.
pub mod codec;
pub mod field;
pub mod generators;
pub mod group;
pub mod io;
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
pub use group::{Bn254, Curve, G1Affine, G2Affine, GroupLike, Grumpkin, GrumpkinAffine, PairingPoints};
pub use poly::Poly;
pub use poseidon2::{Hasher, Poseidon2};
pub use rng::{OsRng, Rng};
pub use srs::{CommitmentKey, GrumpkinKey};
pub use transcript::{NativeTranscript, Transcript};
pub use vk::Vk;
