//! Foundations: field/curve traits over arkworks, serialization, Poseidon2, transcript, SRS.
pub mod codec;
pub mod field;
pub mod group;
pub mod io;
pub mod poseidon2;
pub mod poseidon2_params;
pub mod srs;
pub mod transcript;
pub mod vk;

pub use codec::{ChallengeField, FromChallenge, Transcriptable};
pub use field::{FieldLike, Fq, Fr, U256};
pub use group::{Bn254, Curve, G1Affine, G2Affine, GroupLike, GrumpkinAffine, PairingPoints};
pub use poseidon2::{Hasher, Poseidon2};
pub use transcript::{NativeTranscript, Transcript};
pub use vk::Vk;
