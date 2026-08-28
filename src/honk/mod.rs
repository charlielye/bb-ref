//! The Honk proving system: flavors, relations, sumcheck, PCS, and the UltraHonk prover/verifier.
pub mod circuit_checker;
pub mod decider;
pub mod flavor;
pub mod hypernova;
pub mod multilinear_batching;
pub mod oink;
pub mod oink_prover;
pub mod pcs;
pub mod prover_instance;
pub mod quad_params;
pub mod relations;
pub mod sumcheck;
pub mod ultra_prover;
pub mod ultra_verifier;

pub use flavor::{Ent, FlavorDesc, Layout, Rel, MEGA_APP, MEGA_KERNEL, MEGA_ZK, ULTRA, ULTRA_KECCAK, ULTRA_KECCAK_ZK, ULTRA_ZK};
pub use relations::RelationParams;
