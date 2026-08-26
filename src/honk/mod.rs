//! The Honk proving system: flavors, relations, sumcheck, PCS, and the UltraHonk prover/verifier.
pub mod flavor;
pub mod oink;
pub mod oink_prover;
pub mod pcs;
pub mod prover_instance;
pub mod relations;
pub mod sumcheck;
pub mod ultra_prover;
pub mod ultra_verifier;

pub use flavor::{Ent, FlavorDesc, Layout, Rel, ULTRA, ULTRA_ZK};
pub use relations::RelationParams;
