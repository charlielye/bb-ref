//! Differential tests: eccvm (one test binary; parts as modules).

mod common;

/// ECCVM trace construction
#[path = "eccvm/trace.rs"]
mod trace;
/// ECCVM prover/verifier round-trip
#[path = "eccvm/proof.rs"]
mod proof;
