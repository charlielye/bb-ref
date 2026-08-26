//! bb-ref: a minimal, single-threaded Rust re-implementation of barretenberg's UltraHonk and Chonk.
//!
//! Module layering (each module depends only on those to its left):
//! `base` <- `circuit` <- `stdlib` <- `honk` <- `goblin` <- `chonk` <- `acir`
pub mod base;
pub mod honk;
