//! bb-ref: a minimal, single-threaded Rust re-implementation of barretenberg's UltraHonk and Chonk.
//!
//! Module layering (each module depends only on those to its left):
//! `base` <- `circuit` <- `stdlib` <- `honk` <- `goblin` <- `chonk` <- `acir`
pub mod acir;
pub mod base;
pub mod chonk;
pub mod circuit;
pub mod goblin;
pub mod honk;
pub mod rollup;
pub mod stdlib;
