//! bb-ref: a minimal, single-threaded Rust re-implementation of barretenberg's UltraHonk and Chonk.
//!
//! Module layering (each module depends only on those to its left):
//! `base` <- `circuit` <- `stdlib` <- `honk` <- `goblin` <- `chonk` <- `acir`
//!
//! `msgpack` sits above all of them: bb's wire protocol (generated from the pin's schema) served
//! over the same functions. Nothing below depends on it.
pub mod acir;
pub mod avm;
pub mod base;
pub mod chonk;
pub mod circuit;
pub mod goblin;
pub mod honk;
pub mod msgpack;
pub mod rollup;
pub mod stdlib;
#[cfg(test)]
pub mod testutil;
