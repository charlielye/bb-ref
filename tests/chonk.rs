//! Differential tests: chonk (one test binary; parts as modules).

mod common;

/// Chonk native prove/verify
#[path = "chonk/native.rs"]
mod native;
/// real recursive kernels
#[path = "chonk/kernels.rs"]
mod kernels;
