//! Differential tests: chonk (one test binary; parts as modules).

mod common;

/// real recursive kernels
#[path = "chonk/kernels.rs"]
mod kernels;
/// Chonk native prove/verify
#[path = "chonk/native.rs"]
mod native;
