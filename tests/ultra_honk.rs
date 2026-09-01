//! Differential tests: ultra honk (one test binary; parts as modules).

mod common;

/// UltraHonk VK format
#[path = "ultra_honk/vk_format.rs"]
mod vk_format;
/// native verification of bb proofs
#[path = "ultra_honk/verify.rs"]
mod verify;
/// proving from dumped instances
#[path = "ultra_honk/prove.rs"]
mod prove;
/// circuits built from ACIR
#[path = "ultra_honk/builder.rs"]
mod builder;
/// backend circuits end to end
#[path = "ultra_honk/backend.rs"]
mod backend;
