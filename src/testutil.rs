//! Shared machinery for the standalone unit tests (compiled only under `cfg(test)`).
//!
//! Standalone means: everything here runs with no bb binary, no corpus, no `tests/data` — valid
//! artifacts are produced by proving tiny circuits in-process. The one external artifact permitted
//! is the CRS at `~/.bb-crs` (needed to commit at all); tests that require it call [`crs_or_skip`].

use crate::base::rng::{DebugRng, Rng};
use crate::base::Fr;
use crate::circuit::builder::AddQuad;
use crate::circuit::Builder;

/// A deterministic Rng for tests: seeded, no env coupling.
pub fn test_rng() -> DebugRng {
    DebugRng::new(12345)
}

/// The smallest satisfiable circuit: one big-add gate `a + b + c - d = 0` plus one public input,
/// mirroring bb's `construct_arbitrary_valid_honk_proof_and_vk` scratch circuit.
pub fn tiny_circuit(rng: &mut dyn Rng) -> Builder {
    let mut builder = Builder::new();
    let a = rng.fr();
    let b = rng.fr();
    let c = rng.fr();
    let one = Fr::from(1u8);
    let g = AddQuad {
        a: builder.add_variable(a),
        b: builder.add_variable(b),
        c: builder.add_variable(c),
        d: builder.add_variable(a + b + c),
        a_scaling: one,
        b_scaling: one,
        c_scaling: one,
        d_scaling: -one,
        const_scaling: Fr::from(0u8),
    };
    let a_idx = g.a;
    builder.create_big_add_gate(g, false);
    builder.set_public_input(a_idx);
    builder
}

/// Skip (return None) when the CRS is not installed; tests must degrade to a skip, not a failure,
/// so `cargo test --lib` stays green on a bare machine.
pub fn crs_or_skip() -> Option<()> {
    let dir = std::env::var("CRS_PATH")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from(std::env::var("HOME").unwrap_or_default()).join(".bb-crs"));
    if dir.join("bn254_g1.dat").exists() {
        Some(())
    } else {
        eprintln!("skipping: no CRS at {}", dir.display());
        None
    }
}
