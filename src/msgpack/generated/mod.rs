//! Code generated from the pin's `bb_schema.json` by ipc-codegen (`dev/regen_msgpack.sh`), plus
//! the static template file it expects as a sibling (`error.rs`, here without the template's
//! `thiserror` dependency). One schema defines bb's wire surface; bb's server and this one are
//! both generated from it, so the encoding matches by construction.

// Generated files are kept byte-identical to the generator's output (rustfmt skipped) and
// warning-free from the outside: unreferenced commands leave dead serde helpers.
#[macro_use]
#[rustfmt::skip]
pub mod bb_ffi;
#[rustfmt::skip]
pub mod bb_server;
#[allow(dead_code)]
#[rustfmt::skip]
pub mod bb_types;
#[rustfmt::skip]
pub mod error;
