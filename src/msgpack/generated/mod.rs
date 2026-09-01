//! Code generated from the pin's `bb_schema.json` by ipc-codegen (`dev/regen_msgpack.sh`), plus
//! the two static template files it expects as siblings (`error.rs` here without the template's
//! `thiserror` dependency). One schema defines bb's wire surface; bb's server and this one are
//! both generated from it, so the encoding matches by construction.

// Generated files are kept warning-free from the outside: the template's optional ipc-runtime
// feature is not declared in this crate, and unreferenced commands leave dead serde helpers.
#[allow(unexpected_cfgs)]
pub mod backend;
pub mod bb_client;
pub mod bb_server;
#[allow(dead_code)]
pub mod bb_types;
pub mod error;
