//! Code generated from the pin's `bb_schema.json` by ipc-codegen (`dev/regen_msgpack.sh`), plus
//! the two static template files it expects as siblings (`error.rs` here without the template's
//! `thiserror` dependency). One schema defines bb's wire surface; bb's server and this one are
//! both generated from it, so the encoding matches by construction.

// Generated files are kept byte-identical to the generator's output (rustfmt skipped) and
// warning-free from the outside: the template's optional ipc-runtime feature is not declared in
// this crate, and unreferenced commands leave dead serde helpers.
#[allow(unexpected_cfgs)]
#[rustfmt::skip]
pub mod backend;
#[rustfmt::skip]
pub mod bb_client;
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
