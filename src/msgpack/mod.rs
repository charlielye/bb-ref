//! bb's msgpack wire protocol, served over bb-ref.
#[macro_use]
pub mod generated;
#[cfg(feature = "ffi")]
pub mod ffi;
pub mod handler;
