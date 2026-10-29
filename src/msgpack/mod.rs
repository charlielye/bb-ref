//! bb's msgpack wire protocol, served over bb-ref.
#[macro_use]
pub mod generated;
#[cfg(feature = "ffi")]
pub mod ffi;
// bb's archive exports the same `bb_ipc_ffi_*` symbols as bb-ref's own FFI build.
#[cfg(all(feature = "bb-avm", feature = "ffi"))]
compile_error!("features `bb-avm` and `ffi` are exclusive");
#[cfg(feature = "bb-avm")]
pub mod bb_avm;
pub mod handler;
