//! bb-ref behind the FFI contract ipc-codegen generates for bb: the generated `export_bb_ffi!`
//! defines `bb_ipc_ffi_entry`, `bb_ipc_ffi_alloc` and `bb_ipc_ffi_free` over the handler, so the
//! generated bb-ref.js package (or any other client of the contract) drives bb-ref as it drives bb.
//! Clients send `Init` first, which sets up what a library has no `main` for (the thread pool, the
//! seeded randomness). Built as a cdylib with the `ffi` feature: tools/build_bb_ref_js.sh.

export_bb_ffi!(crate::msgpack::generated::bb_ffi, crate::msgpack::handler::BbRefHandler);
