//! bb itself, linked in-process (the `bb-avm` feature), for what bb-ref does not do: the AVM
//! commands (`avm_prove`, `avm_verify`, `avm_check_circuit`). Commands go to bb's FFI entry
//! (`bb_ipc_ffi_entry`, from bb's `bb-external-avm` archive) as the same msgpack a client would
//! send bb, so one binary serves the whole prover surface. Circuits that recursively verify an AVM
//! proof (the public tx base rollup) are bb-ref's own ([`crate::avm::two_layer`]).

use super::generated::backend::Backend;
use super::generated::bb_client::BbApi;
use super::generated::bb_server::Responder;
use super::generated::error::{IpcError, Result};

extern "C" {
    fn bb_ipc_ffi_entry(input: *const u8, input_len: usize, output: *mut *mut u8, output_len: *mut usize);
    fn bb_ipc_ffi_free(ptr: *mut u8);
    fn bb_ipc_ffi_init_crs(path: *const std::ffi::c_char);
}

/// bb's handlers in this process; [`Backend`] for the generated client.
pub struct InProcess;

impl Backend for InProcess {
    fn call(&mut self, input: &[u8]) -> Result<Vec<u8>> {
        // bb reads its CRS from bb-ref's directory, lazily, as bb's CLI sets it up at startup.
        static CRS: std::sync::Once = std::sync::Once::new();
        CRS.call_once(|| {
            let dir = crate::base::srs::crs_dir();
            let dir = std::ffi::CString::new(dir.to_string_lossy().into_owned()).expect("CRS path has a NUL byte");
            unsafe { bb_ipc_ffi_init_crs(dir.as_ptr()) };
        });
        let (mut out, mut out_len) = (std::ptr::null_mut(), 0usize);
        unsafe {
            bb_ipc_ffi_entry(input.as_ptr(), input.len(), &mut out, &mut out_len);
            let response = std::slice::from_raw_parts(out, out_len).to_vec();
            bb_ipc_ffi_free(out);
            Ok(response)
        }
    }

    fn destroy(&mut self) -> Result<()> {
        Ok(())
    }
}

/// bb's response to `f`; bb's error responses become their message, verbatim.
pub fn call<R>(f: impl FnOnce(&mut BbApi<InProcess>) -> Result<R>) -> std::result::Result<R, String> {
    f(&mut BbApi::new(InProcess)).map_err(|e| match e {
        IpcError::Backend(message) => message,
        e => e.to_string(),
    })
}

/// Answer `respond` with bb's response to `f`.
pub fn forward<R>(respond: Responder<R>, f: impl FnOnce(&mut BbApi<InProcess>) -> Result<R>) {
    match call(f) {
        Ok(r) => respond.ok(r),
        Err(message) => respond.error(message),
    }
}
