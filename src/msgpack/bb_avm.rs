//! bb's AVM simulation and trace generation, linked in-process (the `bb-avm` feature: bb's
//! `libbb-avm-sim.a`, with `pin/bb-avm-sim.patch`'s `vm2/trace_ffi.cpp` as its entry). Everything
//! after the trace is bb-ref's: the prover, the verifier and the circuit check.

use crate::avm::prover::{check_circuit, polys_from_trace, prove};
use crate::avm::public_inputs::public_input_columns;
use crate::avm::verifier::verify;
use crate::base::srs::{bn254_g2, Srs};
use crate::base::Fr;

extern "C" {
    fn bb_avm_trace(input: *const u8, input_len: usize, output: *mut *mut u8, output_len: *mut usize) -> i32;
}

/// bb's AVM trace for serialized proving inputs (simulation with the inputs' hints, then trace
/// generation), in the sparse format [`polys_from_trace`] reads.
pub fn avm_trace(inputs: &[u8]) -> Result<Vec<u8>, String> {
    let (mut out, mut out_len) = (std::ptr::null_mut(), 0usize);
    unsafe {
        let status = bb_avm_trace(inputs.as_ptr(), inputs.len(), &mut out, &mut out_len);
        let bytes = std::slice::from_raw_parts(out, out_len).to_vec();
        libc::free(out.cast());
        if status == 0 { Ok(bytes) } else { Err(String::from_utf8_lossy(&bytes).into_owned()) }
    }
}

/// bb `AvmAPI::prove`.
pub fn avm_prove(inputs: &[u8], srs: &Srs) -> Result<Vec<Fr>, String> {
    // The trace is dropped before proving: it is held only while the columns are built.
    let polys = polys_from_trace(&avm_trace(inputs)?);
    Ok(prove(polys, srs))
}

/// bb `AvmAPI::verify` over serialized public inputs.
pub fn avm_verify(proof: &[Fr], public_inputs: &[u8]) -> Result<bool, String> {
    Ok(verify(proof, &public_input_columns(public_inputs)?, &bn254_g2()))
}

/// bb `AvmAPI::check_circuit`: a failing relation is an error, as bb throws.
pub fn avm_check_circuit(inputs: &[u8]) -> Result<(), String> {
    let polys = polys_from_trace(&avm_trace(inputs)?);
    check_circuit(polys)
}
