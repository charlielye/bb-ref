//! bb's AVM simulation and trace generation, linked in-process (the `bb-avm` feature, bb's
//! `bb-external-avm` archive with `pin/bb-avm.patch`'s `vm2/trace_ffi.cpp`). bb-ref proves and
//! verifies over them, so only the simulator and trace generator of bb's AVM are linked. Circuits
//! that recursively verify an AVM proof (the public tx base rollup) are bb-ref's own
//! ([`crate::avm::two_layer`]).

use crate::avm::prover::{polys_from_trace, prove, public_input_columns};
use crate::avm::verifier::verify;
use crate::base::srs::{bn254_g2, Srs};
use crate::base::Fr;
use ark_ff::{BigInt, PrimeField};

extern "C" {
    fn bb_avm_trace(input: *const u8, input_len: usize, output: *mut *mut u8, output_len: *mut usize) -> i32;
    fn bb_avm_public_inputs(input: *const u8, input_len: usize, output: *mut *mut u8, output_len: *mut usize) -> i32;
    fn free(ptr: *mut u8);
}

type Entry = unsafe extern "C" fn(*const u8, usize, *mut *mut u8, *mut usize) -> i32;

/// `f`'s output (malloc'd, freed here), or its error message.
fn call(f: Entry, input: &[u8]) -> Result<Vec<u8>, String> {
    let (mut out, mut out_len) = (std::ptr::null_mut(), 0usize);
    unsafe {
        let status = f(input.as_ptr(), input.len(), &mut out, &mut out_len);
        let bytes = std::slice::from_raw_parts(out, out_len).to_vec();
        free(out);
        if status == 0 { Ok(bytes) } else { Err(String::from_utf8_lossy(&bytes).into_owned()) }
    }
}

/// bb's AVM trace for serialized proving inputs (simulation with the inputs' hints, then trace
/// generation), in the sparse format [`polys_from_trace`] reads.
pub fn avm_trace(inputs: &[u8]) -> Result<Vec<u8>, String> {
    call(bb_avm_trace, inputs)
}

/// bb `AvmAPI::prove`: the proof, and the public-input columns it was proven for.
pub fn avm_prove(inputs: &[u8], srs: &Srs) -> Result<(Vec<Fr>, Vec<Vec<Fr>>), String> {
    let polys = polys_from_trace(&avm_trace(inputs)?);
    let columns = public_input_columns(&polys);
    Ok((prove(polys, srs), columns))
}

/// bb `AvmAPI::verify` over serialized public inputs (`PublicInputs::to_columns`).
pub fn avm_verify(proof: &[Fr], public_inputs: &[u8]) -> Result<bool, String> {
    let bytes = call(bb_avm_public_inputs, public_inputs)?;
    let mut columns = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        let len = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap()) as usize;
        let values = bytes[at + 4..at + 4 + 32 * len].chunks(32).map(|c| {
            let limbs: [u64; 4] = std::array::from_fn(|i| u64::from_le_bytes(c[8 * i..8 * i + 8].try_into().unwrap()));
            Fr::from_bigint(BigInt(limbs)).expect("non-canonical public input")
        });
        columns.push(values.collect());
        at += 4 + 32 * len;
    }
    Ok(verify(proof, &columns, &bn254_g2()))
}

/// bb `AvmAPI::check_circuit`, as a proof of the trace that verifies: bb checks every row of the
/// trace instead, which would link bb's AVM relations.
pub fn avm_check_circuit(inputs: &[u8], srs: &Srs) -> Result<bool, String> {
    let (proof, columns) = avm_prove(inputs, srs)?;
    Ok(verify(&proof, &columns, &bn254_g2()))
}
