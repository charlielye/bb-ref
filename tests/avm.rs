//! The AVM verifier against bb: a real AVM proof (tests/data/<pin>/avm/, `tools/regen/regen_avm.sh`)
//! verifies natively, and every tampered proof field is rejected.
mod common;

use bb_ref::avm::tables::layout;
use bb_ref::avm::verifier::verify;
use bb_ref::base::srs::bn254_g2;
use bb_ref::base::Fr;
use ark_ff::PrimeField;


fn frs(rel: &str) -> Vec<Fr> {
    common::read(rel).chunks(32).map(Fr::from_be_bytes_mod_order).collect()
}

fn fixture() -> (Vec<Fr>, Vec<Vec<Fr>>) {
    let proof = frs("avm/proof.bin");
    let flat = frs("avm/public_inputs.bin");
    let mut columns = Vec::new();
    let mut at = 0;
    for len in layout().public_input_column_lengths {
        columns.push(flat[at..at + len].to_vec());
        at += len;
    }
    assert_eq!(at, flat.len());
    (proof, columns)
}

#[test]
fn avm_proof_verifies() {
    let (proof, columns) = fixture();
    assert!(verify(&proof, &columns, &bn254_g2()));
}

#[test]
fn avm_tampered_proof_or_public_inputs_rejected() {
    let (proof, columns) = fixture();
    let g2 = bn254_g2();
    // a sumcheck evaluation, a round univariate value, a Gemini evaluation
    let l = layout();
    let evals_start = l.num_witness() * 4 + l.max_trace_log_size * (l.max_partial_length + 1);
    for i in [evals_start + 7, l.num_witness() * 4 + 3, proof.len() - 10] {
        let mut p = proof.clone();
        p[i] += Fr::from(1u64);
        assert!(!verify(&p, &columns, &g2), "tampered proof field {i} accepted");
    }
    let mut c = columns.clone();
    c[1][0] += Fr::from(1u64);
    assert!(!verify(&proof, &c, &g2), "tampered public input accepted");
    assert!(!verify(&proof[1..], &columns, &g2), "short proof accepted");
}

/// bb's inner MegaAvm recursive verifier circuit for the fixture proof (`avm_dump --inner`, gitignored
/// under instance/avm_inner): every polynomial, the public inputs and the VK. Only the op queue's
/// random ops may differ.
#[test]
fn avm_inner_circuit_matches_bb() {
    use bb_ref::base::srs::CommitmentKey;
    use bb_ref::honk::flavor::MEGA_AVM;
    use bb_ref::honk::prover_instance::ProverInstance;
    let dump = common::fixture_dir("instance/avm_inner");
    if !dump.join("vk").exists() {
        eprintln!("skipping: no inner circuit dump");
        return;
    }
    let (proof, columns) = fixture();
    let mut builder = bb_ref::avm::recursive::inner_circuit(&proof, &columns);
    assert!(builder.failed.is_none(), "builder failure {:?}", builder.failed);
    let inst = ProverInstance::from_builder(&MEGA_AVM, &mut builder, &mut bb_ref::base::rng::OsRng);
    let expected = ProverInstance::load_dump(&MEGA_AVM, &dump);
    assert_eq!(inst.dyadic_size, expected.dyadic_size, "dyadic size");
    assert_eq!(inst.pub_inputs_offset, expected.pub_inputs_offset, "pub inputs offset");
    assert_eq!(inst.final_active_wire_idx, expected.final_active_wire_idx, "final active wire");
    let n = inst.layout.num_unshifted();
    common::assert_polys_equal("avm inner", &inst, &expected, &builder, &(0..inst.layout.num_precomputed).collect::<Vec<_>>());
    // The three random ops (bb `GoblinAvm`'s ZK prefix, after one no-op) fill op-queue rows 2..8,
    // mirrored one row later in the wires; their values depend on the RNG draw position.
    let random_rows = |name: &str, r: usize| if name.starts_with("ecc_op_wire") { (2..8).contains(&r) } else { (3..9).contains(&r) };
    let mut witness_diffs = Vec::new();
    for i in inst.layout.num_precomputed..n {
        let name = inst.layout.unshifted[i].name();
        let (a, b) = (&inst.polys[i], &expected.polys[i]);
        if let Some(r) = (0..a.len().max(b.len())).find(|r| a.at(*r) != b.at(*r) && !random_rows(name, *r)) {
            witness_diffs.push(format!("{name} at row {r}"));
        }
    }
    assert_eq!(inst.public_inputs, expected.public_inputs, "public inputs");
    let ck = CommitmentKey::new(inst.max_end_index);
    let vk = inst.compute_vk(&ck);
    assert_eq!(vk.to_bytes(), std::fs::read(dump.join("vk")).unwrap(), "VK");
    assert!(witness_diffs.is_empty(), "witness columns differ: {witness_diffs:?}");
}

/// bb itself in this process, through its FFI entry (in the `bb-external-avm` archive; bb-ref's
/// own code links only bb's AVM simulation and trace generation).
#[cfg(feature = "bb-avm")]
struct InProcessBb;

#[cfg(feature = "bb-avm")]
impl bb_ref::msgpack::generated::backend::Backend for InProcessBb {
    fn call(&mut self, input: &[u8]) -> bb_ref::msgpack::generated::error::Result<Vec<u8>> {
        extern "C" {
            fn bb_ipc_ffi_entry(input: *const u8, input_len: usize, output: *mut *mut u8, output_len: *mut usize);
            fn bb_ipc_ffi_free(ptr: *mut u8);
        }
        let (mut out, mut out_len) = (std::ptr::null_mut(), 0usize);
        unsafe {
            bb_ipc_ffi_entry(input.as_ptr(), input.len(), &mut out, &mut out_len);
            let response = std::slice::from_raw_parts(out, out_len).to_vec();
            bb_ipc_ffi_free(out);
            Ok(response)
        }
    }

    fn destroy(&mut self) -> bb_ref::msgpack::generated::error::Result<()> {
        Ok(())
    }
}

/// bb-ref's AVM prover on bb's trace of the fixture inputs (bb's simulation and trace generation,
/// linked in) against bb's own proof from the same process: the AVM proof has no ZK randomness, so
/// the two are identical, and bb-ref verifies it (bb's `AvmVerify` path, through bb's public-input
/// columns). `BBREF_AVM_INPUTS=<avm_inputs.bin>` runs it on other inputs (bb-prover writes them
/// under `BB_DEBUG_OUTPUT_DIR`) and reports both provers' times.
#[cfg(feature = "bb-avm")]
#[test]
fn avm_prover_matches_bb() {
    use bb_ref::msgpack::bb_avm;
    use bb_ref::msgpack::generated::bb_client::BbApi;
    use std::time::Instant;
    let inputs = match std::env::var("BBREF_AVM_INPUTS") {
        Ok(path) => std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}")),
        Err(_) => common::read("avm/avm_inputs.bin"),
    };
    // Peak resident memory since the last call (Linux: `VmHWM`, reset through `clear_refs`).
    let peak_gb = || {
        let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
        let kb = status.lines().find_map(|l| l.strip_prefix("VmHWM:")).and_then(|v| v.trim().trim_end_matches(" kB").parse::<f64>().ok());
        let _ = std::fs::write("/proc/self/clear_refs", "5");
        kb.unwrap_or(0.0) / (1 << 20) as f64
    };
    peak_gb();
    let t = Instant::now();
    let trace = bb_avm::avm_trace(&inputs).expect("bb trace");
    let t_trace = t.elapsed();
    let mem_trace = peak_gb();
    let t = Instant::now();
    let polys = bb_ref::avm::prover::polys_from_trace(&trace);
    drop(trace);
    let proof = bb_ref::avm::prover::prove(polys, &Default::default());
    let t_ours = t.elapsed();
    let mem_ours = peak_gb();
    // bb's CRS as bb.js sends it: the raw points of the AVM's fixed trace size, and g2.
    let crs = bb_ref::base::srs::crs_dir();
    let n = 1usize << layout().max_trace_log_size;
    let mut points = vec![0u8; 64 * n];
    std::io::Read::read_exact(&mut std::fs::File::open(crs.join("bn254_g1.dat")).unwrap(), &mut points).unwrap();
    let g2 = std::fs::read(crs.join("bn254_g2.dat")).unwrap();
    let mut bb = BbApi::new(InProcessBb);
    bb.srs_init_srs(&points, n as u32, &g2).expect("bb CRS");
    drop(points);
    // bb's AVM prover needs more stack than a test thread's 2 MiB.
    let bb_inputs = inputs.clone();
    let t = Instant::now();
    let expected: Vec<Fr> = std::thread::Builder::new()
        .stack_size(64 << 20)
        .spawn(move || bb.avm_prove(&bb_inputs).expect("bb proof").proof)
        .unwrap()
        .join()
        .unwrap()
        .iter()
        .map(|b| Fr::from_be_bytes_mod_order(&b.0))
        .collect();
    let t_bb = t.elapsed();
    let mem_bb = peak_gb();
    eprintln!(
        "AVM: bb simulate+trace {:.2} s; bb-ref prove {:.2} s; bb simulate+trace+prove {:.2} s",
        t_trace.as_secs_f64(),
        t_ours.as_secs_f64(),
        t_bb.as_secs_f64()
    );
    eprintln!("AVM peak RSS: bb simulate+trace {mem_trace:.2} GB; bb-ref prove {mem_ours:.2} GB; bb simulate+trace+prove {mem_bb:.2} GB");
    assert_eq!(proof.len(), expected.len());
    let first = proof.iter().zip(&expected).position(|(a, b)| a != b);
    assert_eq!(first, None, "first differing proof field");
    if std::env::var_os("BBREF_AVM_INPUTS").is_none() {
        // The inputs' `publicInputs` (a map of `hints` then `publicInputs`), as a client sends them.
        use serde::Deserialize;
        let mut rest = &inputs[3..];
        let mut de = rmp_serde::Deserializer::new(&mut rest);
        assert_eq!(String::deserialize(&mut de).unwrap(), "hints");
        serde::de::IgnoredAny::deserialize(&mut de).unwrap();
        assert_eq!(String::deserialize(&mut de).unwrap(), "publicInputs");
        drop(de);
        // The server's AVM commands, as bb.js sends them.
        struct Server(bb_ref::msgpack::handler::BbRefHandler);
        impl bb_ref::msgpack::generated::backend::Backend for Server {
            fn call(&mut self, input: &[u8]) -> bb_ref::msgpack::generated::error::Result<Vec<u8>> {
                Ok(bb_ref::msgpack::generated::bb_server::handle_request(&mut self.0, input))
            }
            fn destroy(&mut self) -> bb_ref::msgpack::generated::error::Result<()> {
                Ok(())
            }
        }
        let mut server = BbApi::new(Server(bb_ref::msgpack::handler::BbRefHandler::new(Default::default())));
        let served = server.avm_prove(&inputs).unwrap().proof;
        assert!(served.iter().map(|b| Fr::from_be_bytes_mod_order(&b.0)).eq(expected.iter().copied()), "served proof");
        assert!(server.avm_verify(served.clone(), rest).unwrap().verified);
        let mut tampered = served;
        let last = tampered.len() - 10;
        tampered[last].0[31] ^= 1;
        assert!(!server.avm_verify(tampered, rest).unwrap().verified);
        assert!(server.avm_check_circuit(&inputs).unwrap().passed);
    }
}
