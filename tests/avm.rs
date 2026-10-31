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

/// The fixture inputs' `publicInputs` (a map of `hints` then `publicInputs`), as a client sends them
/// with `AvmVerify`.
fn public_inputs_msgpack(inputs: &[u8]) -> &[u8] {
    use serde::Deserialize;
    let mut rest = &inputs[3..];
    let mut de = rmp_serde::Deserializer::new(&mut rest);
    assert_eq!(String::deserialize(&mut de).unwrap(), "hints");
    serde::de::IgnoredAny::deserialize(&mut de).unwrap();
    assert_eq!(String::deserialize(&mut de).unwrap(), "publicInputs");
    drop(de);
    rest
}

/// bb `PublicInputs::to_columns` on the fixture inputs gives the fixture's public-input columns.
#[test]
fn avm_public_inputs_match_bb() {
    let inputs = common::read("avm/avm_inputs.bin");
    let columns = bb_ref::avm::public_inputs::public_input_columns(public_inputs_msgpack(&inputs)).unwrap();
    assert_eq!(columns, fixture().1);
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

/// The AVM commands through the server's handler, as bb.js sends them, on bb's simulation and trace
/// generation (linked in): the proof is bb's (`avm/proof.bin`; the AVM proof has no ZK randomness),
/// it verifies and a tampered one does not, and the circuit check passes. Timings against bb and
/// other inputs are the AVM corpus's (`tools/regen/regen_avm_corpus.sh`).
#[cfg(feature = "bb-avm")]
#[test]
fn avm_commands_match_bb() {
    use bb_ref::msgpack::generated::backend::Backend;
    use bb_ref::msgpack::generated::bb_client::BbApi;
    use bb_ref::msgpack::generated::error::Result;
    struct Server(bb_ref::msgpack::handler::BbRefHandler);
    impl Backend for Server {
        fn call(&mut self, input: &[u8]) -> Result<Vec<u8>> {
            Ok(bb_ref::msgpack::generated::bb_server::handle_request(&mut self.0, input))
        }
        fn destroy(&mut self) -> Result<()> {
            Ok(())
        }
    }
    let inputs = common::read("avm/avm_inputs.bin");
    let mut server = BbApi::new(Server(bb_ref::msgpack::handler::BbRefHandler::new(Default::default())));
    let proof = server.avm_prove(&inputs).unwrap().proof;
    let first = proof.iter().map(|b| Fr::from_be_bytes_mod_order(&b.0)).zip(fixture().0).position(|(a, b)| a != b);
    assert_eq!((proof.len(), first), (fixture().0.len(), None), "proof length, first differing field");
    let public_inputs = public_inputs_msgpack(&inputs);
    assert!(server.avm_verify(proof.clone(), public_inputs).unwrap().verified);
    let mut tampered = proof;
    let last = tampered.len() - 10;
    tampered[last].0[31] ^= 1;
    assert!(!server.avm_verify(tampered, public_inputs).unwrap().verified);
    assert!(server.avm_check_circuit(&inputs).unwrap().passed);
}

/// The circuit check names the relation a corrupted trace breaks, and the row.
#[cfg(feature = "bb-avm")]
#[test]
fn avm_check_circuit_localizes_corruption() {
    use bb_ref::avm::prover::{check_circuit, polys_from_trace};
    let polys = polys_from_trace(&bb_ref::msgpack::bb_avm::avm_trace(&common::read("avm/avm_inputs.bin")).unwrap());
    let l = layout();
    let col = (l.num_precomputed..l.num_precomputed + l.num_wires).find(|&c| polys[c].len() > 10 && polys[c].at(5) != Fr::from(0u64)).unwrap();
    let mut bad = polys.clone();
    bad[col] = bb_ref::base::poly::Poly::from_coeffs((0..bad[col].len()).map(|r| bad[col].at(r) + Fr::from((r == 5) as u64)).collect());
    let err = check_circuit(bad).unwrap_err();
    assert!(err.starts_with("Relation "), "{err}");
    check_circuit(polys).unwrap();
}
