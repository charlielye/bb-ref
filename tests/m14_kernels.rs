//! M14 exit: real recursive kernels. Rust's mock IVC (bb's mock circuit producer + the ported
//! `complete_kernel_circuit_logic`) reproduces every circuit of bb's mock IVC polynomial-for-polynomial
//! and VK-for-VK, its ChonkProof verifies natively and in bb, and with bb's RNG tape the proof is
//! byte-identical.
mod common;
use bb_ref::base::io::{decode_fields, encode_fields};
use bb_ref::base::rng::{Rng, TapeRng};
use bb_ref::base::srs::bn254_g2;
use bb_ref::base::{CommitmentKey, GrumpkinKey, OsRng};
use bb_ref::chonk::ivc::{Chonk, CircuitKind};
use bb_ref::chonk::proof::ChonkProof;
use bb_ref::chonk::verifier::chonk_verify;
use bb_ref::goblin::eccvm::FIXED_SIZE;
use bb_ref::honk::prover_instance::ProverInstance;
use common::mock_ivc::MockIvcCircuits;
use std::path::Path;

/// bb `PrivateFunctionExecutionMockCircuitProducer(num_apps = 2)`.
const KINDS: [CircuitKind; 5] = [
    CircuitKind::App,
    CircuitKind::App,
    CircuitKind::Kernel,
    CircuitKind::Kernel,
    CircuitKind::HidingKernel,
];

fn run_ivc(rng: &mut dyn Rng, compare_with: Option<&Path>) -> (Chonk, ChonkProof) {
    let mut ivc = Chonk::new(KINDS.to_vec(), CommitmentKey::new(1 << 17));
    let mut mock = MockIvcCircuits::new();
    for (idx, kind) in KINDS.iter().enumerate() {
        let mut circuit = mock.next_circuit(&mut ivc, rng);
        assert!(
            circuit.failed.is_none(),
            "circuit {idx}: builder failure {:?}",
            circuit.failed
        );
        // bb's mock producer computes each circuit's VK from a fresh proving instance before accumulating;
        // for the (ZK) hiding kernel that draws masking randomness, which the tape replay must consume too
        if *kind == CircuitKind::HidingKernel && compare_with.is_none() {
            let _vk_instance = ProverInstance::from_builder(kind.flavor(), &mut circuit, rng);
        }
        if let Some(dump) = compare_with {
            let dir = dump.join(format!("circuit_{idx}"));
            let flavor = kind.flavor();
            let inst = ProverInstance::from_builder(flavor, &mut circuit, rng);
            let expected = ProverInstance::load_dump(flavor, &dir);
            assert_eq!(inst.dyadic_size, expected.dyadic_size, "circuit {idx}: dyadic size");
            assert_eq!(
                inst.public_inputs.len(),
                expected.public_inputs.len(),
                "circuit {idx}: public input count"
            );
            // the hiding kernel's IO depends on the random ZK op-queue prefix: only the tape run matches it
            if inst.public_inputs != expected.public_inputs && !flavor.has_zk {
                for (k, (a, b)) in inst.public_inputs.iter().zip(&expected.public_inputs).enumerate() {
                    if a != b {
                        eprintln!("circuit {idx}: public input {k} differs: rust {a:?} bb {b:?}");
                    }
                }
                panic!(
                    "circuit {idx}: public inputs differ ({} vs {} fields)",
                    inst.public_inputs.len(),
                    expected.public_inputs.len()
                );
            }
            let m = inst.layout.num_masking;
            let compare: Vec<usize> = if flavor.has_zk {
                (m..m + inst.layout.num_precomputed).collect()
            } else {
                (0..inst.layout.num_unshifted()).collect()
            };
            common::assert_polys_equal(
                &format!("circuit {idx} ({kind:?})"),
                &inst,
                &expected,
                &circuit,
                &compare,
            );
            assert_eq!(
                inst.compute_vk(&ivc.ck).to_bytes(),
                std::fs::read(dir.join("vk")).unwrap(),
                "circuit {idx}: VK"
            );
        }
        ivc.accumulate(&mut circuit, None, rng);
    }
    let proof = ivc.prove(rng);
    (ivc, proof)
}

#[test]
fn mock_ivc_kernels_match_bb() {
    let dump = common::fixture_dir("instance/chonk/bb_2apps");
    if !dump.join("circuit_0/vk").exists() {
        eprintln!("skipping kernels: no per-circuit dump");
        return;
    }
    let (ivc, proof) = run_ivc(&mut OsRng, Some(&dump));
    assert_eq!(
        ivc.hiding_vk().to_bytes(),
        std::fs::read(dump.join("vk")).unwrap(),
        "hiding kernel VK"
    );
    assert!(
        chonk_verify(ivc.hiding_vk(), &proof, &bn254_g2(), &GrumpkinKey::new(FIXED_SIZE)),
        "Rust Chonk proof rejected"
    );
    let out = common::fixture_dir("instance/chonk/rust_kernels");
    std::fs::create_dir_all(&out).unwrap();
    std::fs::write(out.join("proof_fields.bin"), encode_fields(&proof.to_fields())).unwrap();
    std::fs::write(out.join("proof.msgpack"), proof.to_msgpack()).unwrap();
    std::fs::write(out.join("vk"), ivc.hiding_vk().to_bytes()).unwrap();
}

#[test]
fn mock_ivc_byte_exact_with_tape() {
    let dump = common::fixture_dir("instance/chonk/bb_2apps_tape");
    if !dump.join("rng_tape.bin").exists() {
        eprintln!("skipping kernels tape: no dump");
        return;
    }
    let mut tape = TapeRng::from_bytes(std::fs::read(dump.join("rng_tape.bin")).unwrap());
    let (ivc, proof) = run_ivc(&mut tape, None);
    assert_eq!(
        ivc.hiding_vk().to_bytes(),
        std::fs::read(dump.join("vk")).unwrap(),
        "hiding kernel VK"
    );
    let expected = decode_fields(&std::fs::read(dump.join("proof_fields.bin")).unwrap());
    let fields = proof.to_fields();
    let first_diff = fields.iter().zip(&expected).position(|(a, b)| a != b);
    assert_eq!(first_diff, None, "ChonkProof differs from bb's (first differing field)");
    assert_eq!(fields.len(), expected.len(), "ChonkProof length");
    assert_eq!(tape.remaining(), 0, "unconsumed tape bytes");
}

/// The first outputs of `std::mt19937_64(12345)` (bb's debug engine seed).
#[test]
fn mt19937_64_reference() {
    let mut mt = common::mock_ivc::Mt19937_64::new(12345);
    let expected: [u64; 4] = [
        6597103971274460346,
        7386862472818278521,
        12716877617435052285,
        10325298820568433954,
    ];
    let got: Vec<u64> = (0..4).map(|_| mt.next_u64()).collect();
    assert_eq!(got, expected.to_vec());
}
