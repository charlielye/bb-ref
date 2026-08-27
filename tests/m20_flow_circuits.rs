//! Diff harness for the real pinned flows: with bb's debug engine seeded identically on both sides
//! (`HARDWARE_CONCURRENCY=1 BB_RNG_SEED=12345` for the `BbRefDump.ChonkFlow` dump), every circuit's
//! proving instance of a flow must equal bb's polynomial for polynomial. Localizes the deterministic
//! hiding-kernel divergence seen in the full ChonkProof comparison.

mod common;
use bb_ref::acir::lower::build_circuit_mega;
use bb_ref::acir::steps::decode_steps;
use bb_ref::base::rng::DebugRng;
use bb_ref::base::CommitmentKey;
use bb_ref::chonk::ivc::Chonk;
use bb_ref::honk::prover_instance::ProverInstance;

#[test]
fn real_flow_circuits_match_bb() {
    let flow = std::env::var("BBREF_FLOW").unwrap_or_else(|_| "deploy_ecdsar1+sponsored_fpc".into());
    let dump = common::fixture_dir(&format!("instance/flows/{flow}"));
    let flows = std::env::var("BB_FLOWS")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../aztec-packages2/barretenberg/cpp/chonk-pinned-flows")
        });
    let inputs = flows.join(&flow).join("ivc-inputs.msgpack");
    if !dump.join("circuit_0/vk").exists() || !inputs.exists() {
        eprintln!("skipping {flow}: no dump or no flow inputs");
        return;
    }
    let mut rng = DebugRng::new(12345);
    let steps = decode_steps(&std::fs::read(&inputs).unwrap());
    // The ChonkFlow dumper decodes all witnesses upfront (bb's PrivateExecutionSteps::parse ordering,
    // unlike the CLI's per-step decode) — mirror it so the draw ledgers line up with the dump.
    let witnesses: Vec<Vec<bb_ref::base::Fr>> = steps.iter().map(|s| s.decode_witness(&mut rng)).collect();
    let mut ivc = Chonk::new(steps.iter().map(|s| s.kind).collect(), CommitmentKey::new(1 << 17));
    for (idx, step) in steps.iter().enumerate() {
        let mut circuit = build_circuit_mega(&step.circuit, Some(&witnesses[idx]), Some(&mut ivc), &mut rng);
        assert!(
            circuit.failed.is_none(),
            "circuit {idx} ({}): builder failure {:?}",
            step.name,
            circuit.failed
        );
        let dir = dump.join(format!("circuit_{idx}"));
        let flavor = step.kind.flavor();
        // Mirrors the bb dumper: an instance is built (drawing any masking) before the accumulate.
        let inst = ProverInstance::from_builder(flavor, &mut circuit, &mut rng);
        let expected = ProverInstance::load_dump(flavor, &dir);
        assert_eq!(
            inst.dyadic_size, expected.dyadic_size,
            "circuit {idx} ({}): dyadic size",
            step.name
        );
        if inst.public_inputs != expected.public_inputs {
            for (k, (a, b)) in inst.public_inputs.iter().zip(&expected.public_inputs).enumerate() {
                if a != b {
                    eprintln!("circuit {idx}: public input {k} differs: rust {a:?} bb {b:?}");
                }
            }
            panic!(
                "circuit {idx} ({}): public inputs differ ({} vs {} fields)",
                step.name,
                inst.public_inputs.len(),
                expected.public_inputs.len()
            );
        }
        let compare: Vec<usize> = (0..inst.layout.num_unshifted()).collect();
        common::assert_polys_equal(
            &format!("circuit {idx} ({})", step.name),
            &inst,
            &expected,
            &circuit,
            &compare,
        );
        assert_eq!(
            inst.compute_vk(&ivc.ck).to_bytes(),
            std::fs::read(dir.join("vk")).unwrap(),
            "circuit {idx} ({}): VK",
            step.name
        );
        ivc.accumulate(&mut circuit, Some(step.vk.clone()), &mut rng);
    }
    eprintln!("{flow}: all {} circuits match bb", steps.len());
}
