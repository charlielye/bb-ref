//! M5 exit: HyperNova folding, multilinear batching and the decider reproduce bb byte-for-byte on
//! script-built Mega circuits (`BbRefDump.Folding` fixtures), and the Rust verifiers accept bb's
//! proofs and rebuild the same accumulator.
mod common;
use bb_ref::base::field::{from_bytes_be, Fr};
use bb_ref::base::io::decode_fields;
use bb_ref::base::srs::bn254_g2;
use bb_ref::base::{Bn254, CommitmentKey, Fq, G1Affine, NativeTranscript, OsRng, Vk};
use bb_ref::circuit::{Builder, EccOpQueue};
use bb_ref::honk::decider::{decider_prove, decider_verify};
use bb_ref::honk::hypernova::{FoldingProver, FoldingVerifier, ProverClaim, VerifierClaim};
use bb_ref::honk::multilinear_batching::VIRTUAL_LOG_N;
use bb_ref::honk::prover_instance::ProverInstance;
use bb_ref::honk::{FlavorDesc, MEGA_APP, MEGA_KERNEL};
use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::rc::Rc;

fn build_instance(script: &str, flavor: &'static FlavorDesc) -> ProverInstance {
    let text = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!("tests/data/scripts/{script}.txt")),
    )
    .unwrap();
    let ctx = Rc::new(RefCell::new(Builder::new_mega(Rc::new(
        RefCell::new(EccOpQueue::new()),
    ))));
    common::script::run_script(&ctx, &text);
    let mut builder = Rc::try_unwrap(ctx).ok().unwrap().into_inner();
    ProverInstance::from_builder(flavor, &mut builder, &mut OsRng)
}

fn read_accumulator(path: &Path) -> VerifierClaim<Bn254> {
    let b = std::fs::read(path).unwrap();
    let f = |i: usize| from_bytes_be::<Fr>(&b[32 * i..32 * i + 32]);
    let point = |off: usize| {
        G1Affine::new_unchecked(
            from_bytes_be::<Fq>(&b[off..off + 32]),
            from_bytes_be::<Fq>(&b[off + 32..off + 64]),
        )
    };
    let n = VIRTUAL_LOG_N;
    VerifierClaim {
        challenge: (0..n).map(f).collect(),
        non_shifted_evaluation: f(n),
        shifted_evaluation: f(n + 1),
        non_shifted_commitment: point(32 * (n + 2)),
        shifted_commitment: point(32 * (n + 2) + 64),
    }
}

fn read_proof(path: &Path) -> Vec<Fr> {
    decode_fields(&std::fs::read(path).unwrap())
}

/// Fold the scripted group exactly as the bb fixture did and compare every artifact.
fn check_folding(name: &str, entries: &[(&str, &'static FlavorDesc)], with_prev: bool) {
    let dump = common::fixture_dir(&format!("instance/folding/{name}"));
    if !dump.join("decider_proof.bin").exists() {
        eprintln!("skipping folding/{name}: no dump");
        return;
    }
    let ck = CommitmentKey::new(1 << 12);
    let mut prev: Option<ProverClaim> = None;
    if with_prev {
        let mut p = FoldingProver::new();
        let mut inst = build_instance(entries[0].0, entries[0].1);
        let vk = inst.compute_vk(&ck);
        p.accumulate_instance(&mut inst, &vk, &ck, &mut OsRng);
        let (_, acc) = p.finalize(None);
        assert_eq!(
            acc.to_verifier_claim(),
            read_accumulator(&dump.join("prev_accumulator.bin")),
            "{name}: previous accumulator"
        );
        prev = Some(acc);
    }

    // ---- prover ----
    let mut prover = FoldingProver::new();
    let mut vks: Vec<Vk<Bn254>> = vec![];
    let mut proofs = vec![];
    for (i, (script, flavor)) in entries.iter().enumerate() {
        let mut inst = build_instance(script, flavor);
        let vk = inst.compute_vk(&ck);
        assert_eq!(
            vk.to_bytes(),
            std::fs::read(dump.join(format!("vk_{i}"))).unwrap(),
            "{name}: vk {i}"
        );
        let proof = prover.accumulate_instance(&mut inst, &vk, &ck, &mut OsRng);
        assert_eq!(
            proof,
            read_proof(&dump.join(format!("instance_proof_{i}.bin"))),
            "{name}: instance proof {i}"
        );
        vks.push(vk);
        proofs.push(proof);
    }
    let (batch_proof, acc) = prover.finalize(prev.clone());
    assert_eq!(
        batch_proof,
        read_proof(&dump.join("batch_proof.bin")),
        "{name}: batching proof"
    );
    let expected_acc = read_accumulator(&dump.join("accumulator.bin"));
    assert_eq!(acc.to_verifier_claim(), expected_acc, "{name}: accumulator");
    decider_prove(&acc, &mut prover.transcript);
    assert_eq!(
        prover.transcript.export_proof(),
        read_proof(&dump.join("decider_proof.bin")),
        "{name}: decider proof"
    );

    // ---- verifier, on bb's proofs ----
    let mut verifier = FoldingVerifier::<Bn254>::new();
    for (i, (_, flavor)) in entries.iter().enumerate() {
        assert!(
            verifier
                .accumulate_instance(
                    flavor,
                    &vks[i],
                    &vks[i].hash(),
                    &read_proof(&dump.join(format!("instance_proof_{i}.bin")))
                )
                .0,
            "{name}: instance {i} rejected"
        );
    }
    let (ok, vacc) = verifier.finalize(
        &read_proof(&dump.join("batch_proof.bin")),
        prev.as_ref().map(ProverClaim::to_verifier_claim),
    );
    assert!(ok, "{name}: batching rejected");
    assert_eq!(vacc, expected_acc, "{name}: verifier accumulator");
    verifier
        .transcript
        .load_proof(&read_proof(&dump.join("decider_proof.bin")));
    let pp = decider_verify::<Bn254>(&vacc, &mut verifier.transcript, &());
    assert!(pp.check(&bn254_g2()), "{name}: decider pairing check failed");
}

#[test]
fn fold_kernel_app_app() {
    check_folding(
        "kernel_app_app",
        &[
            ("mega_kernel", &MEGA_KERNEL),
            ("mega_app", &MEGA_APP),
            ("mega_app", &MEGA_APP),
        ],
        false,
    );
}

#[test]
fn fold_prev_kernel_app() {
    check_folding(
        "prev_kernel_app",
        &[("mega_kernel", &MEGA_KERNEL), ("mega_app", &MEGA_APP)],
        true,
    );
}

#[test]
fn fold_single_app() {
    check_folding("single_app", &[("mega_app", &MEGA_APP)], false);
}

#[allow(dead_code)]
fn _unused(_: NativeTranscript) {}
