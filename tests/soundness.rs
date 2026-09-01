//! Verifier soundness, standalone: prove tiny self-built circuits and demand every tampered proof
//! is rejected. No bb binary, no corpus, no committed fixtures — the valid artifact is produced
//! in-process, so what is tested is bb-ref's own accept/reject boundary.
//!
//! Structure per protocol: prove once honestly, verify once (positive control), then
//! (a) flip every proof element in turn, (b) flip every public input, (c) tamper the VK,
//! (d) truncate the proof — each variant must fail verification. Verifiers panic on malformed
//! structure (bb aborts there too); a panic counts as a rejection, exactly as the msgpack
//! boundary's catch_unwind treats it.

use bb_ref::acir::lower::add_default_pairing_points;
use bb_ref::base::field::FieldLike;
use bb_ref::base::rng::{DebugRng, Rng};
use bb_ref::base::srs::{bn254_g2, CommitmentKey};
use bb_ref::base::{Bn254, Fr, KeccakBn254, Vk, U256};
use bb_ref::circuit::builder::AddQuad;
use bb_ref::circuit::Builder;
use bb_ref::honk::flavor::FlavorDesc;
use bb_ref::honk::prover_instance::ProverInstance;
use bb_ref::honk::ultra_prover::{prove_ultra, prove_ultra_as};
use bb_ref::honk::ultra_verifier::{verify_ultra, verify_ultra_keccak};
use bb_ref::honk::{ULTRA, ULTRA_KECCAK, ULTRA_ZK};
use std::panic::{catch_unwind, AssertUnwindSafe};

/// One add gate over random witnesses and one real public input; no IO tail (the caller adds the
/// DefaultIO or RollupIO tail its flavor expects).
fn bare_circuit(rng: &mut dyn Rng) -> Builder {
    let mut b = Builder::new();
    let (x, y, z) = (rng.fr(), rng.fr(), rng.fr());
    let one = Fr::one();
    let g = AddQuad {
        a: b.add_variable(x),
        b: b.add_variable(y),
        c: b.add_variable(z),
        d: b.add_variable(x + y + z),
        a_scaling: one,
        b_scaling: one,
        c_scaling: one,
        d_scaling: -one,
        const_scaling: Fr::zero(),
    };
    let a_idx = g.a;
    b.create_big_add_gate(g, false);
    b.set_public_input(a_idx);
    b
}

/// bare_circuit plus the DefaultIO tail every non-rollup bb circuit carries (two pairing points at
/// infinity as eight zero public inputs).
fn tiny_circuit(rng: &mut dyn Rng) -> Builder {
    let mut b = bare_circuit(rng);
    add_default_pairing_points(&mut b);
    b
}

fn rejected(verify: impl FnOnce() -> bool) -> bool {
    catch_unwind(AssertUnwindSafe(verify)).map(|ok| !ok).unwrap_or(true)
}

/// The harness: honest accept, then every single-element proof flip, every public-input flip,
/// VK metadata + commitment tampers, and truncation must all be rejected.
fn tamper_suite(
    label: &str,
    public_inputs: &[Fr],
    proof: &[Fr],
    verify: &(dyn Fn(&[Fr], &[Fr], &Vk<Bn254>) -> bool + Sync),
    vk: &Vk<Bn254>,
) {
    assert!(verify(public_inputs, proof, vk), "{label}: honest proof must verify");

    for i in 0..proof.len() {
        let mut p = proof.to_vec();
        p[i] += Fr::one();
        assert!(
            rejected(|| verify(public_inputs, &p, vk)),
            "{label}: flipped proof element {i} of {} must be rejected",
            proof.len()
        );
    }
    for i in 0..public_inputs.len() {
        let mut pi = public_inputs.to_vec();
        pi[i] += Fr::one();
        assert!(
            rejected(|| verify(&pi, proof, vk)),
            "{label}: flipped public input {i} must be rejected"
        );
    }
    let mut wrong_meta = vk.clone();
    wrong_meta.pub_inputs_offset += Fr::one();
    assert!(
        rejected(|| verify(public_inputs, proof, &wrong_meta)),
        "{label}: tampered VK metadata must be rejected"
    );
    let mut wrong_comm = vk.clone();
    wrong_comm.comms[0] = (wrong_comm.comms[0] + wrong_comm.comms[1]).into();
    assert!(
        rejected(|| verify(public_inputs, proof, &wrong_comm)),
        "{label}: tampered VK commitment must be rejected"
    );
    assert!(
        rejected(|| verify(public_inputs, &proof[..proof.len() - 1], vk)),
        "{label}: truncated proof must be rejected"
    );
    // Negative control: an untouched second verification still passes (the harness itself does
    // not corrupt shared state).
    assert!(verify(public_inputs, proof, vk), "{label}: control re-verification");
}

fn prove_split(flavor: &'static FlavorDesc, rng: &mut DebugRng) -> (Vec<Fr>, Vec<Fr>, Vk<Bn254>) {
    let mut builder = tiny_circuit(rng);
    let mut inst = ProverInstance::from_builder(flavor, &mut builder, rng);
    let ck = CommitmentKey::new(inst.max_end_index);
    let vk = inst.compute_vk(&ck);
    let num_inner = inst.public_inputs.len() - 8;
    let full = prove_ultra(&mut inst, &vk, rng);
    let (pis, proof) = full.split_at(inst.public_inputs.len());
    // bb's wire split keeps the IO tail (the pairing points) with the proof.
    let (inner, io_tail) = pis.split_at(num_inner);
    let mut proof_with_io = io_tail.to_vec();
    proof_with_io.extend_from_slice(proof);
    (inner.to_vec(), proof_with_io, vk)
}

#[test]
fn ultra_rejects_every_tamper() {
    let mut rng = DebugRng::new(1);
    let (pis, proof, vk) = prove_split(&ULTRA, &mut rng);
    let g2 = bn254_g2();
    tamper_suite("ultra", &pis, &proof, &|pi, pf, vk| verify_ultra(&ULTRA, vk, pi, pf, &g2), &vk);
}

#[test]
fn ultra_zk_rejects_every_tamper() {
    let mut rng = DebugRng::new(2);
    let (pis, proof, vk) = prove_split(&ULTRA_ZK, &mut rng);
    let g2 = bn254_g2();
    tamper_suite("ultra_zk", &pis, &proof, &|pi, pf, vk| verify_ultra(&ULTRA_ZK, vk, pi, pf, &g2), &vk);
}

#[test]
fn keccak_rejects_every_tamper() {
    let mut rng = DebugRng::new(3);
    let mut builder = tiny_circuit(&mut rng);
    let mut inst = ProverInstance::from_builder(&ULTRA_KECCAK, &mut builder, &mut rng);
    let ck = CommitmentKey::new(inst.max_end_index);
    let vk_native = inst.compute_vk(&ck);
    let vk = bb_ref::msgpack::handler::as_keccak_vk(vk_native);
    let num_inner = inst.public_inputs.len() - 8;
    let full = prove_ultra_as::<KeccakBn254>(&mut inst, &vk, &mut rng);
    let (pis_w, proof_w) = full.split_at(inst.public_inputs.len());
    let (inner, io_tail) = pis_w.split_at(num_inner);
    let mut proof_with_io = io_tail.to_vec();
    proof_with_io.extend_from_slice(proof_w);
    let g2 = bn254_g2();

    let to_fr = |w: &U256| bb_ref::base::field::from_u256::<Fr>(*w);
    let inner_fr: Vec<Fr> = inner.iter().map(to_fr).collect();
    let verify = |pi: &[Fr], pf: &[U256]| -> bool {
        verify_ultra_keccak(&ULTRA_KECCAK, &vk, pi, pf, &g2)
    };
    assert!(verify(&inner_fr, &proof_with_io), "keccak: honest proof must verify");
    for i in 0..proof_with_io.len() {
        let mut p = proof_with_io.clone();
        // U256 has no arithmetic ops; flip the low bit instead.
        p[i].0[0] ^= 1;
        assert!(
            rejected(|| verify(&inner_fr, &p)),
            "keccak: flipped proof element {i} must be rejected"
        );
    }
    assert!(verify(&inner_fr, &proof_with_io), "keccak: control re-verification");
}

/// Rollup flavor (UltraFlavor + RollupIO + IPA tail): the circuit carries a random valid IPA claim
/// and its 64-field proof; verification covers the Honk proof, both pairing points, and the IPA
/// reduction — a tamper anywhere in that combined surface must be rejected.
#[test]
fn rollup_rejects_every_tamper() {
    use bb_ref::rollup::{add_default_rollup_io, verify_ultra_rollup};
    use std::cell::RefCell;
    use std::rc::Rc;

    let mut rng = DebugRng::new(4);
    // The RollupIO tail draws from the global engine (bb parity); seed it for determinism.
    bb_ref::base::rng::set_global(Box::new(DebugRng::new(4)));
    let ctx = Rc::new(RefCell::new(bare_circuit(&mut rng)));
    add_default_rollup_io(&ctx);
    let mut builder = Rc::try_unwrap(ctx).ok().unwrap().into_inner();
    let mut inst = ProverInstance::from_builder(&ULTRA, &mut builder, &mut rng);
    let ck = CommitmentKey::new(inst.max_end_index);
    let vk = inst.compute_vk(&ck);
    let num_inner = inst.public_inputs.len() - bb_ref::rollup::ROLLUP_PUBLIC_INPUTS_SIZE;
    let full = prove_ultra(&mut inst, &vk, &mut rng);
    let (pis, honk_proof) = full.split_at(inst.public_inputs.len());
    let (inner, io_tail) = pis.split_at(num_inner);
    // wire layout: [IO tail][honk proof][ipa tail] — prove_ultra appends the IPA tail itself.
    let mut proof = io_tail.to_vec();
    proof.extend_from_slice(honk_proof);

    let g2 = bn254_g2();
    let grumpkin = bb_ref::base::srs::GrumpkinKey::new(1 << 16);
    let inner = inner.to_vec();
    let verify = |pi: &[Fr], pf: &[Fr], vk: &Vk<Bn254>| -> bool {
        verify_ultra_rollup(&ULTRA, vk, pi, pf, &g2, &grumpkin)
    };
    tamper_suite("rollup", &inner, &proof, &verify, &vk);
}
