//! M1 exit: the Rust verifier accepts bb's UltraHonk proofs (ZK and non-ZK) and rejects tampering.
use crate::common;
use bb_ref::base::field::FieldLike;
use bb_ref::base::io::decode_fields;
use bb_ref::base::srs::bn254_g2;
use bb_ref::base::{Bn254, Vk};
use bb_ref::honk::ultra_verifier::verify_ultra;
use bb_ref::honk::{ULTRA, ULTRA_ZK};

fn check(prog: &str, mode: &str) {
    let flavor = if mode == "zk" { &ULTRA_ZK } else { &ULTRA };
    let vk = Vk::<Bn254>::from_bytes(&common::read(&format!("ultra/{prog}/{mode}/vk")), 28);
    let proof = decode_fields(&common::read(&format!("ultra/{prog}/{mode}/proof")));
    let public_inputs = decode_fields(&common::read(&format!("ultra/{prog}/{mode}/public_inputs")));
    let g2 = bn254_g2();
    assert!(
        verify_ultra(flavor, &vk, &public_inputs, &proof, &g2),
        "{prog}/{mode}: bb proof rejected"
    );

    // Tampering with a sumcheck evaluation must be caught by the relation check.
    let mut bad = proof.clone();
    let idx = bad.len() / 2;
    bad[idx] += &bb_ref::base::Fr::one();
    assert!(
        !verify_ultra(flavor, &vk, &public_inputs, &bad, &g2),
        "{prog}/{mode}: tampered proof accepted"
    );
}

macro_rules! fixture_tests {
    ($($name:ident: $prog:literal),* $(,)?) => { $(
        mod $name {
            #[test] fn nozk() { super::check($prog, "nozk"); }
            #[test] fn zk() { super::check($prog, "zk"); }
        }
    )* };
}

fixture_tests! {
    a_1_mul: "a_1_mul",
    array_dynamic: "array_dynamic",
    poseidon: "no_predicates_numeric_generic_poseidon",
    embedded_curve_ops: "embedded_curve_ops",
    ecdsa_secp256k1: "ecdsa_secp256k1",
    unsafe_range_constraint: "unsafe_range_constraint",
    uhashmap: "uhashmap",
}
