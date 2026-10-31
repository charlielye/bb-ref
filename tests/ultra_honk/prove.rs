//! Proving from bb's dumped UltraZK proving instance with bb's CSPRNG tape replayed reproduces bb's
//! proof byte-for-byte. Reads the `instance/<prog>_tape` dumps (tools/regen/regen_merge.sh).
use crate::common;
use bb_ref::base::io::decode_fields;
use bb_ref::base::rng::{Rng, TapeRng};
use bb_ref::base::{Bn254, CommitmentKey, Vk};
use bb_ref::honk::flavor::Ent;
use bb_ref::honk::prover_instance::ProverInstance;
use bb_ref::honk::ultra_prover::prove_ultra;
use bb_ref::honk::ULTRA_ZK;

/// With bb's CSPRNG tape replayed, the Rust UltraZK proof is byte-identical to bb's. The dumped
/// instance already carries bb's masking values; they must be the tape's first draws.
fn check_zk_tape(prog: &str) {
    let dir = common::fixture_dir(&format!("instance/{prog}_tape/zk"));
    let tape = common::require(dir.join("../rng_tape.bin"), "regen_merge.sh");
    let mut tape = TapeRng::from_bytes(std::fs::read(tape).unwrap());
    let mut inst = ProverInstance::load_dump(&ULTRA_ZK, &dir);
    for e in [
        Ent::w_l,
        Ent::w_r,
        Ent::w_o,
        Ent::w_4,
        Ent::z_perm,
        Ent::lookup_read_counts,
        Ent::lookup_read_tags,
        Ent::lookup_inverses,
    ] {
        for row in 1..4 {
            assert_eq!(
                inst.poly(e).coeffs[row],
                tape.fr(),
                "{prog}: masking of {} row {row}",
                e.name()
            );
        }
    }
    let ck = CommitmentKey::new(inst.max_end_index);
    let vk: Vk<Bn254> = inst.compute_vk(&ck);
    let proof = prove_ultra(&mut inst, &vk, &mut tape);
    let expected = decode_fields(&std::fs::read(dir.join("proof.bin")).unwrap());
    let first_diff = proof.iter().zip(&expected).position(|(a, b)| a != b);
    assert!(
        first_diff.is_none(),
        "{prog}: ZK proof differs from bb at field {}",
        first_diff.unwrap()
    );
    assert_eq!(proof.len(), expected.len(), "{prog}: proof length");
    assert_eq!(tape.remaining(), 0, "{prog}: unconsumed tape bytes");
}

#[test]
fn zk_tape_array_dynamic() {
    check_zk_tape("array_dynamic");
}
#[test]
fn zk_tape_a_1_mul() {
    check_zk_tape("a_1_mul");
}
