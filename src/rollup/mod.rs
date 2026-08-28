//! Backend (rollup-side) recursion: the generic verifiers instantiated in-circuit over ULTRA
//! arithmetic — non-goblin bn254 biggroup commitments with native `FieldT` scalars (bb
//! `UltraRecursiveFlavor_<UltraCircuitBuilder>` / `stdlib::bn254<UltraCircuitBuilder>`).

use crate::base::codec::Transcriptable;
use crate::base::group::PairingPoints;
use crate::base::transcript::Transcript;
use crate::base::vk::Vk;
use crate::honk::flavor::FlavorDesc;
use crate::honk::ultra_verifier::reduce_to_pairing_check;
use crate::stdlib::biggroup::Element;
use crate::stdlib::curve::StdUltraBn254;
use crate::stdlib::hash::StdPoseidon2;
use crate::stdlib::{Ctx, FieldT};

type G = Element<ark_bn254::g1::Config>;

pub struct UltraRecursiveOutput {
    pub points_accumulator: PairingPoints<StdUltraBn254>,
    pub public_inputs: Vec<FieldT>,
}

/// bb `DefaultIO::reconstruct_from_public` (stdlib): the last 8 public inputs as two bigfield
/// elements, in-field-checked and on-curve-asserted.
pub fn reconstruct_default_io(public_inputs: &[FieldT]) -> PairingPoints<StdUltraBn254> {
    assert!(public_inputs.len() >= 8, "public inputs too small for DefaultIO");
    let f = &public_inputs[public_inputs.len() - 8..];
    PairingPoints {
        p0: G::from_fields(&f[0..4]),
        p1: G::from_fields(&f[4..8]),
    }
}

/// bb stdlib `PairingPoints::aggregate` on an Ultra builder: a fresh transcript binds both pairs,
/// then `P_i += sep · other.P_i` with a 128-bit separator.
pub fn aggregate_pair(
    acc: PairingPoints<StdUltraBn254>,
    other: PairingPoints<StdUltraBn254>,
) -> PairingPoints<StdUltraBn254> {
    let mut t = Transcript::<FieldT, StdPoseidon2>::new();
    t.add_to_hash_buffer("Accumulator_P0", &acc.p0);
    t.add_to_hash_buffer("Accumulator_P1", &acc.p1);
    t.add_to_hash_buffer("Aggregated_P0", &other.p0);
    t.add_to_hash_buffer("Aggregated_P1", &other.p1);
    let separator: FieldT = t.short_challenges::<FieldT>(&["recursion_separator"]).pop().unwrap();
    let p0 = acc.p0.add(&other.p0.scalar_mul(&separator, 128));
    let p1 = acc.p1.add(&other.p1.scalar_mul(&separator, 128));
    PairingPoints { p0, p1 }
}

/// bb `UltraVerifier_<UltraRecursiveFlavor_<UltraCircuitBuilder>, DefaultIO>::verify_proof`:
/// reduce to the PCS pairing points, reconstruct the inner circuit's own pairing-point public
/// inputs, and aggregate the two into the output accumulator. `vk_hash` is the witness holding the
/// inner VK's hash (bb `VKAndHash_`), not recomputed in-circuit.
pub fn verify_recursive_ultra(
    flavor: &'static FlavorDesc,
    ctx: &Ctx,
    vk: &Vk<StdUltraBn254>,
    vk_hash: &FieldT,
    proof: &[FieldT],
) -> UltraRecursiveOutput {
    let r = reduce_to_pairing_check::<StdUltraBn254>(flavor, vk, vk_hash, proof, ctx);
    let mut pi_points = reconstruct_default_io(&r.public_inputs);
    pi_points = aggregate_pair(pi_points, r.pcs_pairing_points);
    UltraRecursiveOutput {
        points_accumulator: pi_points,
        public_inputs: r.public_inputs,
    }
}

/// bb `DefaultIO::set_public` on the outer Ultra circuit.
pub fn set_ultra_pairing_points_public(pp: &PairingPoints<StdUltraBn254>) -> u32 {
    let start = pp.p0.set_public();
    pp.p1.set_public();
    start
}

/// bb `StdlibVerificationKey_(builder, native_vk)` + `VKAndHash_`: metadata and commitments as
/// witnesses (commitments via `from_witness`, with on-curve checks), the hash as a plain witness.
pub fn vk_to_witnesses_ultra(ctx: &Ctx, vk: &Vk<crate::base::group::Bn254>) -> (Vk<StdUltraBn254>, FieldT) {
    let f = |v: &crate::base::Fr| FieldT::from_witness(ctx, *v);
    let stdlib_vk = Vk::<StdUltraBn254> {
        log_circuit_size: f(&vk.log_circuit_size),
        num_public_inputs: f(&vk.num_public_inputs),
        pub_inputs_offset: f(&vk.pub_inputs_offset),
        comms: vk.comms.iter().map(|c| Element::from_witness(ctx, c)).collect(),
    };
    let hash = f(&vk.hash());
    (stdlib_vk, hash)
}
