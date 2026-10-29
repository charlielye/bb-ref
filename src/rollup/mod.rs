//! Backend (rollup-side) recursion: the generic verifiers instantiated in-circuit over ULTRA
//! arithmetic — non-goblin bn254 biggroup commitments with native `FieldT` scalars (bb
//! `UltraRecursiveFlavor_<UltraCircuitBuilder>` / `stdlib::bn254<UltraCircuitBuilder>`).

pub mod ipa;
pub mod ipa_recursive;

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

type G = Element<crate::base::G1Config>;

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

/// bb stdlib `PairingPoints::aggregate_multiple` (Ultra branch): bind every point in a fresh
/// transcript, draw `n-1` short challenges, then `P_j = P_0 + Σ c_i · P_{i+1}` with one 128-bit
/// scalar mul per point, interleaved P0 then P1.
pub fn aggregate_multiple(points: Vec<PairingPoints<StdUltraBn254>>) -> PairingPoints<StdUltraBn254> {
    assert!(!points.is_empty(), "aggregate_multiple needs at least one pair");
    if points.len() == 1 {
        return points.into_iter().next().unwrap();
    }
    let mut t = Transcript::<FieldT, StdPoseidon2>::new();
    let mut labels = Vec::with_capacity(points.len() - 1);
    for (idx, pp) in points.iter().enumerate() {
        t.add_to_hash_buffer(&format!("first_component_{idx}"), &pp.p0);
        t.add_to_hash_buffer(&format!("second_component_{idx}"), &pp.p1);
        if idx > 0 {
            labels.push(format!("pp_aggregation_challenge_{idx}"));
        }
    }
    let label_refs: Vec<&str> = labels.iter().map(String::as_str).collect();
    let challenges: Vec<FieldT> = t.short_challenges(&label_refs);
    let (mut p0, mut p1) = (points[0].p0.clone(), points[0].p1.clone());
    for (pp, c) in points[1..].iter().zip(&challenges) {
        p0 = p0.add(&pp.p0.scalar_mul(c, 128));
        p1 = p1.add(&pp.p1.scalar_mul(c, 128));
    }
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

/// bb `StdlibVerificationKey_(std::span<FF>)`: a VK from its 115 field-element witnesses (3 meta
/// fields, then 4 limb fields per commitment).
pub fn vk_from_fields(fields: &[FieldT]) -> Vk<StdUltraBn254> {
    assert_eq!(fields.len() % 4, 3, "VK field count");
    let comms = fields[3..].chunks(4).map(G::from_fields).collect();
    Vk::<StdUltraBn254> {
        log_circuit_size: fields[0].clone(),
        num_public_inputs: fields[1].clone(),
        pub_inputs_offset: fields[2].clone(),
        comms,
    }
}

// ---- RollupIO (pairing points + accumulated IPA claim on the public inputs) ----

pub const ROLLUP_PUBLIC_INPUTS_SIZE: usize = 8 + 6;

pub struct RollupRecursiveOutput {
    pub points_accumulator: PairingPoints<StdUltraBn254>,
    pub ipa_claim: ipa_recursive::IpaClaimCt,
    /// The nested proof's 64 IPA-proof fields (witnesses), for the nested reduce-verify.
    pub ipa_proof: Vec<FieldT>,
    pub public_inputs: Vec<FieldT>,
}

/// bb stdlib `RollupIO::reconstruct_from_public`.
pub fn reconstruct_rollup_io(public_inputs: &[FieldT]) -> (PairingPoints<StdUltraBn254>, ipa_recursive::IpaClaimCt) {
    assert!(
        public_inputs.len() >= ROLLUP_PUBLIC_INPUTS_SIZE,
        "public inputs too small for RollupIO"
    );
    let f = &public_inputs[public_inputs.len() - ROLLUP_PUBLIC_INPUTS_SIZE..];
    let pairing = PairingPoints {
        p0: G::from_fields(&f[0..4]),
        p1: G::from_fields(&f[4..8]),
    };
    let claim = ipa_recursive::IpaClaimCt::reconstruct_from_public(&f[8..14]);
    (pairing, claim)
}

/// bb stdlib `RollupIO::set_public`: pairing points then the IPA claim.
pub fn set_rollup_io_public(pairing: &PairingPoints<StdUltraBn254>, claim: &ipa_recursive::IpaClaimCt) -> u32 {
    let start = set_ultra_pairing_points_public(pairing);
    claim.set_public();
    start
}

/// bb stdlib `RollupIO::add_default`: default (infinity) pairing points as fixed zero public inputs,
/// a random valid IPA claim, and its proof left for `builder.ipa_proof`.
pub fn add_default_rollup_io(ctx: &Ctx) -> Vec<crate::base::Fr> {
    // bb constructs the random claim first; the pairing points and claim publish afterwards.
    let ck = crate::base::GrumpkinKey::new(ipa::POLY_LENGTH);
    let (claim, ipa_proof) = ipa_recursive::create_random_valid_ipa_claim_and_proof(ctx, &ck);
    crate::stdlib::io::set_default_pairing_points_public(ctx);
    claim.set_public();
    ctx.borrow_mut().ipa_proof = ipa_proof.clone();
    ipa_proof
}

/// bb `UltraVerifier_<UltraRecursiveFlavor_, RollupIO>::verify_proof`: split the combined proof,
/// reduce the Honk part, aggregate the inner pairing points and pass the inner IPA claim upward.
pub fn verify_recursive_ultra_rollup(
    flavor: &'static FlavorDesc,
    ctx: &Ctx,
    vk: &Vk<StdUltraBn254>,
    vk_hash: &FieldT,
    combined_proof: &[FieldT],
) -> RollupRecursiveOutput {
    let (honk_proof, ipa_proof) = ipa_recursive::split_rollup_proof(combined_proof);
    let r = reduce_to_pairing_check::<StdUltraBn254>(flavor, vk, vk_hash, honk_proof, ctx);
    let (mut pi_points, ipa_claim) = reconstruct_rollup_io(&r.public_inputs);
    pi_points = aggregate_pair(pi_points, r.pcs_pairing_points);
    RollupRecursiveOutput {
        points_accumulator: pi_points,
        ipa_claim,
        ipa_proof: ipa_proof.to_vec(),
        public_inputs: r.public_inputs,
    }
}

/// Native verification of a rollup (UltraFlavor + RollupIO) proof: the Honk part, both pairing
/// checks, and the appended 64-field IPA proof against the published claim.
pub fn verify_ultra_rollup(
    flavor: &FlavorDesc,
    vk: &Vk<crate::base::group::Bn254>,
    public_inputs: &[crate::base::Fr],
    proof: &[crate::base::Fr],
    g2: &crate::base::group::G2Points,
    grumpkin_key: &crate::base::GrumpkinKey,
) -> bool {
    use crate::base::group::Bn254;
    assert!(proof.len() > ipa::IPA_PROOF_LENGTH);
    let (honk_proof, ipa_fields) = proof.split_at(proof.len() - ipa::IPA_PROOF_LENGTH);
    let full: Vec<_> = [public_inputs, honk_proof].concat();
    crate::base::timing::phase("      vfy: start");
    let r = reduce_to_pairing_check::<Bn254>(flavor, vk, &vk.hash(), &full, &());
    crate::base::timing::phase("      vfy: honk reduce");
    if !r.succeeded {
        return false;
    }
    let pis = &r.public_inputs;
    assert!(pis.len() >= ROLLUP_PUBLIC_INPUTS_SIZE);
    let f = &pis[pis.len() - ROLLUP_PUBLIC_INPUTS_SIZE..];
    let pairing = PairingPoints::<Bn254>::from_fields(&f[0..8]);
    let claim = ipa::IpaClaim {
        challenge: <crate::base::Fq as Transcriptable<crate::base::Fr>>::from_fields(&f[8..10]),
        evaluation: <crate::base::Fq as Transcriptable<crate::base::Fr>>::from_fields(&f[10..12]),
        commitment: <crate::base::GrumpkinAffine as Transcriptable<crate::base::Fr>>::from_fields(&f[12..14]),
    };
    let ok = crate::honk::ultra_verifier::aggregate_and_check(&pairing, &r.pcs_pairing_points, g2);
    crate::base::timing::phase("      vfy: pairing");
    if !ok {
        return false;
    }
    let mut t = ipa::NativeTranscript::from_proof(ipa_fields);
    let out = ipa::reduce_verify(grumpkin_key, &claim, &mut t);
    crate::base::timing::phase("      vfy: ipa reduce_verify");
    t.enforce_proof_fully_consumed("UltraVerifier IPA");
    out
}
