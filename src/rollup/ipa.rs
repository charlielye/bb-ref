//! The plain Grumpkin IPA at size 2^CONST_ECCVM_LOG_N (bb `commitment_schemes/ipa/ipa.hpp`,
//! native side): the prover behind every rollup circuit's appended 64-field IPA proof, and the
//! native verifier a rollup proof's IPA tail is checked with.

use crate::base::transcript::Transcript;
use crate::base::{Fq, Fr, GrumpkinAffine, GrumpkinKey, Poseidon2};
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{Field, One, Zero};

pub const LOG_POLY_LENGTH: usize = 15;
pub const POLY_LENGTH: usize = 1 << LOG_POLY_LENGTH;
/// `(4 * CONST_ECCVM_LOG_N) + 4` bn254 fields.
pub const IPA_PROOF_LENGTH: usize = 4 * LOG_POLY_LENGTH + 4;

pub type NativeTranscript = Transcript<Fr, Poseidon2>;

#[derive(Clone, Debug, PartialEq)]
pub struct IpaClaim {
    pub challenge: Fq,
    pub evaluation: Fq,
    pub commitment: GrumpkinAffine,
}

/// Affine MSM over explicit bases.
pub fn msm_affine(points: &[GrumpkinAffine], scalars: &[Fq]) -> GrumpkinAffine {
    msm(points, scalars).into_affine()
}

fn msm(points: &[GrumpkinAffine], scalars: &[Fq]) -> ark_grumpkin::Projective {
    ark_grumpkin::Projective::msm(points, scalars).unwrap()
}

/// `b[i] = challenge^i` (bb `powers_tensor`).
fn powers(challenge: Fq, n: usize) -> Vec<Fq> {
    let mut out = Vec::with_capacity(n);
    let mut p = Fq::one();
    for _ in 0..n {
        out.push(p);
        p *= challenge;
    }
    out
}

/// bb prover-side `add_claim_to_hash_buffer`: commits the polynomial and binds the claim.
pub fn add_claim_to_hash_buffer_prover(
    ck: &GrumpkinKey,
    poly: &[Fq],
    challenge: &Fq,
    evaluation: &Fq,
    t: &mut NativeTranscript,
) {
    let commitment = msm(&ck.points[..poly.len()], poly).into_affine();
    t.add_to_hash_buffer("IPA:commitment", &commitment);
    t.add_to_hash_buffer("IPA:challenge", challenge);
    t.add_to_hash_buffer("IPA:evaluation", evaluation);
}

/// bb verifier-side `add_claim_to_hash_buffer`.
pub fn add_claim_to_hash_buffer_verifier(claim: &IpaClaim, t: &mut NativeTranscript) {
    t.add_to_hash_buffer("IPA:commitment", &claim.commitment);
    t.add_to_hash_buffer("IPA:challenge", &claim.challenge);
    t.add_to_hash_buffer("IPA:evaluation", &claim.evaluation);
}

/// bb `IPA::compute_opening_proof_internal` (single-round folds; bb's two-round variant is a
/// wall-clock optimization with identical proof bytes).
pub fn compute_opening_proof(ck: &GrumpkinKey, poly: &[Fq], challenge: &Fq, t: &mut NativeTranscript) {
    let generator_challenge: Fq = t.challenge("IPA:generator_challenge");
    assert!(
        !Zero::is_zero(&generator_challenge),
        "the generator challenge can't be zero"
    );
    let aux_generator = (GrumpkinAffine::generator() * generator_challenge).into_affine();
    let mut a_vec = poly.to_vec();
    a_vec.resize(POLY_LENGTH, Fq::zero());
    let mut b_vec = powers(*challenge, POLY_LENGTH);
    let mut g_vec: Vec<GrumpkinAffine> = ck.points[..POLY_LENGTH].to_vec();
    let mut round_size = POLY_LENGTH;
    let mut challenge_product = Fq::one();
    for round_idx in 0..LOG_POLY_LENGTH {
        let half = round_size / 2;
        let inner_l: Fq = (0..half).map(|i| a_vec[i] * b_vec[half + i]).sum();
        let inner_r: Fq = (0..half).map(|i| a_vec[half + i] * b_vec[i]).sum();
        let l = (msm(&g_vec[half..2 * half], &a_vec[..half]) + aux_generator * inner_l).into_affine();
        let r = (msm(&g_vec[..half], &a_vec[half..2 * half]) + aux_generator * inner_r).into_affine();
        let index = LOG_POLY_LENGTH - round_idx - 1;
        t.send(&format!("IPA:L_{index}"), &l);
        t.send(&format!("IPA:R_{index}"), &r);
        let u: Fq = t
            .short_challenges(&[&format!("IPA:round_challenge_{index}")])
            .pop()
            .unwrap();
        assert!(!Zero::is_zero(&u), "IPA round challenge is zero");
        let u_inv = u.inverse().unwrap();
        challenge_product *= u;
        for i in 0..half {
            a_vec[i] = u_inv * a_vec[i] + a_vec[half + i];
            b_vec[i] = u * b_vec[i] + b_vec[half + i];
        }
        // The G fold is ~2^16 full scalar muls across the rounds — the dominant cost of this
        // prover — and every element is independent.
        use rayon::prelude::*;
        let folded_g: Vec<ark_grumpkin::Projective> =
            (0..half).into_par_iter().map(|i| g_vec[i] * u + g_vec[half + i]).collect();
        let normalized = ark_grumpkin::Projective::normalize_batch(&folded_g);
        g_vec[..half].copy_from_slice(&normalized);
        round_size = half;
    }
    let challenge_product_inv = challenge_product.inverse().unwrap();
    t.send("IPA:G_0", &(g_vec[0] * challenge_product_inv).into_affine());
    t.send("IPA:a_0", &(a_vec[0] * challenge_product));
}

/// bb `construct_poly_from_u_challenges_inv`: `s[i] = ∏_{j : bit j of i} u_j⁻¹`.
pub fn construct_poly_from_u_challenges_inv(u_challenges_inv: &[Fq]) -> Vec<Fq> {
    assert_eq!(u_challenges_inv.len(), LOG_POLY_LENGTH);
    let mut s = vec![Fq::one(); 1];
    for u in u_challenges_inv.iter().take(LOG_POLY_LENGTH) {
        let mut next = Vec::with_capacity(s.len() * 2);
        for v in &s {
            next.push(*v);
            next.push(*v * u);
        }
        s = next;
    }
    s
}

/// bb `evaluate_challenge_poly`: `∏ (1 + u_{k-1-i}⁻¹ · r^{2^i})`, native.
pub fn evaluate_challenge_poly(u_challenges_inv: &[Fq], r: Fq) -> Fq {
    let mut eval = Fq::one();
    let mut r_pow = r;
    for i in 0..LOG_POLY_LENGTH {
        let idx = if i < LOG_POLY_LENGTH - 1 {
            LOG_POLY_LENGTH - 1 - i
        } else {
            0
        };
        eval *= Fq::one() + u_challenges_inv[idx] * r_pow;
        r_pow = r_pow.square();
    }
    eval
}

/// bb `reduce_verify` (native): the full IPA check of a claim against a 64-field proof.
pub fn reduce_verify(ck: &GrumpkinKey, claim: &IpaClaim, t: &mut NativeTranscript) -> bool {
    add_claim_to_hash_buffer_verifier(claim, t);
    let generator_challenge: Fq = t.challenge("IPA:generator_challenge");
    let aux_generator = GrumpkinAffine::generator() * generator_challenge;
    let c_prime = ark_grumpkin::Projective::from(claim.commitment) + aux_generator * claim.evaluation;
    let mut msm_elements = Vec::with_capacity(2 * LOG_POLY_LENGTH);
    let mut round_challenges = Vec::with_capacity(LOG_POLY_LENGTH);
    for round_idx in 0..LOG_POLY_LENGTH {
        let index = LOG_POLY_LENGTH - round_idx - 1;
        let l: GrumpkinAffine = t.receive(&format!("IPA:L_{index}"));
        let r: GrumpkinAffine = t.receive(&format!("IPA:R_{index}"));
        let u: Fq = t
            .short_challenges(&[&format!("IPA:round_challenge_{index}")])
            .pop()
            .unwrap();
        assert!(!Zero::is_zero(&u), "round challenges can't be zero");
        msm_elements.push(l);
        msm_elements.push(r);
        round_challenges.push(u);
    }
    let round_challenges_inv: Vec<Fq> = round_challenges.iter().map(|u| u.inverse().unwrap()).collect();
    let mut msm_scalars = Vec::with_capacity(2 * LOG_POLY_LENGTH);
    for i in 0..LOG_POLY_LENGTH {
        msm_scalars.push(round_challenges_inv[i]);
        msm_scalars.push(round_challenges[i]);
    }
    let c_zero = c_prime + msm(&msm_elements, &msm_scalars);
    let b_zero = evaluate_challenge_poly(&round_challenges_inv, claim.challenge);
    let s_vec = construct_poly_from_u_challenges_inv(&round_challenges_inv);
    let g_zero_from_prover: GrumpkinAffine = t.receive("IPA:G_0");
    let a_zero: Fq = t.receive("IPA:a_0");
    let g_zero = msm(&ck.points[..POLY_LENGTH], &s_vec).into_affine();
    if g_zero != g_zero_from_prover {
        return false;
    }
    let rhs = ark_grumpkin::Projective::from(g_zero) * a_zero + aux_generator * (a_zero * b_zero);
    c_zero.into_affine() == rhs.into_affine()
}
