//! The in-circuit Grumpkin IPA over ULTRA arithmetic (bb `IPA<stdlib::grumpkin<UltraCircuitBuilder>>`):
//! scalars are bigfield grumpkin-scalars, commitments are native-field `cycle_group` points. A
//! rollup circuit reduces every nested IPA claim to an accumulator, combines the accumulators, and
//! natively re-proves the combined claim (the 64-field proof carried by `builder.ipa_proof`).

use super::ipa::{self, IpaClaim, IPA_PROOF_LENGTH, LOG_POLY_LENGTH, POLY_LENGTH};
use crate::base::codec::{FromChallenge, Transcriptable};
use crate::base::field::{from_u256, U256};
use crate::base::transcript::Transcript;
use crate::base::{Fq, Fr, GrumpkinKey};
use crate::stdlib::bigfield::{BigField, NUM_LIMB_BITS};
use crate::stdlib::cycle_group::{CycleGroup, CycleScalar};
use crate::stdlib::field::split_unique;
use crate::stdlib::hash::StdPoseidon2;
use crate::stdlib::{Ctx, FieldT};
use ark_ec::AffineRepr;

pub type FqCt = BigField<Fq>;
pub type StdlibTranscript = Transcript<FieldT, StdPoseidon2>;

/// bb `StdlibCodec` for a grumpkin scalar: the four 68-bit limbs combined pairwise.
impl Transcriptable<FieldT> for FqCt {
    fn num_fields() -> usize {
        2
    }
    fn to_fields(&self) -> Vec<FieldT> {
        let shift = FieldT::constant(from_u256(U256::from(1u64) << NUM_LIMB_BITS as u32));
        vec![
            FieldT::add(
                &self.get_limb(0).element,
                &FieldT::mul(&self.get_limb(1).element, &shift),
            ),
            FieldT::add(
                &self.get_limb(2).element,
                &FieldT::mul(&self.get_limb(3).element, &shift),
            ),
        ]
    }
    fn from_fields(f: &[FieldT]) -> Self {
        let v = FqCt::from_halves(&f[0], &f[1], false, 0);
        v.assert_is_in_field();
        v
    }
}

/// bb `StdlibCodec::convert_full_challenge` / `convert_short_challenge` to `fq`.
impl FromChallenge<FieldT> for FqCt {
    fn full(c: FieldT) -> Self {
        let (low_bits, high_bits) = split_unique(&c, 2 * NUM_LIMB_BITS as u32);
        FqCt::from_halves(&low_bits, &high_bits, false, 0)
    }
    fn short(c: FieldT) -> Self {
        let ctx = c.ctx.clone().unwrap();
        let zero_idx = ctx.borrow().zero_idx();
        let high_limb = FieldT::from_witness_index(&ctx, zero_idx);
        FqCt::from_halves(&c, &high_limb, false, 0)
    }
}

/// bb `StdlibCodec` for a grumpkin commitment: the two native-field coordinates, on-curve-checked
/// (and `(0, 0)`-is-infinity) on read.
impl Transcriptable<FieldT> for CycleGroup {
    fn num_fields() -> usize {
        2
    }
    fn to_fields(&self) -> Vec<FieldT> {
        // bb StdlibCodec canonicalizes: (0,0) for infinity points.
        let zero = FieldT::constant(crate::base::Fr::from(0u64));
        vec![
            FieldT::conditional_assign(&self.is_infinity, &zero, &self.x),
            FieldT::conditional_assign(&self.is_infinity, &zero, &self.y),
        ]
    }
    fn from_fields(f: &[FieldT]) -> Self {
        CycleGroup::from_xy(f[0].clone(), f[1].clone(), true)
    }
}

/// bb `IpaAccumulator<stdlib::grumpkin>`.
pub struct IpaAccumulatorCt {
    pub u_challenges_inv: Vec<FqCt>,
    pub comm: CycleGroup,
}

/// bb in-circuit `OpeningClaim<stdlib::grumpkin>`.
#[derive(Clone)]
pub struct IpaClaimCt {
    pub challenge: FqCt,
    pub evaluation: FqCt,
    pub commitment: CycleGroup,
}

impl IpaClaimCt {
    pub fn value(&self) -> IpaClaim {
        IpaClaim {
            challenge: self.challenge.get_native_value(),
            evaluation: self.evaluation.get_native_value(),
            commitment: self.commitment.get_value(),
        }
    }
    /// bb `OpeningClaim::set_public`: challenge, evaluation, commitment.
    pub fn set_public(&self) -> u32 {
        let start = self.challenge.set_public();
        self.evaluation.set_public();
        self.commitment.set_public();
        start
    }
    /// bb `OpeningClaim::reconstruct_from_public` (6 fields).
    pub fn reconstruct_from_public(f: &[FieldT]) -> Self {
        Self {
            challenge: FqCt::from_fields(&f[0..2]),
            evaluation: FqCt::from_fields(&f[2..4]),
            commitment: CycleGroup::from_fields(&f[4..6]),
        }
    }
}

fn add_claim_to_hash_buffer_ct(claim: &IpaClaimCt, t: &mut StdlibTranscript) {
    t.add_to_hash_buffer("IPA:commitment", &claim.commitment);
    t.add_to_hash_buffer("IPA:challenge", &claim.challenge);
    t.add_to_hash_buffer("IPA:evaluation", &claim.evaluation);
}

/// bb in-circuit `evaluate_challenge_poly`: `∏ (1 + u⁻¹ · r^{2^i})` in bigfield arithmetic.
fn evaluate_challenge_poly_ct(u_challenges_inv: &[FqCt], r: &FqCt) -> FqCt {
    let one = FqCt::from_u64(1);
    let mut eval = one.clone();
    let mut r_pow = r.clone();
    for i in 0..LOG_POLY_LENGTH {
        let idx = if i < LOG_POLY_LENGTH - 1 {
            LOG_POLY_LENGTH - 1 - i
        } else {
            0
        };
        let monomial = u_challenges_inv[idx].mul(&r_pow);
        eval = eval.mul(&one.add(&monomial));
        if i < LOG_POLY_LENGTH - 1 {
            r_pow = r_pow.sqr();
        }
    }
    eval
}

/// bb `IPA<stdlib::grumpkin>::reduce_verify`: verify a claim's 64-field proof in-circuit, up to the
/// deferred `G_0` SRS check, returning the accumulator.
pub fn reduce_verify_ct(ctx: &Ctx, claim: &IpaClaimCt, t: &mut StdlibTranscript) -> IpaAccumulatorCt {
    add_claim_to_hash_buffer_ct(claim, t);
    let generator_challenge: FqCt = t.challenge("IPA:generator_challenge");
    let pippenger_size = 2 * LOG_POLY_LENGTH + 2;
    let mut round_challenges_inv: Vec<FqCt> = Vec::with_capacity(LOG_POLY_LENGTH);
    let mut msm_elements: Vec<CycleGroup> = Vec::with_capacity(pippenger_size);
    let mut msm_scalars: Vec<FqCt> = Vec::with_capacity(pippenger_size);
    for round_idx in 0..LOG_POLY_LENGTH {
        let index = LOG_POLY_LENGTH - round_idx - 1;
        let element_l: CycleGroup = t.receive(&format!("IPA:L_{index}"));
        let element_r: CycleGroup = t.receive(&format!("IPA:R_{index}"));
        let u: FqCt = t
            .short_challenges(&[&format!("IPA:round_challenge_{index}")])
            .pop()
            .unwrap();
        let u_inv = u.invert();
        msm_elements.push(element_l);
        msm_elements.push(element_r);
        msm_scalars.push(u_inv.clone());
        msm_scalars.push(u);
        round_challenges_inv.push(u_inv);
    }
    let b_zero = evaluate_challenge_poly_ct(&round_challenges_inv, &claim.challenge);
    let g_zero: CycleGroup = t.receive("IPA:G_0");
    let a_zero: FqCt = t.receive("IPA:a_0");
    msm_elements.push(g_zero.neg());
    msm_elements.push(CycleGroup::constant(crate::base::GrumpkinAffine::generator()).neg());
    msm_scalars.push(a_zero.clone());
    msm_scalars.push(generator_challenge.mul(&a_zero.madd(&b_zero, &[claim.evaluation.neg()])));
    let cycle_scalars: Vec<CycleScalar> = msm_scalars.iter().map(CycleScalar::from_bigfield).collect();
    let mut ipa_relation = CycleGroup::batch_mul(&msm_elements, &cycle_scalars);
    let mut neg_commitment = claim.commitment.neg();
    ipa_relation.assert_equal(&mut neg_commitment);
    let _ = ctx;
    IpaAccumulatorCt {
        u_challenges_inv: round_challenges_inv,
        comm: g_zero,
    }
}

/// Native proving of an accumulated challenge-poly claim (bb `prove_challenge_poly_opening`); the
/// in-circuit evaluation is self-reduced afterwards like bb.
fn prove_challenge_poly_opening(ck: &GrumpkinKey, claim: &IpaClaimCt, challenge_poly: &[Fq]) -> Vec<Fr> {
    let challenge = claim.challenge.get_native_value();
    let evaluation = claim.evaluation.get_native_value();
    let native_eval: Fq = challenge_poly
        .iter()
        .rev()
        .fold(Fq::from(0u64), |acc, c| acc * challenge + c);
    assert_eq!(
        native_eval, evaluation,
        "opening claim does not hold for challenge polynomial"
    );
    let mut t = ipa::NativeTranscript::new();
    ipa::add_claim_to_hash_buffer_prover(ck, challenge_poly, &challenge, &evaluation, &mut t);
    ipa::compute_opening_proof(ck, challenge_poly, &challenge, &mut t);
    claim.evaluation.self_reduce();
    t.export_proof()
}

/// bb `IPA::full_verify_recursive`: reduce, then recompute `G_zero` from the round challenges by
/// an in-circuit MSM over the (constant) SRS. The first SRS point is handled via a plain scalar
/// mul so the plookup-table rows stay within `2^23` (bb's comment on table sizing).
pub fn full_verify_ct(ctx: &Ctx, claim: &IpaClaimCt, t: &mut StdlibTranscript) {
    let acc = reduce_verify_ct(ctx, claim, t);
    let round_challenges_inv = &acc.u_challenges_inv;
    let mut claimed_g_zero = acc.comm;

    // s_vec[r] = prod (u_i)^{-r_i}, computed with bb's linear-time doubling algorithm.
    let one = FqCt::one();
    let mut s_vec_temporaries: Vec<FqCt> = vec![one.clone(); POLY_LENGTH / 2];
    let mut s_vec: Vec<FqCt> = vec![one.clone(); POLY_LENGTH];
    let (mut previous_round_s, mut current_round_s): (&mut [FqCt], &mut [FqCt]) = if LOG_POLY_LENGTH % 2 == 0 {
        (&mut s_vec, &mut s_vec_temporaries)
    } else {
        (&mut s_vec_temporaries, &mut s_vec)
    };
    previous_round_s[0] = one;
    for (i, round_challenge) in round_challenges_inv.iter().enumerate().take(LOG_POLY_LENGTH) {
        let round_size = 1usize << (i + 1);
        for j in 0..round_size / 2 {
            current_round_s[j * 2] = previous_round_s[j].clone();
            current_round_s[j * 2 + 1] = previous_round_s[j].mul(round_challenge);
        }
        std::mem::swap(&mut previous_round_s, &mut current_round_s);
    }
    let srs = GrumpkinKey::new(POLY_LENGTH);
    let first_term = CycleGroup::batch_mul(
        &[CycleGroup::constant(srs.points[0])],
        &[CycleScalar::from_bigfield(&s_vec[0])],
    );
    let remaining_points: Vec<CycleGroup> = srs.points[1..POLY_LENGTH]
        .iter()
        .map(|p| CycleGroup::constant(*p))
        .collect();
    let remaining_scalars: Vec<CycleScalar> = s_vec[1..].iter().map(CycleScalar::from_bigfield).collect();
    let remaining_term = CycleGroup::fixed_batch_mul(&remaining_points, &remaining_scalars, 8);
    let mut computed_g_zero = first_term.add(&remaining_term);
    claimed_g_zero.assert_equal(&mut computed_g_zero);
}

/// bb `IPA::accumulate` on two accumulators: bind both, squeeze `alpha`/`r`, combine, natively
/// re-prove the combined challenge polynomial.
pub fn accumulate(ck: &GrumpkinKey, acc_1: IpaAccumulatorCt, acc_2: IpaAccumulatorCt) -> (IpaClaimCt, Vec<Fr>) {
    let mut t = StdlibTranscript::new();
    for u in &acc_1.u_challenges_inv {
        t.add_to_hash_buffer("u_challenges_inv_1", u);
    }
    t.add_to_hash_buffer("U_1", &acc_1.comm);
    for u in &acc_2.u_challenges_inv {
        t.add_to_hash_buffer("u_challenges_inv_2", u);
    }
    t.add_to_hash_buffer("U_2", &acc_2.comm);
    let mut ar: Vec<FqCt> = t.challenges(&["IPA:alpha", "IPA:r"]);
    let r = ar.pop().unwrap();
    let alpha = ar.pop().unwrap();
    let scaled = CycleGroup::batch_mul(&[acc_2.comm.clone()], &[CycleScalar::from_bigfield(&alpha)]);
    let commitment = acc_1.comm.add(&scaled);
    let e1 = evaluate_challenge_poly_ct(&acc_1.u_challenges_inv, &r);
    let e2 = evaluate_challenge_poly_ct(&acc_2.u_challenges_inv, &r);
    let evaluation = e1.add(&alpha.mul(&e2));
    let claim = IpaClaimCt {
        challenge: r,
        evaluation,
        commitment,
    };
    let u1: Vec<Fq> = acc_1.u_challenges_inv.iter().map(BigField::get_native_value).collect();
    let u2: Vec<Fq> = acc_2.u_challenges_inv.iter().map(BigField::get_native_value).collect();
    let alpha_native = alpha.get_native_value();
    let poly1 = ipa::construct_poly_from_u_challenges_inv(&u1);
    let poly2 = ipa::construct_poly_from_u_challenges_inv(&u2);
    let challenge_poly: Vec<Fq> = poly1.iter().zip(&poly2).map(|(a, b)| *a + alpha_native * b).collect();
    let proof = prove_challenge_poly_opening(ck, &claim, &challenge_poly);
    (claim, proof)
}

/// bb `IPA::prove_accumulator_claim`: the single-accumulator variant.
pub fn prove_accumulator_claim(ck: &GrumpkinKey, acc: IpaAccumulatorCt) -> (IpaClaimCt, Vec<Fr>) {
    let mut t = StdlibTranscript::new();
    for u in &acc.u_challenges_inv {
        t.add_to_hash_buffer("u_challenges_inv", u);
    }
    t.add_to_hash_buffer("U", &acc.comm);
    let r: FqCt = t.challenge("IPA:r");
    let evaluation = evaluate_challenge_poly_ct(&acc.u_challenges_inv, &r);
    let claim = IpaClaimCt {
        challenge: r,
        evaluation,
        commitment: acc.comm,
    };
    let u: Vec<Fq> = acc.u_challenges_inv.iter().map(BigField::get_native_value).collect();
    let challenge_poly = ipa::construct_poly_from_u_challenges_inv(&u);
    let proof = prove_challenge_poly_opening(ck, &claim, &challenge_poly);
    (claim, proof)
}

/// bb `IPA::create_random_valid_ipa_claim_and_proof`: a random polynomial opened at a random point,
/// drawn from the global engine, witnessed into the circuit.
pub fn create_random_valid_ipa_claim_and_proof(ctx: &Ctx) -> (IpaClaimCt, Vec<Fr>) {
    let ck = GrumpkinKey::new(POLY_LENGTH);
    let poly: Vec<Fq> = (0..POLY_LENGTH).map(|_| crate::base::rng::global_field()).collect();
    let x: Fq = crate::base::rng::global_field();
    let eval: Fq = poly.iter().rev().fold(Fq::from(0u64), |acc, c| acc * x + c);
    let commitment = super::ipa::msm_affine(&ck.points[..poly.len()], &poly);
    let mut t = ipa::NativeTranscript::new();
    ipa::add_claim_to_hash_buffer_prover(&ck, &poly, &x, &eval, &mut t);
    ipa::compute_opening_proof(&ck, &poly, &x, &mut t);
    // bb creates the stdlib witnesses in order: commitment, challenge, evaluation.
    let commitment_ct = CycleGroup::from_witness(ctx, commitment);
    let claim = IpaClaimCt {
        challenge: FqCt::from_witness(ctx, &x),
        evaluation: FqCt::from_witness(ctx, &eval),
        commitment: commitment_ct,
    };
    (claim, t.export_proof())
}

/// The 64 IPA-proof fields of a combined rollup proof, as witnesses.
pub fn split_rollup_proof(proof: &[FieldT]) -> (&[FieldT], &[FieldT]) {
    assert!(proof.len() > IPA_PROOF_LENGTH);
    proof.split_at(proof.len() - IPA_PROOF_LENGTH)
}
