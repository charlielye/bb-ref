//! The inner-product argument over Grumpkin (bb `commitment_schemes/ipa/ipa.hpp`) and the TripleIPA
//! (bb `triple_ipa/triple_ipa.hpp`) that opens the ECCVM's batched multilinear claim, its shifted
//! claim and a univariate claim with a single inner-product proof. Native only: Chonk's client verifier
//! runs the ECCVM verifier natively, and Grumpkin openings are discharged as accumulators.

use crate::base::field::FieldLike;
use crate::base::poly::{eq_table, Polynomial};
use crate::base::{Fq, GrumpkinAffine, GrumpkinKey, NativeTranscript};
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};

type P = Polynomial<Fq>;
type Proj = ark_grumpkin::Projective;

fn msm(points: &[GrumpkinAffine], scalars: &[Fq]) -> Proj {
    Proj::msm_unchecked(points, scalars)
}

/// `[1, r, r^2, ..., r^{n-1}]` (bb `IPA::powers_tensor`).
pub fn powers_tensor(r: &Fq, n: usize) -> Vec<Fq> {
    let mut out = vec![Fq::one()];
    for i in 1..n {
        out.push(out[i - 1] * r);
    }
    out
}

/// `s[i] = ∏_{bits j of i} u_inv[log_n - 1 - j]`, the coefficients of the folded generator `G_0`
/// (bb `IPA::construct_poly_from_u_challenges_inv`).
pub fn challenge_poly(u_inv: &[Fq]) -> P {
    let mut s = vec![Fq::one()];
    for u in u_inv {
        s = s.iter().flat_map(|prev| [*prev, *prev * u]).collect();
    }
    P::from_coeffs(s)
}

/// `∏_{i} (1 + u_inv[log_n - 1 - i] r^{2^i})`, the univariate `s(r)` (bb `IPA::evaluate_challenge_poly`).
pub fn evaluate_challenge_poly(u_inv: &[Fq], r: &Fq) -> Fq {
    let log_n = u_inv.len();
    let mut result = Fq::one();
    let mut r_pow = *r;
    for i in 0..log_n {
        result *= Fq::one() + u_inv[log_n - 1 - i] * r_pow;
        r_pow = r_pow.sqr();
    }
    result
}

/// bb `IPA::compute_inner_product_proof_internal`, folding one round at a time (bb's two-round fold
/// sends the same `L`/`R`). Proves `⟨a, G⟩ = C` and `⟨a, b⟩ = v` for the witness `a` and the tensor `b`.
pub fn inner_product_prove(ck: &GrumpkinKey, witness: &P, mut b: Vec<Fq>, t: &mut NativeTranscript) {
    let gen_challenge: Fq = t.challenge("IPA:generator_challenge");
    assert!(!gen_challenge.is_zero(), "the generator challenge can't be zero");
    let aux_generator = GrumpkinAffine::generator() * gen_challenge;
    let n = witness.len();
    assert!(n.is_power_of_two() && b.len() == n);
    let log_n = n.trailing_zeros() as usize;
    let mut a = witness.coeffs.clone();
    let mut g = ck.points[..n].to_vec();
    let mut challenge_product = Fq::one();
    for round in 0..log_n {
        let half = n >> (round + 1);
        let inner_l: Fq = (0..half).map(|i| a[i] * b[half + i]).sum();
        let inner_r: Fq = (0..half).map(|i| a[half + i] * b[i]).sum();
        let l = msm(&g[half..2 * half], &a[..half]) + aux_generator * inner_l;
        let r = msm(&g[..half], &a[half..2 * half]) + aux_generator * inner_r;
        let index = log_n - round - 1;
        t.send(&format!("IPA:L_{index}"), &l.into_affine());
        t.send(&format!("IPA:R_{index}"), &r.into_affine());
        let u: Fq = t.short_challenge(&format!("IPA:round_challenge_{index}"));
        assert!(!u.is_zero(), "IPA round challenge is zero");
        let u_inv = u.invert();
        challenge_product *= u;
        for i in 0..half {
            a[i] = u_inv * a[i] + a[half + i];
            b[i] = u * b[i] + b[half + i];
        }
        g = Proj::normalize_batch(&(0..half).map(|i| g[i] * u + g[half + i]).collect::<Vec<_>>());
    }
    t.send("IPA:G_0", &(g[0] * challenge_product.invert()).into_affine());
    t.send("IPA:a_0", &(a[0] * challenge_product));
}

/// A verified-but-undischarged IPA: `claimed_commitment` must equal `⟨s(u_inv), SRS⟩`
/// (bb `IPA::NativeAccumulator`).
pub struct IpaAccumulator {
    pub u_challenges_inv: Vec<Fq>,
    pub claimed_commitment: GrumpkinAffine,
    pub relation_succeeded: bool,
}

/// bb `IPA::read_inner_product_transcript_data` + the group relation of `reduce_to_accumulator_internal`:
/// checks `C + v U + Σ (u_j^{-1} L_j + u_j R_j) == a_0 G_0 + a_0 b_0 U` with `b_0 = b_zero(u_inv)`.
pub fn inner_product_reduce_to_accumulator(commitment: &GrumpkinAffine, evaluation: &Fq, b_zero: impl Fn(&[Fq]) -> Fq, log_n: usize, t: &mut NativeTranscript) -> IpaAccumulator {
    let gen_challenge: Fq = t.challenge("IPA:generator_challenge");
    assert!(!gen_challenge.is_zero(), "the generator challenge can't be zero");
    let aux_generator = GrumpkinAffine::generator() * gen_challenge;
    let mut c_zero = commitment.into_group() + aux_generator * evaluation;
    let mut u_inv = Vec::with_capacity(log_n);
    for round in 0..log_n {
        let index = log_n - round - 1;
        let l: GrumpkinAffine = t.receive(&format!("IPA:L_{index}"));
        let r: GrumpkinAffine = t.receive(&format!("IPA:R_{index}"));
        let u: Fq = t.short_challenge(&format!("IPA:round_challenge_{index}"));
        assert!(!u.is_zero(), "round challenges can't be zero");
        u_inv.push(u.invert());
        c_zero += l * u_inv[round] + r * u;
    }
    let b_zero = b_zero(&u_inv);
    let g_zero: GrumpkinAffine = t.receive("IPA:G_0");
    let a_zero: Fq = t.receive("IPA:a_0");
    let rhs = g_zero * a_zero + aux_generator * (a_zero * b_zero);
    IpaAccumulator { u_challenges_inv: u_inv, claimed_commitment: g_zero, relation_succeeded: c_zero == rhs }
}

/// bb `IPA::batch_verify_accumulators`: one SRS MSM settles every accumulator's claimed `G_0`.
pub fn batch_verify_accumulators(srs: &GrumpkinKey, accumulators: &[IpaAccumulator]) -> bool {
    if accumulators.is_empty() {
        return true;
    }
    let mut t = NativeTranscript::new();
    for (idx, acc) in accumulators.iter().enumerate() {
        for u in &acc.u_challenges_inv {
            t.add_to_hash_buffer(&format!("IPA:batch_u_{idx}"), u);
        }
        t.add_to_hash_buffer(&format!("IPA:batch_U_{idx}"), &acc.claimed_commitment);
    }
    let rho: Fq = t.challenge("IPA:batch_rho");
    let n = 1 << accumulators[0].u_challenges_inv.len();
    let mut combined = P::zero(n);
    let mut combined_commitment = Proj::default();
    let mut rho_power = Fq::one();
    for acc in accumulators {
        combined.add_scaled(&challenge_poly(&acc.u_challenges_inv), &rho_power);
        combined_commitment += acc.claimed_commitment * rho_power;
        rho_power *= rho;
    }
    msm(&srs.points[..n], &combined.coeffs) == combined_commitment && accumulators.iter().all(|a| a.relation_succeeded)
}

// ---------------------------------------------------------------------------------------------
// TripleIPA
// ---------------------------------------------------------------------------------------------

/// Everything the verifier knows about the three claims (bb `TripleIpaClaimData`): the batched
/// unshifted claim `F(u) = Σ ρ_i v_i`, the batched shifted claim `F'_shift(u)` whose sources are
/// `shifted_commitments`, and the univariate claim `P(x) = v_P`.
pub struct TripleIpaClaims {
    pub unshifted_commitments: Vec<GrumpkinAffine>,
    pub unshifted_evaluations: Vec<Fq>,
    pub unshifted_rho_powers: Vec<Fq>,
    pub shifted_commitments: Vec<GrumpkinAffine>,
    /// The sources' own (unshifted) evaluations at `u`, reused for the `⟨F', eq⟩` cross sum.
    pub shifted_source_evaluations: Vec<Fq>,
    pub shifted_evaluations: Vec<Fq>,
    pub shifted_rho_powers: Vec<Fq>,
    pub multilinear_challenge: Vec<Fq>,
    pub univariate_commitment: GrumpkinAffine,
    pub univariate_challenge: Fq,
    pub univariate_evaluation: Fq,
}

/// The batched form of [`TripleIpaClaims`] (bb `TripleIpaClaim`).
pub struct TripleIpaClaim {
    pub unshifted_commitment: GrumpkinAffine,
    pub unshifted_evaluation: Fq,
    pub shifted_commitment: GrumpkinAffine,
    pub shifted_evaluation: Fq,
    pub univariate_commitment: GrumpkinAffine,
    pub univariate_challenge: Fq,
    pub univariate_evaluation: Fq,
    pub multilinear_challenge: Vec<Fq>,
}

/// `ρ^offset, ..., ρ^{offset + count - 1}`.
pub fn rho_powers(rho: &Fq, count: usize, offset: usize) -> Vec<Fq> {
    let mut power = rho.pow_u64(offset as u64);
    (0..count)
        .map(|_| {
            let p = power;
            power *= rho;
            p
        })
        .collect()
}

fn dot(evals: &[Fq], scalars: &[Fq]) -> Fq {
    evals.iter().zip(scalars).map(|(e, s)| *e * s).sum()
}

impl TripleIpaClaims {
    pub fn batch(&self) -> TripleIpaClaim {
        TripleIpaClaim {
            unshifted_commitment: msm(&self.unshifted_commitments, &self.unshifted_rho_powers).into_affine(),
            unshifted_evaluation: dot(&self.unshifted_evaluations, &self.unshifted_rho_powers),
            shifted_commitment: msm(&self.shifted_commitments, &self.shifted_rho_powers).into_affine(),
            shifted_evaluation: dot(&self.shifted_evaluations, &self.shifted_rho_powers),
            univariate_commitment: self.univariate_commitment,
            univariate_challenge: self.univariate_challenge,
            univariate_evaluation: self.univariate_evaluation,
            multilinear_challenge: self.multilinear_challenge.clone(),
        }
    }
}

pub struct TripleIpaInput {
    pub claims: TripleIpaClaims,
    pub unshifted_polys: Vec<P>,
    /// The sources of the shift claim (the flavor's to-be-shifted polynomials).
    pub shifted_polys: Vec<P>,
    pub univariate_poly: P,
}

/// The three opening vectors combined: `ζ_F eq(u) + ζ_sh shift(eq(u)) + ζ_P pow(x)`.
struct OpeningVector {
    multilinear_challenge: Vec<Fq>,
    univariate_challenge: Fq,
    zeta: [Fq; 3],
}

impl OpeningVector {
    fn tensor(&self, eq: &[Fq]) -> Vec<Fq> {
        let n = eq.len();
        let pow = powers_tensor(&self.univariate_challenge, n);
        (0..n).map(|i| self.zeta[0] * eq[i] + if i > 0 { self.zeta[1] * eq[i - 1] } else { Fq::zero() } + self.zeta[2] * pow[i]).collect()
    }
    /// The tensor folded by the IPA round challenges (bb `IpaOpeningVector::evaluate_folded`).
    fn evaluate_folded(&self, u_inv: &[Fq]) -> Fq {
        let point = &self.multilinear_challenge;
        let log_n = point.len();
        let fold = |i: usize| u_inv[log_n - 1 - i];
        // eq(u, ·) folded: ∏_i (1 + u_i (s_i - 1))
        let eq_factor = |i: usize| Fq::one() + point[i] * (fold(i) - Fq::one());
        let eq_folded: Fq = (0..log_n).map(eq_factor).product();
        // shift(eq(u, ·)) folded (bb `ShiftedEqPolynomial::evaluate_folded`)
        let mut lower_prefix = vec![Fq::one(); log_n];
        for i in 1..log_n {
            lower_prefix[i] = lower_prefix[i - 1] * point[i - 1];
        }
        let mut upper_suffix = vec![Fq::one(); log_n];
        for i in (0..log_n - 1).rev() {
            upper_suffix[i] = upper_suffix[i + 1] * eq_factor(i + 1);
        }
        let shift_folded: Fq = (0..log_n).map(|i| lower_prefix[i] * (Fq::one() - point[i]) * fold(i) * upper_suffix[i]).sum();
        self.zeta[0] * eq_folded + self.zeta[1] * shift_folded + self.zeta[2] * evaluate_challenge_poly(u_inv, &self.univariate_challenge)
    }
}

fn combined_inner_product(diagonal: [Fq; 3], zeta: &[Fq; 3], cross: &[Fq; 3]) -> Fq {
    let weights = [zeta[0].sqr(), zeta[1].sqr(), zeta[2].sqr(), zeta[0] * zeta[1], zeta[0] * zeta[2], zeta[1] * zeta[2]];
    let values = [diagonal[0], diagonal[1], diagonal[2], cross[0], cross[1], cross[2]];
    dot(&values, &weights)
}

fn add_claim_to_hash_buffer(claim: &TripleIpaClaim, t: &mut NativeTranscript) {
    t.add_to_hash_buffer("TripleIPA:F:commitment", &claim.unshifted_commitment);
    t.add_to_hash_buffer("TripleIPA:F:evaluation", &claim.unshifted_evaluation);
    t.add_to_hash_buffer("TripleIPA:F_shift:commitment", &claim.shifted_commitment);
    t.add_to_hash_buffer("TripleIPA:F_shift:evaluation", &claim.shifted_evaluation);
    t.add_to_hash_buffer("TripleIPA:P:commitment", &claim.univariate_commitment);
    t.add_to_hash_buffer("TripleIPA:P:evaluation", &claim.univariate_evaluation);
    t.add_to_hash_buffer("TripleIPA:P:x", &claim.univariate_challenge);
    for (i, u) in claim.multilinear_challenge.iter().enumerate() {
        t.add_to_hash_buffer(&format!("TripleIPA:u_{i}"), u);
    }
}

/// Batch the three claims into one IPA claim `(C, b, v)` after the cross sums are on the transcript.
fn combine(claim: &TripleIpaClaim, zeta: [Fq; 3], cross: &[Fq; 3], t: &mut NativeTranscript) -> (GrumpkinAffine, OpeningVector, Fq) {
    let commitment = msm(&[claim.unshifted_commitment, claim.shifted_commitment, claim.univariate_commitment], &zeta).into_affine();
    let evaluation = combined_inner_product([claim.unshifted_evaluation, claim.shifted_evaluation, claim.univariate_evaluation], &zeta, cross);
    t.add_to_hash_buffer("TripleIPA:combined:commitment", &commitment);
    t.add_to_hash_buffer("TripleIPA:combined:evaluation", &evaluation);
    let vector = OpeningVector { multilinear_challenge: claim.multilinear_challenge.clone(), univariate_challenge: claim.univariate_challenge, zeta };
    (commitment, vector, evaluation)
}

fn zeta_challenges(t: &mut NativeTranscript) -> [Fq; 3] {
    t.challenges::<Fq>(&["TripleIPA:zeta_F", "TripleIPA:zeta_shift", "TripleIPA:zeta_P"]).try_into().unwrap()
}

/// bb `TripleIPA::compute_opening_proof`.
pub fn triple_ipa_prove(ck: &GrumpkinKey, input: &TripleIpaInput, t: &mut NativeTranscript) {
    let n = input.univariate_poly.len();
    let log_n = n.trailing_zeros() as usize;
    let claims = &input.claims;
    let claim = claims.batch();
    let batch = |polys: &[P], rhos: &[Fq]| {
        let mut acc = P::zero(n);
        for (p, r) in polys.iter().zip(rhos) {
            acc.add_scaled(p, r);
        }
        acc
    };
    let unshifted = batch(&input.unshifted_polys, &claims.unshifted_rho_powers);
    let shifted = batch(&input.shifted_polys, &claims.shifted_rho_powers);
    add_claim_to_hash_buffer(&claim, t);

    let eq = eq_table(&claim.multilinear_challenge, log_n);
    let x = &claim.univariate_challenge;
    let against_shift = |p: &P| (0..n - 1).map(|i| eq[i] * p.coeffs[i + 1]).sum::<Fq>();
    let cross = [
        against_shift(&unshifted) + dot(&claims.shifted_source_evaluations, &claims.shifted_rho_powers),
        unshifted.evaluate(x) + input.univariate_poly.evaluate_mle(&claim.multilinear_challenge),
        shifted.evaluate(x) + against_shift(&input.univariate_poly),
    ];
    t.send("TripleIPA:cross_F_shift", &cross[0]);
    t.send("TripleIPA:cross_F_P", &cross[1]);
    t.send("TripleIPA:cross_shift_P", &cross[2]);

    let zeta = zeta_challenges(t);
    let witness = batch(&[unshifted, shifted, input.univariate_poly.clone()], &zeta);
    let (_, vector, _) = combine(&claim, zeta, &cross, t);
    inner_product_prove(ck, &witness, vector.tensor(&eq), t);
}

/// bb `TripleIPA::reduce_to_accumulator`.
pub fn triple_ipa_reduce_to_accumulator(claim: &TripleIpaClaim, t: &mut NativeTranscript) -> IpaAccumulator {
    add_claim_to_hash_buffer(claim, t);
    let cross = [t.receive("TripleIPA:cross_F_shift"), t.receive("TripleIPA:cross_F_P"), t.receive("TripleIPA:cross_shift_P")];
    let zeta = zeta_challenges(t);
    let (commitment, vector, evaluation) = combine(claim, zeta, &cross, t);
    inner_product_reduce_to_accumulator(&commitment, &evaluation, |u_inv| vector.evaluate_folded(u_inv), claim.multilinear_challenge.len(), t)
}

/// bb `TripleIPA::reduce_verify` (native).
pub fn triple_ipa_verify(srs: &GrumpkinKey, claim: &TripleIpaClaim, t: &mut NativeTranscript) -> bool {
    batch_verify_accumulators(srs, &[triple_ipa_reduce_to_accumulator(claim, t)])
}
