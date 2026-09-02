//! The inner-product argument over Grumpkin (bb `commitment_schemes/ipa/ipa.hpp`) and the TripleIPA
//! (bb `triple_ipa/triple_ipa.hpp`) that opens the ECCVM's batched multilinear claim, its shifted
//! claim and a univariate claim with a single inner-product proof. Native only: Chonk's client verifier
//! runs the ECCVM verifier natively, and Grumpkin openings are discharged as accumulators.

use crate::base::field::FieldLike;
use crate::base::group::{Curve, GroupLike};
use crate::base::poly::{eq_table, Polynomial};
use crate::base::transcript::Transcript;
use crate::base::{Fq, Grumpkin, GrumpkinAffine, GrumpkinKey, NativeTranscript};
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use rayon::prelude::*;

type P = Polynomial<Fq>;
type Proj = ark_grumpkin::Projective;

fn msm(points: &[GrumpkinAffine], scalars: &[Fq]) -> Proj {
    crate::base::msm::msm(points, scalars)
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
pub fn evaluate_challenge_poly<F: FieldLike>(u_inv: &[F], r: &F) -> F {
    let log_n = u_inv.len();
    let mut result = F::one();
    let mut r_pow = r.clone();
    for i in 0..log_n {
        let monomial = u_inv[log_n - 1 - i].clone() * &r_pow;
        result *= F::one() + &monomial;
        if i < log_n - 1 {
            r_pow = r_pow.sqr();
        }
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
    let stage_timing = std::env::var_os("BBREF_IPA_TIMING").is_some();
    let (mut t_inner, mut t_msm, mut t_fold_ab, mut t_fold_g) = (
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
    );
    for round in 0..log_n {
        let half = n >> (round + 1);
        let t0 = std::time::Instant::now();
        let inner_l: Fq = (0..half).into_par_iter().map(|i| a[i] * b[half + i]).sum();
        let inner_r: Fq = (0..half).into_par_iter().map(|i| a[half + i] * b[i]).sum();
        let t1 = std::time::Instant::now();
        let l = msm(&g[half..2 * half], &a[..half]) + aux_generator * inner_l;
        let r = msm(&g[..half], &a[half..2 * half]) + aux_generator * inner_r;
        let t2 = std::time::Instant::now();
        let index = log_n - round - 1;
        t.send(&format!("IPA:L_{index}"), &l.into_affine());
        t.send(&format!("IPA:R_{index}"), &r.into_affine());
        let u: Fq = t.short_challenge(&format!("IPA:round_challenge_{index}"));
        assert!(!u.is_zero(), "IPA round challenge is zero");
        let u_inv = u.invert();
        challenge_product *= u;
        let t3 = std::time::Instant::now();
        let (a_lo, a_hi) = a.split_at_mut(half);
        a_lo.par_iter_mut()
            .zip(&a_hi[..half])
            .for_each(|(lo, hi)| *lo = u_inv * *lo + hi);
        let (b_lo, b_hi) = b.split_at_mut(half);
        b_lo.par_iter_mut()
            .zip(&b_hi[..half])
            .for_each(|(lo, hi)| *lo = u * *lo + hi);
        let t4 = std::time::Instant::now();
        g = Proj::normalize_batch(
            &(0..half)
                .into_par_iter()
                .map(|i| g[i] * u + g[half + i])
                .collect::<Vec<_>>(),
        );
        if stage_timing {
            t_inner += t1 - t0;
            t_msm += t2 - t1;
            t_fold_ab += t4 - t3;
            t_fold_g += t4.elapsed();
        }
    }
    if stage_timing {
        eprintln!(
            "[ipa] inner {:?} lr-msm {:?} fold-ab {:?} fold-g {:?}",
            t_inner, t_msm, t_fold_ab, t_fold_g
        );
    }
    t.send("IPA:G_0", &(g[0] * challenge_product.invert()).into_affine());
    t.send("IPA:a_0", &(a[0] * challenge_product));
}

/// A verified-but-undischarged IPA: `claimed_commitment` must equal `⟨s(u_inv), SRS⟩`
/// (bb `IPA::NativeAccumulator`).
pub struct IpaAccumulator<C: Curve = Grumpkin> {
    pub u_challenges_inv: Vec<C::Fr>,
    pub claimed_commitment: C::G,
    pub relation_succeeded: bool,
}

/// bb `IPA::read_inner_product_transcript_data` + the group relation of `reduce_to_accumulator_internal`:
/// checks `C + v U + Σ (u_j^{-1} L_j + u_j R_j) == a_0 G_0 + a_0 b_0 U` with `b_0 = b_zero(u_inv)`.
pub fn inner_product_reduce_to_accumulator<C: Curve>(
    ctx: &<C::Fr as FieldLike>::Ctx,
    commitment: &C::G,
    evaluation: &C::Fr,
    b_zero: impl Fn(&[C::Fr]) -> C::Fr,
    log_n: usize,
    t: &mut Transcript<C::TF, C::Hash>,
) -> IpaAccumulator<C>
where
    C::TF: crate::base::codec::ChallengeField,
{
    let gen_challenge: C::Fr = t.challenge("IPA:generator_challenge");
    assert!(!gen_challenge.is_zero(), "the generator challenge can't be zero");
    let pippenger_size = 2 * log_n + 2;
    let mut msm_elements: Vec<C::G> = Vec::with_capacity(pippenger_size);
    let mut msm_scalars: Vec<C::Fr> = Vec::with_capacity(pippenger_size);
    let mut u_inv = Vec::with_capacity(log_n);
    for round in 0..log_n {
        let index = log_n - round - 1;
        let l: C::G = t.receive(&format!("IPA:L_{index}"));
        let r: C::G = t.receive(&format!("IPA:R_{index}"));
        let u: C::Fr = t.short_challenge(&format!("IPA:round_challenge_{index}"));
        assert!(!u.is_zero(), "round challenges can't be zero");
        let u_inverse = u.invert();
        msm_elements.push(l);
        msm_elements.push(r);
        msm_scalars.push(u_inverse.clone());
        msm_scalars.push(u);
        u_inv.push(u_inverse);
    }
    let b_zero = b_zero(&u_inv);
    let g_zero: C::G = t.receive("IPA:G_0");
    let a_zero: C::Fr = t.receive("IPA:a_0");
    msm_elements.push(g_zero.neg());
    msm_elements.push(C::G::one(ctx).neg());
    msm_scalars.push(a_zero.clone());
    msm_scalars.push(gen_challenge * &a_zero.madd(&b_zero, &[-evaluation.clone()]));
    let ipa_relation = C::G::batch_mul(&msm_elements, &msm_scalars);
    let neg_commitment = commitment.neg();
    ipa_relation.enforce_equal(&neg_commitment);
    IpaAccumulator {
        u_challenges_inv: u_inv,
        claimed_commitment: g_zero,
        relation_succeeded: ipa_relation.value() == neg_commitment.value(),
    }
}

/// bb `IPA::batch_verify_accumulators`: one SRS MSM settles every accumulator's claimed `G_0`.
pub fn batch_verify_accumulators(srs: &GrumpkinKey, accumulators: &[IpaAccumulator<Grumpkin>]) -> bool {
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
pub struct TripleIpaClaims<C: Curve = Grumpkin> {
    pub unshifted_commitments: Vec<C::G>,
    pub unshifted_evaluations: Vec<C::Fr>,
    pub unshifted_rho_powers: Vec<C::Fr>,
    pub shifted_commitments: Vec<C::G>,
    /// The sources' own (unshifted) evaluations at `u`, reused for the `⟨F', eq⟩` cross sum.
    pub shifted_source_evaluations: Vec<C::Fr>,
    pub shifted_evaluations: Vec<C::Fr>,
    pub shifted_rho_powers: Vec<C::Fr>,
    pub multilinear_challenge: Vec<C::Fr>,
    pub univariate_commitment: C::G,
    pub univariate_challenge: C::Fr,
    pub univariate_evaluation: C::Fr,
}

/// The batched form of [`TripleIpaClaims`] (bb `TripleIpaClaim`).
pub struct TripleIpaClaim<C: Curve = Grumpkin> {
    pub unshifted_commitment: C::G,
    pub unshifted_evaluation: C::Fr,
    pub shifted_commitment: C::G,
    pub shifted_evaluation: C::Fr,
    pub univariate_commitment: C::G,
    pub univariate_challenge: C::Fr,
    pub univariate_evaluation: C::Fr,
    pub multilinear_challenge: Vec<C::Fr>,
}

/// `ρ^offset, ..., ρ^{offset + count - 1}`.
pub fn rho_powers<F: FieldLike>(rho: &F, count: usize, offset: usize) -> Vec<F> {
    // bb reaches rho^offset by sequential multiplications, not a pow ladder.
    let mut power = F::one();
    for _ in 0..offset {
        power *= rho;
    }
    (0..count)
        .map(|_| {
            let p = power.clone();
            power *= rho;
            p
        })
        .collect()
}

fn dot(evals: &[Fq], scalars: &[Fq]) -> Fq {
    evals.iter().zip(scalars).map(|(e, s)| *e * s).sum()
}

/// bb `batch_evaluations`: a dot product, `mult_madd` in chunks of 16 in-circuit.
pub fn batch_evaluations<F: FieldLike>(evals: &[F], scalars: &[F]) -> F {
    assert_eq!(evals.len(), scalars.len());
    if evals.is_empty() {
        return F::zero();
    }
    let mut result = F::zero();
    for (start, chunk) in evals.chunks(16).enumerate().map(|(i, c)| (i * 16, c)) {
        let scalar_chunk = &scalars[start..start + chunk.len()];
        result = if start == 0 {
            F::mult_madd(scalar_chunk, chunk, &[])
        } else {
            F::mult_madd(scalar_chunk, chunk, &[result])
        };
    }
    result
}

impl<C: Curve> TripleIpaClaims<C> {
    pub fn batch(&self) -> TripleIpaClaim<C> {
        TripleIpaClaim {
            unshifted_commitment: C::G::batch_mul(&self.unshifted_commitments, &self.unshifted_rho_powers),
            unshifted_evaluation: batch_evaluations(&self.unshifted_evaluations, &self.unshifted_rho_powers),
            shifted_commitment: C::G::batch_mul(&self.shifted_commitments, &self.shifted_rho_powers),
            shifted_evaluation: batch_evaluations(&self.shifted_evaluations, &self.shifted_rho_powers),
            univariate_commitment: self.univariate_commitment.clone(),
            univariate_challenge: self.univariate_challenge.clone(),
            univariate_evaluation: self.univariate_evaluation.clone(),
            multilinear_challenge: self.multilinear_challenge.clone(),
        }
    }
}

pub struct TripleIpaInput<'a> {
    pub claims: TripleIpaClaims,
    pub unshifted_polys: Vec<&'a P>,
    /// The sources of the shift claim (the flavor's to-be-shifted polynomials).
    pub shifted_polys: Vec<&'a P>,
    pub univariate_poly: P,
}

/// The three opening vectors combined: `ζ_F eq(u) + ζ_sh shift(eq(u)) + ζ_P pow(x)`.
struct OpeningVector<C: Curve = Grumpkin> {
    multilinear_challenge: Vec<C::Fr>,
    univariate_challenge: C::Fr,
    zeta: [C::Fr; 3],
}

impl OpeningVector<Grumpkin> {
    fn tensor(&self, eq: &[Fq]) -> Vec<Fq> {
        let n = eq.len();
        let pow = powers_tensor(&self.univariate_challenge, n);
        (0..n)
            .map(|i| {
                self.zeta[0] * eq[i] + if i > 0 { self.zeta[1] * eq[i - 1] } else { Fq::zero() } + self.zeta[2] * pow[i]
            })
            .collect()
    }
}

impl<C: Curve> OpeningVector<C> {
    /// The tensor folded by the IPA round challenges (bb `IpaOpeningVector::evaluate_folded`).
    fn evaluate_folded(&self, u_inv: &[C::Fr]) -> C::Fr {
        let point = &self.multilinear_challenge;
        let log_n = point.len();
        let fold = |i: usize| u_inv[log_n - 1 - i].clone();
        // eq(u, ·) folded: ∏_i (1 + u_i (s_i - 1))
        let eq_factor = |i: usize| C::Fr::one() + &(point[i].clone() * &(fold(i) - &C::Fr::one()));
        let mut eq_folded = C::Fr::one();
        for i in 0..log_n {
            eq_folded *= eq_factor(i);
        }
        let mut result = self.zeta[0].clone() * &eq_folded;
        // bb `ShiftedEqPolynomial::evaluate_folded`: prefix/suffix arrays with their final unused
        // multiplies, then every (left, right) product pair, then the sum of products.
        let mut lower_prefix = vec![C::Fr::one(); log_n];
        let mut lower = C::Fr::one();
        for i in 0..log_n {
            lower_prefix[i] = lower.clone();
            lower = lower * &point[i];
        }
        let mut upper_suffix = vec![C::Fr::one(); log_n];
        let mut upper = C::Fr::one();
        for r in 0..log_n {
            let idx = log_n - 1 - r;
            upper_suffix[idx] = upper.clone();
            upper = upper * &eq_factor(idx);
        }
        let mut left = Vec::with_capacity(log_n);
        let mut right = Vec::with_capacity(log_n);
        for i in 0..log_n {
            left.push(lower_prefix[i].clone() * &(C::Fr::one() - &point[i]));
            right.push(fold(i) * &upper_suffix[i]);
        }
        let mut shift_folded = C::Fr::zero();
        for i in 0..log_n {
            shift_folded += left[i].clone() * &right[i];
        }
        result += self.zeta[1].clone() * &shift_folded;
        result += self.zeta[2].clone() * &evaluate_challenge_poly(u_inv, &self.univariate_challenge);
        result
    }
}

fn combined_inner_product<F: FieldLike>(diagonal: [F; 3], zeta: &[F; 3], cross: &[F; 3]) -> F {
    let weights = [
        zeta[0].sqr(),
        zeta[1].sqr(),
        zeta[2].sqr(),
        zeta[0].clone() * &zeta[1],
        zeta[0].clone() * &zeta[2],
        zeta[1].clone() * &zeta[2],
    ];
    let values = [
        diagonal[0].clone(),
        diagonal[1].clone(),
        diagonal[2].clone(),
        cross[0].clone(),
        cross[1].clone(),
        cross[2].clone(),
    ];
    F::mult_madd(&weights, &values, &[])
}

fn add_claim_to_hash_buffer<C: Curve>(claim: &TripleIpaClaim<C>, t: &mut Transcript<C::TF, C::Hash>)
where
    C::TF: crate::base::codec::ChallengeField,
{
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
fn combine<C: Curve>(
    claim: &TripleIpaClaim<C>,
    zeta: [C::Fr; 3],
    cross: &[C::Fr; 3],
    t: &mut Transcript<C::TF, C::Hash>,
) -> (C::G, OpeningVector<C>, C::Fr)
where
    C::TF: crate::base::codec::ChallengeField,
{
    let commitment = C::G::batch_mul(
        &[
            claim.unshifted_commitment.clone(),
            claim.shifted_commitment.clone(),
            claim.univariate_commitment.clone(),
        ],
        &zeta,
    );
    let evaluation = combined_inner_product(
        [
            claim.unshifted_evaluation.clone(),
            claim.shifted_evaluation.clone(),
            claim.univariate_evaluation.clone(),
        ],
        &zeta,
        cross,
    );
    t.add_to_hash_buffer("TripleIPA:combined:commitment", &commitment);
    t.add_to_hash_buffer("TripleIPA:combined:evaluation", &evaluation);
    let vector = OpeningVector {
        multilinear_challenge: claim.multilinear_challenge.clone(),
        univariate_challenge: claim.univariate_challenge.clone(),
        zeta,
    };
    (commitment, vector, evaluation)
}

fn zeta_challenges<C: Curve>(t: &mut Transcript<C::TF, C::Hash>) -> [C::Fr; 3]
where
    C::TF: crate::base::codec::ChallengeField,
{
    t.challenges::<C::Fr>(&["TripleIPA:zeta_F", "TripleIPA:zeta_shift", "TripleIPA:zeta_P"])
        .try_into()
        .map_err(|_| ())
        .unwrap()
}

/// bb `TripleIPA::compute_opening_proof`.
pub fn triple_ipa_prove(ck: &GrumpkinKey, input: &TripleIpaInput<'_>, t: &mut NativeTranscript) {
    let n = input.univariate_poly.len();
    let log_n = n.trailing_zeros() as usize;
    let claims = &input.claims;
    let claim = claims.batch();
    let batch = |polys: &[&P], rhos: &[Fq]| {
        let mut acc = P::zero(n);
        acc.add_scaled_batch(&polys.iter().zip(rhos).map(|(p, r)| (*p, *r)).collect::<Vec<_>>());
        acc
    };
    let unshifted = batch(&input.unshifted_polys, &claims.unshifted_rho_powers);
    let shifted = batch(&input.shifted_polys, &claims.shifted_rho_powers);
    crate::base::timing::phase("    ipa: batching");
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

    let zeta = zeta_challenges::<Grumpkin>(t);
    let witness = batch(&[&unshifted, &shifted, &input.univariate_poly], &zeta);
    let (_, vector, _) = combine(&claim, zeta, &cross, t);
    crate::base::timing::phase("    ipa: cross terms + combine");
    inner_product_prove(ck, &witness, vector.tensor(&eq), t);
    crate::base::timing::phase("    ipa: inner product prove");
}

/// bb `TripleIPA::reduce_to_accumulator`.
pub fn triple_ipa_reduce_to_accumulator<C: Curve>(
    ctx: &<C::Fr as FieldLike>::Ctx,
    claim: &TripleIpaClaim<C>,
    t: &mut Transcript<C::TF, C::Hash>,
) -> IpaAccumulator<C>
where
    C::TF: crate::base::codec::ChallengeField,
{
    add_claim_to_hash_buffer(claim, t);
    let cross: [C::Fr; 3] = [
        t.receive("TripleIPA:cross_F_shift"),
        t.receive("TripleIPA:cross_F_P"),
        t.receive("TripleIPA:cross_shift_P"),
    ];
    let zeta = zeta_challenges::<C>(t);
    let (commitment, vector, evaluation) = combine(claim, zeta, &cross, t);
    inner_product_reduce_to_accumulator::<C>(
        ctx,
        &commitment,
        &evaluation,
        |u_inv| vector.evaluate_folded(u_inv),
        claim.multilinear_challenge.len(),
        t,
    )
}

/// bb `TripleIPA::reduce_verify` (native).
pub fn triple_ipa_verify(srs: &GrumpkinKey, claim: &TripleIpaClaim<Grumpkin>, t: &mut NativeTranscript) -> bool {
    batch_verify_accumulators(srs, &[triple_ipa_reduce_to_accumulator::<Grumpkin>(&(), claim, t)])
}
