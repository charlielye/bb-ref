//! Multilinear batching (bb `multilinear_batching/`): reduce `n` claims `P_i(r_i) = v_i`,
//! `S_i(r_i) = w_i` to one claim at a fresh point `u` with a sumcheck over
//! `Σ_i γ^i (P_i(x) + α S_i(x)) eq(x, r_i)`, then merge the outputs with powers of `ρ`.
//! The width is a runtime value (bb instantiates one flavor per width).

use super::hypernova::{ProverClaim, VerifierClaim};
use crate::base::codec::FromChallenge;
use crate::base::field::NativeField;
use crate::base::field::FieldLike;
use crate::base::group::{Curve, GroupLike};
use crate::base::poly::eq_table;
use crate::base::poly::evaluate_univariate;
use crate::base::transcript::Transcript;
use crate::base::{Fr, G1Affine, NativeTranscript, Poly};
use rayon::prelude::*;

/// bb `CONST_FOLDING_LOG_N`: every batching sumcheck is padded to this many rounds.
pub const VIRTUAL_LOG_N: usize = super::flavor::CONST_FOLDING_LOG_N;
/// The relation has degree 2, so round univariates have three evaluations.
pub const UNIVARIATE_LENGTH: usize = 3;

fn powers<F: FieldLike>(base: &F, n: usize) -> Vec<F> {
    let mut out = vec![F::one()];
    for i in 1..n {
        let next = out[i - 1].clone() * base;
        out.push(next);
    }
    out
}

/// `eq(r, u)` over points of equal length (bb `VerifierEqPolynomial::eval`).
pub fn eq_eval<F: FieldLike>(r: &[F], u: &[F]) -> F {
    assert_eq!(r.len(), u.len());
    let mut acc = F::one();
    for (ri, ui) in r.iter().zip(u) {
        let a = ri.clone() + ri - &F::one();
        let b = F::one() - ri;
        acc *= &(b + &(ui.clone() * &a));
    }
    acc
}

/// bb `MultilinearBatchingProver::construct_proof` + `compute_new_claim`; the proof is left in `t`.
pub fn mlb_prove(claims: Vec<ProverClaim>, t: &mut NativeTranscript) -> ProverClaim {
    let _g_setup = crate::base::bench::Scope::new("mlb/setup");
    let n = claims.len();
    assert!(n >= 2);
    let circuit_size = claims.iter().map(|c| c.dyadic_size).max().unwrap();
    let log_n = circuit_size.trailing_zeros() as usize;
    let gamma: Fr = t.challenge("claim_batching_challenge");
    let gamma_powers = powers(&gamma, n);
    let alpha: Fr = t.challenge("Sumcheck:alpha");

    use std::borrow::Cow;
    // Columns: [non_shifted_i, shifted_i, eq_i]; the shifted columns are the shifts of the pre-shift
    // polynomials. Round 0 reads the claims' own coefficient vectors where they already have the
    // full size (the first fold writes a fresh vector regardless), so no up-front copies.
    // `src` from `off` on, zero-extended to the circuit size, filled on the pool.
    let window = |src: &[Fr], off: usize| -> Vec<Fr> {
        (0..circuit_size)
            .into_par_iter()
            .map(|i| src.get(i + off).copied().unwrap_or_default())
            .collect()
    };
    let mut non_shifted: Vec<Cow<[Fr]>> = claims
        .iter()
        .map(|c| match &c.non_shifted_polynomial.coeffs {
            p if p.len() == circuit_size => Cow::Borrowed(&p[..]),
            p => Cow::Owned(window(p, 0)),
        })
        .collect();
    let mut shifted: Vec<Cow<[Fr]>> = claims
        .iter()
        .map(|c| {
            let p = &c.shifted_polynomial.coeffs;
            assert!(
                p.first().map_or(true, Fr::is_zero),
                "shifting a polynomial with non-zero constant term"
            );
            Cow::Owned(window(p, 1))
        })
        .collect();
    let mut eq: Vec<Cow<[Fr]>> = claims.iter().map(|c| Cow::Owned(eq_table(&c.challenge, log_n))).collect();

    let mut challenge = Vec::with_capacity(VIRTUAL_LOG_N);
    // `Fr::small` is a table lookup; `Fr::from(u64)` is a Montgomery multiplication, and this
    // runs three times per point of every edge.
    let linear = |v0: Fr, v1: Fr, k: usize| v0 + Fr::small(k as u64) * (v1 - v0);
    drop(_g_setup);
    let _g_sc = crate::base::bench::Scope::new("mlb/sumcheck");
    for round in 0..VIRTUAL_LOG_N {
        let mut univariate = vec![Fr::zero(); UNIVARIATE_LENGTH];
        if round < log_n {
            let half = circuit_size >> (round + 1);
            // Per (claim, edge): γ-scale eq's endpoints once, then step all three linear factors
            // by addition across the evaluation points — 8 multiplications instead of 18 — and
            // batch the α-weighting once per round outside the loop.
            let zeros = || vec![Fr::zero(); 2 * UNIVARIATE_LENGTH];
            let edges = (0..half)
                .into_par_iter()
                .with_min_len(64)
                .fold(zeros, |mut acc, e| {
                    for i in 0..n {
                        let eq0 = eq[i][2 * e];
                        let eqg = eq0 * gamma_powers[i];
                        let eqdg = (eq[i][2 * e + 1] - eq0) * gamma_powers[i];
                        let ns0 = non_shifted[i][2 * e];
                        let nsd = non_shifted[i][2 * e + 1] - ns0;
                        let sh0 = shifted[i][2 * e];
                        let shd = shifted[i][2 * e + 1] - sh0;
                        let (mut eqk, mut nsk, mut shk) = (eqg, ns0, sh0);
                        for k in 0..UNIVARIATE_LENGTH {
                            if k > 0 {
                                eqk += eqdg;
                                nsk += nsd;
                                shk += shd;
                            }
                            acc[k] += nsk * eqk;
                            acc[UNIVARIATE_LENGTH + k] += shk * eqk;
                        }
                    }
                    acc
                })
                .reduce(zeros, |a, b| a.iter().zip(&b).map(|(x, y)| *x + *y).collect());
            for k in 0..UNIVARIATE_LENGTH {
                univariate[k] += edges[k] + alpha * edges[UNIVARIATE_LENGTH + k];
            }
        } else {
            // Virtual round: the polynomials are extended by zero; eq needs its true value at 1.
            let mut point = vec![Fr::zero(); VIRTUAL_LOG_N];
            point[..round].copy_from_slice(&challenge);
            point[round] = Fr::one();
            for i in 0..n {
                let e1 = eq_eval(&claims[i].challenge, &point);
                eq[i] = Cow::Owned(vec![eq[i][0], e1]);
            }
            for k in 0..UNIVARIATE_LENGTH {
                let (mut s0, mut s1) = (Fr::zero(), Fr::zero());
                for i in 0..n {
                    let eq_k = linear(eq[i][0], eq[i][1], k) * gamma_powers[i];
                    s0 += linear(non_shifted[i][0], Fr::zero(), k) * eq_k;
                    s1 += linear(shifted[i][0], Fr::zero(), k) * eq_k;
                }
                univariate[k] += s0 + alpha * s1;
            }
        }
        t.send_vec(&format!("Sumcheck:univariate_{round}"), &univariate);
        let u: Fr = t.challenge(&format!("Sumcheck:u_{round}"));
        // With two or three claims there are only 3n columns, so each column's fold runs on the pool.
        let fold = |col: &mut Cow<[Fr]>| *col = Cow::Owned(crate::base::poly::fold_par(col, &u));
        if round < log_n {
            for col in non_shifted.iter_mut().chain(shifted.iter_mut()).chain(eq.iter_mut()) {
                fold(col);
            }
        } else {
            for col in non_shifted.iter_mut().chain(shifted.iter_mut()) {
                col.to_mut()[0] *= Fr::one() - u;
            }
            for col in eq.iter_mut() {
                let v = col.to_mut();
                v[0] = v[0] * (Fr::one() - u) + v[1] * u;
                col.to_mut()[1] = Fr::zero();
            }
        }
        challenge.push(u);
    }
    drop(_g_sc);
    let _g_post = crate::base::bench::Scope::new("mlb/post");
    let evals: Vec<Fr> = non_shifted.iter().chain(&shifted).chain(&eq).map(|c| c[0]).collect();
    t.send_vec("Sumcheck:evaluations", &evals);

    // Merge with powers of ρ, drawn after the evaluations are bound.
    let rho: Fr = t.challenge("claim_merge_challenge");
    let scalars = powers(&rho, n);
    drop((non_shifted, shifted, eq));
    // ρ^0 = 1: the first claim's polynomials start the sums, moved rather than added to zeros.
    let mut claims = claims;
    let take = |p: &mut Poly| {
        let mut p = std::mem::replace(p, Poly::from_coeffs(Vec::new()));
        p.coeffs.resize(circuit_size, Fr::zero());
        p
    };
    let mut new_non_shifted = take(&mut claims[0].non_shifted_polynomial);
    let mut new_shifted = take(&mut claims[0].shifted_polynomial);
    let mut non_shifted_evaluation = Fr::zero();
    let mut shifted_evaluation = Fr::zero();
    let rest = || claims[1..].iter().zip(&scalars[1..]);
    new_non_shifted.add_scaled_batch(&rest().map(|(c, s)| (&c.non_shifted_polynomial, *s)).collect::<Vec<_>>());
    new_shifted.add_scaled_batch(&rest().map(|(c, s)| (&c.shifted_polynomial, *s)).collect::<Vec<_>>());
    for i in 0..n {
        non_shifted_evaluation += scalars[i] * evals[i];
        shifted_evaluation += scalars[i] * evals[n + i];
    }
    let comms = |f: fn(&ProverClaim) -> G1Affine| -> G1Affine {
        let points: Vec<G1Affine> = claims.iter().map(f).collect();
        G1Affine::batch_mul(&points, &scalars)
    };
    ProverClaim {
        challenge,
        non_shifted_evaluation,
        shifted_evaluation,
        non_shifted_commitment: comms(|c| c.non_shifted_commitment),
        shifted_commitment: comms(|c| c.shifted_commitment),
        non_shifted_polynomial: new_non_shifted,
        shifted_polynomial: new_shifted,
        dyadic_size: circuit_size,
    }
}

/// bb `MultilinearBatchingVerifier::verify_proof`; the batching proof must already be in `t`.
pub fn mlb_verify<C: Curve>(claims: &[VerifierClaim<C>], t: &mut Transcript<C::TF, C::Hash>) -> (bool, VerifierClaim<C>)
where
    C::Fr: FromChallenge<C::TF>,
{
    type F<C> = <C as Curve>::Fr;
    let n = claims.len();
    assert!(n >= 2);
    let gamma: F<C> = t.challenge("claim_batching_challenge");
    let gamma_powers = powers(&gamma, n);
    let alpha: F<C> = t.challenge("Sumcheck:alpha");

    let mut non_shifted_target = F::<C>::zero();
    let mut shifted_target = F::<C>::zero();
    for (i, c) in claims.iter().enumerate() {
        non_shifted_target += &(c.non_shifted_evaluation.clone() * &gamma_powers[i]);
        shifted_target += &(c.shifted_evaluation.clone() * &gamma_powers[i]);
    }
    let mut target_sum = non_shifted_target + &(shifted_target * &alpha);

    let mut verified = true;
    let mut challenge = Vec::with_capacity(VIRTUAL_LOG_N);
    for round in 0..VIRTUAL_LOG_N {
        let univariate: Vec<F<C>> = t.receive_vec(&format!("Sumcheck:univariate_{round}"), UNIVARIATE_LENGTH);
        let u: F<C> = t.challenge(&format!("Sumcheck:u_{round}"));
        let round_sum = univariate[0].clone() + &univariate[1];
        if round_sum.value() != target_sum.value() {
            verified = false;
        }
        target_sum.assert_equal(&round_sum);
        target_sum = evaluate_univariate(&univariate, &u);
        challenge.push(u);
    }
    let evals: Vec<F<C>> = t.receive_vec("Sumcheck:evaluations", 3 * n);

    let mut sub0 = F::<C>::zero();
    let mut sub1 = F::<C>::zero();
    for i in 0..n {
        let eq = evals[2 * n + i].clone() * &gamma_powers[i];
        sub0 += &(evals[i].clone() * &eq);
        sub1 += &(evals[n + i].clone() * &eq);
    }
    let full_value = sub0 + &(sub1 * &alpha);
    if full_value.value() != target_sum.value() {
        verified = false;
    }
    full_value.assert_equal(&target_sum);

    for (i, c) in claims.iter().enumerate() {
        let diff = evals[2 * n + i].clone() - &eq_eval(&c.challenge, &challenge);
        if !diff.is_zero() {
            verified = false;
        }
        diff.assert_equal(&F::<C>::zero());
    }

    let rho: F<C> = t.challenge("claim_merge_challenge");
    let scalars = powers(&rho, n);
    // bb `compute_new_claim`: the commitments are batched before the evaluations are summed
    let ns: Vec<C::G> = claims.iter().map(|c| c.non_shifted_commitment.clone()).collect();
    let sh: Vec<C::G> = claims.iter().map(|c| c.shifted_commitment.clone()).collect();
    let non_shifted_commitment = C::G::batch_mul(&ns, &scalars);
    let shifted_commitment = C::G::batch_mul(&sh, &scalars);
    let mut non_shifted_evaluation = F::<C>::zero();
    let mut shifted_evaluation = F::<C>::zero();
    for i in 0..n {
        non_shifted_evaluation += &(scalars[i].clone() * &evals[i]);
        shifted_evaluation += &(scalars[i].clone() * &evals[n + i]);
    }
    let claim = VerifierClaim {
        challenge,
        non_shifted_evaluation,
        shifted_evaluation,
        non_shifted_commitment,
        shifted_commitment,
    };
    (verified, claim)
}
