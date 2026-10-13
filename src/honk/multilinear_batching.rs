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
    assert!(log_n >= 1);
    let gamma: Fr = t.challenge("claim_batching_challenge");
    let gamma_powers = powers(&gamma, n);
    let alpha: Fr = t.challenge("Sumcheck:alpha");

    use std::borrow::Cow;
    // Columns borrow each claim's coefficients up to its last non-zero entry (at least one entry);
    // the shift is the same vector one row ahead. Past a column's end it reads zero, so a claim's
    // edges past its support add nothing and are skipped, and its folds stay support-sized.
    // eq(x, r_i) is never materialised at full width: with round k's variable split off,
    // eq[2e + b] = c_i · (b ? r_k : 1 − r_k) · H_i[e], where H_i is the table over the remaining
    // variables (half width, built once) and c_i the product of the factors bound so far. Binding a
    // variable is then a scalar update of c_i plus pairwise sums of H_i (the two factors sum to 1).
    fn lean(p: &[Fr], off: usize) -> Cow<'_, [Fr]> {
        match p.iter().rposition(|x| !x.is_zero()) {
            Some(e) if e >= off => Cow::Borrowed(&p[off..=e]),
            _ => Cow::Owned(vec![Fr::zero()]),
        }
    }
    let mut non_shifted: Vec<Cow<[Fr]>> = claims.iter().map(|c| lean(&c.non_shifted_polynomial.coeffs, 0)).collect();
    let mut shifted: Vec<Cow<[Fr]>> = claims
        .iter()
        .map(|c| {
            let p = &c.shifted_polynomial.coeffs;
            assert!(
                p.first().map_or(true, Fr::is_zero),
                "shifting a polynomial with non-zero constant term"
            );
            lean(p, 1)
        })
        .collect();
    let mut half_eq: Vec<Vec<Fr>> = claims.iter().map(|c| eq_table(&c.challenge[1..], log_n - 1)).collect();
    let mut eq_scale = vec![Fr::one(); n];
    let mut eq: Vec<[Fr; 2]> = Vec::new();

    let mut challenge = Vec::with_capacity(VIRTUAL_LOG_N);
    // `Fr::small` is a table lookup; `Fr::from(u64)` is a Montgomery multiplication.
    let linear = |v0: Fr, v1: Fr, k: usize| v0 + Fr::small(k as u64) * (v1 - v0);
    let at = |c: &[Fr], i: usize| c.get(i).copied().unwrap_or_default();
    drop(_g_setup);
    let _g_sc = crate::base::bench::Scope::new("mlb/sumcheck");
    for round in 0..VIRTUAL_LOG_N {
        let mut univariate = vec![Fr::zero(); UNIVARIATE_LENGTH];
        if round < log_n {
            // Per claim: A = Σ_e H[e]·(P + αS)(2e), B = Σ_e H[e]·Δ(P + αS)(2e), so the claim's
            // round polynomial is γ^i c_i ((1 − r_k) + X(2r_k − 1))(A + X B): 4 multiplications
            // per (claim, edge).
            let ends: Vec<usize> = (0..n).map(|i| non_shifted[i].len().max(shifted[i].len())).collect();
            let zeros = || vec![Fr::zero(); 2 * n];
            let ab = (0..ends.iter().max().unwrap().div_ceil(2))
                .into_par_iter()
                .with_min_len(64)
                .fold(zeros, |mut acc, e| {
                    for i in (0..n).filter(|&i| 2 * e < ends[i]) {
                        let h = half_eq[i][e];
                        let t0 = at(&non_shifted[i], 2 * e) + alpha * at(&shifted[i], 2 * e);
                        let t1 = at(&non_shifted[i], 2 * e + 1) + alpha * at(&shifted[i], 2 * e + 1);
                        acc[i] += h * t0;
                        acc[n + i] += h * (t1 - t0);
                    }
                    acc
                })
                .reduce(zeros, |a, b| a.iter().zip(&b).map(|(x, y)| *x + *y).collect());
            for i in 0..n {
                let rk = claims[i].challenge[round];
                let s = gamma_powers[i] * eq_scale[i];
                for k in 0..UNIVARIATE_LENGTH {
                    let x = Fr::small(k as u64);
                    univariate[k] += s * (Fr::one() - rk + x * (rk + rk - Fr::one())) * (ab[i] + x * ab[n + i]);
                }
            }
        } else {
            // Virtual round: the polynomials are extended by zero; eq needs its true value at 1.
            let mut point = vec![Fr::zero(); VIRTUAL_LOG_N];
            point[..round].copy_from_slice(&challenge);
            point[round] = Fr::one();
            for i in 0..n {
                eq[i][1] = eq_eval(&claims[i].challenge, &point);
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
        if round < log_n {
            // With two or three claims there are only 2n columns, so each column's fold runs on the
            // pool; an odd end's last pair is (a, 0), which folds to a·(1 − u).
            for col in non_shifted.iter_mut().chain(shifted.iter_mut()) {
                let len = col.len();
                let mut out = crate::base::poly::fold_par(&col[..len & !1], &u);
                if len % 2 == 1 {
                    out.push(col[len - 1] * (Fr::one() - u));
                }
                *col = Cow::Owned(out);
            }
            for i in 0..n {
                let rk = claims[i].challenge[round];
                eq_scale[i] *= Fr::one() - rk + u * (rk + rk - Fr::one());
                let h = &mut half_eq[i];
                let m = h.len() / 2;
                for j in 0..m {
                    h[j] = h[2 * j] + h[2 * j + 1];
                }
                h.truncate(m.max(1));
            }
            if round == log_n - 1 {
                eq = (0..n).map(|i| [eq_scale[i] * half_eq[i][0], Fr::zero()]).collect();
            }
        } else {
            for col in non_shifted.iter_mut().chain(shifted.iter_mut()) {
                col.to_mut()[0] *= Fr::one() - u;
            }
            for v in eq.iter_mut() {
                *v = [v[0] * (Fr::one() - u) + v[1] * u, Fr::zero()];
            }
        }
        challenge.push(u);
    }
    drop(_g_sc);
    let _g_post = crate::base::bench::Scope::new("mlb/post");
    let evals: Vec<Fr> = non_shifted.iter().chain(&shifted).map(|c| c[0]).chain(eq.iter().map(|v| v[0])).collect();
    t.send_vec("Sumcheck:evaluations", &evals);

    // Merge with powers of ρ, drawn after the evaluations are bound.
    let rho: Fr = t.challenge("claim_merge_challenge");
    let scalars = powers(&rho, n);
    drop((non_shifted, shifted, half_eq));
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
