//! The batched Goblin merge (bb `goblin/batch_merge_prover.cpp`, `batch_merge_verifier.cpp`): proves once
//! per IVC that the merged table `T` is the concatenation of the ZK prefix and the `N` subtables
//! `C_0..C_{N-1}` (padded to `max_subtables` slots), each column shifted by the sizes of the tables before
//! it, with a batched degree check `G(X) = Σ_i α_i X^{size_i - 1} C_i(1/X)`. The verifier also checks the
//! subtable commitments against the running hash the kernels computed during accumulation.

use crate::base::codec::{FromChallenge, Transcriptable};
use crate::base::field::{u256, u256_to_u64, FieldLike};
use crate::base::group::{Curve, GroupLike, PairingPoints};
use crate::base::poseidon2::Hasher;
use crate::base::{CommitmentKey, Fr, G1Affine, NativeTranscript, Poly, Transcript};
use crate::circuit::op_queue::{EccOpQueue, ZK_ULTRA_OPS};
use crate::honk::pcs::{kzg_open, kzg_reduce_verify_batch_opening_claim, shplonk_prove, shplonk_verify, ProverClaim, VerifierOpeningClaim};

const NUM_WIRES: usize = 4;
/// `CHONK_MAX_NUM_APPS + kernels + reset-tail + hiding`: the slots of a production batch merge.
pub const CHONK_MAX_NUM_CIRCUITS: usize = 45 + (45 + 5 - 1) / 5 + 2;

fn powers(base: &Fr, n: usize) -> Vec<Fr> {
    let mut out = vec![Fr::one()];
    for i in 1..n {
        out.push(out[i - 1] * base);
    }
    out
}

/// Prove the batch merge of all merged subtables of `q` (whose ZK prefix must already be built) on a
/// fresh transcript. `ck` must cover the merged table.
pub fn batch_merge_prove(q: &EccOpQueue, max_subtables: usize, ck: &CommitmentKey) -> Vec<Fr> {
    let m = max_subtables;
    let subtable_cols = q.construct_subtable_columns();
    let n = subtable_cols.len();
    assert!(n <= m, "more subtables than max_subtables");
    let mut t = NativeTranscript::new();
    for (idx, cols) in subtable_cols.iter().enumerate() {
        for (col, p) in cols.iter().enumerate() {
            t.send(&format!("COLUMN_{col}_{idx}"), &ck.commit(p));
        }
        // Keeps the transcript in step with the running hash the verifier recomputes.
        let _: Fr = t.challenge(&format!("HASH_{idx}"));
    }
    for idx in n..m {
        for col in 0..NUM_WIRES {
            t.send(&format!("COLUMN_{col}_{idx}"), &G1Affine::identity());
        }
        let _: Fr = t.challenge(&format!("HASH_{idx}"));
    }
    let zk_cols = q.zk_columns();
    for (col, p) in zk_cols.iter().enumerate() {
        t.send(&format!("ZK_COLUMN_{col}"), &ck.commit(p));
    }
    let flattened: Vec<Poly> = zk_cols.into_iter().chain(subtable_cols.into_iter().flatten()).collect();
    let max_shift = flattened.iter().map(Poly::len).max().unwrap();

    t.send("NUM_SUBTABLES", &(n as u32));
    for i in 0..m {
        let shift = if i < n { flattened[(i + 1) * NUM_WIRES].len() } else { 0 };
        t.send(&format!("SHIFT_SIZE_{i}"), &(shift as u32));
    }
    let merged = q.construct_ultra_ops_table_columns(true);
    for (col, p) in merged.iter().enumerate() {
        t.send(&format!("MERGED_COLUMN_{col}"), &ck.commit(p));
    }

    let alpha: Fr = t.challenge("DEGREE_CHECK_CHALLENGE");
    let alphas = powers(&alpha, (m + 1) * NUM_WIRES);
    let mut g = Poly::zero(max_shift);
    for (p, a) in flattened.iter().zip(&alphas) {
        g.add_scaled(&p.reverse(), a);
    }
    t.send("DEGREE_CHECK_POLY", &ck.commit(&g));

    let kappa: Fr = t.challenge("KAPPA");
    let kappa_inv = kappa.invert();
    let mut evals = Vec::with_capacity((m + 2) * NUM_WIRES + 1);
    for col in 0..(m + 1) * NUM_WIRES {
        evals.push(flattened.get(col).map_or(Fr::zero(), |p| p.evaluate(&kappa)));
        t.send(&format!("C_EVAL_{col}"), &evals[col]);
    }
    for (col, p) in merged.iter().enumerate() {
        evals.push(p.evaluate(&kappa));
        t.send(&format!("MERGED_EVAL_{col}"), evals.last().unwrap());
    }
    evals.push(g.evaluate(&kappa_inv));
    t.send("DEGREE_CHECK_EVAL", evals.last().unwrap());

    let mut claims = Vec::with_capacity((m + 2) * NUM_WIRES + 1);
    let mut flattened = flattened.into_iter();
    for idx in 0..(m + 1) * NUM_WIRES {
        // Padding slots (and empty columns) open the zero polynomial.
        let poly = flattened.next().filter(|p| !p.is_empty()).unwrap_or_else(|| Poly::zero(1));
        let evaluation = if poly.len() == 1 && poly.coeffs[0].is_zero() { Fr::zero() } else { evals[idx] };
        claims.push(ProverClaim { poly, challenge: kappa, evaluation, gemini_fold: false });
    }
    for (col, poly) in merged.into_iter().enumerate() {
        claims.push(ProverClaim { poly, challenge: kappa, evaluation: evals[(m + 1) * NUM_WIRES + col], gemini_fold: false });
    }
    claims.push(ProverClaim { poly: g, challenge: kappa_inv, evaluation: *evals.last().unwrap(), gemini_fold: false });
    let opening = shplonk_prove(0, &claims, &[], ck, &mut t);
    kzg_open(opening, ck, &mut t);
    t.export_proof()
}

/// One step of the running hash over subtable commitments: `Poseidon2(prev_hash ‖ fields(commitments))`.
pub fn ecc_op_hash_step<C: Curve>(col_commitments: &[C::G], prev_hash: Option<&C::Fr>) -> C::Fr {
    let mut inputs: Vec<C::TF> = prev_hash.map(Transcriptable::to_fields).unwrap_or_default();
    for c in col_commitments {
        inputs.extend(c.to_fields());
    }
    C::Fr::full(C::Hash::hash(&inputs))
}

pub struct BatchMergeOutput<C: Curve> {
    pub pairing_points: PairingPoints<C>,
    pub merged_commitments: [C::G; NUM_WIRES],
    /// Concatenation, degree, hash and subtable-count checks hold.
    pub ok: bool,
}

/// bb `BatchMergeVerifier_::reduce_to_pairing_check`; `hash` is the running hash from accumulation.
pub fn batch_merge_verify<C: Curve>(proof: &[C::TF], hash: &C::Fr, max_subtables: usize, ctx: &<C::Fr as FieldLike>::Ctx) -> BatchMergeOutput<C> {
    let m = max_subtables;
    let mut t = Transcript::<C::TF, C::Hash>::from_proof(proof);
    let mut flattened: Vec<C::G> = Vec::with_capacity((m + 1) * NUM_WIRES);
    let mut subtable_cols: Vec<C::G> = Vec::with_capacity(m * NUM_WIRES);
    let mut calculated_hashes: Vec<C::Fr> = Vec::with_capacity(m);
    for idx in 0..m {
        for col in 0..NUM_WIRES {
            subtable_cols.push(t.receive(&format!("COLUMN_{col}_{idx}")));
        }
        calculated_hashes.push(t.challenge(&format!("HASH_{idx}")));
    }
    for col in 0..NUM_WIRES {
        flattened.push(t.receive(&format!("ZK_COLUMN_{col}")));
    }
    flattened.extend(subtable_cols);

    let num_subtables: C::Fr = t.receive("NUM_SUBTABLES");
    let mut running_product = C::Fr::one();
    for idx in 0..m {
        running_product *= num_subtables.clone() - C::Fr::from_u64(idx as u64 + 1);
    }
    let mut ok = running_product.is_zero();
    let n = u256_to_u64(&u256(&num_subtables.value()));
    assert!(n > 0);
    let indicator: Vec<C::Fr> = (0..m).map(|i| C::Fr::from_u64(((i as u64) < n) as u64)).collect();
    let mut shift_sizes = vec![C::Fr::from_u64(ZK_ULTRA_OPS as u64)];
    for i in 0..m {
        let s: C::Fr = t.receive(&format!("SHIFT_SIZE_{i}"));
        shift_sizes.push(s * &indicator[i]);
    }
    let merged_commitments: [C::G; NUM_WIRES] = std::array::from_fn(|col| t.receive(&format!("MERGED_COLUMN_{col}")));
    let alpha: C::Fr = t.challenge("DEGREE_CHECK_CHALLENGE");
    let mut alphas = vec![C::Fr::one(), alpha.clone()];
    for idx in 2..(m + 1) * NUM_WIRES {
        alphas.push(alphas[idx - 1].clone() * &alpha);
    }
    let g_commitment: C::G = t.receive("DEGREE_CHECK_POLY");
    let kappa: C::Fr = t.challenge("KAPPA");
    let kappa_inv = kappa.invert();
    let powers_of_kappa: Vec<C::Fr> = shift_sizes.iter().map(|s| kappa.pow_u64(u256_to_u64(&u256(&s.value())))).collect();
    let powers_of_kappa_inv: Vec<C::Fr> = powers_of_kappa.iter().map(FieldLike::invert).collect();

    let num_column_evals = (m + 1) * NUM_WIRES;
    let mut evals: Vec<C::Fr> = (0..num_column_evals).map(|i| t.receive(&format!("C_EVAL_{i}"))).collect();
    for col in 0..NUM_WIRES {
        evals.push(t.receive(&format!("MERGED_EVAL_{col}")));
    }
    evals.push(t.receive("DEGREE_CHECK_EVAL"));

    // T(κ) = Σ_i κ^{Σ_{l<i} size_l} C_i(κ) per column, by Horner from the last table.
    for j in 0..NUM_WIRES {
        let mut diff = evals[m * NUM_WIRES + j].clone();
        for i in (0..m).rev() {
            diff *= &powers_of_kappa[i];
            diff += &evals[i * NUM_WIRES + j];
        }
        diff -= &evals[num_column_evals + j];
        ok &= diff.is_zero();
    }
    // G(κ⁻¹) = κ Σ_{i,j} α_{i,j} κ^{-size_i} C_{i,j}(κ)
    let mut degree_diff = C::Fr::zero();
    for i in 0..=m {
        for j in 0..NUM_WIRES {
            degree_diff += alphas[i * NUM_WIRES + j].clone() * &powers_of_kappa_inv[i] * &evals[i * NUM_WIRES + j];
        }
    }
    degree_diff *= &kappa;
    degree_diff -= evals.last().unwrap();
    ok &= degree_diff.is_zero();
    // The hash after subtable N-1 must equal the running hash: select it with dirac[i] = (i == N-1).
    let mut expected_hash = C::Fr::zero();
    for i in 0..m {
        let next = if i + 1 < m { indicator[i + 1].clone() } else { C::Fr::zero() };
        let dirac = indicator[i].clone() - next;
        expected_hash += calculated_hashes[i].clone() * dirac;
    }
    ok &= (expected_hash - hash).is_zero();

    let mut claims: Vec<VerifierOpeningClaim<C>> = flattened
        .into_iter()
        .zip(&evals)
        .map(|(commitment, e)| VerifierOpeningClaim { commitment, challenge: kappa.clone(), evaluation: e.clone() })
        .collect();
    for (col, commitment) in merged_commitments.iter().enumerate() {
        claims.push(VerifierOpeningClaim { commitment: commitment.clone(), challenge: kappa.clone(), evaluation: evals[num_column_evals + col].clone() });
    }
    claims.push(VerifierOpeningClaim { commitment: g_commitment, challenge: kappa_inv, evaluation: evals.last().unwrap().clone() });
    let num_claims = claims.len();
    let batch = shplonk_verify(&claims, C::G::one(ctx), &mut t);
    let pairing_points = kzg_reduce_verify_batch_opening_claim(batch, &mut t, num_claims + 3);
    BatchMergeOutput { pairing_points, merged_commitments, ok }
}
