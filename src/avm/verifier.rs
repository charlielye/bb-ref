//! The AVM verifier (bb `vm2/constraining/verifier.cpp`, and `recursion/recursive_verifier.cpp` for
//! the in-circuit instance): one generic body, natively over [`Bn254`] and in-circuit over
//! [`StdBn254`](crate::stdlib::curve::StdBn254) on a Mega builder, where every EC operation goes to the ECC op queue.
//!
//! The proof reduces to a pairing check: sumcheck over the AVM relations at the fixed trace size, a
//! check that the public-input columns sent in the clear match the committed ones, then Shplemini
//! over two commitments batched with short (128-bit) challenges.

use super::relations::AvmRelations;
use super::tables::layout;
use crate::base::field::{FieldLike, Fr};
use crate::base::group::{Bn254, Curve, G2Points, GroupLike, PairingPoints};
use crate::base::transcript::Transcript;
use crate::honk::pcs::{kzg_reduce_verify_batch_opening_claim, shplemini_verify, ClaimBatcher};
use crate::honk::relations::RelationParams;
use crate::honk::sumcheck::{alpha_powers, verify_sumcheck, RelationSet, SumcheckSpec};

pub struct Reduction<C: Curve> {
    pub pairing_points: PairingPoints<C>,
    /// Sumcheck and the public-input consistency checks (natively; in-circuit they are constraints).
    pub verified: bool,
    /// The transcript after verification, for bb `hash_avm_transcript`.
    pub transcript: Transcript<C::TF, C::Hash>,
}

/// bb `evaluate_public_input_column` / `generic_evaluate_mle`: the multilinear extension of a
/// column (zero past its length, up to the full trace) at `u`, folding only the first
/// `ceil(log2 len)` variables over values and scaling by `(1 - u_i)` for the rest.
pub fn evaluate_public_input_column<F: FieldLike>(points: &[F], u: &[F]) -> F {
    if points.is_empty() {
        return F::zero();
    }
    let dim = usize::BITS as usize - (points.len() - 1).leading_zeros() as usize;
    let dim = dim.max(1);
    let get = |i: usize| points.get(i).cloned().unwrap_or_else(F::zero);
    let mut tmp: Vec<F> = (0..1usize << (dim - 1))
        .map(|i| get(2 * i) + &(u[0].clone() * &(get(2 * i + 1) - &get(2 * i))))
        .collect();
    for (l, u_l) in u.iter().enumerate().take(dim).skip(1) {
        let n_l = 1usize << (dim - l - 1);
        for i in 0..n_l {
            tmp[i] = tmp[2 * i].clone() + &(u_l.clone() * &(tmp[2 * i + 1].clone() - &tmp[2 * i]));
        }
    }
    let mut result = tmp.swap_remove(0);
    for u_i in &u[dim..] {
        result *= &(F::one() - u_i);
    }
    result
}

/// bb `AvmVerifier::verify_proof` up to the pairing check. Natively a malformed input returns
/// `Err` (bb logs and returns false); bb's recursive verifier aborts on the same conditions.
pub fn reduce_to_pairing_check<C: Curve>(
    proof: &[C::TF],
    public_inputs: &[Vec<C::Fr>],
    vk: &[C::G],
    vk_hash: &C::Fr,
    ctx: &<C::Fr as FieldLike>::Ctx,
) -> Result<Reduction<C>, &'static str>
where
    C::Fr: FieldLike<Native = Fr>,
    C::Fr: crate::base::codec::Transcriptable<C::TF>,
    C::TF: crate::base::codec::ChallengeField,
{
    let l = layout();
    let log_n = l.max_trace_log_size;
    if proof.len() != l.proof_length {
        return Err("Proof length mismatch");
    }
    let mut t = Transcript::<C::TF, C::Hash>::from_proof(proof);
    t.add_to_hash_buffer("avm_vk_hash", vk_hash);

    if public_inputs.len() != l.public_input_column_lengths.len() {
        return Err("Public inputs size mismatch");
    }
    for (i, column) in public_inputs.iter().enumerate() {
        if column.len() != l.public_input_column_lengths[i] {
            return Err("Public input size mismatch");
        }
        for v in column {
            t.add_to_hash_buffer("public_input", v);
        }
    }

    // Commitments: the fixed precomputed ones, then the wires, then (after beta, gamma) the
    // log-derivative inverses.
    let mut commitments: Vec<C::G> = vk.to_vec();
    for _ in 0..l.num_wires {
        commitments.push(t.receive("wire"));
    }
    let bg: Vec<C::Fr> = t.challenges(&["beta", "gamma"]);
    let params = RelationParams {
        beta: bg[0].clone(),
        gamma: bg[1].clone(),
        ..Default::default()
    };
    for _ in 0..l.num_derived {
        commitments.push(t.receive("derived"));
    }

    let alpha: C::Fr = t.challenge("Sumcheck:alpha");
    let rels = AvmRelations;
    // bb's SumcheckVerifier computes the separator powers in its constructor, before the gate
    // challenges are drawn.
    let alphas = alpha_powers(&alpha, RelationSet::<C::Fr>::total_subrelations(&rels) - 1);
    let gate_challenges: Vec<C::Fr> = t.dyadic_powers("Sumcheck:gate_challenge", log_n);
    let n_unshifted = l.num_unshifted();
    let spec = SumcheckSpec {
        witness_end: usize::MAX,
        active_prefix_end: None,
        virtual_log_n: log_n,
        has_zk: false,
        row_disabling: false,
        trace_offset: 0,
        committed: false,
        batched_len: l.max_partial_length + 1,
        shifted_sources: (l.to_be_shifted_start()..l.to_be_shifted_end()).collect(),
        num_entities: l.num_all(),
    };
    let sc = verify_sumcheck::<C>(&rels, &spec, &mut t, &alphas, &params, &gate_challenges);
    let mut verified = sc.verified;

    // The public-input columns sent in the clear must match the committed ones at the challenge.
    for (i, column) in public_inputs.iter().enumerate() {
        let claimed = &sc.evals[l.col(&format!("public_inputs_cols_{i}_"))];
        let evaluation = evaluate_public_input_column(column, &sc.challenge);
        if evaluation.value() != claimed.value() {
            verified = false;
        }
        evaluation.assert_equal(claimed);
    }

    // Batch every commitment and evaluation with short challenges: one unshifted claim, one shifted.
    let challenges: Vec<C::Fr> = t.short_challenges(&vec!["unshifted"; n_unshifted]);
    let (tbs_start, tbs_end) = (l.to_be_shifted_start(), l.to_be_shifted_end());
    let batched_shifted = C::G::batch_mul(&commitments[tbs_start..tbs_end], &challenges[tbs_start..tbs_end]);
    let batched_unshifted = C::G::batch_mul(&commitments[..tbs_start], &challenges[..tbs_start])
        .add(&C::G::batch_mul(&commitments[tbs_end..n_unshifted], &challenges[tbs_end..n_unshifted]))
        .add(&batched_shifted);
    let inner_product = |cs: &[C::Fr], es: &[C::Fr]| {
        let mut acc = C::Fr::zero();
        for (c, e) in cs.iter().zip(es) {
            acc = acc + &(c.clone() * e);
        }
        acc
    };
    let batched_unshifted_eval = inner_product(&challenges, &sc.evals[..n_unshifted]);
    let batched_shifted_eval = inner_product(&challenges[tbs_start..tbs_end], &sc.evals[n_unshifted..]);

    let batcher = ClaimBatcher::<C> {
        unshifted_comms: vec![batched_unshifted],
        unshifted_evals: vec![batched_unshifted_eval],
        shifted_comms: vec![batched_shifted],
        shifted_evals: vec![batched_shifted_eval],
    };
    let one = C::G::one(ctx);
    let shplemini = shplemini_verify::<C>(false, false, &batcher, &sc.challenge, &one, &mut t, &[], &[], &C::Fr::zero(), &[], &[]);
    // Q, the two batched claims, the fold commitments, the G1 identity, then W.
    let pairing_points = kzg_reduce_verify_batch_opening_claim::<C>(shplemini.claim, &mut t, log_n + 4);
    Ok(Reduction {
        pairing_points,
        verified,
        transcript: t,
    })
}

/// Native AVM verification over the public-input columns (bb `AvmVerifier::verify_proof`).
pub fn verify(proof: &[Fr], public_inputs: &[Vec<Fr>], g2: &G2Points) -> bool {
    let l = layout();
    match reduce_to_pairing_check::<Bn254>(proof, public_inputs, &l.vk, &l.vk_hash, &()) {
        Ok(r) => r.verified && r.pairing_points.check(g2),
        Err(_) => false,
    }
}
