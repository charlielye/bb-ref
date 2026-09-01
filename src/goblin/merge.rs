//! The single-step Goblin merge (bb `goblin/merge_prover.cpp`, `merge_verifier.cpp`): the hiding
//! kernel's subtable `R` is appended at the fixed offset `k` to the aggregate table `L`, giving the
//! merged table `M`. Proves `M_j = L_j + X^k R_j` and `deg(L_j) < k` for the four columns, batched with
//! a hand-rolled Shplonk at `κ` / `κ⁻¹` and opened with KZG.

use crate::base::codec::ChallengeField;
use crate::base::field::FieldLike;
use crate::base::group::{Curve, GroupLike, PairingPoints};
use crate::base::{CommitmentKey, Fr, NativeTranscript, Poly, Transcript};
use crate::circuit::op_queue::{EccOpQueue, HIDING_KERNEL_ULTRA_OPS};
use crate::honk::pcs::{kzg_open, kzg_reduce_verify_batch_opening_claim, BatchOpeningClaim, ProverClaim};

const NUM_WIRES: usize = 4;
const DEGREE_LABELS: [&str; NUM_WIRES] = [
    "LEFT_TABLE_DEGREE_CHECK_0",
    "LEFT_TABLE_DEGREE_CHECK_1",
    "LEFT_TABLE_DEGREE_CHECK_2",
    "LEFT_TABLE_DEGREE_CHECK_3",
];
const SHPLONK_LABELS: [&str; 3 * NUM_WIRES + 1] = [
    "SHPLONK_MERGE_BATCHING_CHALLENGE_0",
    "SHPLONK_MERGE_BATCHING_CHALLENGE_1",
    "SHPLONK_MERGE_BATCHING_CHALLENGE_2",
    "SHPLONK_MERGE_BATCHING_CHALLENGE_3",
    "SHPLONK_MERGE_BATCHING_CHALLENGE_4",
    "SHPLONK_MERGE_BATCHING_CHALLENGE_5",
    "SHPLONK_MERGE_BATCHING_CHALLENGE_6",
    "SHPLONK_MERGE_BATCHING_CHALLENGE_7",
    "SHPLONK_MERGE_BATCHING_CHALLENGE_8",
    "SHPLONK_MERGE_BATCHING_CHALLENGE_9",
    "SHPLONK_MERGE_BATCHING_CHALLENGE_10",
    "SHPLONK_MERGE_BATCHING_CHALLENGE_11",
    "SHPLONK_MERGE_BATCHING_CHALLENGE_12",
];
/// Field elements in a merge proof.
pub const MERGE_PROOF_SIZE: usize = 41;

/// The shift `k` of the final merge, fixed by the hiding kernel's op count.
pub fn fixed_shift_size() -> usize {
    EccOpQueue::compute_fixed_append_offset(EccOpQueue::append_offset_for_verifier(), true)
}

/// Merge the current (hiding kernel) subtable at the fixed offset and prove the merge on `t`.
/// `ck` must cover the merged table (`num_ultra_rows + ZK_ULTRA_OPS` points).
pub fn merge_prove(q: &mut EccOpQueue, ck: &CommitmentKey, t: &mut NativeTranscript) {
    assert_eq!(
        q.current_subtable_size(),
        HIDING_KERNEL_ULTRA_OPS,
        "the hiding kernel subtable has a fixed size"
    );
    let append_offset = q.append_offset_for_prover();
    let shift = EccOpQueue::compute_fixed_append_offset(append_offset, true);
    q.merge_fixed_append(append_offset);
    let merged = q.construct_ultra_ops_table_columns(true);
    let left = q.construct_table_columns_up_to_tail();
    let right = q.construct_current_subtable_columns();

    for (j, m) in merged.iter().enumerate() {
        t.send(&format!("MERGED_TABLE_{j}"), &ck.commit(m));
    }
    // G(X) = X^{k-1} (Σ_j α_j L_j)(1/X): a commitment to it proves deg(L_j) < k.
    let alphas: Vec<Fr> = t.challenges(&DEGREE_LABELS);
    let mut batched_left = Poly::zero(shift);
    for (l, a) in left.iter().zip(&alphas) {
        batched_left.add_scaled(l, a);
    }
    let g = batched_left.reverse();
    t.send("REVERSED_BATCHED_LEFT_TABLES", &ck.commit(&g));

    let kappa: Fr = t.challenge("kappa");
    let kappa_inv = kappa.invert();
    let tables: Vec<&Poly> = left.iter().chain(&right).chain(&merged).collect();
    let mut evals = Vec::with_capacity(tables.len() + 1);
    for (i, f) in tables.iter().enumerate() {
        let prefix = ["LEFT_TABLE_EVAL_", "RIGHT_TABLE_EVAL_", "MERGED_TABLE_EVAL_"][i / NUM_WIRES];
        evals.push(f.evaluate(&kappa));
        t.send(&format!("{prefix}{}", i % NUM_WIRES), &evals[i]);
    }
    let g_eval = g.evaluate(&kappa_inv);
    t.send("REVERSED_BATCHED_LEFT_TABLES_EVAL", &g_eval);
    let betas: Vec<Fr> = t.short_challenges(&SHPLONK_LABELS);

    // Q(X) (X - κ)(X - κ⁻¹) = (X - κ⁻¹) Σ_i β_i (F_i - f_i) + (X - κ) β_12 (G - g)
    let mut quotient = Poly::zero(merged[0].len());
    for (i, f) in tables.iter().enumerate() {
        quotient.add_scaled(f, &betas[i]);
        quotient.coeffs[0] -= betas[i] * evals[i];
    }
    quotient.factor_root(&kappa);
    let mut g_quotient = g.clone();
    g_quotient.coeffs[0] -= g_eval;
    g_quotient.factor_root(&kappa_inv);
    quotient.add_scaled(&g_quotient, &betas[3 * NUM_WIRES]);
    t.send("SHPLONK_BATCHED_QUOTIENT", &ck.commit(&quotient));
    let z: Fr = t.challenge("shplonk_opening_challenge");

    // Q'(X) = -Q(X)(z - κ) + Σ_i β_i (F_i - f_i) + (z - κ)/(z - κ⁻¹) β_12 (G - g), opened at z with value 0.
    let mut partial = quotient;
    let scale = -(z - kappa);
    partial.coeffs.iter_mut().for_each(|c| *c *= scale);
    for (i, f) in tables.iter().enumerate() {
        partial.add_scaled(f, &betas[i]);
        partial.coeffs[0] -= betas[i] * evals[i];
    }
    let mut g_minus = g;
    g_minus.coeffs[0] -= g_eval;
    partial.add_scaled(
        &g_minus,
        &(betas[3 * NUM_WIRES] * (z - kappa) * (z - kappa_inv).invert()),
    );
    kzg_open::<crate::base::Bn254>(
        ProverClaim {
            poly: partial,
            challenge: z,
            evaluation: Fr::zero(),
            gemini_fold: false,
        },
        ck,
        t,
    );
}

/// Commitments the merge verifier gets from its caller (bound to the transcript by the preceding Oink).
pub struct MergeInputs<C: Curve> {
    /// The subtable being appended (the hiding kernel's ecc op wire commitments).
    pub t_commitments: [C::G; NUM_WIRES],
    /// The aggregate table up to and including the tail subtable.
    pub t_prev_commitments: [C::G; NUM_WIRES],
}

pub struct MergeOutput<C: Curve> {
    pub pairing_points: PairingPoints<C>,
    pub merged_commitments: [C::G; NUM_WIRES],
    /// Concatenation and degree identities hold.
    pub ok: bool,
}

/// bb `MergeVerifier_::reduce_to_pairing_check`.
pub fn merge_verify<C: Curve>(
    inputs: &MergeInputs<C>,
    t: &mut Transcript<C::TF, C::Hash>,
    ctx: &<C::Fr as FieldLike>::Ctx,
) -> MergeOutput<C>
where
    C::TF: ChallengeField,
{
    let shift = fixed_shift_size();
    // [L_1..4], [R_1..4], [M_1..4], [G]
    let mut commitments: Vec<C::G> = inputs
        .t_prev_commitments
        .iter()
        .chain(&inputs.t_commitments)
        .cloned()
        .collect();
    let merged_commitments: [C::G; NUM_WIRES] = std::array::from_fn(|j| t.receive(&format!("MERGED_TABLE_{j}")));
    commitments.extend(merged_commitments.iter().cloned());
    let alphas: Vec<C::Fr> = t.challenges(&DEGREE_LABELS);
    commitments.push(t.receive("REVERSED_BATCHED_LEFT_TABLES"));

    let kappa: C::Fr = t.challenge("kappa");
    let kappa_inv = kappa.invert();
    let pow_kappa = kappa.pow_u64(shift as u64);
    let pow_kappa_minus_one = pow_kappa.clone() * &kappa_inv;
    let mut evals: Vec<C::Fr> = Vec::with_capacity(3 * NUM_WIRES + 1);
    for prefix in ["LEFT_TABLE_EVAL_", "RIGHT_TABLE_EVAL_", "MERGED_TABLE_EVAL_"] {
        for j in 0..NUM_WIRES {
            evals.push(t.receive(&format!("{prefix}{j}")));
        }
    }
    evals.push(t.receive("REVERSED_BATCHED_LEFT_TABLES_EVAL"));

    // L(κ) + κ^k R(κ) = M(κ) per column; Σ_j α_j L_j(κ) = κ^{k-1} G(κ⁻¹).
    let mut ok = true;
    for j in 0..NUM_WIRES {
        let diff = evals[j].clone() + (pow_kappa.clone() * &evals[j + NUM_WIRES]) - &evals[j + 2 * NUM_WIRES];
        ok &= diff.is_zero();
        // bb constrains the identity in-circuit: `concatenation_diff.assert_equal(FF(0))`.
        diff.assert_equal(&C::Fr::constant(<C::Fr as FieldLike>::Native::from(0u64)));
    }
    let mut degree_diff = C::Fr::zero();
    for j in 0..NUM_WIRES {
        degree_diff += evals[j].clone() * &alphas[j];
    }
    degree_diff -= evals[3 * NUM_WIRES].clone() * &pow_kappa_minus_one;
    ok &= degree_diff.is_zero();
    degree_diff.assert_equal(&C::Fr::constant(<C::Fr as FieldLike>::Native::from(0u64)));

    let betas: Vec<C::Fr> = t.short_challenges(&SHPLONK_LABELS);
    let quotient: C::G = t.receive("SHPLONK_BATCHED_QUOTIENT");
    let z: C::Fr = t.challenge("shplonk_opening_challenge");

    // [Q'] = -(z - κ)[Q] + Σ_i β_i [F_i] + β_12 (z - κ)/(z - κ⁻¹) [G] - (Σ_i β_i f_i + β_12 (z - κ)/(z - κ⁻¹) g) [1]
    let mut msm_commitments = vec![quotient];
    msm_commitments.extend(commitments);
    msm_commitments.push(C::G::one(ctx));
    let mut scalars = vec![C::Fr::zero() - (z.clone() - &kappa)];
    scalars.extend(betas.iter().cloned());
    let ratio = (z.clone() - &kappa) * (z.clone() - &kappa_inv).invert();
    *scalars.last_mut().unwrap() *= &ratio;
    let mut constant = C::Fr::zero();
    for i in 0..3 * NUM_WIRES {
        constant -= evals[i].clone() * &betas[i];
    }
    constant -= betas[3 * NUM_WIRES].clone() * &evals[3 * NUM_WIRES] * &ratio;
    scalars.push(constant);
    let claim = BatchOpeningClaim {
        commitments: msm_commitments,
        scalars,
        evaluation_point: z,
        evaluation: C::Fr::zero(),
    };
    let pairing_points = kzg_reduce_verify_batch_opening_claim(claim, t, 3 * NUM_WIRES + 4);
    MergeOutput {
        pairing_points,
        merged_commitments,
        ok,
    }
}
