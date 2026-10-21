//! Sumcheck prover and verifier (bb `sumcheck/sumcheck.hpp`, `sumcheck_round.hpp`,
//! `polynomials/gate_separator.hpp`, `polynomials/row_disabling_polynomial.hpp`), written once over
//! a [`RelationSet`] so that Ultra/Mega flavors, the multilinear batching relation and the ECCVM share
//! it. The prover is pointwise: each entity's edge `(P[2e], P[2e+1])` is extended linearly to
//! `k = 0..D-1` and the relations are evaluated on the resulting rows with the same `accumulate` the
//! verifier uses. The committed variant (ECCVM) sends a commitment to each round univariate and its
//! values at 0 and 1 instead of the univariate itself.

use super::flavor::{FlavorDesc, Layout};
use super::graded::{lift_params, lift_params_wide, Graded, GradedWide, MAX_LEN as GRADED_MAX_LEN, WIDE_LEN as GRADED_WIDE_LEN};
use super::relations::{quad_batching_constants, RelationParams, Row};
use crate::base::field::NativeField;
use crate::base::field::{FieldLike, U256};
use crate::base::group::Curve;
use crate::base::poly::Polynomial;
use crate::base::rng::{random_field, Rng};
use crate::base::srs::Ck;
use crate::base::transcript::Transcript;
use crate::base::wasm::{PermLanes, PERM_INPUTS, PERM_LANES, PERM_POINTS};
use crate::honk::flavor::{Ent, Rel, BUS_SPECS};
use ark_ff::PrimeField;
use rayon::prelude::*;

pub use crate::base::poly::evaluate_univariate;

/// The relations a sumcheck runs over: `accumulate` adds relation `r`'s subrelation values on a row
/// of entity values (bb's `Relation::accumulate` over `AllValues`).
pub trait RelationSet<F: FieldLike> {
    fn num_relations(&self) -> usize;
    fn num_subrelations(&self, r: usize) -> usize;
    fn linearly_independent(&self, r: usize, j: usize) -> bool;
    /// Relations checked only on the sumcheck-disabled rows (bb `IsOffsetOnlyRelation`).
    fn offset_only(&self, r: usize) -> bool;
    fn accumulate(&self, r: usize, acc: &mut [F], row: &[F], p: &RelationParams<F>, scaling: &F);
    /// bb `Relation::skip`: the relation contributes nothing on the edge `(row0, row1)` (its
    /// selector, or the combination bb tests, vanishes on both rows), so the prover may skip it.
    fn skip(&self, _r: usize, _row0: &[F], _row1: &[F]) -> bool {
        false
    }
    /// bb `Flavor::skip_entire_row`: every relation vanishes on the edge `(row0, row1)`.
    fn skip_row(&self, _row0: &[F], _row1: &[F]) -> bool {
        false
    }
    /// Every column `skip` / `skip_row` may read (`None`: unknown, the edge loop fills every
    /// column). Must stay in sync with the `skip` implementations: the edge loop only fills these
    /// columns before evaluating the skips.
    fn skip_columns(&self) -> Option<Vec<usize>> {
        None
    }
    /// The relation's univariate length (bb's max subrelation partial length): the prover only
    /// evaluates it at that many points and extends the accumulator afterwards.
    fn partial_length(&self, _r: usize) -> usize {
        usize::MAX
    }
    /// Whether `accumulate_graded` is implemented (the coefficient-basis edge path, `graded.rs`).
    fn supports_graded(&self) -> bool {
        false
    }
    /// Whether relations over the narrow coefficient capacity should run on `GradedWide` rather
    /// than pointwise. Opt-in: the Translator's high-degree add-heavy relations measured slower in
    /// coefficient form and stay pointwise.
    fn supports_wide_graded(&self) -> bool {
        false
    }
    /// `accumulate` over degree-tracked coefficient-basis univariates: the same relation bodies,
    /// with each ring operation costing its true degree. Only called when `supports_graded` is
    /// true and every partial length fits `GRADED_MAX_LEN`.
    fn accumulate_graded(
        &self,
        _r: usize,
        _acc: &mut [Graded<F::Native>],
        _row: &[Graded<F::Native>],
        _p: &RelationParams<Graded<F::Native>>,
        _scaling: &Graded<F::Native>,
    ) {
        unreachable!("no graded evaluation for this relation set")
    }
    /// `accumulate_graded` on the wide coefficient capacity, for relations whose partial length
    /// exceeds `GRADED_MAX_LEN` but fits `GRADED_WIDE_LEN` (the ECCVM's set and lookup relations).
    fn accumulate_graded_wide(
        &self,
        _r: usize,
        _acc: &mut [GradedWide<F::Native>],
        _row: &[GradedWide<F::Native>],
        _p: &RelationParams<GradedWide<F::Native>>,
        _scaling: &GradedWide<F::Native>,
    ) {
        unreachable!("no wide graded evaluation for this relation set")
    }
    /// Prover: `params` with the set's subrelation-separator folding constants for `alphas`
    /// (`quad_batching_constants`), or `None` when it has none.
    fn fold_separators(&self, _params: &RelationParams<F>, _alphas: &[F]) -> Option<RelationParams<F>> {
        None
    }
    fn total_subrelations(&self) -> usize {
        (0..self.num_relations()).map(|r| self.num_subrelations(r)).sum()
    }
    /// The permutation relation's index and columns, for the lane kernel (`PermLanes`).
    fn permutation_columns(&self) -> Option<PermCols> {
        None
    }
}

/// Columns of the permutation relation's grand-product identity (`PermLanes`).
#[derive(Clone, Copy)]
pub struct PermCols {
    pub ri: usize,
    pub w: [usize; 4],
    pub id: [usize; 4],
    pub sigma: [usize; 4],
    pub z: usize,
    pub z_shift: usize,
    pub lagrange_first: usize,
    pub lagrange_last: usize,
}

/// The relations of an Ultra/Mega flavor.
pub struct HonkRelations<'a> {
    pub flavor: &'a FlavorDesc,
    pub layout: &'a Layout,
}

impl<F: FieldLike> RelationSet<F> for HonkRelations<'_> {
    fn num_relations(&self) -> usize {
        self.flavor.relations.len()
    }
    fn num_subrelations(&self, r: usize) -> usize {
        self.flavor.relations[r].num_subrelations()
    }
    fn linearly_independent(&self, r: usize, j: usize) -> bool {
        self.flavor.relations[r].spec().lin_indep[j]
    }
    fn offset_only(&self, r: usize) -> bool {
        self.flavor.relations[r].spec().offset_only
    }
    fn accumulate(&self, r: usize, acc: &mut [F], row: &[F], p: &RelationParams<F>, scaling: &F) {
        self.flavor.relations[r].accumulate(
            acc,
            &Row {
                vals: row,
                layout: self.layout,
            },
            p,
            scaling,
        )
    }
    fn partial_length(&self, r: usize) -> usize {
        self.flavor.relations[r]
            .spec()
            .partial_lengths
            .iter()
            .copied()
            .max()
            .unwrap_or(0)
    }
    fn supports_graded(&self) -> bool {
        true
    }
    fn accumulate_graded(
        &self,
        r: usize,
        acc: &mut [Graded<F::Native>],
        row: &[Graded<F::Native>],
        p: &RelationParams<Graded<F::Native>>,
        scaling: &Graded<F::Native>,
    ) {
        self.flavor.relations[r].accumulate(
            acc,
            &Row {
                vals: row,
                layout: self.layout,
            },
            p,
            scaling,
        )
    }
    fn accumulate_graded_wide(
        &self,
        r: usize,
        acc: &mut [GradedWide<F::Native>],
        row: &[GradedWide<F::Native>],
        p: &RelationParams<GradedWide<F::Native>>,
        scaling: &GradedWide<F::Native>,
    ) {
        self.flavor.relations[r].accumulate(
            acc,
            &Row {
                vals: row,
                layout: self.layout,
            },
            p,
            scaling,
        )
    }
    fn fold_separators(&self, params: &RelationParams<F>, alphas: &[F]) -> Option<RelationParams<F>> {
        let quad = [Rel::Poseidon2QuadInternal, Rel::Poseidon2QuadInternalTerminal, Rel::Poseidon2TransitionEntry];
        let alpha = |g: usize| if g == 0 { F::one() } else { alphas[g - 1].clone() };
        let mut out = params.clone();
        out.quad_batching = vec![Vec::new(); quad.len()];
        let mut g = 0;
        for rel in self.flavor.relations {
            if let Some(i) = quad.iter().position(|q| q == rel) {
                // α_0 = 0 only for α = 0, where every α_j vanishes too: zero weights stay exact.
                let inv = if alpha(g).is_zero() { F::zero() } else { alpha(g).invert() };
                let w: Vec<F> = (0..rel.num_subrelations()).map(|j| alpha(g + j) * &inv).collect();
                out.quad_batching[i] = quad_batching_constants(*rel, &w);
            }
            g += rel.num_subrelations();
        }
        out.quad_batching.iter().any(|v| !v.is_empty()).then_some(out)
    }
    fn permutation_columns(&self) -> Option<PermCols> {
        let l = self.layout;
        Some(PermCols {
            ri: self.flavor.relations.iter().position(|r| *r == Rel::Permutation)?,
            w: [Ent::w_l, Ent::w_r, Ent::w_o, Ent::w_4].map(|e| l.idx(e)),
            id: [Ent::id_1, Ent::id_2, Ent::id_3, Ent::id_4].map(|e| l.idx(e)),
            sigma: [Ent::sigma_1, Ent::sigma_2, Ent::sigma_3, Ent::sigma_4].map(|e| l.idx(e)),
            z: l.idx(Ent::z_perm),
            z_shift: l.shift_idx(Ent::z_perm),
            lagrange_first: l.idx(Ent::lagrange_first),
            lagrange_last: l.idx(Ent::lagrange_last),
        })
    }
    fn skip_columns(&self) -> Option<Vec<usize>> {
        let l = self.layout;
        let mut cols = Vec::new();
        for rel in self.flavor.relations {
            match rel {
                Rel::Permutation => cols.extend([l.idx(Ent::z_perm), l.shift_idx(Ent::z_perm)]),
                Rel::LogDerivLookup => cols.extend([l.idx(Ent::q_lookup), l.idx(Ent::lookup_read_counts)]),
                Rel::Arithmetic => cols.push(l.idx(Ent::q_arith)),
                Rel::DeltaRange => cols.push(l.idx(Ent::q_delta_range)),
                Rel::Elliptic => cols.push(l.idx(Ent::q_elliptic)),
                Rel::Memory => cols.push(l.idx(Ent::q_memory)),
                Rel::NonNativeField => cols.push(l.idx(Ent::q_nnf)),
                Rel::Poseidon2External => cols.push(l.idx(Ent::q_poseidon2_external)),
                Rel::Poseidon2Internal => cols.push(l.idx(Ent::q_poseidon2_internal)),
                Rel::Masking | Rel::MegaEccOpBoundary => {}
                Rel::BilinearBatchedEq => cols.push(l.idx(Ent::q_bilinear_batched_eq)),
                Rel::EccOpQueue => cols.push(l.idx(Ent::lagrange_ecc_op)),
                Rel::Bus(b) => {
                    let s = &BUS_SPECS[*b];
                    cols.extend([s.selector, Ent::q_busread, s.read_counts, s.value].map(|e| l.idx(e)))
                }
                Rel::Poseidon2InitialExternal => cols.push(l.idx(Ent::q_poseidon2_external_initial)),
                Rel::Poseidon2QuadInternal => cols.push(l.idx(Ent::q_poseidon2_quad_internal)),
                Rel::Poseidon2QuadInternalTerminal => cols.push(l.idx(Ent::q_poseidon2_quad_internal_terminal)),
                Rel::Poseidon2TransitionEntry => cols.push(l.idx(Ent::q_poseidon2_transition_entry)),
            }
        }
        cols.sort_unstable();
        cols.dedup();
        Some(cols)
    }
    fn skip(&self, r: usize, row0: &[F], row1: &[F]) -> bool {
        let l = self.layout;
        let zero = |e: Ent| row0[l.idx(e)].is_zero() && row1[l.idx(e)].is_zero();
        match self.flavor.relations[r] {
            Rel::Permutation => {
                (row0[l.idx(Ent::z_perm)].clone() - &row0[l.shift_idx(Ent::z_perm)]).is_zero()
                    && (row1[l.idx(Ent::z_perm)].clone() - &row1[l.shift_idx(Ent::z_perm)]).is_zero()
            }
            Rel::LogDerivLookup => zero(Ent::q_lookup) && zero(Ent::lookup_read_counts),
            Rel::Arithmetic => zero(Ent::q_arith),
            Rel::DeltaRange => zero(Ent::q_delta_range),
            Rel::Elliptic => zero(Ent::q_elliptic),
            Rel::Memory => zero(Ent::q_memory),
            Rel::NonNativeField => zero(Ent::q_nnf),
            Rel::Poseidon2External => zero(Ent::q_poseidon2_external),
            Rel::Poseidon2Internal => zero(Ent::q_poseidon2_internal),
            Rel::Masking | Rel::MegaEccOpBoundary => false,
            Rel::BilinearBatchedEq => zero(Ent::q_bilinear_batched_eq),
            Rel::EccOpQueue => zero(Ent::lagrange_ecc_op),
            // a read gate of another bus column has this column's read selector q_busread·selector = 0
            Rel::Bus(b) => {
                (zero(Ent::q_busread) || zero(BUS_SPECS[b].selector))
                    && zero(BUS_SPECS[b].read_counts)
                    && zero(BUS_SPECS[b].value)
            }
            Rel::Poseidon2InitialExternal => zero(Ent::q_poseidon2_external_initial),
            Rel::Poseidon2QuadInternal => zero(Ent::q_poseidon2_quad_internal),
            Rel::Poseidon2QuadInternalTerminal => zero(Ent::q_poseidon2_quad_internal_terminal),
            Rel::Poseidon2TransitionEntry => zero(Ent::q_poseidon2_transition_entry),
        }
    }
}

/// Shape of one sumcheck instance.
#[derive(Clone)]
pub struct SumcheckSpec {
    /// bb `compute_effective_round_size`: edges past the witness polynomials' extent are all-zero
    /// witness rows on which every relation vanishes, so the prover skips them (halved each round).
    pub witness_end: usize,
    /// bb `row_skip_active_prefix_end` (ECCVM): the trace rows, after which only the final edge
    /// (`lagrange_last`) can contribute.
    pub active_prefix_end: Option<usize>,
    pub virtual_log_n: usize,
    pub has_zk: bool,
    /// Rows `0..trace_offset` are excluded from the relation and handled by the row-disabling
    /// polynomial (all ZK Honk flavors and the ECCVM).
    pub row_disabling: bool,
    pub trace_offset: usize,
    /// Committed sumcheck: round univariates are committed to, not sent.
    pub committed: bool,
    /// `BATCHED_RELATION_PARTIAL_LENGTH`.
    pub batched_len: usize,
    /// Source column of every shifted entity, in order; the shifted columns follow the given
    /// polynomials in the round table and are read one row ahead of their source.
    pub shifted_sources: Vec<usize>,
    pub num_entities: usize,
}

impl SumcheckSpec {
    pub fn honk(flavor: &FlavorDesc, layout: &Layout) -> Self {
        Self {
            witness_end: usize::MAX,
            active_prefix_end: None,
            virtual_log_n: flavor.virtual_log_n,
            has_zk: flavor.has_zk,
            row_disabling: flavor.has_zk,
            trace_offset: flavor.trace_offset,
            committed: false,
            batched_len: layout.batched_len,
            num_entities: layout.num_all(),
            shifted_sources: layout.shifted.iter().map(|e| layout.idx(*e)).collect(),
        }
    }
    pub fn with_witness_end(mut self, witness_end: usize) -> Self {
        self.witness_end = witness_end;
        self
    }
}

/// `alpha, alpha^2, ..., alpha^{n}`.
pub fn alpha_powers<F: FieldLike>(alpha: &F, n: usize) -> Vec<F> {
    let mut out = Vec::with_capacity(n);
    if n > 0 {
        out.push(alpha.clone());
        for i in 1..n {
            let next = out[i - 1].clone() * alpha;
            out.push(next);
        }
    }
    out
}

/// `(1 - u) + u * beta`, the per-variable factor of pow_beta.
pub fn gate_separator_factor<F: FieldLike>(u: &F, beta: &F) -> F {
    F::one() + &(u.clone() * &(beta.clone() - &F::one()))
}

/// `1 - L(u)` where `L` is the indicator of the first `NUM_DISABLED_ROWS_IN_SUMCHECK` rows
/// (`RowDisablingPolynomial::evaluate_at_challenge`).
pub fn row_disabling_main_factor<F: FieldLike>(u: &[F]) -> F {
    let mut eval = F::one();
    for u_k in u.iter().skip(2) {
        eval *= &(F::one() - u_k);
    }
    F::one() - &eval
}

/// Evaluate the full (alpha-batched) relation at a claimed row of evaluations.
/// `scaling` is `pow_beta(u)`; `(main, offset)` are the row-disabling factors `(1-L(u), L(u))`
/// or `(1, 0)` (bb `compute_full_relation_purported_value` + `scale_and_batch_elements`).
pub fn full_relation_value<F: FieldLike>(
    rels: &impl RelationSet<F>,
    evals: &[F],
    params: &RelationParams<F>,
    scaling: &F,
    alphas: &[F],
    row_disabling_challenge: Option<&[F]>,
) -> F {
    // every relation is accumulated before any batching (bb `accumulate_relation_evaluations` then
    // `scale_and_batch_elements`), which fixes the in-circuit gate order
    let accumulated: Vec<Vec<F>> = (0..rels.num_relations())
        .map(|ri| {
            let mut acc = vec![F::zero(); rels.num_subrelations(ri)];
            rels.accumulate(ri, &mut acc, evals, params, scaling);
            acc
        })
        .collect();
    // bb computes the row-disabling factors AFTER accumulating every relation and before batching
    // (`compute_full_relation_purported_value`).
    let (main_factor, offset_factor) = match row_disabling_challenge {
        Some(challenge) => {
            let m = row_disabling_main_factor(challenge);
            let o = F::one() - &m;
            (m, o)
        }
        None => (F::one(), F::zero()),
    };
    let (main_factor, offset_factor) = (&main_factor, &offset_factor);
    let mut result = F::zero();
    let mut alpha_idx = 0;
    for (ri, acc) in accumulated.iter().enumerate() {
        let factor = if rels.offset_only(ri) {
            offset_factor
        } else {
            main_factor
        };
        for (j, e) in acc.iter().enumerate() {
            if ri == 0 && j == 0 {
                result += &(e.clone() * factor);
            } else {
                result += &(e.clone() * &alphas[alpha_idx] * factor);
                alpha_idx += 1;
            }
        }
    }
    result
}

pub struct SumcheckOutput<C: Curve> {
    pub challenge: Vec<C::Fr>,
    /// Claimed evaluations of all entities (unshifted then shifted) at `challenge`.
    pub evals: Vec<C::Fr>,
    pub verified: bool,
    /// ZK only: claimed evaluation of the Libra masking multivariate.
    pub libra_evaluation: C::Fr,
    /// Committed sumcheck only: the round univariate commitments and their values at `0`, `1`, `u_i`.
    pub round_commitments: Vec<C::G>,
    pub round_evaluations: Vec<[C::Fr; 3]>,
}

/// Verify a sumcheck proof: reads round univariates (or their commitments and values at 0, 1) and
/// the claimed evaluations from the transcript, checks each round's sum and the final relation value.
pub fn verify_sumcheck<C: Curve>(
    rels: &impl RelationSet<C::Fr>,
    spec: &SumcheckSpec,
    t: &mut Transcript<C::TF, C::Hash>,
    alphas: &[C::Fr],
    params: &RelationParams<C::Fr>,
    gate_challenges: &[C::Fr],
) -> SumcheckOutput<C> {
    type F<C> = <C as Curve>::Fr;
    assert_eq!(alphas.len(), rels.total_subrelations() - 1, "precomputed alpha powers");

    let mut target_sum = F::<C>::zero();
    let mut libra_challenge = F::<C>::zero();
    if spec.has_zk {
        let libra_total_sum: F<C> = t.receive("Libra:Sum");
        libra_challenge = t.challenge("Libra:Challenge");
        target_sum = libra_total_sum * &libra_challenge;
    }

    let mut verified = true;
    let mut challenge = Vec::with_capacity(spec.virtual_log_n);
    let mut partial_evaluation_result = F::<C>::one();
    let mut round_commitments = Vec::new();
    let mut round_evaluations: Vec<[F<C>; 3]> = Vec::new();
    for round in 0..spec.virtual_log_n {
        if spec.committed {
            round_commitments.push(t.receive(&format!("Sumcheck:univariate_comm_{round}")));
            let e0: F<C> = t.receive(&format!("Sumcheck:univariate_{round}_eval_0"));
            let e1: F<C> = t.receive(&format!("Sumcheck:univariate_{round}_eval_1"));
            round_evaluations.push([e0, e1, F::<C>::zero()]);
            let u: F<C> = t.challenge(&format!("Sumcheck:u_{round}"));
            let factor = gate_separator_factor(&u, &gate_challenges[round]);
            partial_evaluation_result *= &factor;
            challenge.push(u);
        } else {
            let univariate: Vec<F<C>> = t.receive_vec(&format!("Sumcheck:univariate_{round}"), spec.batched_len);
            let u: F<C> = t.challenge(&format!("Sumcheck:u_{round}"));
            let round_sum = univariate[0].clone() + &univariate[1];
            if round_sum.value() != target_sum.value() {
                verified = false;
            }
            target_sum.assert_equal(&round_sum);
            target_sum = evaluate_univariate(&univariate, &u);
            partial_evaluation_result *= &gate_separator_factor(&u, &gate_challenges[round]);
            challenge.push(u);
        }
    }

    let evals: Vec<F<C>> = t.receive_vec("Sumcheck:evaluations", spec.num_entities);

    let mut full_value = full_relation_value(
        rels,
        &evals,
        params,
        &partial_evaluation_result,
        &alphas,
        spec.row_disabling.then_some(challenge.as_slice()),
    );

    let mut libra_evaluation = F::<C>::zero();
    if spec.has_zk {
        libra_evaluation = t.receive("Libra:claimed_evaluation");
        full_value += &(libra_evaluation.clone() * &libra_challenge);
    }

    if spec.committed {
        // Only the first round's sum is checked here; the chain S_i(u_i) = S_{i+1}(0) + S_{i+1}(1) and
        // S_{d-1}(u_{d-1}) = full relation value are enforced through the univariate opening claims.
        let first_sum = round_evaluations[0][0].clone() + &round_evaluations[0][1];
        // bb Grumpkin recursive `perform_final_verification`: reduce all three before the equality.
        first_sum.self_reduce();
        target_sum.self_reduce();
        full_value.self_reduce();
        if first_sum.value() != target_sum.value() {
            verified = false;
        }
        first_sum.assert_equal(&target_sum);
        let d = round_evaluations.len();
        for i in 1..d {
            round_evaluations[i - 1][2] = round_evaluations[i][0].clone() + &round_evaluations[i][1];
        }
        round_evaluations[d - 1][2] = full_value.clone();
    } else {
        if full_value.value() != target_sum.value() {
            verified = false;
        }
        full_value.assert_equal(&target_sum);
    }

    SumcheckOutput {
        challenge,
        evals,
        verified,
        libra_evaluation,
        round_commitments,
        round_evaluations,
    }
}

// ---------------------------------------------------------------------------------------------
// Prover
// ---------------------------------------------------------------------------------------------

/// Libra masking data for ZK sumcheck (bb `ZKSumcheckData`).
pub struct ZkData<C: Curve> {
    pub constant_term: C::Fr,
    /// One random univariate (monomial coefficients) per round, scaled as bb does.
    pub libra_univariates: Vec<Polynomial<C::Fr>>,
    pub libra_concatenated_lagrange: Vec<C::Fr>,
    pub libra_concatenated_monomial: Polynomial<C::Fr>,
    pub interpolation_domain: Vec<C::Fr>,
    pub libra_scaling_factor: C::Fr,
    pub libra_challenge: C::Fr,
    pub libra_running_sum: C::Fr,
    pub libra_evaluations: Vec<C::Fr>,
    pub num_rounds: usize,
}

/// Monomial coefficients of the polynomial with the given values on the subgroup `{g^i}`.
pub fn interpolate_on_subgroup<F: FieldLike + Copy + Send + Sync>(evals: &[F], g: &F) -> Polynomial<F> {
    let n = evals.len();
    let n_inv = F::from_u64(n as u64).invert();
    // coefficient j is n^{-1} sum_k e_k g^{-jk}, the powers read from a table of g^{-i}
    let g_inv = g.invert();
    let mut inv_powers = vec![F::one(); n];
    for i in 1..n {
        inv_powers[i] = inv_powers[i - 1] * g_inv;
    }
    assert!((inv_powers[n - 1] * g_inv) == F::one(), "g is not of order n");
    let nonzero: Vec<(usize, &F)> = evals.iter().enumerate().filter(|(_, e)| !e.is_zero()).collect();
    let coeffs = (0..n)
        .into_par_iter()
        .map(|j| {
            let mut acc = F::zero();
            for (k, e) in &nonzero {
                acc += **e * inv_powers[j * k % n];
            }
            acc * n_inv
        })
        .collect();
    Polynomial::from_coeffs(coeffs)
}

/// The subgroup `{1, g, g^2, ...}` of size `C::SUBGROUP_SIZE`.
pub fn subgroup_domain<C: Curve>() -> Vec<C::Fr>
where
    C::Fr: Copy,
{
    let g = C::Fr::constant(C::subgroup_generator());
    let mut domain = vec![C::Fr::one(); C::SUBGROUP_SIZE];
    for i in 1..C::SUBGROUP_SIZE {
        domain[i] = domain[i - 1] * g;
    }
    domain
}

impl<C: Curve> ZkData<C>
where
    C::Fr: PrimeField<BigInt = U256>,
    C::G: crate::base::msm::BatchMsm<ScalarField = C::Fr>,
{
    pub fn new(
        num_rounds: usize,
        t: &mut crate::base::transcript::Transcript<C::TF, C::Hash>,
        ck: &Ck<C::G>,
        rng: &mut dyn Rng,
    ) -> Self {
        type F<C> = <C as Curve>::Fr;
        let subgroup_size = C::SUBGROUP_SIZE;
        let libra_len = C::LIBRA_UNIVARIATES_LENGTH;
        let constant_term: F<C> = random_field(rng);
        let libra_univariates: Vec<Polynomial<F<C>>> = (0..num_rounds)
            .map(|_| Polynomial::from_coeffs((0..libra_len).map(|_| random_field(rng)).collect()))
            .collect();
        let g = F::<C>::constant(C::subgroup_generator());
        let interpolation_domain = subgroup_domain::<C>();
        // concatenated Libra polynomial in the Lagrange basis over H, then monomial + masking
        assert!(num_rounds * libra_len + 1 < subgroup_size);
        let mut lagrange = vec![F::<C>::zero(); subgroup_size];
        lagrange[0] = constant_term;
        for (r, u) in libra_univariates.iter().enumerate() {
            for (i, c) in u.coeffs.iter().enumerate() {
                lagrange[1 + r * libra_len + i] = *c;
            }
        }
        let mut monomial = interpolate_on_subgroup(&lagrange, &g);
        monomial.coeffs.resize(subgroup_size + 2, F::<C>::zero());
        let masking: [F<C>; 2] = [random_field(rng), random_field(rng)];
        for (i, m) in masking.iter().enumerate() {
            monomial.coeffs[i] -= m;
            monomial.coeffs[subgroup_size + i] += m;
        }
        t.send("Libra:concatenation_commitment", &ck.commit(&monomial));

        // total sum over the hypercube: 2^{d-1} sum_i (g_i(0) + g_i(1)) + 2^d * constant
        let two = F::<C>::from_u64(2);
        let mut total_sum = F::<C>::zero();
        let mut scaling_factor = two.invert();
        for u in &libra_univariates {
            total_sum += u.coeffs[0] + u.evaluate(&F::<C>::one());
            scaling_factor *= two;
        }
        total_sum *= scaling_factor;
        total_sum += constant_term * F::<C>::from_u64(1u64 << num_rounds);
        t.send("Libra:Sum", &total_sum);
        let libra_challenge: F<C> = t.challenge("Libra:Challenge");
        let mut running_sum = total_sum * libra_challenge;

        // setup_auxiliary_data
        scaling_factor *= libra_challenge;
        let mut libra_univariates = libra_univariates;
        for u in libra_univariates.iter_mut() {
            for c in u.coeffs.iter_mut() {
                *c *= scaling_factor;
            }
        }
        running_sum += -libra_univariates[0].coeffs[0] - libra_univariates[0].evaluate(&F::<C>::one());
        running_sum *= two.invert();

        Self {
            constant_term,
            libra_univariates,
            libra_concatenated_lagrange: lagrange,
            libra_concatenated_monomial: monomial,
            interpolation_domain,
            libra_scaling_factor: scaling_factor,
            libra_challenge,
            libra_running_sum: running_sum,
            libra_evaluations: Vec::new(),
            num_rounds,
        }
    }
}

impl<C: Curve> ZkData<C>
where
    C::Fr: Copy,
{
    /// Values of the Libra round univariate at `k = 0..len-1`.
    pub fn round_univariate(&self, round: usize, len: usize) -> Vec<C::Fr> {
        (0..len)
            .map(|k| self.libra_univariates[round].evaluate(&C::Fr::from_u64(k as u64)) + self.libra_running_sum)
            .collect()
    }

    /// bb `update_zk_sumcheck_data`.
    pub fn update(&mut self, u: &C::Fr, round: usize) {
        let half = C::Fr::from_u64(2).invert();
        if round < self.num_rounds - 1 {
            for p in self.libra_univariates.iter_mut() {
                for c in p.coeffs.iter_mut() {
                    *c *= half;
                }
            }
            let eval = self.libra_univariates[round].evaluate(u);
            let next = &self.libra_univariates[round + 1];
            self.libra_running_sum += -next.coeffs[0] - next.evaluate(&C::Fr::one());
            self.libra_running_sum *= half;
            self.libra_running_sum += eval;
            self.libra_scaling_factor *= half;
            self.libra_evaluations.push(eval * self.libra_scaling_factor.invert());
        } else {
            let eval = self.libra_univariates[round].evaluate(u) * self.libra_scaling_factor.invert();
            self.libra_evaluations.push(eval);
        }
    }

    /// `constant + sum_i g_i(u_i)`: the claimed evaluation of the Libra multivariate.
    pub fn claimed_evaluation(&self) -> C::Fr {
        self.libra_evaluations.iter().fold(self.constant_term, |a, e| a + *e)
    }
}

/// Linear univariate given by its values at 0 and 1, evaluated at `k`.
fn linear_at<F: FieldLike + Copy>(v0: &F, v1: &F, k: usize) -> F {
    *v0 + F::from_u64(k as u64) * (*v1 - *v0)
}

/// Relation accumulators, point-major per relation: subrelation `j` of relation `ri` at point `k`
/// lives at `offsets[ri] + k * ns[ri] + j`, so a relation adds point `k` of all its subrelations
/// into one contiguous slice.
struct Accumulators<F> {
    data: Vec<F>,
    offsets: Vec<usize>,
    ns: Vec<usize>,
}

impl<F: FieldLike + Copy> Accumulators<F> {
    fn new(rels: &impl RelationSet<F>, d: usize) -> Self {
        let ns: Vec<usize> = (0..rels.num_relations()).map(|r| rels.num_subrelations(r)).collect();
        let mut offsets = Vec::with_capacity(ns.len());
        let mut total = 0;
        for n in &ns {
            offsets.push(total);
            total += n * d;
        }
        Self {
            data: vec![F::zero(); total],
            offsets,
            ns,
        }
    }
    fn point(&mut self, ri: usize, k: usize) -> &mut [F] {
        let start = self.offsets[ri] + k * self.ns[ri];
        &mut self.data[start..start + self.ns[ri]]
    }
    fn at(&self, ri: usize, j: usize, k: usize) -> F {
        self.data[self.offsets[ri] + k * self.ns[ri] + j]
    }
    fn add(mut self, other: Self) -> Self {
        for (x, y) in self.data.iter_mut().zip(other.data) {
            *x += y;
        }
        self
    }
}

/// `prod_{bits j of e} betas[round + 1 + j]` for every edge `e` of the round (bb `beta_products`):
/// one multiplication per entry.
/// Round r's gate-separator products are the stride-2^r subsequence of round 0's: index the
/// round-0 table instead of materializing a strided copy every round.
#[derive(Clone, Copy)]
struct Pows<'a, F> {
    base: &'a [F],
    step: usize,
}
impl<F: Copy> Pows<'_, F> {
    #[inline]
    fn at(&self, e: usize) -> F {
        self.base[e * self.step]
    }
}

fn gate_separator_products<F: FieldLike + Copy>(betas: &[F], round: usize, num_edges: usize) -> Vec<F> {
    let mut p = vec![F::one(); num_edges.max(1)];
    let mut j = 0;
    while (1 << j) < num_edges {
        let b = betas[round + 1 + j];
        let (lo, hi) = p.split_at_mut(1 << j);
        for (x, y) in hi.iter_mut().zip(lo.iter()) {
            *x = *y * b;
        }
        j += 1;
    }
    p
}

/// `BBREF_TIMING_RELATIONS=1`: nanoseconds and active edges per relation of the current round
/// (meaningful single-threaded), printed for round 0 of every sumcheck.
static RELATION_STATS: std::sync::Mutex<Vec<(u128, u64)>> = std::sync::Mutex::new(Vec::new());
static EXTENSION_NS: std::sync::Mutex<u128> = std::sync::Mutex::new(0);
pub fn relation_stats_enabled() -> bool {
    // Read once. This is called per edge, and `std::env::var_os` takes a process-wide lock, so a
    // per-call lookup serializes every worker against every other one.
    static V: std::sync::LazyLock<bool> =
        std::sync::LazyLock::new(|| std::env::var_os("BBREF_TIMING_RELATIONS").is_some());
    *V
}
fn print_relation_stats<F: FieldLike>(rels: &impl RelationSet<F>, num_edges: usize) {
    let mut stats = RELATION_STATS.lock().unwrap();
    let ext = std::mem::take(&mut *EXTENSION_NS.lock().unwrap());
    eprintln!(
        "[relations] {} edges, row extension {:.0} ms",
        num_edges,
        ext as f64 / 1e6
    );
    for (r, (ns, edges)) in stats.iter().enumerate() {
        eprintln!(
            "[relations]   rel {r:2}: {:8.1} ms over {:7} active edges ({:.1} us/edge, partial length {})",
            *ns as f64 / 1e6,
            edges,
            *ns as f64 / 1e3 / (*edges).max(1) as f64,
            rels.partial_length(r).min(64)
        );
    }
    stats.clear();
}

/// Per-thread scratch for `accumulate_edge`.
struct Scratch<F: NativeField> {
    row0: Vec<F>,
    row1: Vec<F>,
    /// `row1 - row0`: the edge univariate is stepped by repeated addition (bb `extend_edges`).
    delta: Vec<F>,
    row: Vec<F>,
    active: Vec<bool>,
    /// Points evaluated per relation: `min(partial_length, d)`.
    len: Vec<usize>,
    /// Columns read by the edge's active relations: the only ones stepped.
    cols: Vec<usize>,
    mark: Vec<bool>,
    /// Columns the skip predicates read: filled for every edge before the skips run.
    skip_cols: Vec<usize>,
    /// Membership mask of `skip_cols`, so the active-column fill skips what is already filled.
    in_skip: Vec<bool>,
    /// Coefficient-basis path (every relation's univariate fits `GRADED_MAX_LEN`): the edge rows as
    /// degree-tracked univariates and one accumulator per subrelation, converted to point
    /// evaluations once per chunk.
    graded: bool,
    /// Per relation: evaluated in coefficient basis (its univariate fits `GRADED_MAX_LEN`) or by
    /// the pointwise loop (e.g. the ECCVM's degree-21 set relation).
    graded_rel: Vec<bool>,
    row_uni: Vec<Graded<F>>,
    acc_uni: Vec<Vec<Graded<F>>>,
    /// Wide coefficient-basis path for relations over the narrow capacity (ECCVM set/lookup):
    /// rows filled only for the columns those relations read, parameters lifted on first use.
    wide: bool,
    wide_rel: Vec<bool>,
    row_wide: Vec<GradedWide<F>>,
    acc_wide: Vec<Vec<GradedWide<F>>>,
    cols_wide: Vec<usize>,
    params_wide: Option<RelationParams<GradedWide<F>>>,
    /// The permutation identity on lanes of edges (`PermLanes`), where a kernel exists: its
    /// columns, and the kernel once the first edge has supplied β and γ (`Some(None)`: none).
    perm_cols: Option<PermCols>,
    perm: Option<Option<Box<PermLanes>>>,
}

impl<F: NativeField> Scratch<F> {
    fn new(rels: &impl RelationSet<F>, num_columns: usize, d: usize) -> Self {
        Self {
            row0: vec![F::zero(); num_columns],
            row1: vec![F::zero(); num_columns],
            delta: vec![F::zero(); num_columns],
            row: vec![F::zero(); num_columns],
            active: vec![false; rels.num_relations()],
            len: (0..rels.num_relations())
                .map(|r| rels.partial_length(r).min(d))
                .collect(),
            cols: Vec::with_capacity(num_columns),
            mark: vec![false; num_columns],
            skip_cols: {
                let sc = rels.skip_columns().unwrap_or_else(|| (0..num_columns).collect());
                debug_assert!(sc.iter().all(|&j| j < num_columns));
                sc
            },
            in_skip: Vec::new(),
            graded: false,
            graded_rel: Vec::new(),
            row_uni: Vec::new(),
            acc_uni: Vec::new(),
            wide: false,
            wide_rel: Vec::new(),
            row_wide: Vec::new(),
            acc_wide: Vec::new(),
            cols_wide: Vec::new(),
            params_wide: None,
            perm_cols: None,
            perm: None,
        }
        .init_in_skip(num_columns)
        .init_graded(rels, num_columns, d)
    }
    fn init_graded(mut self, rels: &impl RelationSet<F>, num_columns: usize, d: usize) -> Self {
        let zero = Graded::<F, GRADED_MAX_LEN>::constant(<F as ark_ff::AdditiveGroup>::ZERO);
        self.graded_rel = (0..rels.num_relations()).map(|r| graded_relation(rels, r, d)).collect();
        self.graded = self.graded_rel.iter().any(|&g| g);
        self.perm_cols = (rels.permutation_columns())
            .filter(|pc| PERM_LANES && self.graded_rel[pc.ri] && rels.partial_length(pc.ri).min(d) == PERM_POINTS);
        if self.graded {
            self.row_uni = vec![zero; num_columns];
            self.acc_uni = (0..rels.num_relations())
                .map(|r| vec![zero; rels.num_subrelations(r)])
                .collect();
        }
        let zero_wide = GradedWide::<F>::constant(<F as ark_ff::AdditiveGroup>::ZERO);
        self.wide_rel = (0..rels.num_relations()).map(|r| wide_relation(rels, r, d)).collect();
        self.wide = self.wide_rel.iter().any(|&w| w);
        if self.wide {
            self.row_wide = vec![zero_wide; num_columns];
            self.acc_wide = (0..rels.num_relations())
                .map(|r| if self.wide_rel[r] { vec![zero_wide; rels.num_subrelations(r)] } else { Vec::new() })
                .collect();
            self.cols_wide = Vec::with_capacity(num_columns);
        }
        self
    }
    fn init_in_skip(mut self, num_columns: usize) -> Self {
        self.in_skip = vec![false; num_columns];
        for &j in &self.skip_cols {
            self.in_skip[j] = true;
        }
        self
    }
}

/// The columns each relation reads, found by re-randomizing one column at a time: a body that
/// depends on a column changes value with overwhelming probability (Schwartz-Zippel), so the
/// edge extension can skip the others (bb `LazyExtendedEdges`).
fn used_columns<F: FieldLike + Copy>(
    rels: &impl RelationSet<F>,
    num_columns: usize,
    params: &RelationParams<F>,
) -> Vec<Vec<usize>> {
    let mut rng = ark_std::test_rng();
    let mut draw = || F::constant(<F::Native as ark_ff::UniformRand>::rand(&mut rng));
    let row: Vec<F> = (0..num_columns).map(|_| draw()).collect();
    let alt: Vec<F> = (0..num_columns).map(|_| draw()).collect();
    let scaling = draw();
    let eval = |r: usize, row: &[F]| {
        let mut acc = vec![F::zero(); rels.num_subrelations(r)];
        rels.accumulate(r, &mut acc, row, params, &scaling);
        acc
    };
    (0..rels.num_relations())
        .map(|r| {
            let base = eval(r, &row);
            let mut probe = row.clone();
            (0..num_columns)
                .filter(|&j| {
                    probe[j] = alt[j];
                    let changed = eval(r, &probe).iter().zip(&base).any(|(a, b)| !(*a - b).is_zero());
                    probe[j] = row[j];
                    changed
                })
                .collect()
        })
        .collect()
}

/// Lagrange weights extending a univariate known at `0..len` to the points `len..d`:
/// `weights[len][k - len][i] = prod_{j != i} (k - j) / (i - j)` (bb `BarycentricData`), one
/// batched inversion for all of them.
pub struct ExtensionWeights<F> {
    weights: Vec<Vec<Vec<F>>>,
}

impl<F: FieldLike + Copy> ExtensionWeights<F> {
    pub fn new(lengths: impl Iterator<Item = usize>, d: usize) -> Self {
        let mut weights = vec![vec![]; d + 1];
        for len in lengths.filter(|l| *l < d) {
            if !weights[len].is_empty() {
                continue;
            }
            let mut inverse: Vec<F> = (0..len)
                .map(|i| {
                    let mut den = F::one();
                    for j in (0..len).filter(|j| *j != i) {
                        den *= &(F::from_u64(i as u64) - &F::from_u64(j as u64));
                    }
                    den
                })
                .collect();
            for x in inverse.iter_mut() {
                *x = x.invert();
            }
            weights[len] = (len..d)
                .map(|k| {
                    (0..len)
                        .map(|i| {
                            let mut num = F::one();
                            for j in (0..len).filter(|j| *j != i) {
                                num *= &(F::from_u64(k as u64) - &F::from_u64(j as u64));
                            }
                            num * inverse[i]
                        })
                        .collect()
                })
                .collect();
        }
        Self { weights }
    }
    /// The accumulator of subrelation `j` of relation `ri` at point `k`: stored for `k` below the
    /// relation's partial length, extended beyond it.
    fn accumulator_at(
        &self,
        rels: &impl RelationSet<F>,
        acc: &Accumulators<F>,
        ri: usize,
        j: usize,
        k: usize,
        d: usize,
    ) -> F {
        let len = rels.partial_length(ri).min(d);
        if k < len {
            acc.at(ri, j, k)
        } else {
            let mut v = F::zero();
            for (i, w) in self.weights[len][k - len].iter().enumerate() {
                v += &(*w * acc.at(ri, j, i));
            }
            v
        }
    }
}

/// Whether relation `ri` accumulates in coefficient form (`Graded`) for this round size. Shared by
/// the per-worker scratch and the batching step so the two agree on each relation's representation.
fn graded_relation<F: FieldLike>(rels: &impl RelationSet<F>, ri: usize, d: usize) -> bool {
    rels.supports_graded() && rels.partial_length(ri).min(d) <= GRADED_MAX_LEN && !relation_stats_enabled()
}
/// Relations over the narrow capacity but within the wide one run on `GradedWide`.
fn wide_relation<F: FieldLike>(rels: &impl RelationSet<F>, ri: usize, d: usize) -> bool {
    let len = rels.partial_length(ri).min(d);
    rels.supports_wide_graded() && len > GRADED_MAX_LEN && len <= GRADED_WIDE_LEN && !relation_stats_enabled()
}
/// Whether relation `ri`'s accumulators hold coefficients (either graded width) rather than points.
fn coefficient_form<F: FieldLike>(rels: &impl RelationSet<F>, ri: usize, d: usize) -> bool {
    graded_relation(rels, ri, d) || wide_relation(rels, ri, d)
}

/// Add a chunk's coefficient-basis subrelation accumulators into the round accumulators, which for
/// graded relations hold coefficients (slot `k` = coefficient of X^k) rather than point values.
/// Staying in coefficient form makes the per-round batching O(len) per subrelation instead of a
/// barycentric extension to every one of the d points (bb's short-monomial flavors do the same).
fn flush_graded<F: NativeField>(s: &mut Scratch<F>, acc: &mut Accumulators<F>) {
    if let (Some(pc), Some(Some(lanes))) = (s.perm_cols, s.perm.as_mut()) {
        if let Some(v) = lanes.finish::<F>() {
            for (k, c) in points_to_coefficients(&v).into_iter().enumerate() {
                acc.point(pc.ri, k)[0] += c;
            }
        }
    }
    for ri in 0..s.acc_uni.len() {
        if !s.graded_rel[ri] {
            continue;
        }
        for (j, g) in s.acc_uni[ri].iter().enumerate() {
            for (k, c) in g.coeffs().iter().enumerate() {
                acc.point(ri, k)[j] += *c;
            }
        }
    }
    for ri in 0..s.acc_wide.len() {
        if !s.wide_rel[ri] {
            continue;
        }
        for (j, g) in s.acc_wide[ri].iter().enumerate() {
            for (k, c) in g.coeffs().iter().enumerate() {
                acc.point(ri, k)[j] += *c;
            }
        }
    }
}

/// Coefficients of the degree-5 univariate with values `v` at `0..6`: Newton's forward differences
/// `Δᵏv(0)/k!` against the falling factorials `X(X−1)…(X−k+1)`.
fn points_to_coefficients<F: NativeField>(v: &[F; PERM_POINTS]) -> [F; PERM_POINTS] {
    let mut d = *v;
    for k in 1..PERM_POINTS {
        for i in (k..PERM_POINTS).rev() {
            d[i] = d[i] - d[i - 1];
        }
    }
    let mut out = [F::ZERO; PERM_POINTS];
    let mut falling = [F::ZERO; PERM_POINTS];
    falling[0] = F::ONE;
    let mut factorial = F::ONE;
    for k in 0..PERM_POINTS {
        if k > 0 {
            // falling *= (X - (k - 1)); factorial *= k
            let m = F::from((k - 1) as u64);
            for j in (0..=k).rev() {
                let lower = if j > 0 { falling[j - 1] } else { F::ZERO };
                falling[j] = lower - m * falling[j];
            }
            factorial *= F::from(k as u64);
        }
        let w = d[k] * factorial.inverse().unwrap();
        for j in 0..=k {
            out[j] += w * falling[j];
        }
    }
    out
}

/// BBREF_ROUND_DETAIL=1: per-round breakdown of the univariate (pows / edges / head / assembly)
/// and the per-worker busy-time spread inside the edge loop, to locate barrier idle.
fn round_detail() -> bool {
    static V: std::sync::LazyLock<bool> =
        std::sync::LazyLock::new(|| std::env::var_os("BBREF_ROUND_DETAIL").is_some());
    *V
}
static SLOT_BUSY_NS: std::sync::Mutex<Vec<u64>> = std::sync::Mutex::new(Vec::new());

/// The row-disabling head is `trace_offset / 2` edges (two for the Mega flavors); summed on the
/// calling thread because a pool dispatch costs more than the work.
fn accumulate_edges_serial<F: NativeField>(
    rels: &(impl RelationSet<F> + Sync),
    used: &[Vec<usize>],
    table: &[Column<F>],
    edges: std::ops::Range<usize>,
    params: &RelationParams<F>,
    pows: Pows<F>,
    d: usize,
) -> Accumulators<F>
where
    RelationParams<F>: Sync,
{
    let params_uni = lift_params(params);
    let mut acc = Accumulators::new(rels, d);
    let mut scratch = Scratch::new(rels, table.len(), d);
    for e in edges {
        accumulate_edge(rels, used, table, e, params, &params_uni, &pows.at(e), &mut acc, &mut scratch);
    }
    if scratch.graded {
        flush_graded(&mut scratch, &mut acc);
    }
    acc
}

const SERIAL_EDGES: usize = 8;

#[allow(clippy::too_many_arguments)]
fn accumulate_edges<F: NativeField>(
    rels: &(impl RelationSet<F> + Sync),
    used: &[Vec<usize>],
    table: &[Column<F>],
    edges: std::ops::Range<usize>,
    head: Option<std::ops::Range<usize>>,
    params: &RelationParams<F>,
    pows: Pows<F>,
    d: usize,
) -> (Accumulators<F>, Option<Accumulators<F>>)
where
    RelationParams<F>: Sync,
{
    // A few edges cost less than waking the pool (~100us per round).
    if edges.len() <= SERIAL_EDGES {
        let serial = |e| accumulate_edges_serial(rels, used, table, e, params, pows, d);
        return (serial(edges), head.map(serial));
    }
    let params_uni = lift_params(params);
    let params_uni = &params_uni;
    // Several chunks per thread: active-edge cost is skewed (a poseidon2 block's edges cost
    // multiples of an arithmetic block's), so coarse chunks leave threads idle behind stragglers.
    // Floor 1: with per-worker scratch a chunk is cheap, and a floor of 16 left the 8-128-edge
    // rounds on one worker.
    let nthreads = rayon::current_num_threads().max(1);
    // 32 chunks per thread measured better than 16 (6/6 pairs): the straggler spread in the big
    // rounds shrinks faster than the per-chunk claim cost grows.
    let chunk = (edges.len() / (32 * nthreads)).max(1);
    let starts: Vec<usize> = edges.clone().step_by(chunk).collect();
    let nchunks = starts.len();
    // Work items: the main chunks, plus (when present) the row-disabling head as one more item
    // that accumulates into its own slot. Everything in this round — chunks, head, and the graded
    // flush of each slot — happens inside one dispatch; a second dispatch for the flush, or a
    // serial head, was ~0.6ms per round of workers waiting at the barrier.
    let nitems = nchunks + usize::from(head.is_some());
    let next = std::sync::atomic::AtomicUsize::new(0);
    let slots: Vec<std::sync::Mutex<Option<(Accumulators<F>, Scratch<F>)>>> =
        (0..nthreads).map(|_| std::sync::Mutex::new(None)).collect();
    let head_slot: std::sync::Mutex<Option<(Accumulators<F>, Scratch<F>)>> = std::sync::Mutex::new(None);
    let detail = round_detail();
    let busy: Vec<std::sync::atomic::AtomicU64> =
        (0..nthreads).map(|_| std::sync::atomic::AtomicU64::new(0)).collect();
    let work = |w: usize| {
        let t0 = detail.then(std::time::Instant::now);
        let mut guard = slots[w].lock().unwrap();
        let (acc, scratch) = guard
            .get_or_insert_with(|| (Accumulators::new(rels, d), Scratch::new(rels, table.len(), d)));
        let mut did_head = false;
        loop {
            let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if i >= nitems {
                break;
            }
            if i == nchunks {
                let h = head.clone().unwrap();
                let mut hg = head_slot.lock().unwrap();
                let (hacc, hscratch) =
                    hg.get_or_insert_with(|| (Accumulators::new(rels, d), Scratch::new(rels, table.len(), d)));
                for e in h {
                    accumulate_edge(rels, used, table, e, params, params_uni, &pows.at(e), hacc, hscratch);
                }
                did_head = true;
                continue;
            }
            let start = starts[i];
            for e in start..(start + chunk).min(edges.end) {
                accumulate_edge(rels, used, table, e, params, params_uni, &pows.at(e), acc, scratch);
            }
        }
        if scratch.graded {
            flush_graded(scratch, acc);
        }
        if did_head {
            if let Some((hacc, hscratch)) = head_slot.lock().unwrap().as_mut() {
                if hscratch.graded {
                    flush_graded(hscratch, hacc);
                }
            }
        }
        if let Some(t0) = t0 {
            busy[w].fetch_add(t0.elapsed().as_nanos() as u64, std::sync::atomic::Ordering::Relaxed);
        }
    };
    rayon::in_place_scope(|scope| {
        for w in 1..nthreads {
            let work = &work;
            scope.spawn(move |_| work(w));
        }
        work(0);
    });
    if detail {
        let mut g = SLOT_BUSY_NS.lock().unwrap();
        g.clear();
        g.extend(busy.iter().map(|b| b.load(std::sync::atomic::Ordering::Relaxed)));
    }
    let mut out = Accumulators::new(rels, d);
    for slot in &slots {
        if let Some((acc, _)) = slot.lock().unwrap().take() {
            out = Accumulators::add(out, acc);
        }
    }
    let head_acc = head.map(|_| {
        head_slot
            .lock()
            .unwrap()
            .take()
            .map(|(a, _)| a)
            .unwrap_or_else(|| Accumulators::new(rels, d))
    });
    (out, head_acc)
}

/// Add the contributions of the edge `(table[·][2e], table[·][2e+1])` at every `k`, skipping the
/// relations that vanish on it.
#[allow(clippy::too_many_arguments)]
fn accumulate_edge<F: NativeField>(
    rels: &impl RelationSet<F>,
    used: &[Vec<usize>],
    table: &[Column<F>],
    e: usize,
    params: &RelationParams<F>,
    params_uni: &RelationParams<Graded<F>>,
    scaling: &F,
    acc: &mut Accumulators<F>,
    s: &mut Scratch<F>,
) {
    for &j in &s.skip_cols {
        s.row0[j] = column_value(table, j, 2 * e);
        s.row1[j] = column_value(table, j, 2 * e + 1);
    }
    if rels.skip_row(&s.row0, &s.row1) {
        return;
    }
    let mut num_points = 0;
    s.cols.clear();
    for ri in 0..rels.num_relations() {
        s.active[ri] = !rels.skip(ri, &s.row0, &s.row1);
        if s.active[ri] {
            if !(s.graded && s.graded_rel[ri]) && !(s.wide && s.wide_rel[ri]) {
                num_points = num_points.max(s.len[ri]);
            }
            for &j in &used[ri] {
                if !s.mark[j] {
                    s.mark[j] = true;
                    s.cols.push(j);
                }
            }
        }
    }
    // Prefetch the edge two ahead: its ~40 interleaved column streams outrun the hardware prefetchers.
    #[cfg(target_arch = "x86_64")]
    for &j in s.cols.iter().chain(&s.skip_cols) {
        if let Some(r) = column_ref(table, j, 2 * e + 4) {
            unsafe { std::arch::x86_64::_mm_prefetch(r as *const F as *const i8, std::arch::x86_64::_MM_HINT_T0) };
        }
    }
    for &j in &s.cols {
        s.mark[j] = false;
        if !s.in_skip[j] {
            s.row0[j] = column_value(table, j, 2 * e);
            s.row1[j] = column_value(table, j, 2 * e + 1);
        }
        s.delta[j] = s.row1[j] - s.row0[j];
    }
    // The permutation identity goes to the lane kernel on edges without the Lagrange terms.
    let mut perm_ri = usize::MAX;
    if let Some(pc) = s.perm_cols {
        let lagrange = [pc.lagrange_first, pc.lagrange_last];
        if s.active[pc.ri] && lagrange.iter().all(|&j| s.row0[j].is_zero() && s.row1[j].is_zero()) {
            if let Some(lanes) = s.perm.get_or_insert_with(|| PermLanes::new(&params.beta, &params.gamma)) {
                let (r0, dl) = (&s.row0, &s.delta);
                let mut v = [F::zero(); PERM_INPUTS];
                for i in 0..4 {
                    v[6 * i..6 * i + 6].copy_from_slice(&[
                        r0[pc.w[i]],
                        dl[pc.w[i]],
                        r0[pc.id[i]],
                        dl[pc.id[i]],
                        r0[pc.sigma[i]],
                        dl[pc.sigma[i]],
                    ]);
                }
                v[24..].copy_from_slice(&[r0[pc.z], dl[pc.z], r0[pc.z_shift], dl[pc.z_shift], *scaling]);
                lanes.push(&v);
                perm_ri = pc.ri;
            }
        }
    }
    if s.graded {
        for &j in &s.cols {
            s.row_uni[j].set_linear(s.row0[j], s.delta[j]);
        }
        let scaling_uni = Graded::constant(*scaling);
        for ri in 0..rels.num_relations() {
            if s.active[ri] && s.graded_rel[ri] && ri != perm_ri {
                rels.accumulate_graded(ri, &mut s.acc_uni[ri], &s.row_uni, params_uni, &scaling_uni);
            }
        }
    }
    if s.wide {
        s.cols_wide.clear();
        let mut any_wide = false;
        for ri in 0..rels.num_relations() {
            if s.active[ri] && s.wide_rel[ri] {
                any_wide = true;
                for &j in &used[ri] {
                    if !s.mark[j] {
                        s.mark[j] = true;
                        s.cols_wide.push(j);
                    }
                }
            }
        }
        if any_wide {
            if s.params_wide.is_none() {
                s.params_wide = Some(lift_params_wide(params));
            }
            let Scratch { cols_wide, mark, row_wide, row0, delta, acc_wide, active, wide_rel, params_wide, .. } = s;
            for &j in cols_wide.iter() {
                mark[j] = false;
                row_wide[j].set_linear(row0[j], delta[j]);
            }
            let pw = params_wide.as_ref().unwrap();
            let scaling_wide = GradedWide::constant(*scaling);
            for ri in 0..rels.num_relations() {
                if active[ri] && wide_rel[ri] {
                    rels.accumulate_graded_wide(ri, &mut acc_wide[ri], row_wide, pw, &scaling_wide);
                }
            }
        }
    }
    if (0..rels.num_relations()).all(|ri| !s.active[ri] || (s.graded && s.graded_rel[ri]) || (s.wide && s.wide_rel[ri])) {
        return;
    }
    let stats = relation_stats_enabled();
    let mut ext_ns = 0u128;
    let mut rel_ns = vec![0u128; if stats { rels.num_relations() } else { 0 }];
    for k in 0..num_points {
        let t0 = stats.then(std::time::Instant::now);
        for &j in &s.cols {
            if k == 0 {
                s.row[j] = s.row0[j];
            } else {
                s.row[j] += s.delta[j];
            }
        }
        if let Some(t0) = t0 {
            ext_ns += t0.elapsed().as_nanos();
        }
        for ri in 0..rels.num_relations() {
            if !s.active[ri] || k >= s.len[ri] || (s.graded && s.graded_rel[ri]) || (s.wide && s.wide_rel[ri]) {
                continue;
            }
            let t0 = stats.then(std::time::Instant::now);
            rels.accumulate(ri, acc.point(ri, k), &s.row, params, scaling);
            if let Some(t0) = t0 {
                rel_ns[ri] += t0.elapsed().as_nanos();
            }
        }
    }
    if stats {
        let mut st = RELATION_STATS.lock().unwrap();
        st.resize(rels.num_relations(), (0, 0));
        for ri in 0..rels.num_relations() {
            st[ri].0 += rel_ns[ri];
            st[ri].1 += s.active[ri] as u64;
        }
        *EXTENSION_NS.lock().unwrap() += ext_ns;
    }
}

/// bb `batch_over_relations`: `S(k) = sum_r Λ_r(k) sum_j α_{r,j} acc_{r,j}(k) [lin. indep.: · (1 + k(β - 1)) · c]`.
fn batch_over_relations<F: FieldLike + Copy>(
    rels: &impl RelationSet<F>,
    ext: &ExtensionWeights<F>,
    acc: &Accumulators<F>,
    alphas: &[F],
    beta: &F,
    partial_eval: &F,
    row_disabling: Option<(F, F)>,
    d: usize,
) -> Vec<F> {
    // Linear factors as coefficient pairs: pow(X) = pe·(1 + (β−1)X); with row disabling,
    // l(X) = l0 + (l1−l0)X scales offset-only relations and 1 − l(X) the rest. Without row disabling
    // those factors are the constants 1 and 0, which must not grow the polynomial: non-ZK flavors
    // size d = max partial length + 1 for the pow factor alone.
    let pow_lin = [*partial_eval, *partial_eval * (*beta - F::one())];
    let (main_lin, off_lin): (Option<[F; 2]>, Option<[F; 2]>) = match row_disabling {
        Some((l0, l1)) => {
            let dl = l1 - l0;
            (Some([F::one() - l0, F::zero() - dl]), Some([l0, dl]))
        }
        None => (None, None),
    };
    // Batched polynomial of the coefficient-form relations, and the point values of the rest.
    let mut coeffs = vec![F::zero(); d];
    let mut points = vec![F::zero(); d];
    let mut tmp: Vec<F> = Vec::with_capacity(d);
    let mut alpha_idx = 0;
    for ri in 0..rels.num_relations() {
        let offset_only = rels.offset_only(ri);
        let m = if offset_only { off_lin } else { main_lin };
        let graded = coefficient_form(rels, ri, d);
        let len = rels.partial_length(ri).min(d);
        for j in 0..rels.num_subrelations(ri) {
            let alpha = if ri == 0 && j == 0 { F::one() } else { alphas[alpha_idx] };
            if !(ri == 0 && j == 0) {
                alpha_idx += 1;
            }
            // Offset-only relation with no row disabling: factor 0, contributes nothing.
            if offset_only && m.is_none() {
                continue;
            }
            let lin = rels.linearly_independent(ri, j);
            if graded {
                tmp.clear();
                tmp.extend((0..len).map(|k| acc.at(ri, j, k) * alpha));
                if lin {
                    mul_linear(&mut tmp, &pow_lin);
                }
                if let Some(l) = &m {
                    mul_linear(&mut tmp, l);
                }
                assert!(tmp.len() <= d, "batched univariate degree overflow");
                for (c, t) in coeffs.iter_mut().zip(&tmp) {
                    *c += *t;
                }
            } else {
                for k in 0..d {
                    let mut term = ext.accumulator_at(rels, acc, ri, j, k, d) * alpha;
                    if lin {
                        term *= linear_at(&pow_lin[0], &(pow_lin[0] + pow_lin[1]), k);
                    }
                    if let Some(l) = &m {
                        term *= linear_at(&l[0], &(l[0] + l[1]), k);
                    }
                    points[k] += term;
                }
            }
        }
    }
    // Evaluate the batched polynomial at the points 0, 1, ..., d-1 and add the pointwise terms.
    let mut x = F::zero();
    for out in points.iter_mut() {
        let mut v = coeffs[d - 1];
        for c in coeffs[..d - 1].iter().rev() {
            v = v * x + *c;
        }
        *out += v;
        x += &F::one();
    }
    points
}

/// `p *= (l[0] + l[1]·X)` in place on a coefficient vector (grows by one).
fn mul_linear<F: FieldLike + Copy>(p: &mut Vec<F>, l: &[F; 2]) {
    let n = p.len();
    p.push(F::zero());
    for i in (0..n).rev() {
        let pi = p[i];
        p[i + 1] += pi * l[1];
        p[i] = pi * l[0];
    }
}

/// `pow_beta` factor of edge pair `e` in `round`: product of `betas[round+1+j]` over the set bits `j` of `e`.

/// Per-round prover state for one relation set (bb `SumcheckProverRound` +
/// `PartiallyEvaluatedMultivariates`): the table being folded and the row-disabling bookkeeping.
/// A column of the round table: the prover's polynomial itself until the first fold (trimmed to
/// its last non-zero coefficient, bb `end_index`), the shift of another column (read one row
/// ahead), the folded values of rows `start..` once a round has been evaluated (the rows below
/// `start` are zero; golf 0069), or — in round 1 only — the round-0 column (shift applied) read
/// folded at `u_0` on access.
/// `Borrowed` and `Folded` hold rows `start..` of the polynomial (its window, `Polynomial::start`).
pub enum Column<'a, F> {
    Borrowed(usize, &'a [F]),
    ShiftOf(usize),
    Own(usize, Vec<F>),
    Folded(usize, &'a [F], F),
}

/// The owned tables skip each column's leading zeros (selectors of the gate blocks placed late in
/// the trace) from a row aligned to this, so the window start stays even through the folds that
/// matter; once a halving makes it odd the column is a few hundred rows and takes a zero.
const WINDOW_ALIGN: usize = 1 << 10;

/// First row of `s` the folded table must hold: its leading zeros, rounded down to `WINDOW_ALIGN`.
fn window_start<F: FieldLike>(s: &[F]) -> usize {
    s.iter().position(|c| !c.is_zero()).unwrap_or(s.len()) & !(WINDOW_ALIGN - 1)
}

/// Address of column `j` at row `i`, for the prefetch (`None` past the column's end, and for a
/// `Folded` column).
#[cfg(target_arch = "x86_64")]
fn column_ref<'t, F>(table: &'t [Column<F>], j: usize, i: usize) -> Option<&'t F> {
    match &table[j] {
        Column::Borrowed(st, s) => s.get(i.wrapping_sub(*st)),
        Column::Own(st, v) => v.get(i.wrapping_sub(*st)),
        Column::ShiftOf(k) => column_ref(table, *k, i + 1),
        Column::Folded(..) => None,
    }
}

/// Value of column `j` at row `i` (zero past the column's end).
fn column_value<F: FieldLike + Copy>(table: &[Column<F>], j: usize, i: usize) -> F {
    match &table[j] {
        Column::Borrowed(st, s) => s.get(i.wrapping_sub(*st)).copied().unwrap_or_else(F::zero),
        Column::Own(st, v) => v.get(i.wrapping_sub(*st)).copied().unwrap_or_else(F::zero),
        Column::ShiftOf(k) => column_value(table, *k, i + 1),
        Column::Folded(st, s, u) => folded_value(*st, s, u, i),
    }
}

/// Row `i` of the window `s` (from row `st`, even) folded at `u`. Out of line: the multiply would
/// otherwise be inlined into every table read, which slows the rounds that never see a `Folded`
/// column.
#[inline(never)]
fn folded_value<F: FieldLike + Copy>(st: usize, s: &[F], u: &F, i: usize) -> F {
    let at = |k: usize| s.get(k.wrapping_sub(st)).copied().unwrap_or_else(F::zero);
    let (a, b) = (at(2 * i), at(2 * i + 1));
    if a == b { a } else { a + *u * (b - a) }
}

/// One fold of `src` (zero-padded to even length): `a[2k] + u * (a[2k+1] - a[2k])`.
fn fold_vec<F: FieldLike + Copy + 'static>(src: &[F], u: &F) -> Vec<F> {
    if let Some(v) = crate::base::wasm::try_fold_from(src, src.len(), u) {
        return v;
    }
    src.chunks(2)
        .map(|p| {
            let (a, b) = (p[0], p.get(1).copied().unwrap_or_else(F::zero));
            if a == b { a } else { a + *u * (b - a) }
        })
        .collect()
}

/// `fold_vec` in place, halving `v`.
fn fold_halve<F: FieldLike + Copy + 'static>(v: &mut Vec<F>, u: &F) {
    if crate::base::wasm::try_fold_halve(v, u) {
        return;
    }
    let half = v.len().div_ceil(2);
    for k in 0..half {
        let a = v[2 * k];
        let b = if 2 * k + 1 < v.len() { v[2 * k + 1] } else { F::zero() };
        // Equal neighbours (constant selector runs, zero padding) fold to themselves.
        v[k] = if a == b { a } else { a + *u * (b - a) };
    }
    v.truncate(half);
}

/// Rounds past `log_n` are virtual (zero-extension) rounds.
pub struct RoundProver<'a, F> {
    table: Vec<Column<'a, F>>,
    log_n: usize,
    row_disabling: bool,
    excluded_head: usize,
    rd0: F,
    rd1: F,
    round: usize,
    /// Rows past this are all-zero witness rows (bb witness `end_index`), halved each round.
    witness_end: usize,
    active_prefix_end: Option<usize>,
    ext: ExtensionWeights<F>,
    /// Columns read by each relation (`used_columns`), found on the first round.
    used: Vec<Vec<usize>>,
    /// Round-0 gate separators; round r's are the stride-2^r subsequence, so they are built once.
    pows0: Vec<F>,
    /// The relation parameters with the separator-folding constants (`fold_separators`), if any.
    folded: Option<RelationParams<F>>,
    /// Build the owned tables after round 1 rather than round 0 (see `partially_evaluate`): a
    /// quarter of the columns' size instead of half, for an extra multiply per round-1 read.
    pub late_tables: bool,
}

impl<'a, F: NativeField> RoundProver<'a, F>
where
    RelationParams<F>: Sync,
{
    /// The table is `polys` followed by the shifts of `polys[shifted_sources[..]]`. `witness_end`:
    /// rows from there on are all-zero witness rows (bb witness `end_index`; the full size disables
    /// row skipping). `active_prefix_end`: the ECCVM's trace rows, beyond which only the last edge
    /// is evaluated (bb `row_skip_active_prefix_end`).
    pub fn new(
        n: usize,
        polys: &'a [Polynomial<F>],
        shifted_sources: &[usize],
        row_disabling: bool,
        trace_offset: usize,
        witness_end: usize,
        active_prefix_end: Option<usize>,
    ) -> Self {
        debug_assert!(n.is_power_of_two() && polys.iter().all(|p| p.len() <= n));
        let trim = |p: &'a Polynomial<F>| {
            let end = p.coeffs.iter().rposition(|c| !c.is_zero()).map_or(0, |i| i + 1);
            Column::Borrowed(p.start, &p.coeffs[..end])
        };
        let table = {
            // The trailing-zero scans stream every column once; sequential they cost a visible
            // fraction of the whole sumcheck at large sizes.
            let mut table: Vec<Column<'a, F>> = polys.par_iter().map(trim).collect();
            table.extend(shifted_sources.iter().map(|s| Column::ShiftOf(*s)));
            table
        };
        Self {
            table,
            log_n: n.trailing_zeros() as usize,
            row_disabling,
            excluded_head: if row_disabling { trace_offset } else { 0 },
            rd0: F::one(),
            rd1: F::one(),
            round: 0,
            witness_end: witness_end.min(n),
            active_prefix_end,
            ext: ExtensionWeights { weights: vec![] },
            used: vec![],
            pows0: vec![],
            folded: None,
            late_tables: false,
        }
    }
    /// Extension weights for this relation set and univariate length (built once, on the first round).
    fn ensure_weights(&mut self, rels: &impl RelationSet<F>, params: &RelationParams<F>, alphas: &[F], d: usize) {
        if self.ext.weights.is_empty() {
            self.folded = rels.fold_separators(params, alphas);
            self.ext = ExtensionWeights::new((0..rels.num_relations()).map(|r| rels.partial_length(r)), d);
            self.used = used_columns(rels, self.table.len(), params);
        }
    }

    /// bb `compute_edge_ranges`: the edges to evaluate this round, after the disabled head.
    fn edge_ranges(&self, round_size: usize) -> Vec<std::ops::Range<usize>> {
        let head = self.excluded_head / 2;
        let effective = round_size.min(self.witness_end + self.witness_end % 2) / 2;
        let mut ranges = vec![];
        match self.active_prefix_end {
            Some(prefix) if prefix < round_size => {
                let prefix_end = ((prefix + prefix % 2) / 2).min(effective).max(head);
                ranges.push(head..prefix_end);
                if effective > prefix_end && effective >= head + 1 {
                    ranges.push(effective - 1..effective);
                }
            }
            _ => ranges.push(head..effective),
        }
        ranges
    }
    pub fn log_n(&self) -> usize {
        self.log_n
    }
    /// Current value of column `i` (its evaluation once all real rounds are done).
    pub fn current(&self, i: usize) -> F {
        column_value(&self.table, i, 0)
    }
    pub fn evals(&self) -> Vec<F> {
        (0..self.table.len()).map(|i| self.current(i)).collect()
    }

    /// The round univariate of the relations (bb `compute_univariate` + `compute_offset_area_contribution`,
    /// or `compute_virtual_contribution` for a virtual round), without any Libra term.
    pub fn univariate(
        &mut self,
        rels: &(impl RelationSet<F> + Sync),
        params: &RelationParams<F>,
        betas: &[F],
        partial_eval: &F,
        alphas: &[F],
        d: usize,
    ) -> Vec<F> {
        self.ensure_weights(rels, params, alphas, d);
        let folded = self.folded.clone();
        let params = folded.as_ref().unwrap_or(params);
        let round = self.round;
        if round < self.log_n {
            let round_size = 1 << (self.log_n - round);
            if relation_stats_enabled() {
                RELATION_STATS.lock().unwrap().clear();
                *EXTENSION_NS.lock().unwrap() = 0;
            }
            let detail = round_detail();
            let t_pows = std::time::Instant::now();
            if self.pows0.is_empty() {
                self.pows0 = gate_separator_products(betas, 0, 1 << (self.log_n - 1));
            }
            // Round r's separators are the stride-2^r subsequence of round 0's.
            let pows = Pows { base: &self.pows0[..], step: 1usize << round };
            let pows_us = t_pows.elapsed().as_micros();
            let t_edges = std::time::Instant::now();
            let _ge = crate::base::bench::Scope::new("sumcheck/accumulate_edge_chunks");
            let head_range = self.row_disabling.then(|| 0..self.excluded_head / 2);
            let mut head_acc: Option<Accumulators<F>> = None;
            let acc = self
                .edge_ranges(round_size)
                .into_iter()
                .enumerate()
                .map(|(ri, edges)| {
                    let head = if ri == 0 { head_range.clone() } else { None };
                    let (a, h) = accumulate_edges(rels, &self.used, &self.table, edges, head, params, pows, d);
                    if h.is_some() {
                        head_acc = h;
                    }
                    a
                })
                .reduce(Accumulators::add)
                .unwrap_or_else(|| Accumulators::new(rels, d));
            if self.row_disabling && head_acc.is_none() {
                head_acc = Some(accumulate_edges_serial(
                    rels,
                    &self.used,
                    &self.table,
                    head_range.clone().unwrap(),
                    params,
                    pows,
                    d,
                ));
            }
            if relation_stats_enabled() {
                print_relation_stats::<F>(rels, round_size / 2);
            }
            drop(_ge);
            let edges_us = t_edges.elapsed().as_micros();
            let slot_busy: Vec<u64> = if detail { SLOT_BUSY_NS.lock().unwrap().clone() } else { vec![] };
            let t_rest = std::time::Instant::now();
            let _gb = crate::base::bench::Scope::new("sumcheck/extend_and_batch_univariates");
            let mut univariate =
                batch_over_relations(rels, &self.ext, &acc, alphas, &betas[round], partial_eval, None, d);
            if let Some(head) = head_acc {
                let head_uni = batch_over_relations(
                    rels,
                    &self.ext,
                    &head,
                    alphas,
                    &betas[round],
                    partial_eval,
                    Some((self.rd0, self.rd1)),
                    d,
                );
                for (k, v) in head_uni.into_iter().enumerate() {
                    univariate[k] += v;
                }
            }
            drop(_gb);
            if detail {
                let rest_us = t_rest.elapsed().as_micros();
                let (mn, mx, sum) = slot_busy.iter().fold((u64::MAX, 0u64, 0u64), |(a, b, c), &v| {
                    (a.min(v), b.max(v), c + v)
                });
                let n = slot_busy.len().max(1) as f64;
                eprintln!(
                    "[detail r{round:2}] edges={:<6} pows {pows_us:6}us  edges {edges_us:7}us  rest(head+assembly) {rest_us:6}us   worker busy min {:7.0}us mean {:7.0}us max {:7.0}us",
                    round_size / 2,
                    mn as f64 / 1e3,
                    sum as f64 / n / 1e3,
                    mx as f64 / 1e3,
                );
            }
            univariate
        } else {
            // virtual round: the table has one row and the edge is (P(u), 0)
            let mut acc = Accumulators::new(rels, d);
            let edge_table: Vec<Column<F>> = (0..self.table.len())
                .map(|i| Column::Own(0, vec![self.current(i), F::zero()]))
                .collect();
            let params_uni = lift_params(params);
            let mut scratch = Scratch::new(rels, edge_table.len(), d);
            accumulate_edge(
                rels,
                &self.used,
                &edge_table,
                0,
                params,
                &params_uni,
                &F::one(),
                &mut acc,
                &mut scratch,
            );
            if scratch.graded {
                flush_graded(&mut scratch, &mut acc);
            }
            let rd = if self.row_disabling {
                Some((self.rd0, self.rd1))
            } else {
                None
            };
            batch_over_relations(rels, &self.ext, &acc, alphas, &betas[round], partial_eval, rd, d)
        }
    }

    /// bb `partially_evaluate` / `fold_for_zero_extension` plus the row-disabling updates.
    pub fn partially_evaluate(&mut self, u: &F) {
        let round = self.round;
        if round < self.log_n {
            // The folded table is half the size and owned (bb `PartiallyEvaluatedMultivariates`).
            // The first fold must allocate (borrowed and shifted columns read across the table);
            // every later fold halves the owned columns in place, so the round-table footprint is
            // one owned copy rather than a fresh allocation per round.
            if self.table.iter().all(|c| matches!(c, Column::Own(..))) {
                let elems: usize = self
                    .table
                    .iter()
                    .map(|c| match c {
                        Column::Own(_, v) => v.len(),
                        _ => 0,
                    })
                    .sum();
                let fold_col = |col: &mut Column<F>| {
                    let Column::Own(st, v) = col else { unreachable!() };
                    if *st % 2 == 1 {
                        v.insert(0, F::zero());
                        *st -= 1;
                    }
                    fold_halve(v, u);
                    *st /= 2;
                };
                // Late rounds hold a few elements per column; the pool dispatch outweighs the fold.
                if elems < 4096 {
                    self.table.iter_mut().for_each(fold_col);
                } else {
                    self.table.par_iter_mut().for_each(fold_col);
                }
            } else if round == 0 && self.late_tables && self.log_n >= 2 {
                // Late materialization (golf 0074): round 1 reads the round-0 columns folded at u_0
                // on access, and the owned tables are first built after it at a quarter of the size,
                // so no half-size copy of every column ever sits next to the polynomials.
                let src = |c: &Column<'a, F>| match c {
                    Column::Borrowed(st, s) => (*st, *s),
                    _ => unreachable!("round 0 reads borrowed columns"),
                };
                let folded = (self.table.iter())
                    .map(|c| match c {
                        Column::ShiftOf(k) => match src(&self.table[*k]) {
                            (0, s) => (0, s.get(1..).unwrap_or(&[])),
                            _ => unreachable!("windowed columns are not shifted"),
                        },
                        c => src(c),
                    })
                    .map(|(st, s)| Column::Folded(st, s, *u))
                    .collect();
                self.table = folded;
            } else {
                let table = &self.table;
                let folded: Vec<Column<F>> = (0..table.len())
                    .into_par_iter()
                    .map(|j| {
                        let (st, src): (usize, &[F]) = match &table[j] {
                            Column::Borrowed(st, s) => (*st, s),
                            Column::ShiftOf(k) => match &table[*k] {
                                Column::Borrowed(0, s) => (0, &s[1.min(s.len())..]),
                                _ => unreachable!("the first fold reads unwindowed borrowed columns"),
                            },
                            Column::Folded(st, s, u0) => {
                                // Both folds block by block: the half-size intermediate stays small.
                                let w = window_start(s);
                                let s = &s[w..];
                                let mut out = Vec::with_capacity(s.len().div_ceil(4));
                                for block in s.chunks(1 << 12) {
                                    let mut h = fold_vec(block, u0);
                                    fold_halve(&mut h, u);
                                    out.extend_from_slice(&h);
                                }
                                return Column::Own((st + w) / 4, out);
                            }
                            Column::Own(..) => unreachable!("owned columns fold in place"),
                        };
                        let w = window_start(src);
                        Column::Own((st + w) / 2, fold_vec(&src[w..], u))
                    })
                    .collect();
                self.table = folded;
            }
        } else {
            for j in 0..self.table.len() {
                let v = column_value(&self.table, j, 0) * (F::one() - *u);
                self.table[j] = Column::Own(0, vec![v]);
            }
        }
        self.witness_end = self.witness_end.div_ceil(2);
        self.active_prefix_end = self.active_prefix_end.map(|p| p.div_ceil(2));
        if round == 1 {
            self.rd1 = F::zero();
        }
        if round >= 2 {
            self.rd0 *= F::one() - *u;
        }
        if self.row_disabling {
            self.excluded_head = 2;
        }
        self.round += 1;
    }
}

/// Committed-sumcheck bookkeeping (bb `RoundUnivariateHandler<Flavor, true>`).
pub struct CommittedRounds<C: Curve> {
    pub univariates: Vec<Polynomial<C::Fr>>,
    pub commitments: Vec<C::G>,
    pub evaluations: Vec<[C::Fr; 3]>,
    /// Coefficients of the Lagrange basis over the points 0..n-1, built once per sumcheck: the
    /// round univariates all live on the same domain, and interpolating each from scratch cost
    /// n inversions and an O(n³) product per round.
    basis: Vec<Vec<C::Fr>>,
}

impl<C: Curve> CommittedRounds<C>
where
    C::Fr: Copy,
    C::G: crate::base::msm::BatchMsm<ScalarField = C::Fr>,
{
    pub fn new() -> Self {
        Self {
            univariates: Vec::new(),
            commitments: Vec::new(),
            evaluations: Vec::new(),
            basis: Vec::new(),
        }
    }
    /// `basis[i]` = coefficients of the Lagrange polynomial that is 1 at point `i` and 0 at the
    /// other points of 0..n-1 (the same products `Polynomial::interpolate` forms, kept).
    fn lagrange_basis(n: usize) -> Vec<Vec<C::Fr>> {
        let points: Vec<C::Fr> = (0..n).map(|k| C::Fr::from_u64(k as u64)).collect();
        (0..n)
            .map(|i| {
                let mut num = vec![C::Fr::zero(); n];
                num[0] = C::Fr::one();
                let mut deg = 0;
                let mut denom = C::Fr::one();
                for j in 0..n {
                    if j == i {
                        continue;
                    }
                    for k in (0..=deg).rev() {
                        let v = num[k];
                        num[k + 1] += &v;
                        num[k] = v * &(C::Fr::zero() - points[j]);
                    }
                    deg += 1;
                    denom *= &(points[i] - points[j]);
                }
                let inv = denom.invert();
                num.iter().map(|c| *c * inv).collect()
            })
            .collect()
    }
    /// Commit to the round univariate and send its values at 0 and 1.
    pub fn process(
        &mut self,
        round: usize,
        univariate: &[C::Fr],
        ck: &Ck<C::G>,
        t: &mut crate::base::transcript::Transcript<C::TF, C::Hash>,
    ) {
        let n = univariate.len();
        if self.basis.len() != n {
            self.basis = Self::lagrange_basis(n);
        }
        let mut coeffs = vec![C::Fr::zero(); n];
        for (i, e) in univariate.iter().enumerate() {
            for (c, b) in coeffs.iter_mut().zip(&self.basis[i]) {
                *c += &(*b * e);
            }
        }
        let monomial = Polynomial::from_coeffs(coeffs);
        let commitment = ck.commit(&monomial);
        t.send(&format!("Sumcheck:univariate_comm_{round}"), &commitment);
        self.commitments.push(commitment);
        self.univariates.push(monomial);
        t.send(&format!("Sumcheck:univariate_{round}_eval_0"), &univariate[0]);
        t.send(&format!("Sumcheck:univariate_{round}_eval_1"), &univariate[1]);
        self.evaluations.push([univariate[0], univariate[1], C::Fr::zero()]);
        if round > 0 {
            self.evaluations[round - 1][2] = univariate[0] + univariate[1];
        }
    }
    pub fn finalize(&mut self, last_univariate: &[C::Fr], last_challenge: &C::Fr) {
        let last = self.evaluations.len() - 1;
        self.evaluations[last][2] = evaluate_univariate(last_univariate, last_challenge);
    }
}

impl<C: Curve> Default for CommittedRounds<C>
where
    C::Fr: Copy,
    C::G: crate::base::msm::BatchMsm<ScalarField = C::Fr>,
{
    fn default() -> Self {
        Self::new()
    }
}

pub struct SumcheckProverOutput<C: Curve> {
    pub challenge: Vec<C::Fr>,
    pub evals: Vec<C::Fr>,
    pub libra_evaluation: C::Fr,
    /// Committed sumcheck only: round univariates in monomial form, their commitments, and their
    /// values at `0`, `1`, `u_i`.
    pub round_univariates: Vec<Polynomial<C::Fr>>,
    pub round_commitments: Vec<C::G>,
    pub round_evaluations: Vec<[C::Fr; 3]>,
}

/// bb `SumcheckProver::prove` (plain, ZK and committed variants). `ck` is required for the
/// committed variant (to commit to the round univariates).
pub fn prove_sumcheck<C: Curve>(
    n: usize,
    rels: &(impl RelationSet<C::Fr> + Sync),
    spec: &SumcheckSpec,
    polys: &[Polynomial<C::Fr>],
    t: &mut crate::base::transcript::Transcript<C::TF, C::Hash>,
    alpha: &C::Fr,
    betas: &[C::Fr],
    params: &RelationParams<C::Fr>,
    mut zk: Option<&mut ZkData<C>>,
    ck: Option<&Ck<C::G>>,
) -> SumcheckProverOutput<C>
where
    C::Fr: NativeField,
    C::G: crate::base::msm::BatchMsm<ScalarField = C::Fr>,
    RelationParams<C::Fr>: Sync,
{
    type F<C> = <C as Curve>::Fr;
    let d = spec.batched_len;
    let alphas = alpha_powers(alpha, RelationSet::<C::Fr>::total_subrelations(rels) - 1);
    let t_setup = std::time::Instant::now();
    // The committed sumcheck is the ECCVM's alone, so these scopes isolate its per-round work.
    let tag = true;
    let c = spec.committed;
    let _gn = tag.then(|| crate::base::bench::Scope::new(if c { "eccvm-sc/new" } else { "sc/new" })).flatten();
    let mut state = RoundProver::new(
        n,
        polys,
        &spec.shifted_sources,
        spec.row_disabling,
        spec.trace_offset,
        spec.witness_end,
        spec.active_prefix_end,
    );
    drop(_gn);
    let mut committed = CommittedRounds::<C>::new();
    let mut challenge = Vec::with_capacity(spec.virtual_log_n);
    let mut partial_eval = F::<C>::one();
    let mut last_univariate = Vec::new();
    let split_timing = std::env::var_os("BBREF_TIMING").is_some();
    let (mut t_uni, mut t_fold) = (std::time::Duration::ZERO, std::time::Duration::ZERO);
    for round in 0..spec.virtual_log_n {
        let round_start = relation_stats_enabled().then(std::time::Instant::now);
        let t0 = std::time::Instant::now();
        // Split round 0 from the rest: they behave differently (round 0 reads borrowed and
        // shifted columns; later rounds an owned contiguous table) and bb reports the same split.
        let _gu = crate::base::bench::Scope::new(if round == 0 { "sumcheck loop 0" } else { "sumcheck loop" });
        let _gt = tag.then(|| crate::base::bench::Scope::new(if c { "eccvm-sc/univariate" } else { "sc/univariate" })).flatten();
        let mut univariate = state.univariate(rels, params, betas, &partial_eval, &alphas, d);
        drop(_gt);
        drop(_gu);
        t_uni += t0.elapsed();
        if let Some(zk) = zk.as_deref_mut() {
            let _g = tag.then(|| crate::base::bench::Scope::new(if c { "eccvm-sc/zk_univariate" } else { "sc/zk_univariate" })).flatten();
            for (k, v) in zk.round_univariate(round, d).into_iter().enumerate() {
                univariate[k] += v;
            }
        }
        if spec.committed {
            let _g = crate::base::bench::Scope::new("eccvm-sc/commit");
            committed.process(
                round,
                &univariate,
                ck.expect("committed sumcheck needs a commitment key"),
                t,
            );
        } else {
            let _g = crate::base::bench::Scope::new("sc/send");
            t.send_vec(&format!("Sumcheck:univariate_{round}"), &univariate);
        }
        let _gc = tag.then(|| crate::base::bench::Scope::new(if c { "eccvm-sc/challenge" } else { "sc/challenge" })).flatten();
        let u: F<C> = t.challenge(&format!("Sumcheck:u_{round}"));
        drop(_gc);
        let t0 = std::time::Instant::now();
        let _gf = crate::base::bench::Scope::new("Sumcheck::partially_evaluate");
        let _gf2 = tag.then(|| crate::base::bench::Scope::new(if c { "eccvm-sc/fold" } else { "sc/fold" })).flatten();
        state.partially_evaluate(&u);
        drop(_gf2);
        drop(_gf);
        t_fold += t0.elapsed();
        if let Some(t0) = round_start {
            eprintln!("[round {round}] {:.1} ms", t0.elapsed().as_secs_f64() * 1e3);
        }
        if let Some(zk) = zk.as_deref_mut() {
            let _g = tag.then(|| crate::base::bench::Scope::new(if c { "eccvm-sc/zk_update" } else { "sc/zk_update" })).flatten();
            zk.update(&u, round);
        }
        partial_eval *= gate_separator_factor(&u, &betas[round]);
        challenge.push(u);
        last_univariate = univariate;
    }
    if spec.committed {
        let _g = crate::base::bench::Scope::new("eccvm-sc/finalize");
        committed.finalize(&last_univariate, challenge.last().unwrap());
    }
    if split_timing {
        eprintln!(
            "[timing]     sumcheck split: univariate {:.2}s, fold {:.2}s, setup {:.2}s",
            t_uni.as_secs_f64(),
            t_fold.as_secs_f64(),
            t_setup.elapsed().as_secs_f64() - t_uni.as_secs_f64() - t_fold.as_secs_f64()
        );
    }
    let _ge = tag.then(|| crate::base::bench::Scope::new(if c { "eccvm-sc/evals" } else { "sc/evals" })).flatten();
    let evals = state.evals();
    t.send_vec("Sumcheck:evaluations", &evals);
    drop(_ge);
    let mut libra_evaluation = F::<C>::zero();
    if let Some(zk) = zk {
        libra_evaluation = zk.claimed_evaluation();
        t.send("Libra:claimed_evaluation", &libra_evaluation);
    }
    SumcheckProverOutput {
        challenge,
        evals,
        libra_evaluation,
        round_univariates: committed.univariates,
        round_commitments: committed.commitments,
        round_evaluations: committed.evaluations,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::transcript::NativeTranscript;
    use crate::base::{Bn254, Fr};

    /// The prover's relation paths (coefficient basis, gate-type shortcuts, folded Poseidon2
    /// separators) against the circuit-order bodies (constant `FieldT`s, `IS_PROVER = false`) on
    /// edges whose columns are zero, one, another constant or linear, compared as the
    /// separator-batched sum of each relation at every point of its univariate (bb golf 0050).
    #[test]
    fn prover_relation_paths_match_circuit_bodies_on_gate_like_edges() {
        use crate::honk::flavor::{MEGA_APP, MEGA_KERNEL};
        use crate::stdlib::field::FieldT;
        use ark_ff::UniformRand;
        let mut rng = ark_std::test_rng();
        let mut params = RelationParams::<Fr>::default();
        for v in [&mut params.eta, &mut params.eta_two, &mut params.eta_three, &mut params.rom_logup_gamma]
            .into_iter()
            .chain([&mut params.beta, &mut params.gamma, &mut params.public_input_delta])
            .chain([&mut params.beta_sqr, &mut params.beta_cube])
        {
            *v = Fr::rand(&mut rng);
        }
        let k = |v: &Fr| FieldT::constant(*v);
        let params_ref = RelationParams::<FieldT> {
            eta: k(&params.eta),
            eta_two: k(&params.eta_two),
            eta_three: k(&params.eta_three),
            rom_logup_gamma: k(&params.rom_logup_gamma),
            beta: k(&params.beta),
            gamma: k(&params.gamma),
            public_input_delta: k(&params.public_input_delta),
            beta_sqr: k(&params.beta_sqr),
            beta_cube: k(&params.beta_cube),
            ..Default::default()
        };
        let scaling = Fr::rand(&mut rng);
        for flavor in [&MEGA_KERNEL, &MEGA_APP] {
            let layout = flavor.layout();
            let rels = HonkRelations { flavor, layout: &layout };
            let alphas = alpha_powers(&Fr::rand(&mut rng), RelationSet::<Fr>::total_subrelations(&rels) - 1);
            let alpha = |g: usize| if g == 0 { Fr::one() } else { alphas[g - 1] };
            let params_uni = lift_params(&RelationSet::<Fr>::fold_separators(&rels, &params, &alphas).unwrap());
            for _ in 0..300 {
                let edge: Vec<(Fr, Fr)> = (0..layout.num_all())
                    .map(|_| match u8::rand(&mut rng) % 4 {
                        0 => (Fr::zero(), Fr::zero()),
                        1 => (Fr::one(), Fr::one()),
                        2 => (Fr::rand(&mut rng), Fr::zero()),
                        _ => (Fr::rand(&mut rng), Fr::rand(&mut rng)),
                    })
                    .map(|(v, d)| if d.is_zero() { (v, v) } else { (v, d) })
                    .collect();
                let row_uni: Vec<Graded<Fr>> = edge.iter().map(|(a, b)| Graded::linear(*a, *b - a)).collect();
                let mut g = 0;
                for ri in 0..flavor.relations.len() {
                    let n = RelationSet::<Fr>::num_subrelations(&rels, ri);
                    let mut acc = vec![Graded::constant(Fr::zero()); n];
                    let s = Graded::constant(scaling);
                    RelationSet::<Fr>::accumulate_graded(&rels, ri, &mut acc, &row_uni, &params_uni, &s);
                    for x in 0..RelationSet::<Fr>::partial_length(&rels, ri) as u64 {
                        let x = Fr::from(x);
                        let row: Vec<FieldT> = edge.iter().map(|(a, b)| k(&(*a + x * (*b - a)))).collect();
                        let mut acc_ref = vec![FieldT::constant(Fr::zero()); n];
                        rels.accumulate(ri, &mut acc_ref, &row, &params_ref, &k(&scaling));
                        let at = |p: &Graded<Fr>| p.coeffs().iter().rev().fold(Fr::zero(), |v, c| v * x + c);
                        let (mut got, mut want) = (Fr::zero(), Fr::zero());
                        for j in 0..n {
                            got += alpha(g + j) * at(&acc[j]);
                            want += alpha(g + j) * acc_ref[j].get_value();
                        }
                        assert_eq!(got, want, "{} {:?} at {x}", flavor.name, flavor.relations[ri]);
                    }
                    g += n;
                }
            }
        }
    }

    /// One relation, one subrelation: `w0 · w1 == 0` on every row. The relation itself has degree 2
    /// (partial length 3); the batched univariate carries one more point for the linear
    /// gate-separator factor, exactly like bb's `BATCHED_RELATION_PARTIAL_LENGTH`.
    struct ProductVanishes;
    impl<T: FieldLike<Native = Fr>> RelationSet<T> for ProductVanishes {
        fn num_relations(&self) -> usize {
            1
        }
        fn num_subrelations(&self, _r: usize) -> usize {
            1
        }
        fn linearly_independent(&self, _r: usize, _j: usize) -> bool {
            true
        }
        fn offset_only(&self, _r: usize) -> bool {
            false
        }
        fn accumulate(&self, _r: usize, acc: &mut [T], row: &[T], _p: &RelationParams<T>, scaling: &T) {
            acc[0] += row[0].clone() * &row[1] * scaling;
        }
        fn partial_length(&self, _r: usize) -> usize {
            3
        }
    }

    fn spec(log_n: usize) -> SumcheckSpec {
        SumcheckSpec {
            witness_end: 1 << log_n,
            active_prefix_end: None,
            virtual_log_n: log_n,
            has_zk: false,
            row_disabling: false,
            trace_offset: 0,
            committed: false,
            batched_len: 4,
            shifted_sources: vec![],
            num_entities: 2,
        }
    }

    fn run(w0: Vec<u64>, w1: Vec<u64>) -> (SumcheckOutput<Bn254>, Vec<Fr>, Vec<Fr>) {
        let log_n = w0.len().trailing_zeros() as usize;
        let polys = [w0, w1].map(|w| Polynomial::from_coeffs(w.into_iter().map(Fr::from).collect()));
        let params = RelationParams::default();
        let alpha = Fr::from(0u64); // one subrelation: no batching challenge is consumed
        let betas: Vec<Fr> = (0..log_n).map(|i| Fr::from(3 + i as u64)).collect();

        let mut pt = NativeTranscript::new();
        let out = prove_sumcheck::<Bn254>(
            1 << log_n,
            &ProductVanishes,
            &spec(log_n),
            &polys,
            &mut pt,
            &alpha,
            &betas,
            &params,
            None,
            None,
        );
        let proof = pt.export_proof();

        let mut vt = NativeTranscript::from_proof(&proof);
        let v = verify_sumcheck::<Bn254>(&ProductVanishes, &spec(log_n), &mut vt, &[], &params, &betas);
        (v, out.challenge, out.evals)
    }

    /// A satisfying trace round-trips: the verifier accepts and lands on the prover's challenge
    /// point and claimed evaluations.
    #[test]
    fn round_trip_on_satisfying_trace() {
        let (v, p_challenge, p_evals) = run(vec![0, 5, 0, 7], vec![3, 0, 9, 0]);
        assert!(v.verified);
        assert_eq!(v.challenge, p_challenge);
        assert_eq!(v.evals, p_evals);
    }

    /// One violating row (w0·w1 ≠ 0) makes the honestly-computed proof claim a nonzero sum, which
    /// the first round check (u(0) + u(1) == target) rejects.
    #[test]
    fn violating_row_rejected_at_first_round() {
        let (v, _, _) = run(vec![0, 5, 2, 7], vec![3, 0, 9, 0]);
        assert!(!v.verified);
    }
}
