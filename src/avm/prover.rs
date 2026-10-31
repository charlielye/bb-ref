//! The AVM prover (bb `vm2/constraining/prover.cpp`) over a generated trace, the relations
//! interpreted from the same tables as the verifier. The transcript is the verifier's
//! ([`super::verifier::reduce_to_pairing_check`]) from the prover's side: the vk hash and the
//! public-input columns, the wire commitments, `beta, gamma`, the log-derivative inverse
//! commitments, sumcheck at the fixed trace size, then Shplemini over one unshifted and one
//! shifted polynomial batched with short challenges, and KZG.

use super::relations::AvmRelations;
use super::tables::{layout, relations, Body};
use crate::base::field::{batch_invert, Fr};
use crate::base::poly::Poly;
use crate::base::srs::Srs;
use crate::base::transcript::Transcript;
use crate::base::Bn254;
use crate::base::group::Curve;
use crate::honk::pcs::{kzg_open, shplemini_prove};
use crate::honk::relations::RelationParams;
use crate::honk::sumcheck::{prove_sumcheck, SumcheckSpec};
use ark_ff::{BigInt, One, PrimeField, Zero};
use rayon::prelude::*;

/// The unshifted columns, in bb's `Column` order, from bb's sparse trace (`bb_avm_trace`): per
/// column a u32 entry count, then that many (u32 row, four u64 canonical limbs) entries, all
/// little-endian. Each column is sized to its last non-zero row, as bb's polynomials are.
pub fn polys_from_trace(bytes: &[u8]) -> Vec<Poly> {
    let l = layout();
    let u32_at = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
    let mut starts = Vec::with_capacity(l.num_unshifted());
    let mut at = 0;
    while at < bytes.len() {
        let count = u32_at(at) as usize;
        starts.push((at + 4, count));
        at += 4 + count * 36;
    }
    assert_eq!(at, bytes.len(), "truncated AVM trace");
    assert_eq!(starts.len(), l.num_unshifted(), "AVM trace column count");
    starts
        .into_par_iter()
        .map(|(from, count)| {
            let entry = |k: usize| {
                let e = &bytes[from + 36 * k..from + 36 * (k + 1)];
                let limbs: [u64; 4] = std::array::from_fn(|i| u64::from_le_bytes(e[4 + 8 * i..12 + 8 * i].try_into().unwrap()));
                (u32::from_le_bytes(e[..4].try_into().unwrap()) as usize, Fr::from_bigint(BigInt(limbs)).expect("non-canonical trace value"))
            };
            let rows = (0..count).map(|k| entry(k).0 + 1).max().unwrap_or(0);
            let mut coeffs = vec![Fr::zero(); rows];
            for k in 0..count {
                let (row, v) = entry(k);
                coeffs[row] = v;
            }
            Poly::from_coeffs(coeffs)
        })
        .collect()
}

/// Entity `e` (an unshifted column, or past them a shift of a to-be-shifted one) at `row`.
fn entity_at(polys: &[Poly], e: usize, row: usize) -> Fr {
    let l = layout();
    match e.checked_sub(l.num_unshifted()) {
        None => polys[e].at(row),
        Some(k) => polys[l.to_be_shifted_start() + k].at(row + 1),
    }
}

/// bb `GenericLookupSettings`/`GenericPermutationSettings` term at a row: `((0·β + c₀)·β + c₁)·… + γ`.
fn tuple_term(polys: &[Poly], cols: &[usize], row: usize, p: &RelationParams<Fr>) -> Fr {
    cols.iter().fold(Fr::zero(), |acc, &c| acc * p.beta + entity_at(polys, c, row)) + p.gamma
}

/// bb `compute_logderivative_inverse` for every interaction: on the rows where either selector is
/// one, the inverse of the product of the lookup and table terms; sized to the longer selector.
fn compute_inverses(polys: &mut [Poly], p: &RelationParams<Fr>) {
    let interactions: Vec<_> = relations()
        .iter()
        .filter_map(|r| match &r.body {
            Body::Interaction { src_sel, dst_sel, inverses, src, dst, .. } => Some((*src_sel, *dst_sel, *inverses, src, dst)),
            _ => None,
        })
        .collect();
    let inverses: Vec<(usize, Poly)> = interactions
        .par_iter()
        .map(|&(src_sel, dst_sel, inverses, src, dst)| {
            let polys = &*polys;
            let len = |e: usize| match e.checked_sub(layout().num_unshifted()) {
                None => polys[e].len(),
                Some(k) => polys[layout().to_be_shifted_start() + k].len().saturating_sub(1),
            };
            let end = len(src_sel).max(len(dst_sel));
            let mut inv: Vec<Fr> = (0..end)
                .map(|row| {
                    if entity_at(polys, src_sel, row).is_one() || entity_at(polys, dst_sel, row).is_one() {
                        tuple_term(polys, src, row, p) * tuple_term(polys, dst, row, p)
                    } else {
                        Fr::zero()
                    }
                })
                .collect();
            batch_invert(&mut inv);
            (inverses, Poly::from_coeffs(inv))
        })
        .collect();
    for (i, poly) in inverses {
        assert!(polys[i].end_index() == 0, "inverse column {i} is expected to be empty");
        polys[i] = poly;
    }
}

/// The public-input columns the verifier reads, from the trace's `public_inputs_cols_*`.
pub fn public_input_columns(polys: &[Poly]) -> Vec<Vec<Fr>> {
    let l = layout();
    let column = |i: usize, len: usize| (0..len).map(|j| polys[l.col(&format!("public_inputs_cols_{i}_"))].at(j)).collect();
    l.public_input_column_lengths.iter().enumerate().map(|(i, &len)| column(i, len)).collect()
}

/// bb `AvmProver::construct_proof` over the trace's unshifted columns (the derived ones empty).
pub fn prove(mut polys: Vec<Poly>, srs: &Srs) -> Vec<Fr> {
    let l = layout();
    assert_eq!(polys.len(), l.num_unshifted());
    let log_n = l.max_trace_log_size;
    let n = 1usize << log_n;
    let (np, nw) = (l.num_precomputed, l.num_wires);
    let mut t = Transcript::<<Bn254 as Curve>::TF, <Bn254 as Curve>::Hash>::new();
    t.add_to_hash_buffer("avm_vk_hash", &l.vk_hash);
    for column in public_input_columns(&polys) {
        for v in &column {
            t.add_to_hash_buffer("public_input", v);
        }
    }

    let max_end = polys.iter().map(Poly::len).max().unwrap_or(0);
    let ck = srs.bn254_key(max_end.next_power_of_two());
    crate::base::timing::phase("avm: polynomials");
    let wires: Vec<&Poly> = polys[np..np + nw].iter().collect();
    for c in ck.batch_commit(&wires) {
        t.send("wire", &c);
    }
    crate::base::timing::phase("avm: wire commitments");

    let bg: Vec<Fr> = t.challenges(&["beta", "gamma"]);
    let params = RelationParams {
        beta: bg[0],
        gamma: bg[1],
        ..Default::default()
    };
    compute_inverses(&mut polys, &params);
    crate::base::timing::phase("avm: log-derivative inverses");
    let derived: Vec<&Poly> = polys[np + nw..].iter().collect();
    for c in ck.batch_commit(&derived) {
        t.send("derived", &c);
    }
    crate::base::timing::phase("avm: inverse commitments");

    let alpha: Fr = t.challenge("Sumcheck:alpha");
    let gate_challenges: Vec<Fr> = t.dyadic_powers("Sumcheck:gate_challenge", log_n);
    let spec = SumcheckSpec {
        witness_end: max_end,
        active_prefix_end: None,
        virtual_log_n: log_n,
        has_zk: false,
        row_disabling: false,
        trace_offset: 0,
        committed: false,
        batched_len: l.max_partial_length + 1,
        shifted_sources: (l.to_be_shifted_start()..l.to_be_shifted_end()).collect(),
        num_entities: l.num_all(),
        translator: false,
    };
    let sc = prove_sumcheck::<Bn254>(n, &AvmRelations, &spec, &polys, &mut t, &alpha, &gate_challenges, &params, None, None);
    crate::base::timing::phase("avm: sumcheck");

    // Batch with short challenges: the to-be-shifted wires (unshifted form) into one polynomial,
    // every column (those included) into the other.
    let challenges: Vec<Fr> = t.short_challenges(&vec!["unshifted"; l.num_unshifted()]);
    let (tbs_start, tbs_end) = (l.to_be_shifted_start(), l.to_be_shifted_end());
    let dyadic = |p: &[(&Poly, Fr)]| p.iter().map(|(q, _)| q.len()).max().unwrap_or(1).next_power_of_two();
    let shifted_terms: Vec<(&Poly, Fr)> = (tbs_start..tbs_end).map(|i| (&polys[i], challenges[i])).collect();
    let unshifted_terms: Vec<(&Poly, Fr)> = (0..l.num_unshifted()).map(|i| (&polys[i], challenges[i])).collect();
    let size = dyadic(&unshifted_terms);
    let batched_shifted = Poly::linear_combination(size, &shifted_terms);
    let batched_unshifted = Poly::linear_combination(size, &unshifted_terms);
    crate::base::timing::phase("avm: pcs batching");
    let claim = shplemini_prove::<Bn254>(size, &[&batched_unshifted], &[&batched_shifted], &sc.challenge, &ck, &mut t, None, &[]);
    kzg_open::<Bn254>(claim, &ck, &mut t);
    crate::base::timing::phase("avm: pcs");
    t.export_proof()
}
