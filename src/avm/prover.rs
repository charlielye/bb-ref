//! The AVM prover (bb `vm2/constraining/prover.cpp`) over a generated trace, the relations
//! interpreted from the same tables as the verifier. The transcript is the verifier's
//! ([`super::verifier::reduce_to_pairing_check`]) from the prover's side: the vk hash and the
//! public-input columns, the wire commitments, `beta, gamma`, the log-derivative inverse
//! commitments, sumcheck at the fixed trace size, then Shplemini over one unshifted and one
//! shifted polynomial batched with short challenges, and KZG.

use super::program::programs;
use super::relations::AvmRelations;
use super::tables::{layout, relations, Body};
use crate::base::field::Fr;
use crate::base::group::Curve;
use crate::base::poly::Poly;
use crate::base::srs::Srs;
use crate::base::transcript::Transcript;
use crate::base::Bn254;
use crate::honk::pcs::{kzg_open, shplemini_prove};
use crate::honk::relations::RelationParams;
use crate::honk::sumcheck::RelationSet;
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
            let row = |k: usize| u32_at(from + 36 * k) as usize;
            let mut coeffs = vec![Fr::zero(); (0..count).map(|k| row(k) + 1).max().unwrap_or(0)];
            for k in 0..count {
                let e = &bytes[from + 36 * k + 4..from + 36 * (k + 1)];
                let limbs: [u64; 4] =
                    std::array::from_fn(|i| u64::from_le_bytes(e[8 * i..8 * i + 8].try_into().unwrap()));
                coeffs[row(k)] = Fr::from_bigint(BigInt(limbs)).expect("non-canonical trace value");
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

/// Entity `e`'s stored rows: past them it is zero.
fn entity_len(polys: &[Poly], e: usize) -> usize {
    let l = layout();
    match e.checked_sub(l.num_unshifted()) {
        None => polys[e].len(),
        Some(k) => polys[l.to_be_shifted_start() + k].len().saturating_sub(1),
    }
}

/// bb `GenericLookupSettings`/`GenericPermutationSettings` term at a row: `((0·β + c₀)·β + c₁)·… + γ`.
fn tuple_term(polys: &[Poly], cols: &[usize], row: usize, p: &RelationParams<Fr>) -> Fr {
    cols.iter()
        .fold(Fr::zero(), |acc, &c| acc * p.beta + entity_at(polys, c, row))
        + p.gamma
}

/// bb `compute_logderivative_inverse` for every interaction: on the rows where either selector is
/// one, the inverse of the product of the lookup and table terms; sized to the longer selector.
fn compute_inverses(polys: &mut [Poly], p: &RelationParams<Fr>) {
    let interactions: Vec<_> = relations()
        .iter()
        .filter_map(|r| match &r.body {
            Body::Interaction {
                src_sel,
                dst_sel,
                inverses,
                src,
                dst,
                ..
            } => Some((*src_sel, *dst_sel, *inverses, src, dst)),
            _ => None,
        })
        .collect();
    // Each interaction in row chunks, inverted chunk by chunk: one interaction can span the trace.
    const CHUNK: usize = 1 << 14;
    let polys_ref = &*polys;
    let ends: Vec<usize> = interactions
        .iter()
        .map(|&(src_sel, dst_sel, ..)| entity_len(polys_ref, src_sel).max(entity_len(polys_ref, dst_sel)))
        .collect();
    // Past every one of a tuple's columns the term is γ alone (golf): no Horner there.
    let tuple_end = |cols: &[usize]| cols.iter().map(|&c| entity_len(polys_ref, c)).max().unwrap_or(0);
    let tuple_ends: Vec<(usize, usize)> = interactions
        .iter()
        .map(|&(_, _, _, src, dst)| (tuple_end(src), tuple_end(dst)))
        .collect();
    let mut inv: Vec<Vec<Fr>> = ends.iter().map(|&end| vec![Fr::zero(); end]).collect();
    let mut chunks: Vec<(usize, usize, &mut [Fr])> = Vec::new();
    for (k, v) in inv.iter_mut().enumerate() {
        chunks.extend(v.chunks_mut(CHUNK).enumerate().map(|(c, s)| (k, c * CHUNK, s)));
    }
    chunks.into_par_iter().for_each(|(k, from, out)| {
        let (src_sel, dst_sel, _, src, dst) = interactions[k];
        let (src_end, dst_end) = tuple_ends[k];
        let term = |cols: &[usize], end: usize, row: usize| {
            if row < end {
                tuple_term(polys_ref, cols, row, p)
            } else {
                p.gamma
            }
        };
        for (o, row) in out.iter_mut().zip(from..) {
            if entity_at(polys_ref, src_sel, row).is_one() || entity_at(polys_ref, dst_sel, row).is_one() {
                *o = term(src, src_end, row) * term(dst, dst_end, row);
            }
        }
        ark_ff::serial_batch_inversion_and_mul(out, &Fr::one());
    });
    let inverses: Vec<(usize, Poly)> = interactions
        .iter()
        .zip(inv)
        .map(|(&(_, _, inverses, ..), v)| (inverses, Poly::from_coeffs(v)))
        .collect();
    for (i, poly) in inverses {
        assert!(polys[i].end_index() == 0, "inverse column {i} is expected to be empty");
        polys[i] = poly;
    }
}

/// bb `run_check_circuit`: every relation on every row of the trace, with random `beta, gamma`
/// and the inverses they give. A linearly independent subrelation must vanish on each row (where
/// its relation's skip condition does not hold); every subrelation must sum to zero over the trace.
/// Relation by relation, as bb, in row chunks, reading the columns in place: a relation stops at
/// its skip columns' end, past which they are zero and it skips.
pub fn check_circuit(mut polys: Vec<Poly>) -> Result<(), String> {
    const CHUNK: usize = 1 << 14;
    let l = layout();
    let params = RelationParams {
        beta: crate::base::rng::global_field(),
        gamma: crate::base::rng::global_field(),
        ..Default::default()
    };
    compute_inverses(&mut polys, &params);
    crate::base::timing::phase("avm check: log-derivative inverses");
    let polys = &polys;
    let num_rows = polys.iter().map(Poly::len).max().unwrap_or(0);
    let work: Vec<(usize, usize, usize)> = relations()
        .iter()
        .enumerate()
        .flat_map(|(r, rel)| {
            let end = match rel.skip.is_empty() {
                true => num_rows,
                false => rel.skip.iter().map(|&c| entity_len(polys, c)).max().unwrap(),
            };
            (0..end)
                .step_by(CHUNK)
                .map(move |from| (r, from, (from + CHUNK).min(end)))
        })
        .collect();
    // Per chunk: its relation's sums, or the first row a linearly independent subrelation fails.
    let chunks: Vec<(usize, Result<Vec<Fr>, usize>)> = work
        .into_par_iter()
        .map(|(r, from, to)| {
            let rel = &relations()[r];
            let mut sum = vec![Fr::zero(); rel.num_subrelations];
            let (mut regs, mut row) = (Vec::new(), Vec::new());
            for i in from..to {
                if !rel.skip.is_empty() && rel.skip.iter().map(|&c| entity_at(polys, c, i)).sum::<Fr>().is_zero() {
                    continue;
                }
                let mut acc = vec![Fr::zero(); rel.num_subrelations];
                match &programs()[r] {
                    Some(program) => program.accumulate_row(&mut acc, |e| entity_at(polys, e, i), &params, &mut regs),
                    None => {
                        row.resize(l.num_all(), Fr::zero());
                        row.iter_mut()
                            .enumerate()
                            .for_each(|(e, v)| *v = entity_at(polys, e, i));
                        RelationSet::accumulate(&AvmRelations, r, &mut acc, &row, &params, &Fr::one());
                    }
                }
                for (j, v) in acc.iter().enumerate() {
                    if RelationSet::<Fr>::linearly_independent(&AvmRelations, r, j) && !v.is_zero() {
                        return (r, Err(i));
                    }
                    sum[j] += v;
                }
            }
            (r, Ok(sum))
        })
        .collect();
    crate::base::timing::phase("avm check: relations");
    let mut sums: Vec<Vec<Fr>> = relations()
        .iter()
        .map(|r| vec![Fr::zero(); r.num_subrelations])
        .collect();
    let mut failed: Vec<Option<usize>> = vec![None; sums.len()];
    for (r, c) in chunks {
        match c {
            Ok(sum) => sums[r].iter_mut().zip(sum).for_each(|(x, y)| *x += y),
            Err(i) => failed[r] = Some(failed[r].map_or(i, |f| f.min(i))),
        }
    }
    for (r, rel) in relations().iter().enumerate() {
        if let Some(i) = failed[r] {
            let mut acc = vec![Fr::zero(); rel.num_subrelations];
            let row: Vec<Fr> = (0..l.num_all()).map(|e| entity_at(polys, e, i)).collect();
            RelationSet::accumulate(&AvmRelations, r, &mut acc, &row, &params, &Fr::one());
            let j = (0..acc.len())
                .position(|j| RelationSet::<Fr>::linearly_independent(&AvmRelations, r, j) && !acc[j].is_zero())
                .unwrap();
            return Err(format!("Relation {}, subrelation {j} failed at row {i}", rel.name));
        }
    }
    for (r, sum) in sums.iter().enumerate() {
        if let Some(j) = sum.iter().position(|v| !v.is_zero()) {
            return Err(format!("Relation {}, subrelation {j} failed.", relations()[r].name));
        }
    }
    Ok(())
}

/// The public-input columns the verifier reads, from the trace's `public_inputs_cols_*`.
fn public_input_columns(polys: &[Poly]) -> Vec<Vec<Fr>> {
    let l = layout();
    let column = |i: usize, len: usize| {
        let col = &polys[l.col(&format!("public_inputs_cols_{i}_"))];
        (0..len).map(|j| col.at(j)).collect()
    };
    l.public_input_column_lengths
        .iter()
        .enumerate()
        .map(|(i, &len)| column(i, len))
        .collect()
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
    let sc = prove_sumcheck::<Bn254>(
        n,
        &AvmRelations,
        &spec,
        &polys,
        &mut t,
        &alpha,
        &gate_challenges,
        &params,
        None,
        None,
    );
    crate::base::timing::phase("avm: sumcheck");

    // Batch with short challenges: the to-be-shifted wires (unshifted form) into one polynomial,
    // every column (those included) into the other.
    let challenges: Vec<Fr> = t.short_challenges(&vec!["unshifted"; l.num_unshifted()]);
    let (tbs_start, tbs_end) = (l.to_be_shifted_start(), l.to_be_shifted_end());
    let dyadic = |p: &[(&Poly, Fr)]| p.iter().map(|(q, _)| q.len()).max().unwrap_or(1).next_power_of_two();
    let shifted_terms: Vec<(&Poly, Fr)> = (tbs_start..tbs_end).map(|i| (&polys[i], challenges[i])).collect();
    let size = dyadic(
        &(0..l.num_unshifted())
            .map(|i| (&polys[i], challenges[i]))
            .collect::<Vec<_>>(),
    );
    let batched_shifted = Poly::linear_combination(size, &shifted_terms);
    // The to-be-shifted columns carry the same challenges in both batches: the unshifted batch is
    // the shifted one plus the other columns (bb's `batched_unshifted += batched_shifted`).
    let mut unshifted_terms: Vec<(&Poly, Fr)> = (0..l.num_unshifted())
        .filter(|i| !(tbs_start..tbs_end).contains(i))
        .map(|i| (&polys[i], challenges[i]))
        .collect();
    unshifted_terms.push((&batched_shifted, Fr::one()));
    let batched_unshifted = Poly::linear_combination(size, &unshifted_terms);
    crate::base::timing::phase("avm: pcs batching");
    let claim = shplemini_prove::<Bn254>(
        size,
        &[&batched_unshifted],
        &[&batched_shifted],
        &sc.challenge,
        &ck,
        &mut t,
        None,
        &[],
    );
    kzg_open::<Bn254>(claim, &ck, &mut t);
    crate::base::timing::phase("avm: pcs");
    t.export_proof()
}
