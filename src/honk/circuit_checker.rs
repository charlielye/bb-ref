//! Check that every relation of a flavor vanishes on a proving instance (bb `circuit_checker/`,
//! reduced to reusing `Rel::accumulate`): linearly independent subrelations must be zero on every
//! active row, linearly dependent ones must sum to zero over the trace.

use super::flavor::Rel;
use super::prover_instance::ProverInstance;
use super::relations::{RelationParams, Row};
use crate::base::field::FieldLike;
use crate::base::Fr;

/// The first failing `(relation, subrelation, row)` (row = `None` for a trace-wide sum), if any.
/// The instance must already hold the Oink-derived witness (`w_4` records, inverses, `z_perm`).
pub fn check_circuit(inst: &ProverInstance, params: &RelationParams<Fr>) -> Option<(Rel, usize, Option<usize>)> {
    let flavor = inst.flavor;
    let one = Fr::one();
    let mut sums: Vec<Vec<Fr>> = flavor
        .relations
        .iter()
        .map(|r| vec![Fr::zero(); r.num_subrelations()])
        .collect();
    for i in 0..inst.dyadic_size {
        let vals = inst.row(i);
        let row = Row {
            vals: &vals,
            layout: &inst.layout,
        };
        let disabled = flavor.has_zk && i < flavor.trace_offset;
        for (ri, rel) in flavor.relations.iter().enumerate() {
            let spec = rel.spec();
            if spec.structural || spec.offset_only != disabled {
                continue;
            }
            let mut acc = vec![Fr::zero(); rel.num_subrelations()];
            rel.accumulate(&mut acc, &row, params, &one);
            for (j, v) in acc.iter().enumerate() {
                if spec.lin_indep[j] {
                    if !v.is_zero() {
                        return Some((*rel, j, Some(i)));
                    }
                } else {
                    sums[ri][j] += v;
                }
            }
        }
    }
    for (ri, rel) in flavor.relations.iter().enumerate() {
        for (j, v) in sums[ri].iter().enumerate() {
            if !v.is_zero() {
                return Some((*rel, j, None));
            }
        }
    }
    None
}
