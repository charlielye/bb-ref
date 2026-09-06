//! Derived ECCVM witness (lookup inverses, `z_perm`) and the row-by-row relation check
//! (bb `ECCVMTraceChecker`).

use super::relations::{
    lookup_inverse_exists, lookup_terms, set_denominator, set_numerator, EccvmRel, ECCVM_RELATIONS,
};
use super::{EccvmPolys, Ent, TRACE_OFFSET};
use crate::base::field::{batch_invert, grand_product, FieldLike};
use crate::base::Fq;
use crate::honk::relations::RelationParams;
use rayon::prelude::*;

/// The ECCVM's relation parameters from `beta`, `gamma` (bb `ECCVMProver`/`ECCVMTraceChecker`).
pub fn eccvm_relation_params<F: crate::base::field::FieldLike<Native = Fq>>(beta: F, gamma: F) -> RelationParams<F> {
    // bb's exact operation order and kinds (multiplications, not squarings — the bigfield gate
    // patterns differ): beta², beta⁴, beta³, then the delta product, then its inversion.
    let beta_sqr = beta.clone() * &beta;
    let beta_quartic = beta_sqr.clone() * &beta_sqr;
    let beta_cube = beta_sqr.clone() * &beta;
    let tag = beta_quartic.clone();
    let delta = (gamma.clone() + &tag)
        * &(gamma.clone() + &beta_sqr + &tag)
        * &(gamma.clone() + &beta_sqr + &beta_sqr + &tag)
        * &(gamma.clone() + &beta_sqr + &beta_sqr + &beta_sqr + &tag);
    RelationParams {
        beta,
        gamma,
        beta_sqr,
        beta_cube,
        beta_quartic,
        eccvm_set_permutation_delta: delta.invert(),
        ..Default::default()
    }
}

impl EccvmPolys {
    /// bb `compute_logderivative_inverse` + `compute_grand_product` for the ECCVM, then the shifts.
    pub fn compute_derived(&mut self, p: &RelationParams<Fq>) {
        let n = self.size();
        let mut denominators: Vec<Fq> = (TRACE_OFFSET..n)
            .into_par_iter()
            .map_init(Vec::new, |row, i| {
                self.row_into(i, row);
                if lookup_inverse_exists(row).is_zero() {
                    return Fq::zero();
                }
                lookup_terms(row, p).iter().product()
            })
            .collect();
        crate::base::field::batch_invert_par(&mut denominators);
        for (i, d) in (TRACE_OFFSET..n).zip(denominators) {
            if !d.is_zero() {
                self.cols[Ent::lookup_inverses as usize].coeffs[i] = d;
            }
        }
        let terms: Vec<(Fq, Fq)> = (TRACE_OFFSET..n - 1)
            .into_par_iter()
            .map_init(Vec::new, |row, i| {
                self.row_into(i, row);
                (set_numerator(row, p), set_denominator(row, p))
            })
            .collect();
        let (num, den): (Vec<Fq>, Vec<Fq>) = terms.into_iter().unzip();
        let prefix = crate::base::field::grand_product_par(&num, &den);
        self.cols[Ent::z_perm as usize].coeffs[TRACE_OFFSET + 1..n].copy_from_slice(&prefix[1..]);
    }
}

/// The first failing `(relation, subrelation, row)` (row `None` for the trace-wide lookup sum).
pub fn check_circuit(polys: &EccvmPolys, p: &RelationParams<Fq>) -> Option<(EccvmRel, usize, Option<usize>)> {
    let one = Fq::one();
    let mut sums: Vec<Vec<Fq>> = ECCVM_RELATIONS
        .iter()
        .map(|r| vec![Fq::zero(); r.num_subrelations()])
        .collect();
    for i in TRACE_OFFSET..polys.size() {
        let row = polys.row(i);
        for (ri, rel) in ECCVM_RELATIONS.iter().enumerate() {
            let mut acc = vec![Fq::zero(); rel.num_subrelations()];
            rel.accumulate(&mut acc, &row, p, &one);
            for (j, v) in acc.iter().enumerate() {
                if rel.linearly_independent(j) {
                    if !v.is_zero() {
                        return Some((*rel, j, Some(i)));
                    }
                } else {
                    sums[ri][j] += v;
                }
            }
        }
    }
    for (ri, rel) in ECCVM_RELATIONS.iter().enumerate() {
        if let Some(j) = sums[ri].iter().position(|v| !v.is_zero()) {
            return Some((*rel, j, None));
        }
    }
    None
}
