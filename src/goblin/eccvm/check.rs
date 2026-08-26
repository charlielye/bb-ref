//! Derived ECCVM witness (lookup inverses, `z_perm`) and the row-by-row relation check
//! (bb `ECCVMTraceChecker`).

use super::relations::{lookup_inverse_exists, lookup_terms, set_denominator, set_numerator, EccvmRel, ECCVM_RELATIONS};
use super::{Ent, EccvmPolys, TRACE_OFFSET};
use crate::base::field::FieldLike;
use crate::base::Fq;
use crate::honk::relations::RelationParams;

/// The ECCVM's relation parameters from `beta`, `gamma` (bb `ECCVMProver`/`ECCVMTraceChecker`).
pub fn eccvm_relation_params(beta: Fq, gamma: Fq) -> RelationParams<Fq> {
    let beta_sqr = beta.sqr();
    let beta_quartic = beta_sqr.sqr();
    let tag = beta_quartic;
    let delta = (gamma + tag) * (gamma + beta_sqr + tag) * (gamma + beta_sqr + beta_sqr + tag) * (gamma + beta_sqr + beta_sqr + beta_sqr + tag);
    RelationParams { beta, gamma, beta_sqr, beta_cube: beta_sqr * beta, beta_quartic, eccvm_set_permutation_delta: delta.invert(), ..Default::default() }
}

impl EccvmPolys {
    /// bb `compute_logderivative_inverse` + `compute_grand_product` for the ECCVM, then the shifts.
    pub fn compute_derived(&mut self, p: &RelationParams<Fq>) {
        let n = self.size();
        for i in TRACE_OFFSET..n {
            let row = self.row(i);
            if lookup_inverse_exists(&row).is_zero() {
                continue;
            }
            let denominator: Fq = lookup_terms(&row, p).iter().product();
            self.cols[Ent::lookup_inverses as usize].coeffs[i] = denominator.invert();
        }
        let mut running = Fq::one();
        for i in TRACE_OFFSET..n - 1 {
            let row = self.row(i);
            running *= set_numerator(&row, p) * set_denominator(&row, p).invert();
            self.cols[Ent::z_perm as usize].coeffs[i + 1] = running;
        }
        self.set_shifted();
    }
}

/// The first failing `(relation, subrelation, row)` (row `None` for the trace-wide lookup sum).
pub fn check_circuit(polys: &EccvmPolys, p: &RelationParams<Fq>) -> Option<(EccvmRel, usize, Option<usize>)> {
    let one = Fq::one();
    let mut sums: Vec<Vec<Fq>> = ECCVM_RELATIONS.iter().map(|r| vec![Fq::zero(); r.num_subrelations()]).collect();
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
