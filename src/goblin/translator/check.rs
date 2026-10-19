//! Translator relation parameters, the grand product, and the row-by-row relation check.

use super::builder::split_fq_into_limbs;
use super::relations::{permutation_denominator, permutation_numerator, TranslatorRel, TRANSLATOR_RELATIONS};
use super::{Ent, TranslatorPolys, CIRCUIT_SIZE};
use crate::base::field::{from_u256, grand_product_par, u256, FieldLike};
use crate::base::{Fq, Fr};
use crate::honk::relations::RelationParams;

/// The Translator's relation parameters: the limbs of `x` and `v..v⁴`, the claimed result limbs,
/// and the permutation challenges (bb `TranslatorProver`/`TranslatorCircuitChecker`).
pub fn translator_relation_params(
    v: &Fq,
    x: &Fq,
    accumulated_result: [Fr; 4],
    beta: Fr,
    gamma: Fr,
) -> RelationParams<Fr> {
    let native = |f: &Fq| from_u256::<Fr>(u256(f));
    let with_native = |f: &Fq| {
        let l = split_fq_into_limbs(f);
        [l[0], l[1], l[2], l[3], native(f)]
    };
    let v2 = *v * v;
    let v3 = v2 * v;
    let v4 = v3 * v;
    RelationParams {
        beta,
        gamma,
        evaluation_input_x: with_native(x),
        batching_challenge_v: [with_native(v), with_native(&v2), with_native(&v3), with_native(&v4)],
        accumulated_result,
        ..Default::default()
    }
}

impl TranslatorPolys {
    /// bb `compute_grand_product` for the permutation relation. The prover reads shift entities as
    /// views, so no shifted columns are materialized here; `check_circuit` callers need a
    /// `set_shifted` afterwards because `row` reads the dense shift columns.
    pub fn compute_grand_product(&mut self, p: &RelationParams<Fr>) {
        use Ent::*;
        crate::scope!("TranslatorProver::compute_grand_product");
        // The only columns the numerator and denominator read; the rest of the row stays zero.
        const COLS: [Ent; 12] = [
            lagrange_masking,
            lagrange_ordered_masking,
            concatenated_range_constraints_0,
            concatenated_range_constraints_1,
            concatenated_range_constraints_2,
            concatenated_range_constraints_3,
            ordered_extra_range_constraints_numerator,
            ordered_range_constraints_0,
            ordered_range_constraints_1,
            ordered_range_constraints_2,
            ordered_range_constraints_3,
            ordered_range_constraints_4,
        ];
        let mut z = std::mem::take(&mut self.cols[z_perm as usize].coeffs);
        grand_product_par(&mut z[1..CIRCUIT_SIZE], |lo, num, den| {
            let mut row = vec![Fr::zero(); self.cols.len()];
            for (k, (n, d)) in num.iter_mut().zip(den).enumerate() {
                let mut zero = true;
                for e in COLS {
                    row[e as usize] = self.cols[e as usize].at(lo + k);
                    zero &= row[e as usize].is_zero();
                }
                // All inputs zero: numerator and denominator are both gamma^5, a ratio of exactly
                // one (most of a small flow's rows), so the products are skipped.
                (*n, *d) = if zero {
                    (Fr::one(), Fr::one())
                } else {
                    (permutation_numerator(&row, p), permutation_denominator(&row, p))
                };
            }
        });
        self.cols[z_perm as usize].coeffs = z;
    }
}

/// The first failing `(relation, subrelation, row)`, if any.
pub fn check_circuit(polys: &TranslatorPolys, p: &RelationParams<Fr>) -> Option<(TranslatorRel, usize, usize)> {
    let one = Fr::one();
    for i in 0..CIRCUIT_SIZE {
        let row = polys.row(i);
        for rel in TRANSLATOR_RELATIONS {
            let mut acc = vec![Fr::zero(); rel.num_subrelations()];
            rel.accumulate(&mut acc, &row, p, &one);
            if let Some(j) = acc.iter().position(|v| !v.is_zero()) {
                return Some((rel, j, i));
            }
        }
    }
    None
}
