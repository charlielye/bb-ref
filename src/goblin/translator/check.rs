//! Translator relation parameters, the grand product, and the row-by-row relation check.

use super::builder::split_fq_into_limbs;
use super::relations::{permutation_denominator, permutation_numerator, TranslatorRel, TRANSLATOR_RELATIONS};
use super::{Ent, TranslatorPolys, CIRCUIT_SIZE};
use crate::base::field::{from_u256, grand_product, u256, FieldLike};
use crate::base::{Fq, Fr};
use crate::honk::relations::RelationParams;
use rayon::prelude::*;

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
    /// bb `compute_grand_product` for the permutation relation, then the shifts.
    pub fn compute_grand_product(&mut self, p: &RelationParams<Fr>) {
        let terms: Vec<(Fr, Fr)> = (0..CIRCUIT_SIZE - 1)
            .into_par_iter()
            .map(|i| {
                let row = self.row(i);
                (permutation_numerator(&row, p), permutation_denominator(&row, p))
            })
            .collect();
        let (num, den): (Vec<Fr>, Vec<Fr>) = terms.into_iter().unzip();
        let prefix = grand_product(&num, &den);
        self.cols[Ent::z_perm as usize].coeffs[1..CIRCUIT_SIZE].copy_from_slice(&prefix[1..]);
        self.set_shifted();
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
