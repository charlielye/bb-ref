//! The AVM relations as a [`RelationSet`]: an interpreter over the generated tables, so prover-free
//! code never instantiates ~13k lines of constraint expressions per field type. Natively it is the
//! AVM verifier's relation check; over `FieldT` it is bb's in-circuit AVM verifier, gate for gate:
//! every expression is evaluated in bb's C++ order (aliases first, operands left to right).

use super::poseidon2_perm;
use super::tables::{relations, Body, Expr};
use crate::base::field::{FieldLike, Fr};
use crate::honk::relations::RelationParams;
use crate::honk::sumcheck::RelationSet;

pub struct AvmRelations;

fn eval<F: FieldLike<Native = Fr>>(e: &Expr, row: &[F], lets: &[F]) -> F {
    match e {
        Expr::Col(i) => row[*i].clone(),
        Expr::Const(c) => F::constant(*c),
        Expr::Alias(i) => lets[*i].clone(),
        Expr::Add(a, b) => eval(a, row, lets) + &eval(b, row, lets),
        Expr::Sub(a, b) => eval(a, row, lets) - &eval(b, row, lets),
        Expr::Mul(a, b) => eval(a, row, lets) * &eval(b, row, lets),
        Expr::Neg(a) => -eval(a, row, lets),
    }
}

/// bb `GenericLookupSettings`/`GenericPermutationSettings` term: `((0·β + c₀)·β + c₁)·… + γ`.
fn tuple_term<F: FieldLike>(cols: &[usize], row: &[F], p: &RelationParams<F>) -> F {
    let mut result = F::zero();
    for &c in cols {
        result = result * &p.beta + &row[c];
    }
    result + &p.gamma
}

/// bb `_accumulate_logderivative_subrelation_contributions` with one lookup and one table term.
#[allow(clippy::too_many_arguments)]
fn logderivative<F: FieldLike>(
    acc: &mut [F],
    row: &[F],
    p: &RelationParams<F>,
    scaling: &F,
    (src_sel, dst_sel, inverses, counts): (usize, usize, usize, Option<usize>),
    src: &[usize],
    dst: &[usize],
) {
    let inv = row[inverses].clone();
    let t0 = tuple_term(src, row, p);
    let t1 = tuple_term(dst, row, p);
    let d0 = t0.clone();
    let d1 = t1.clone() * &d0;
    let mut inverse_accumulator = inv.clone();
    let (a, b) = (&row[src_sel], &row[dst_sel]);
    let inverse_exists = a.clone() + b - &(a.clone() * b);
    acc[0] += &((d1 * &inv - &inverse_exists) * scaling);
    let d1 = d0 * &inverse_accumulator;
    inverse_accumulator = inverse_accumulator * &t1;
    let d0 = inverse_accumulator;
    acc[1] += &(row[src_sel].clone() * &d0);
    let mut to_subtract = row[dst_sel].clone() * &d1;
    if let Some(c) = counts {
        to_subtract *= &row[c];
    }
    acc[1] -= &to_subtract;
}

impl<F: FieldLike<Native = Fr>> RelationSet<F> for AvmRelations {
    fn num_relations(&self) -> usize {
        relations().len()
    }
    fn num_subrelations(&self, r: usize) -> usize {
        relations()[r].num_subrelations
    }
    fn linearly_independent(&self, r: usize, j: usize) -> bool {
        !matches!(relations()[r].body, Body::Interaction { .. }) || j == 0
    }
    fn partial_length(&self, r: usize) -> usize {
        relations()[r].partial_length
    }
    fn offset_only(&self, _r: usize) -> bool {
        false
    }
    fn skip(&self, r: usize, row0: &[F], row1: &[F]) -> bool {
        let cols = &relations()[r].skip;
        let zero = |row: &[F]| {
            let mut sum = F::zero();
            for &c in cols {
                sum = sum + &row[c];
            }
            sum.is_zero()
        };
        !cols.is_empty() && zero(row0) && zero(row1)
    }
    fn relation_columns(&self, r: usize) -> Option<Vec<usize>> {
        fn walk(e: &Expr, out: &mut Vec<usize>) {
            match e {
                Expr::Col(i) => out.push(*i),
                Expr::Const(_) | Expr::Alias(_) => {}
                Expr::Add(a, b) | Expr::Sub(a, b) | Expr::Mul(a, b) => {
                    walk(a, out);
                    walk(b, out);
                }
                Expr::Neg(a) => walk(a, out),
            }
        }
        let mut cols = Vec::new();
        match &relations()[r].body {
            Body::Generated { lets, subs } => lets.iter().chain(subs).for_each(|e| walk(e, &mut cols)),
            Body::Handwritten => return None,
            Body::Interaction { src_sel, dst_sel, inverses, counts, src, dst } => {
                cols.extend([*src_sel, *dst_sel, *inverses].into_iter().chain(*counts).chain(src.iter().copied()).chain(dst.iter().copied()))
            }
        }
        cols.sort_unstable();
        cols.dedup();
        Some(cols)
    }
    fn vanishing_columns(&self, r: usize) -> Option<Vec<usize>> {
        let cols = &relations()[r].skip;
        (!cols.is_empty()).then(|| cols.clone())
    }
    fn skip_columns(&self) -> Option<Vec<usize>> {
        let mut cols: Vec<usize> = relations().iter().flat_map(|r| r.skip.iter().copied()).collect();
        cols.sort_unstable();
        cols.dedup();
        Some(cols)
    }
    fn accumulate(&self, r: usize, acc: &mut [F], row: &[F], p: &RelationParams<F>, scaling: &F) {
        match &relations()[r].body {
            Body::Generated { lets, subs } => {
                let mut values: Vec<F> = Vec::with_capacity(lets.len());
                for e in lets {
                    let v = eval(e, row, &values);
                    values.push(v);
                }
                for (a, e) in acc.iter_mut().zip(subs) {
                    *a += &(eval(e, row, &values) * scaling);
                }
            }
            Body::Handwritten => poseidon2_perm::accumulate(acc, row, scaling),
            Body::Interaction {
                src_sel,
                dst_sel,
                inverses,
                counts,
                src,
                dst,
            } => logderivative(acc, row, p, scaling, (*src_sel, *dst_sel, *inverses, *counts), src, dst),
        }
    }
}
