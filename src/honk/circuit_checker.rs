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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::rng::Rng;
    use crate::base::srs::CommitmentKey;
    use crate::base::transcript::NativeTranscript;
    use crate::honk::flavor::{Ent, ULTRA};
    use crate::honk::oink_prover::prove_oink;
    use crate::honk::prover_instance::ProverInstance;

    /// Build a one-gate circuit, derive the Oink witness, and demand every relation vanishes; then
    /// corrupt one wire on an active arithmetic row and demand the checker names the arithmetic
    /// relation AT THAT ROW. This is the regression-localization contract: a bad builder or
    /// relation edit fails here with a name, not as "proof byte N differs" in a differential test.
    #[test]
    fn checker_accepts_satisfying_and_localizes_corruption() {
        if crate::testutil::crs_or_skip().is_none() {
            return;
        }
        let mut rng = crate::testutil::test_rng();
        let mut builder = crate::testutil::tiny_circuit(&mut rng);
        let mut inst = ProverInstance::from_builder(&ULTRA, &mut builder, &mut rng);
        let ck = CommitmentKey::new(inst.max_end_index);
        let vk = inst.compute_vk(&ck);
        let mut t = NativeTranscript::new();
        let out = prove_oink(&mut inst, &vk, &ck, &mut t, &mut rng, true);

        assert_eq!(check_circuit(&inst, &out.params), None, "satisfying circuit must pass");

        // The last arithmetic row is our add gate; its w_o is a singleton wire (no copy cycle), so
        // the corruption must surface as an Arithmetic failure, not a Permutation one. (Corrupting
        // a copied wire, e.g. on the public-input rows, is caught by Permutation instead.)
        let gate_row = {
            let q = inst.poly(Ent::q_arith);
            q.coeffs.iter().rposition(|c| !c.is_zero()).expect("an arithmetic gate exists")
        };
        let w_o = inst.layout.idx(Ent::w_o);
        inst.polys[w_o].coeffs[gate_row] += Fr::one();
        let failure = check_circuit(&inst, &out.params).expect("corruption must be caught");
        assert_eq!(failure.2, Some(gate_row), "failure localized to the corrupted row");
        assert!(format!("{:?}", failure.0).contains("Arithmetic"), "named relation: {failure:?}");
    }
}
