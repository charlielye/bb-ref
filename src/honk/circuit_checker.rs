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

#[cfg(test)]
mod gate_family_tests {
    use super::*;
    use crate::base::srs::CommitmentKey;
    use crate::base::transcript::NativeTranscript;
    use crate::circuit::Builder;
    use crate::honk::flavor::{Ent, ULTRA};
    use crate::honk::oink_prover::prove_oink;
    use crate::honk::prover_instance::ProverInstance;
    use crate::stdlib::field::FieldT;
    use std::cell::RefCell;
    use std::rc::Rc;

    /// One circuit exercising every Ultra gate family, then per family: corrupt a wire on a row
    /// where that family's selector is active and demand the checker reports a failure whose
    /// relation is the family itself (or Permutation, when the corrupted wire sits in a copy
    /// cycle — the copy constraint legitimately fires first).
    #[test]
    fn every_gate_family_catches_a_corruption() {
        if crate::testutil::crs_or_skip().is_none() {
            return;
        }
        let mut rng = crate::testutil::test_rng();
        let ctx = Rc::new(RefCell::new(crate::testutil::tiny_circuit(&mut rng)));
        {
            // Poseidon2 (external + internal rounds) via the in-circuit sponge.
            let inputs = [FieldT::from_witness(&ctx, crate::base::Fr::from(3u64))];
            let _ = crate::stdlib::hash::hash(&inputs);
            // Plookup via 32-bit XOR.
            let a = FieldT::from_witness(&ctx, crate::base::Fr::from(0x1234u64));
            let b = FieldT::from_witness(&ctx, crate::base::Fr::from(0x5678u64));
            let _ = crate::stdlib::logic::create_logic_constraint(&a, &b, 32, true);
            let mut builder = ctx.borrow_mut();
            // Delta range.
            let r = builder.add_variable(crate::base::Fr::from(200u64));
            builder.create_dyadic_range_constraint(r, 8);
            // ROM (memory relation).
            let rom = builder.create_rom_array(2);
            let v0 = builder.add_variable(crate::base::Fr::from(41u64));
            let v1 = builder.add_variable(crate::base::Fr::from(42u64));
            builder.set_rom_element(rom, 0, v0);
            builder.set_rom_element(rom, 1, v1);
            let idx = builder.add_variable(crate::base::Fr::from(1u64));
            let _ = builder.read_rom_array(rom, idx);
        }
        let mut builder = Rc::try_unwrap(ctx).ok().unwrap().into_inner();
        assert!(builder.failed.is_none(), "gate-family circuit must be satisfiable");
        let mut inst = ProverInstance::from_builder(&ULTRA, &mut builder, &mut rng);
        let ck = CommitmentKey::new(inst.max_end_index);
        let vk = inst.compute_vk(&ck);
        let mut t = NativeTranscript::new();
        let out = prove_oink(&mut inst, &vk, &ck, &mut t, &mut rng, true);
        assert_eq!(check_circuit(&inst, &out.params), None, "satisfying circuit must pass");

        let families: [(Ent, &[&str]); 5] = [
            (Ent::q_delta_range, &["DeltaRange", "Permutation"]),
            (Ent::q_memory, &["Memory", "Permutation"]),
            (Ent::q_lookup, &["Lookup", "Permutation"]),
            (Ent::q_poseidon2_external, &["Poseidon2External", "Permutation"]),
            (Ent::q_poseidon2_internal, &["Poseidon2Internal", "Permutation"]),
        ];
        for (selector, expected) in families {
            let row = inst
                .poly(selector)
                .coeffs
                .iter()
                .position(|c| !c.is_zero())
                .unwrap_or_else(|| panic!("{selector:?} has no active row"));
            let w = inst.layout.idx(Ent::w_l);
            let saved = inst.polys[w].coeffs[row];
            inst.polys[w].coeffs[row] += Fr::one();
            let failure = check_circuit(&inst, &out.params)
                .unwrap_or_else(|| panic!("{selector:?}: corruption at row {row} must be caught"));
            let name = format!("{:?}", failure.0);
            assert!(
                expected.iter().any(|e| name.contains(e)),
                "{selector:?}: expected one of {expected:?}, got {name} at {:?}",
                failure.2
            );
            inst.polys[w].coeffs[row] = saved;
        }
        assert_eq!(check_circuit(&inst, &out.params), None, "restored circuit passes again");
    }
}
