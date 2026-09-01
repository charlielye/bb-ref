//! In-circuit multi-table reads (bb `stdlib/primitives/plookup/plookup.cpp`).

use super::field::{Ctx, FieldT};
use crate::base::Fr;
use crate::circuit::plookup::{get_lookup_accumulators as native_accumulators, MultiTableId, ReadData};
use crate::circuit::IS_CONSTANT;

/// bb `plookup_read::get_lookup_accumulators`: constant keys are read natively; witness keys emit
/// the lookup gates and return the accumulator witnesses.
pub fn get_lookup_accumulators(
    id: MultiTableId,
    key_a: &FieldT,
    key_b: &FieldT,
    is_2_to_1_lookup: bool,
) -> ReadData<FieldT> {
    let ctx: Option<Ctx> = key_a.ctx.clone().or_else(|| key_b.ctx.clone());
    let lookup_data = native_accumulators(id, key_a.get_value(), key_b.get_value(), is_2_to_1_lookup);
    let mut columns = [vec![], vec![], vec![]];
    if key_a.is_constant() && (key_b.is_constant() || !is_2_to_1_lookup) {
        for c in 0..3 {
            columns[c] = lookup_data.columns[c].iter().map(|v| FieldT::constant(*v)).collect();
        }
    } else {
        let ctx = ctx.expect("witness key without a builder");
        let mut lhs_index = key_a.get_witness_index();
        let mut rhs_index = key_b.get_witness_index();
        if key_a.is_constant() {
            lhs_index = ctx.borrow_mut().put_constant_variable(key_a.get_value());
        }
        if key_b.is_constant() && is_2_to_1_lookup {
            rhs_index = ctx.borrow_mut().put_constant_variable(key_b.get_value());
        }
        let key_b_witness = (rhs_index != IS_CONSTANT).then_some(rhs_index);
        let witnesses =
            ctx.borrow_mut()
                .create_gates_from_plookup_accumulators(id, &lookup_data, lhs_index, key_b_witness);
        for c in 0..3 {
            columns[c] = witnesses.columns[c]
                .iter()
                .map(|w| FieldT::from_witness_index(&ctx, *w))
                .collect();
        }
    }
    ReadData {
        columns,
        lookup_entries: lookup_data.lookup_entries,
    }
}

fn accumulators_1(id: MultiTableId, key: &FieldT) -> ReadData<FieldT> {
    get_lookup_accumulators(id, key, &FieldT::constant(Fr::from(0u64)), false)
}

pub fn read_pair_from_table(id: MultiTableId, key: &FieldT) -> (FieldT, FieldT) {
    let lookup = accumulators_1(id, key);
    (lookup.columns[1][0].clone(), lookup.columns[2][0].clone())
}

pub fn read_from_2_to_1_table(id: MultiTableId, key_a: &FieldT, key_b: &FieldT) -> FieldT {
    get_lookup_accumulators(id, key_a, key_b, true).columns[2][0].clone()
}

pub fn read_from_1_to_2_table(id: MultiTableId, key_a: &FieldT) -> FieldT {
    accumulators_1(id, key_a).columns[1][0].clone()
}

/// The full accumulator read of a single-key multi-table.
pub fn read_accumulators(id: MultiTableId, key_a: &FieldT) -> ReadData<FieldT> {
    accumulators_1(id, key_a)
}
