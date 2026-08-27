//! Bitwise XOR/AND plookup tables (bb `plookup_tables/uint.hpp`): twin-key tables over 6-bit slices
//! plus a 2-bit slice to cover 32 bits.

use super::plookup::{BasicTable, BasicTableId, MultiTable, TableValues};
use crate::base::Fr;

const SLICE_BITS: usize = 6;

pub fn values(key: [u64; 2], is_xor: bool) -> [Fr; 2] {
    [
        Fr::from(if is_xor { key[0] ^ key[1] } else { key[0] & key[1] }),
        Fr::from(0u64),
    ]
}

pub fn table(id: BasicTableId, table_index: usize, bits: usize, is_xor: bool) -> BasicTable {
    let base = 1u64 << bits;
    let mut columns = [vec![], vec![], vec![]];
    for i in 0..base {
        for j in 0..base {
            columns[0].push(Fr::from(i));
            columns[1].push(Fr::from(j));
            columns[2].push(values([i, j], is_xor)[0]);
        }
    }
    BasicTable {
        id,
        table_index,
        use_twin_keys: true,
        columns,
        lookup_gates: vec![],
    }
}

/// bb `get_uint_xor_table<32>` / `get_uint_and_table<32>`.
pub fn uint32_multitable(is_xor: bool) -> MultiTable {
    let num_entries = 32 / SLICE_BITS;
    let last_bits = 32 - SLICE_BITS * num_entries;
    let base = Fr::from(1u64 << SLICE_BITS);
    let id = |bits: usize| {
        if is_xor {
            BasicTableId::UintXor(bits as u8)
        } else {
            BasicTableId::UintAnd(bits as u8)
        }
    };
    let values = if is_xor {
        TableValues::UintXor
    } else {
        TableValues::UintAnd
    };
    let mut coefficients = vec![Fr::from(1u64)];
    for i in 1..=num_entries {
        coefficients.push(coefficients[i - 1] * base);
    }
    let mut slice_sizes = vec![1u64 << SLICE_BITS; num_entries];
    slice_sizes.push(1 << last_bits);
    let mut ids = vec![id(SLICE_BITS); num_entries];
    ids.push(id(last_bits));
    MultiTable::new(
        [coefficients.clone(), coefficients.clone(), coefficients],
        slice_sizes,
        ids,
        vec![values; num_entries + 1],
    )
}
