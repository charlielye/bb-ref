//! Blake2s/Blake3s XOR-rotate plookup tables (bb `plookup_tables/blake2s.hpp`): 32-bit
//! `ROTR^k(a ^ b)` as six 6-bit slices (the last 5 bits wide), with per-slice rotations chosen so
//! one multi-table read yields the rotated result up to a power-of-two scaling.

use super::plookup::{BasicTable, BasicTableId, MultiTable, TableValues};
use crate::base::field::FieldLike;
use crate::base::Fr;

pub const BITS_IN_LAST_SLICE: u64 = 5;
pub const SIZE_OF_LAST_SLICE: u64 = 1 << BITS_IN_LAST_SLICE;

/// bb `get_xor_rotate_values_from_key<bits, rotation, filter>`: `filter` keeps only the two least
/// significant bits of each key (the last slice holds 5 bits of which 3 are another slice's).
pub fn xor_rotate_values(rotation: u32, filter: bool, key: [u64; 2]) -> [Fr; 2] {
    let (mut k0, mut k1) = (key[0], key[1]);
    if filter {
        k0 &= 3;
        k1 &= 3;
    }
    let rotated = ((k0 as u32) ^ (k1 as u32)).rotate_right(rotation);
    [Fr::from(rotated as u64), Fr::from(0u64)]
}

pub fn xor_rotate_table(id: BasicTableId, table_index: usize, bits: u64, rotation: u32, filter: bool) -> BasicTable {
    let base = 1u64 << bits;
    let mut columns = [vec![], vec![], vec![]];
    for i in 0..base {
        for j in 0..base {
            columns[0].push(Fr::from(i));
            columns[1].push(Fr::from(j));
            columns[2].push(xor_rotate_values(rotation, filter, [i, j])[0]);
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

fn slice_sizes() -> Vec<u64> {
    vec![64, 64, 64, 64, 64, SIZE_OF_LAST_SLICE]
}

fn rotate0(rotation_of_slice: &[(usize, u8)]) -> (Vec<BasicTableId>, Vec<TableValues>) {
    let mut ids = vec![BasicTableId::BlakeXorRotate(0); 6];
    let mut values = vec![
        TableValues::BlakeXor {
            rotation: 0,
            filter: false
        };
        6
    ];
    for &(slice, rot) in rotation_of_slice {
        ids[slice] = BasicTableId::BlakeXorRotate(rot);
        values[slice] = TableValues::BlakeXor {
            rotation: rot,
            filter: false,
        };
    }
    ids[5] = BasicTableId::BlakeXorRotate0Slice5Mod4;
    values[5] = TableValues::BlakeXor {
        rotation: 0,
        filter: true,
    };
    (ids, values)
}

/// bb `get_blake2s_xor_table`: plain 32-bit XOR, geometric coefficients in base 2^6.
pub fn xor_multitable() -> MultiTable {
    let geometric: Vec<Fr> = (0..6).map(|i| Fr::from(1u64 << (6 * i))).collect();
    let (ids, values) = rotate0(&[]);
    MultiTable::new(
        [geometric.clone(), geometric.clone(), geometric],
        slice_sizes(),
        ids,
        values,
    )
}

fn key_coefficients() -> Vec<Fr> {
    (0..6).map(|i| Fr::from(1u64 << (6 * i))).collect()
}

/// bb `get_blake2s_xor_rotate_16_table`.
pub fn xor_rotate_16_multitable() -> MultiTable {
    let c16 = Fr::from(1u64 << 16).invert();
    let column_3 = vec![
        Fr::one(),
        Fr::from(1u64 << 6),
        c16,
        c16 * Fr::from(1u64 << 2),
        c16 * Fr::from(1u64 << 8),
        c16 * Fr::from(1u64 << 14),
    ];
    let (ids, values) = rotate0(&[(2, 4)]);
    MultiTable::new(
        [key_coefficients(), key_coefficients(), column_3],
        slice_sizes(),
        ids,
        values,
    )
}

/// bb `get_blake2s_xor_rotate_8_table`.
pub fn xor_rotate_8_multitable() -> MultiTable {
    let c24 = Fr::from(1u64 << 24).invert();
    let column_3 = vec![
        Fr::one(),
        c24,
        c24 * Fr::from(1u64 << 4),
        c24 * Fr::from(1u64 << (4 + 6)),
        c24 * Fr::from(1u64 << (4 + 12)),
        c24 * Fr::from(1u64 << (4 + 18)),
    ];
    let (ids, values) = rotate0(&[(1, 2)]);
    MultiTable::new(
        [key_coefficients(), key_coefficients(), column_3],
        slice_sizes(),
        ids,
        values,
    )
}

/// bb `get_blake2s_xor_rotate_7_table`.
pub fn xor_rotate_7_multitable() -> MultiTable {
    let c25 = Fr::from(1u64 << 25).invert();
    let column_3 = vec![
        Fr::one(),
        c25,
        c25 * Fr::from(1u64 << 5),
        c25 * Fr::from(1u64 << (5 + 6)),
        c25 * Fr::from(1u64 << (5 + 12)),
        c25 * Fr::from(1u64 << (5 + 18)),
    ];
    let (ids, values) = rotate0(&[(1, 1)]);
    MultiTable::new(
        [key_coefficients(), key_coefficients(), column_3],
        slice_sizes(),
        ids,
        values,
    )
}
