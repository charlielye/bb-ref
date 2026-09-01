//! AES-128 plookup tables (bb `plookup_tables/aes128.hpp`): bytes live in sparse base-9 form so
//! that GF(2) additions (XORs) become field additions; the tables map bytes in and out of sparse
//! form, renormalize accumulated digits, and apply the S-box (with the ×3 MixColumns companion).

use super::plookup::{BasicTable, BasicTableId, MultiTable, MultiTableId, TableValues};
use crate::base::field::FieldLike;
use crate::base::Fr;

pub const AES_BASE: u64 = 9;

pub const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9,
    0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f,
    0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07,
    0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3,
    0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58,
    0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3,
    0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f,
    0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
    0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac,
    0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a,
    0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70,
    0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
    0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42,
    0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

/// A byte's base-9 sparse form (one base-9 digit per bit); fits u64 for 8 digits.
pub fn sparse(byte: u8) -> u64 {
    let mut out = 0u64;
    let mut shift = 1u64;
    for i in 0..8 {
        out += ((byte >> i) & 1) as u64 * shift;
        shift *= AES_BASE;
    }
    out
}

/// bb `map_from_sparse_form`: the LSB of every base-9 digit, repacked as bits.
pub fn from_sparse(mut sparse: u64) -> u8 {
    let mut out = 0u8;
    for i in 0..8 {
        out |= (((sparse % AES_BASE) & 1) as u8) << i;
        sparse /= AES_BASE;
    }
    out
}

/// bb `xtime ∘ sbox` companion: `S(x) ⊕ 2·S(x) = 3·S(x)` in GF(2^8).
fn sbox_pair(byte: u8) -> (u64, u64) {
    let s = SBOX[byte as usize];
    let swizzled = (s << 1) ^ (((s >> 7) & 1) * 0x1b);
    (sparse(s), sparse(s ^ swizzled))
}

pub fn sbox_values(key: [u64; 2]) -> [Fr; 2] {
    let (first, second) = sbox_pair(from_sparse(key[0]));
    [Fr::from(first), Fr::from(second)]
}

/// Digit-wise LSB renormalization of 4 base-9 digits, repacked in base 9.
pub fn normalization_values(key: [u64; 2]) -> [Fr; 2] {
    [Fr::from(sparse(from_sparse(key[0]))), Fr::from(0u64)]
}

/// bb `generate_aes_sparse_normalization_table`: all 9^4 4-digit sparse values → digit LSBs.
pub fn sparse_normalization_table(id: BasicTableId, table_index: usize) -> BasicTable {
    let mut columns = [vec![], vec![], vec![]];
    for i in 0..AES_BASE {
        for j in 0..AES_BASE {
            for k in 0..AES_BASE {
                for m in 0..AES_BASE {
                    let left = ((i * AES_BASE + j) * AES_BASE + k) * AES_BASE + m;
                    let right = (((i & 1) * AES_BASE + (j & 1)) * AES_BASE + (k & 1)) * AES_BASE + (m & 1);
                    columns[0].push(Fr::from(left));
                    columns[1].push(Fr::from(right));
                    columns[2].push(Fr::from(0u64));
                }
            }
        }
    }
    BasicTable {
        id,
        table_index,
        use_twin_keys: false,
        columns,
        lookup_gates: vec![],
    }
}

/// bb `generate_aes_sbox_table`: 256 rows of (sparse byte, sparse S-box, sparse 3·S-box).
pub fn sbox_table(id: BasicTableId, table_index: usize) -> BasicTable {
    let mut columns = [vec![], vec![], vec![]];
    for i in 0..=255u8 {
        let (second, third) = sbox_pair(i);
        columns[0].push(Fr::from(sparse(i)));
        columns[1].push(Fr::from(second));
        columns[2].push(Fr::from(third));
    }
    BasicTable {
        id,
        table_index,
        use_twin_keys: false,
        columns,
        lookup_gates: vec![],
    }
}

/// bb `get_aes_normalization_table` (AES_NORMALIZE): two 4-digit normalizations per byte.
pub fn normalize_multitable() -> MultiTable {
    let pow4 = Fr::from(AES_BASE.pow(4));
    MultiTable::new(
        [
            vec![Fr::one(), pow4],
            vec![Fr::one(), pow4],
            vec![Fr::zero(), Fr::zero()],
        ],
        vec![AES_BASE.pow(4), AES_BASE.pow(4)],
        vec![BasicTableId::AesSparseNormalize; 2],
        vec![TableValues::AesSparseNormalize; 2],
    )
}

/// bb `get_aes_input_table` (AES_INPUT): a 128-bit block as 16 byte→sparse lookups.
pub fn input_multitable() -> MultiTable {
    MultiTable::repeated(
        [Fr::from(256u64), Fr::zero(), Fr::zero()],
        16,
        256,
        BasicTableId::AesSparseMap,
        TableValues::SparseRotation {
            base: AES_BASE,
            rotation: 0,
        },
    )
}

/// bb `get_aes_sbox_table` (AES_SBOX): a single full-width S-box lookup.
pub fn sbox_multitable() -> MultiTable {
    MultiTable::repeated(
        [Fr::zero(), Fr::zero(), Fr::zero()],
        1,
        AES_BASE.pow(8),
        BasicTableId::AesSboxMap,
        TableValues::AesSbox,
    )
}

pub fn multitable(id: MultiTableId) -> MultiTable {
    match id {
        MultiTableId::AesNormalize => normalize_multitable(),
        MultiTableId::AesInput => input_multitable(),
        MultiTableId::AesSbox => sbox_multitable(),
        _ => unreachable!("not an AES table"),
    }
}
