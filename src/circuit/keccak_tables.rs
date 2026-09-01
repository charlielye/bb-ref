//! Keccak-f[1600] plookup tables (bb `plookup_tables/keccak/`). Lanes are held in base-11 "sparse"
//! form (one base-11 digit per bit) so that XORs become additions; the tables renormalize digits back
//! to bits after θ (digits ≤ 10, parity), χ (digits ≤ 4, `[0,0,1,1,0]`), ρ (digits ≤ 2, parity, with
//! the slice's top digit as a third column for the rotation), and convert lanes in and out of sparse
//! form.

use super::plookup::{map_into_sparse_form, BasicTable, BasicTableId, MultiTable, TableValues};
use crate::base::Fr;

pub const BASE: u64 = 11;
pub const LANE_BITS: usize = 64;
pub const ROTATIONS: [usize; 25] = [
    0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
];
/// Widest ρ slice (bits) a single renormalization table covers.
pub const RHO_MAX_BITS: usize = 8;
const THETA_TABLE_BITS: usize = 4;
const CHI_TABLE_BITS: usize = 6;
const IO_TABLE_BITS: usize = 8;
const THETA_NORMALIZATION: [u64; 11] = [0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0];
const CHI_NORMALIZATION: [u64; 5] = [0, 0, 1, 1, 0];
const RHO_NORMALIZATION: [u64; 3] = [0, 1, 0];
pub const OUTPUT_NORMALIZATION: [u64; 2] = [0, 1];

pub fn pow11(e: usize) -> u64 {
    BASE.pow(e as u32)
}

/// The base-11 digits of `key` mapped through `table`, re-packed in base 11.
fn renormalize(mut key: u64, table: &[u64]) -> u64 {
    let mut accumulator = 0;
    let mut base_shift = 1;
    while key > 0 {
        accumulator += table[(key % BASE) as usize] * base_shift;
        key /= BASE;
        base_shift *= BASE;
    }
    accumulator
}
pub fn rho_values(bits: usize, key: u64) -> [Fr; 2] {
    let normalized = renormalize(key, &RHO_NORMALIZATION);
    [Fr::from(normalized), Fr::from(normalized / pow11(bits - 1))]
}
pub fn theta_values(key: u64) -> [Fr; 2] {
    [Fr::from(renormalize(key, &THETA_NORMALIZATION)), Fr::from(0u64)]
}
/// The third column is the top digit of the 64-bit lane's last (4-digit) slice.
pub fn chi_values(key: u64) -> [Fr; 2] {
    let normalized = renormalize(key, &CHI_NORMALIZATION);
    [
        Fr::from(normalized),
        Fr::from(normalized / pow11(LANE_BITS % CHI_TABLE_BITS - 1)),
    ]
}
pub fn input_values(key: u64) -> [Fr; 2] {
    [map_into_sparse_form(BASE, key), Fr::from(key >> (IO_TABLE_BITS - 1))]
}

/// bb's row enumeration: every combination of `table_bits` digits below `effective_base`, counting
/// up little-endian; column 2 is the renormalized value (packed in base 11, or as bits when
/// `binary_output`), column 3 the renormalized value divided by `msb_divisor`.
fn renormalization_table(
    id: BasicTableId,
    table_index: usize,
    table_bits: usize,
    effective_base: u64,
    table: &[u64],
    binary_output: bool,
    msb_divisor: Option<u64>,
) -> BasicTable {
    let mut columns = [vec![], vec![], vec![]];
    let mut counts = vec![0u64; table_bits];
    let mut row = [0u64; 3];
    for _ in 0..effective_base.pow(table_bits as u32) {
        columns[0].push(Fr::from(row[0]));
        columns[1].push(Fr::from(row[1]));
        columns[2].push(Fr::from(row[2]));
        for c in counts.iter_mut() {
            if *c == effective_base - 1 {
                *c = 0;
            } else {
                *c += 1;
                break;
            }
        }
        let (mut value, mut normalized) = (0u64, 0u64);
        for (i, c) in counts.iter().enumerate() {
            value += c * pow11(i);
            normalized += if binary_output {
                table[*c as usize] << i
            } else {
                table[*c as usize] * pow11(i)
            };
        }
        row = [value, normalized, msb_divisor.map_or(0, |d| normalized / d)];
    }
    BasicTable {
        id,
        table_index,
        use_twin_keys: false,
        columns,
        lookup_gates: vec![],
    }
}

pub fn rho_table(id: BasicTableId, table_index: usize, bits: usize) -> BasicTable {
    renormalization_table(
        id,
        table_index,
        bits,
        3,
        &RHO_NORMALIZATION,
        false,
        Some(pow11(bits - 1)),
    )
}
pub fn theta_table(id: BasicTableId, table_index: usize) -> BasicTable {
    renormalization_table(
        id,
        table_index,
        THETA_TABLE_BITS,
        BASE,
        &THETA_NORMALIZATION,
        false,
        None,
    )
}
pub fn chi_table(id: BasicTableId, table_index: usize) -> BasicTable {
    let divisor = pow11(LANE_BITS % CHI_TABLE_BITS - 1);
    renormalization_table(
        id,
        table_index,
        CHI_TABLE_BITS,
        5,
        &CHI_NORMALIZATION,
        false,
        Some(divisor),
    )
}
pub fn output_table(id: BasicTableId, table_index: usize) -> BasicTable {
    renormalization_table(id, table_index, IO_TABLE_BITS, 2, &OUTPUT_NORMALIZATION, true, None)
}
pub fn input_table(id: BasicTableId, table_index: usize) -> BasicTable {
    let mut columns = [vec![], vec![], vec![]];
    for i in 0..(1u64 << IO_TABLE_BITS) {
        let [sparse, msb] = input_values(i);
        columns[0].push(Fr::from(i));
        columns[1].push(sparse);
        columns[2].push(msb);
    }
    BasicTable {
        id,
        table_index,
        use_twin_keys: false,
        columns,
        lookup_gates: vec![],
    }
}

fn uniform(c1: u64, c2: u64, num_lookups: usize, slice_size: u64, id: BasicTableId, values: TableValues) -> MultiTable {
    MultiTable::repeated(
        [Fr::from(c1), Fr::from(c2), Fr::from(0u64)],
        num_lookups,
        slice_size,
        id,
        values,
    )
}
pub fn theta_multitable() -> MultiTable {
    let step = pow11(THETA_TABLE_BITS);
    uniform(
        step,
        step,
        LANE_BITS / THETA_TABLE_BITS,
        step,
        BasicTableId::KeccakTheta,
        TableValues::KeccakTheta,
    )
}
pub fn chi_multitable() -> MultiTable {
    let step = pow11(CHI_TABLE_BITS);
    uniform(
        step,
        step,
        LANE_BITS.div_ceil(CHI_TABLE_BITS),
        step,
        BasicTableId::KeccakChi,
        TableValues::KeccakChi,
    )
}
pub fn input_multitable() -> MultiTable {
    uniform(
        1 << IO_TABLE_BITS,
        pow11(IO_TABLE_BITS),
        8,
        1 << IO_TABLE_BITS,
        BasicTableId::KeccakInput,
        TableValues::KeccakInput,
    )
}
pub fn output_multitable() -> MultiTable {
    let values = TableValues::SparseNormalization {
        base: BASE,
        table: &OUTPUT_NORMALIZATION,
    };
    uniform(
        pow11(IO_TABLE_BITS),
        1 << IO_TABLE_BITS,
        8,
        pow11(IO_TABLE_BITS),
        BasicTableId::KeccakOutput,
        values,
    )
}

/// The slice widths of a lane split at `rotation`: the low `64 − rotation` bits then the high
/// `rotation` bits, each in slices of at most `RHO_MAX_BITS`.
pub fn rho_slices(rotation: usize) -> (Vec<usize>, Vec<usize>) {
    let split = |bits: usize| -> Vec<usize> {
        (0..bits.div_ceil(RHO_MAX_BITS))
            .map(|i| (bits - i * RHO_MAX_BITS).min(RHO_MAX_BITS))
            .collect()
    };
    (split(LANE_BITS - rotation), split(rotation))
}

/// bb `Rho<8, lane>::get_rho_output_table`: column 1 accumulates the whole lane, column 2 the
/// renormalized low and high parts separately (the step into the first high slice is zero), column 3
/// nothing.
pub fn rho_multitable(lane: usize) -> MultiTable {
    let (right, left) = rho_slices(ROTATIONS[lane]);
    let mut steps = [vec![Fr::from(1u64)], vec![Fr::from(1u64)], vec![Fr::from(1u64)]];
    let mut slice_sizes = vec![];
    let mut ids = vec![];
    let mut values = vec![];
    let mut push = |bits: usize, with_steps: bool, carry_c2: bool| {
        let scaled_base = Fr::from(pow11(bits));
        if with_steps {
            steps[0].push(scaled_base);
            steps[1].push(if carry_c2 { scaled_base } else { Fr::from(0u64) });
            steps[2].push(Fr::from(0u64));
        }
        slice_sizes.push(pow11(bits));
        ids.push(BasicTableId::KeccakRho(bits as u8));
        values.push(TableValues::KeccakRho { bits: bits as u8 });
    };
    for (i, bits) in right.iter().enumerate() {
        push(*bits, true, i != right.len() - 1);
    }
    for (i, bits) in left.iter().enumerate() {
        push(*bits, i != left.len() - 1, true);
    }
    MultiTable::from_steps(steps, slice_sizes, ids, values)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::field::{u256, u256_to_u64};

    fn fr_u64(f: &Fr) -> u64 {
        u256_to_u64(&u256(f))
    }

    /// The sparse encoding is the spec: `input_values` puts bit `i` of the key into base-11
    /// digit `i`, and the output normalization (digits `[0,1]`) maps it back — the two IO tables
    /// must be exact inverses on every 8-bit lane slice.
    #[test]
    fn input_and_output_tables_are_inverses() {
        for x in 0..(1u64 << IO_TABLE_BITS) {
            let sparse = fr_u64(&input_values(x)[0]);
            let mut recovered = 0u64;
            let (mut s, mut i) = (sparse, 0);
            while s > 0 {
                let digit = s % BASE;
                assert!(digit <= 1, "sparse-of-binary digit must be a bit");
                recovered += OUTPUT_NORMALIZATION[digit as usize] << i;
                s /= BASE;
                i += 1;
            }
            assert_eq!(recovered, x);
            assert_eq!(fr_u64(&input_values(x)[1]), x >> (IO_TABLE_BITS - 1), "msb column");
        }
    }

    /// θ renormalization is XOR-parity per digit: after summing ≤ 10 sparse lanes, each base-11
    /// digit holds an XOR count and must reduce to `digit mod 2`.
    #[test]
    fn theta_normalization_is_parity() {
        for key in [0u64, 1, 10, 7 + 3 * BASE + 10 * pow11(2), pow11(3) * 6 + 5] {
            let normalized = fr_u64(&theta_values(key)[0]);
            let (mut k, mut expected, mut shift) = (key, 0u64, 1u64);
            while k > 0 {
                expected += (k % BASE % 2) * shift;
                k /= BASE;
                shift *= BASE;
            }
            assert_eq!(normalized, expected, "key {key}");
        }
    }
}
