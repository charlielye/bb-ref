//! Lookup tables (bb `stdlib_circuit_builders/plookup_tables/`): a multi-table splits a key into
//! slices, each read from a basic table, and the builder chains the slices with running accumulators
//! (`create_gates_from_plookup_accumulators`). Only the tables the pinned flows need are here.

use crate::base::field::{u256, FieldLike, U256};
use crate::base::Fr;
use std::sync::LazyLock;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BasicTableId {
    Sha256WitnessNormalize,
    Sha256WitnessSlice3,
    Sha256WitnessSlice7Rotate4,
    Sha256WitnessSlice8Rotate7,
    Sha256WitnessSlice14Rotate1,
    Sha256ChNormalize,
    Sha256MajNormalize,
    Sha256Base28,
    Sha256Base28Rotate6,
    Sha256Base28Rotate3,
    Sha256Base16,
    Sha256Base16Rotate2,
    Secp256r1FixedBase {
        axis: u8,
        window: u8,
    },
    /// bb `STRAUS_EC_POINT`: a dynamic per-point table for `cycle_group::fixed_batch_mul`.
    StrausEcPoint,
    KeccakRho(u8),
    KeccakTheta,
    KeccakChi,
    KeccakInput,
    KeccakOutput,
    UintXor(u8),
    UintAnd(u8),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MultiTableId {
    Sha256ChInput,
    Sha256ChOutput,
    Sha256MajInput,
    Sha256MajOutput,
    Sha256WitnessInput,
    Sha256WitnessOutput,
    Secp256r1FixedBase { axis: u8, is_lo: bool },
    KeccakNormalizeAndRotate(u8),
    KeccakThetaOutput,
    KeccakChiOutput,
    KeccakFormatInput,
    KeccakFormatOutput,
    Uint32Xor,
    Uint32And,
}

/// How a basic table maps a key to its two values (bb `get_values_from_key`).
#[derive(Clone, Copy, Debug)]
pub enum TableValues {
    /// `(sparse(key), sparse(rotate32(key, rotation)))` in the given base.
    SparseRotation {
        base: u64,
        rotation: u32,
    },
    /// The base-digits of `key` mapped through `table`, packed as bits.
    SparseNormalization {
        base: u64,
        table: &'static [u64],
    },
    /// The two limbs of one axis of a secp256r1 fixed-base table entry.
    FixedBase {
        axis: u8,
        window: u8,
    },
    KeccakRho {
        bits: u8,
    },
    KeccakTheta,
    KeccakChi,
    KeccakInput,
    UintXor,
    UintAnd,
}

impl TableValues {
    pub fn eval(&self, key: [u64; 2]) -> [Fr; 2] {
        match *self {
            TableValues::SparseRotation { base, rotation } => {
                let t0 = map_into_sparse_form(base, key[0]);
                let t1 = if rotation > 0 {
                    map_into_sparse_form(base, rotate32(key[0] as u32, rotation) as u64)
                } else {
                    t0
                };
                [t0, t1]
            }
            TableValues::SparseNormalization { base, table } => {
                let mut accumulator = 0u64;
                let mut input = key[0];
                let mut count = 0;
                while input > 0 {
                    let slice = input % base;
                    accumulator += table[slice as usize] << count;
                    input /= base;
                    count += 1;
                }
                [Fr::from(accumulator), Fr::zero()]
            }
            TableValues::KeccakRho { bits } => super::keccak_tables::rho_values(bits as usize, key[0]),
            TableValues::KeccakTheta => super::keccak_tables::theta_values(key[0]),
            TableValues::KeccakChi => super::keccak_tables::chi_values(key[0]),
            TableValues::KeccakInput => super::keccak_tables::input_values(key[0]),
            TableValues::UintXor => super::uint_tables::values(key, true),
            TableValues::UintAnd => super::uint_tables::values(key, false),
            TableValues::FixedBase { axis, window } => super::secp256r1_fixed_base::extract_axis(
                &super::secp256r1_fixed_base::entry(window as usize, key[0] as usize),
                axis,
            ),
        }
    }
}

/// One lookup gate's key slices and values (bb `BasicTable::LookupEntry`).
#[derive(Clone, Copy, Debug)]
pub struct LookupEntry {
    pub key: [u64; 2],
    pub value: [Fr; 2],
}

impl LookupEntry {
    pub fn to_table_components(&self, use_twin_keys: bool) -> [Fr; 3] {
        if use_twin_keys {
            [Fr::from(self.key[0]), Fr::from(self.key[1]), self.value[0]]
        } else {
            [Fr::from(self.key[0]), self.value[0], self.value[1]]
        }
    }
}

pub struct BasicTable {
    pub id: BasicTableId,
    /// 1-based position in the builder's tables (the `table_4` selector value).
    pub table_index: usize,
    pub use_twin_keys: bool,
    pub columns: [Vec<Fr>; 3],
    /// Every lookup gate reading this table.
    pub lookup_gates: Vec<LookupEntry>,
}

impl BasicTable {
    pub fn size(&self) -> usize {
        self.columns[0].len()
    }
}

pub struct MultiTable {
    pub basic_table_ids: Vec<BasicTableId>,
    pub slice_sizes: Vec<u64>,
    pub column_coefficients: [Vec<Fr>; 3],
    /// `coefficient[i] / coefficient[i - 1]` (0 when either is 0), `1` first.
    pub column_step_sizes: [Vec<Fr>; 3],
    pub get_table_values: Vec<TableValues>,
}

impl MultiTable {
    pub(crate) fn new(
        column_coefficients: [Vec<Fr>; 3],
        slice_sizes: Vec<u64>,
        basic_table_ids: Vec<BasicTableId>,
        get_table_values: Vec<TableValues>,
    ) -> Self {
        let steps = |c: &Vec<Fr>| {
            let mut s = vec![Fr::one()];
            for i in 1..c.len() {
                s.push(if c[i - 1].is_zero() {
                    Fr::zero()
                } else {
                    c[i] * c[i - 1].invert()
                });
            }
            s
        };
        let column_step_sizes = [
            steps(&column_coefficients[0]),
            steps(&column_coefficients[1]),
            steps(&column_coefficients[2]),
        ];
        Self {
            basic_table_ids,
            slice_sizes,
            column_coefficients,
            column_step_sizes,
            get_table_values,
        }
    }
    /// bb's tables that set the step sizes directly (the ρ tables).
    pub(crate) fn from_steps(
        column_step_sizes: [Vec<Fr>; 3],
        slice_sizes: Vec<u64>,
        basic_table_ids: Vec<BasicTableId>,
        get_table_values: Vec<TableValues>,
    ) -> Self {
        Self {
            basic_table_ids,
            slice_sizes,
            column_coefficients: [vec![], vec![], vec![]],
            column_step_sizes,
            get_table_values,
        }
    }
    /// Coefficients `1, c, c², …` per column (bb's repeated-coefficient constructor).
    pub(crate) fn repeated(
        c: [Fr; 3],
        num_lookups: usize,
        slice_size: u64,
        id: BasicTableId,
        values: TableValues,
    ) -> Self {
        let geometric = |c: Fr| {
            let mut v = vec![Fr::one()];
            for i in 1..num_lookups {
                v.push(v[i - 1] * c);
            }
            v
        };
        Self::new(
            [geometric(c[0]), geometric(c[1]), geometric(c[2])],
            vec![slice_size; num_lookups],
            vec![id; num_lookups],
            vec![values; num_lookups],
        )
    }
}

/// A multi-table read: three accumulator columns and the per-slice table entries.
pub struct ReadData<T> {
    pub columns: [Vec<T>; 3],
    pub lookup_entries: Vec<LookupEntry>,
}

pub fn get_multitable(id: MultiTableId) -> &'static MultiTable {
    static TABLES: LazyLock<Vec<(MultiTableId, MultiTable)>> = LazyLock::new(|| {
        use MultiTableId::*;
        let mut tables: Vec<(MultiTableId, MultiTable)> = [
            Sha256ChInput,
            Sha256ChOutput,
            Sha256MajInput,
            Sha256MajOutput,
            Sha256WitnessInput,
            Sha256WitnessOutput,
        ]
        .into_iter()
        .map(|id| (id, sha256::multitable(id)))
        .collect();
        for axis in 0..4 {
            for is_lo in [true, false] {
                tables.push((
                    Secp256r1FixedBase { axis, is_lo },
                    super::secp256r1_fixed_base::multitable(axis, is_lo),
                ));
            }
        }
        for lane in 0..25u8 {
            tables.push((
                KeccakNormalizeAndRotate(lane),
                super::keccak_tables::rho_multitable(lane as usize),
            ));
        }
        tables.push((KeccakThetaOutput, super::keccak_tables::theta_multitable()));
        tables.push((KeccakChiOutput, super::keccak_tables::chi_multitable()));
        tables.push((KeccakFormatInput, super::keccak_tables::input_multitable()));
        tables.push((KeccakFormatOutput, super::keccak_tables::output_multitable()));
        tables.push((Uint32Xor, super::uint_tables::uint32_multitable(true)));
        tables.push((Uint32And, super::uint_tables::uint32_multitable(false)));
        tables
    });
    &TABLES.iter().find(|(i, _)| *i == id).expect("multitable").1
}

/// The two 64-bit quotient-and-remainder steps of splitting a key into slices.
fn div_rem_u64(v: U256, d: u64) -> (U256, u64) {
    let mut q = [0u64; 4];
    let mut rem: u128 = 0;
    for i in (0..4).rev() {
        let cur = (rem << 64) | v.0[i] as u128;
        q[i] = (cur / d as u128) as u64;
        rem = cur % d as u128;
    }
    (U256::new(q), rem as u64)
}

/// bb `numeric::slice_input_using_variable_bases`.
fn slice_input(input: &Fr, bases: &[u64]) -> Vec<u64> {
    let mut target = u256(input);
    let mut slices = Vec::with_capacity(bases.len());
    for (i, base) in bases.iter().enumerate() {
        let (q, r) = div_rem_u64(target, *base);
        if i == bases.len() - 1 {
            assert!(q == U256::new([0; 4]), "last key slice exceeds its base");
        }
        slices.push(r);
        target = q;
    }
    slices
}

/// bb `plookup::get_lookup_accumulators`: the accumulator columns of a multi-table read, running
/// from the last slice back to the first.
pub fn get_lookup_accumulators(id: MultiTableId, key_a: Fr, key_b: Fr, is_2_to_1_lookup: bool) -> ReadData<Fr> {
    let multi_table = get_multitable(id);
    let num_lookups = multi_table.basic_table_ids.len();
    let key_a_slices = slice_input(&key_a, &multi_table.slice_sizes);
    let key_b_slices = slice_input(&key_b, &multi_table.slice_sizes);
    let mut raw = [Vec::new(), Vec::new(), Vec::new()];
    let mut lookup_entries = Vec::with_capacity(num_lookups);
    for i in 0..num_lookups {
        let values = multi_table.get_table_values[i].eval([key_a_slices[i], key_b_slices[i]]);
        raw[0].push(Fr::from(key_a_slices[i]));
        raw[1].push(if is_2_to_1_lookup {
            Fr::from(key_b_slices[i])
        } else {
            values[0]
        });
        raw[2].push(if is_2_to_1_lookup { values[0] } else { values[1] });
        lookup_entries.push(LookupEntry {
            key: [key_a_slices[i], key_b_slices[i]],
            value: values,
        });
    }
    let mut columns = [
        vec![Fr::zero(); num_lookups],
        vec![Fr::zero(); num_lookups],
        vec![Fr::zero(); num_lookups],
    ];
    for c in 0..3 {
        columns[c][num_lookups - 1] = raw[c][num_lookups - 1];
        for i in (1..num_lookups).rev() {
            columns[c][i - 1] = raw[c][i - 1] + columns[c][i] * multi_table.column_step_sizes[c][i];
        }
    }
    ReadData {
        columns,
        lookup_entries,
    }
}

/// bb `plookup::create_basic_table`.
pub fn create_basic_table(id: BasicTableId, table_index: usize) -> BasicTable {
    use BasicTableId::*;
    assert!(table_index > 0);
    match id {
        BasicTableId::StrausEcPoint => unreachable!("Straus tables are registered directly with the builder"),
        Sha256WitnessNormalize => {
            sparse_normalization_table(id, table_index, 16, 3, &sha256::WITNESS_EXTENSION_NORMALIZATION)
        }
        Sha256ChNormalize => sparse_normalization_table(id, table_index, 28, 2, &sha256::CHOOSE_NORMALIZATION),
        Sha256MajNormalize => sparse_normalization_table(id, table_index, 16, 3, &sha256::MAJORITY_NORMALIZATION),
        Sha256WitnessSlice3 => sparse_table_with_rotation(id, table_index, 16, 3, 0),
        Sha256WitnessSlice7Rotate4 => sparse_table_with_rotation(id, table_index, 16, 7, 4),
        Sha256WitnessSlice8Rotate7 => sparse_table_with_rotation(id, table_index, 16, 8, 7),
        Sha256WitnessSlice14Rotate1 => sparse_table_with_rotation(id, table_index, 16, 14, 1),
        Sha256Base28 => sparse_table_with_rotation(id, table_index, 28, 11, 0),
        Sha256Base28Rotate6 => sparse_table_with_rotation(id, table_index, 28, 11, 6),
        Sha256Base28Rotate3 => sparse_table_with_rotation(id, table_index, 28, 10, 3),
        Sha256Base16 => sparse_table_with_rotation(id, table_index, 16, 10, 0),
        Sha256Base16Rotate2 => sparse_table_with_rotation(id, table_index, 16, 11, 2),
        Secp256r1FixedBase { axis, window } => {
            super::secp256r1_fixed_base::basic_table(id, table_index, axis, window as usize)
        }
        KeccakRho(bits) => super::keccak_tables::rho_table(id, table_index, bits as usize),
        KeccakTheta => super::keccak_tables::theta_table(id, table_index),
        KeccakChi => super::keccak_tables::chi_table(id, table_index),
        KeccakInput => super::keccak_tables::input_table(id, table_index),
        KeccakOutput => super::keccak_tables::output_table(id, table_index),
        UintXor(bits) => super::uint_tables::table(id, table_index, bits as usize, true),
        UintAnd(bits) => super::uint_tables::table(id, table_index, bits as usize, false),
    }
}

// ---- sparse form (bb `numeric/bitop/sparse_form.hpp`, `plookup_tables/sparse.hpp`) ----

fn rotate32(value: u32, rotation: u32) -> u32 {
    if rotation == 0 {
        value
    } else {
        (value >> rotation) | (value << (32 - rotation))
    }
}

/// Every set bit `i` of `input` becomes `base^i`.
pub fn map_into_sparse_form(base: u64, input: u64) -> Fr {
    let base = Fr::from(base);
    let mut out = Fr::zero();
    let mut power = Fr::one();
    for i in 0..32 {
        if (input >> i) & 1 == 1 {
            out += power;
        }
        power *= base;
    }
    out
}

fn sparse_table_with_rotation(
    id: BasicTableId,
    table_index: usize,
    base: u64,
    bits_per_slice: u32,
    rotation: u32,
) -> BasicTable {
    let values = TableValues::SparseRotation { base, rotation };
    let mut columns = [Vec::new(), Vec::new(), Vec::new()];
    for i in 0..(1u64 << bits_per_slice) {
        let [target, rotated] = values.eval([i, 0]);
        columns[0].push(Fr::from(i));
        columns[1].push(target);
        columns[2].push(rotated);
    }
    BasicTable {
        id,
        table_index,
        use_twin_keys: false,
        columns,
        lookup_gates: vec![],
    }
}

fn sparse_normalization_table(
    id: BasicTableId,
    table_index: usize,
    base: u64,
    num_bits: u32,
    table: &'static [u64],
) -> BasicTable {
    let values = TableValues::SparseNormalization { base, table };
    let mut columns = [Vec::new(), Vec::new(), Vec::new()];
    for i in 0..base.pow(num_bits) {
        columns[0].push(Fr::from(i));
        columns[1].push(values.eval([i, 0])[0]);
        columns[2].push(Fr::zero());
    }
    BasicTable {
        id,
        table_index,
        use_twin_keys: false,
        columns,
        lookup_gates: vec![],
    }
}

/// bb `plookup_tables/sha256.hpp`.
pub mod sha256 {
    use super::*;
    use crate::base::field::FieldLike;

    pub const CHOOSE_BASE: u64 = 28;
    pub const MAJORITY_BASE: u64 = 16;
    pub const WITNESS_EXTENSION_BASE: u64 = 16;

    /// `e + 2f + 3g` (mod 7 twice over) → `Ch(e, f, g)`, per base-28 digit.
    pub static CHOOSE_NORMALIZATION: [u64; 28] = [
        0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 2, 1, 2, 2, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 2, 1, 2, 2,
    ];
    /// `a + b + c` → `Maj(a, b, c)`, per base-16 digit.
    pub static MAJORITY_NORMALIZATION: [u64; 16] = [0, 0, 1, 1, 1, 1, 2, 2, 0, 0, 1, 1, 1, 1, 2, 2];
    pub static WITNESS_EXTENSION_NORMALIZATION: [u64; 16] = [0, 1, 0, 1, 1, 2, 1, 2, 0, 1, 0, 1, 1, 2, 1, 2];

    fn pow(base: u64, e: u64) -> Fr {
        Fr::from(base).pow_u64(e)
    }

    /// Per-limb rotation coefficients of Σ1 (rot 6, 11, 25) over the three 11/11/10-bit limbs;
    /// 0 marks a rotation the basic table handles.
    fn choose_rotation_coefficients() -> [Fr; 3] {
        let b = CHOOSE_BASE;
        let rot6 = [Fr::zero(), pow(b, 11 - 6), pow(b, 22 - 6)];
        let rot11 = [pow(b, 32 - 11), Fr::zero(), pow(b, 22 - 11)];
        let rot25 = [pow(b, 32 - 25), pow(b, 32 - 25 + 11), Fr::zero()];
        std::array::from_fn(|i| rot6[i] + rot11[i] + rot25[i])
    }
    /// Σ0 (rot 2, 13, 22).
    fn majority_rotation_coefficients() -> [Fr; 3] {
        let b = MAJORITY_BASE;
        let rot2 = [Fr::zero(), pow(b, 11 - 2), pow(b, 22 - 2)];
        let rot13 = [pow(b, 32 - 13), Fr::zero(), pow(b, 22 - 13)];
        let rot22 = [pow(b, 32 - 22), pow(b, 32 - 22 + 11), Fr::zero()];
        std::array::from_fn(|i| rot2[i] + rot13[i] + rot22[i])
    }
    pub fn get_majority_rotation_multipliers() -> [Fr; 3] {
        let c = majority_rotation_coefficients();
        [c[0], c[1] - pow(MAJORITY_BASE, 11) * c[0], Fr::zero()]
    }
    pub fn get_choose_rotation_multipliers() -> [Fr; 3] {
        let c = choose_rotation_coefficients();
        [c[0], Fr::zero(), c[2] - pow(CHOOSE_BASE, 22) * c[0]]
    }

    pub fn multitable(id: MultiTableId) -> MultiTable {
        use BasicTableId::*;
        let sparse = |base, rotation| TableValues::SparseRotation { base, rotation };
        match id {
            MultiTableId::Sha256WitnessOutput => MultiTable::repeated(
                [Fr::from(WITNESS_EXTENSION_BASE.pow(3)), Fr::from(1u64 << 3), Fr::zero()],
                11,
                WITNESS_EXTENSION_BASE.pow(3),
                Sha256WitnessNormalize,
                TableValues::SparseNormalization {
                    base: WITNESS_EXTENSION_BASE,
                    table: &WITNESS_EXTENSION_NORMALIZATION,
                },
            ),
            MultiTableId::Sha256ChOutput => MultiTable::repeated(
                [Fr::from(CHOOSE_BASE.pow(2)), Fr::from(1u64 << 2), Fr::zero()],
                16,
                CHOOSE_BASE.pow(2),
                Sha256ChNormalize,
                TableValues::SparseNormalization {
                    base: CHOOSE_BASE,
                    table: &CHOOSE_NORMALIZATION,
                },
            ),
            MultiTableId::Sha256MajOutput => MultiTable::repeated(
                [Fr::from(MAJORITY_BASE.pow(3)), Fr::from(1u64 << 3), Fr::zero()],
                11,
                MAJORITY_BASE.pow(3),
                Sha256MajNormalize,
                TableValues::SparseNormalization {
                    base: MAJORITY_BASE,
                    table: &MAJORITY_NORMALIZATION,
                },
            ),
            MultiTableId::Sha256WitnessInput => MultiTable::new(
                [
                    vec![
                        Fr::one(),
                        Fr::from(1u64 << 3),
                        Fr::from(1u64 << 10),
                        Fr::from(1u64 << 18),
                    ],
                    vec![Fr::zero(); 4],
                    vec![Fr::zero(); 4],
                ],
                vec![1 << 3, 1 << 7, 1 << 8, 1 << 14],
                vec![
                    Sha256WitnessSlice3,
                    Sha256WitnessSlice7Rotate4,
                    Sha256WitnessSlice8Rotate7,
                    Sha256WitnessSlice14Rotate1,
                ],
                vec![sparse(16, 0), sparse(16, 4), sparse(16, 7), sparse(16, 1)],
            ),
            MultiTableId::Sha256ChInput => {
                let c = choose_rotation_coefficients();
                let limb1_table_correction = c[1] - pow(CHOOSE_BASE, 11) * c[0];
                MultiTable::new(
                    [
                        vec![Fr::one(), Fr::from(1u64 << 11), Fr::from(1u64 << 22)],
                        vec![Fr::one(), pow(CHOOSE_BASE, 11), pow(CHOOSE_BASE, 22)],
                        vec![Fr::one(), Fr::one() + limb1_table_correction, Fr::one()],
                    ],
                    vec![1 << 11, 1 << 11, 1 << 10],
                    vec![Sha256Base28Rotate6, Sha256Base28, Sha256Base28Rotate3],
                    vec![sparse(28, 6), sparse(28, 0), sparse(28, 3)],
                )
            }
            MultiTableId::Sha256MajInput => {
                let c = majority_rotation_coefficients();
                let limb2_table_correction = c[2] - pow(MAJORITY_BASE, 11) * c[1];
                MultiTable::new(
                    [
                        vec![Fr::one(), Fr::from(1u64 << 11), Fr::from(1u64 << 22)],
                        vec![Fr::one(), pow(MAJORITY_BASE, 11), pow(MAJORITY_BASE, 22)],
                        vec![Fr::one(), Fr::one(), Fr::one() + limb2_table_correction],
                    ],
                    vec![1 << 11, 1 << 11, 1 << 10],
                    vec![Sha256Base16Rotate2, Sha256Base16Rotate2, Sha256Base16],
                    vec![sparse(16, 2), sparse(16, 2), sparse(16, 0)],
                )
            }
            _ => unreachable!("not a sha256 table"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Table entries are data: a wrong value would still satisfy our own lookup relation (both
    /// sides read the same table), so pin them against the defining function instead. Every row of
    /// the 6-bit XOR and AND tables must be `key_a (op) key_b`.
    #[test]
    fn uint_tables_match_their_defining_functions() {
        for (id, op) in [
            (BasicTableId::UintXor(6), (|a, b| a ^ b) as fn(u64, u64) -> u64),
            (BasicTableId::UintAnd(6), |a, b| a & b),
        ] {
            let table = create_basic_table(id, 1);
            assert!(table.use_twin_keys);
            assert_eq!(table.size(), 1 << 12, "6-bit twin-key table has 2^12 rows");
            for r in 0..table.size() {
                let a = fr_to_u64(&table.columns[0][r]);
                let b = fr_to_u64(&table.columns[1][r]);
                let out = fr_to_u64(&table.columns[2][r]);
                assert_eq!(out, op(a, b), "row {r}: {a} op {b}");
            }
        }
    }

    fn fr_to_u64(f: &Fr) -> u64 {
        crate::base::codec::fr_to_usize(f) as u64
    }

    /// The multitable accumulator chain: looking up a 32-bit XOR through the multitable and
    /// re-assembling the slice outputs reproduces the native XOR.
    #[test]
    fn xor_multitable_accumulators_reassemble() {
        let (a, b) = (0x1234_5678u64, 0x9abc_def0u64);
        let read = get_lookup_accumulators(MultiTableId::Uint32Xor, Fr::from(a), Fr::from(b), true);
        // column 3's first accumulator is the full result of the chained lookups
        let out = crate::base::codec::fr_to_usize(&read.columns[2][0]) as u64;
        assert_eq!(out, a ^ b);
    }
}
