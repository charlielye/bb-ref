//! secp256k1 generator wNAF plookup tables (bb `plookup_tables/non_native_group_generator.cpp`):
//! 256-row tables of `(2w - 255)·G` for wNAF witness values `w ∈ [0, 255]`, one table per pair of
//! 68-bit coordinate limbs plus the prime-basis pair, with endomorphism (`β·x`) variants.

use super::plookup::{BasicTable, BasicTableId, MultiTable, MultiTableId, TableValues};
use crate::base::field::FieldLike;
use crate::base::Fr;
use ark_ec::{AffineRepr, CurveGroup};
use num_bigint::BigUint;
use std::sync::LazyLock;

pub const TABLE_SIZE: usize = 256;
const NUM_LIMB_BITS: u32 = 68;

/// β: the cube root of unity mod the secp256k1 base field (`λ·P = (β·x, y)`).
pub const BETA_HEX: &str = "7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee";

/// Which of the eight generator tables a lookup reads.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum GeneratorTable {
    Xlo,
    Xhi,
    XloEndo,
    XhiEndo,
    Ylo,
    Yhi,
    XyPrime,
    XyPrimeEndo,
}

pub const GENERATOR_TABLES: [GeneratorTable; 8] = [
    GeneratorTable::Xlo,
    GeneratorTable::Xhi,
    GeneratorTable::XloEndo,
    GeneratorTable::XhiEndo,
    GeneratorTable::Ylo,
    GeneratorTable::Yhi,
    GeneratorTable::XyPrime,
    GeneratorTable::XyPrimeEndo,
];

struct Tables {
    rows: [[(Fr, Fr); TABLE_SIZE]; 8],
}

static TABLES: LazyLock<Tables> = LazyLock::new(|| {
    let g = ark_secp256k1::Affine::generator().into_group();
    let d2 = g + g;
    let mut points = vec![ark_secp256k1::Projective::default(); TABLE_SIZE];
    points[TABLE_SIZE / 2] = g;
    for i in 1..TABLE_SIZE / 2 {
        points[i + TABLE_SIZE / 2] = points[i + TABLE_SIZE / 2 - 1] + d2;
    }
    for i in 0..TABLE_SIZE / 2 {
        points[TABLE_SIZE / 2 - 1 - i] = -points[TABLE_SIZE / 2 + i];
    }
    let affine = ark_secp256k1::Projective::normalize_batch(&points);
    let beta = ark_secp256k1::Fq::from(BigUint::parse_bytes(BETA_HEX.as_bytes(), 16).unwrap());

    let mask = (BigUint::from(1u64) << NUM_LIMB_BITS) - 1u64;
    let limb = |v: &BigUint, i: u32| Fr::from((v >> (i * NUM_LIMB_BITS)) & &mask);
    let prime = |v: &BigUint| Fr::from(v.clone());

    let mut rows = [[(Fr::zero(), Fr::zero()); TABLE_SIZE]; 8];
    for (i, p) in affine.iter().enumerate() {
        let x: BigUint = p.x.into();
        let y: BigUint = p.y.into();
        let endo_x: BigUint = (p.x * beta).into();
        rows[0][i] = (limb(&x, 0), limb(&x, 1));
        rows[1][i] = (limb(&x, 2), limb(&x, 3));
        rows[2][i] = (limb(&endo_x, 0), limb(&endo_x, 1));
        rows[3][i] = (limb(&endo_x, 2), limb(&endo_x, 3));
        rows[4][i] = (limb(&y, 0), limb(&y, 1));
        rows[5][i] = (limb(&y, 2), limb(&y, 3));
        rows[6][i] = (prime(&x), prime(&y));
        rows[7][i] = (prime(&endo_x), prime(&y));
    }
    Tables { rows }
});

pub fn values(table: GeneratorTable, key: [u64; 2]) -> [Fr; 2] {
    let row = TABLES.rows[table as usize][key[0] as usize];
    [row.0, row.1]
}

pub fn basic_table(table: GeneratorTable, id: BasicTableId, table_index: usize) -> BasicTable {
    let mut columns = [vec![], vec![], vec![]];
    for i in 0..TABLE_SIZE {
        let row = TABLES.rows[table as usize][i];
        columns[0].push(Fr::from(i as u64));
        columns[1].push(row.0);
        columns[2].push(row.1);
    }
    BasicTable {
        id,
        table_index,
        use_twin_keys: false,
        columns,
        lookup_gates: vec![],
    }
}

pub fn multitable(table: GeneratorTable) -> MultiTable {
    MultiTable::repeated(
        [Fr::from(TABLE_SIZE as u64), Fr::zero(), Fr::zero()],
        1,
        TABLE_SIZE as u64,
        BasicTableId::Secp256k1Generator(table),
        TableValues::Secp256k1Generator(table),
    )
}

pub fn multitable_id(table: GeneratorTable) -> MultiTableId {
    MultiTableId::Secp256k1Generator(table)
}
