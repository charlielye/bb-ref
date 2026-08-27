//! secp256r1 fixed-base plookup tables (bb `plookup_tables/secp256r1_fixed_base`): window `w`, entry
//! `k` holds `k · 2^bit_offset(w) · G + 2^w · H` with `H` the "biggroup table offset generator". The
//! scalar is sliced into 7-bit windows with a 3-bit tail for the low 136 bits and a 1-bit tail for the
//! high 120 bits; every point is spread over four basic tables, one per pair of 68-bit limbs.

use super::nnf::DEFAULT_NON_NATIVE_FIELD_LIMB_BITS as NUM_LIMB_BITS;
use super::plookup::{BasicTable, BasicTableId, MultiTable, TableValues};
use crate::base::Fr;
use ark_ec::short_weierstrass::{Affine, Projective};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{AdditiveGroup, PrimeField, Zero};
use ark_secp256r1::Config;
use num_bigint::BigUint;
use std::sync::LazyLock;

pub const NUM_WINDOWS_LO: usize = 20;
pub const NUM_WINDOWS_HI: usize = 18;
pub const NUM_WINDOWS: usize = NUM_WINDOWS_LO + NUM_WINDOWS_HI;
const WINDOW_BITS: usize = 7;
const TABLE_SIZE_BIG: u64 = 1 << WINDOW_BITS;
const LO_TAIL_WINDOW: usize = NUM_WINDOWS_LO - 1;
const HI_TAIL_WINDOW: usize = NUM_WINDOWS - 1;

pub fn window_bits(w: usize) -> usize {
    match w {
        LO_TAIL_WINDOW => 3,
        HI_TAIL_WINDOW => 1,
        _ => WINDOW_BITS,
    }
}
pub fn table_size(w: usize) -> u64 {
    1 << window_bits(w)
}

/// bb's "biggroup table offset generator" for secp256r1.
pub fn table_offset_generator() -> Affine<Config> {
    let x = ark_secp256r1::Fq::from(
        BigUint::parse_bytes(b"12f1907bc0f7caa93716082e67e3466f525281c6a2cd95990b6d3582b5c1375f", 16).unwrap(),
    );
    let y = ark_secp256r1::Fq::from(
        BigUint::parse_bytes(b"3111b47a8c982605786143f3d7b4f4c754a1b83aeaa81a7af6b90176b7328d08", 16).unwrap(),
    );
    Affine::new_unchecked(x, y)
}

struct Tables {
    entries: Vec<Vec<Affine<Config>>>,
    total_offset: Affine<Config>,
}

static TABLES: LazyLock<Tables> = LazyLock::new(|| {
    let h = table_offset_generator();
    let mut window_step: Projective<Config> = Affine::<Config>::generator().into_group();
    let mut offset_total = Projective::<Config>::zero();
    let mut entries = Vec::with_capacity(NUM_WINDOWS);
    for w in 0..NUM_WINDOWS {
        let window_offset = h * ark_secp256r1::Fr::from(BigUint::from(1u64) << w);
        offset_total += window_offset;
        let mut projective = vec![window_offset];
        for k in 1..table_size(w) as usize {
            projective.push(projective[k - 1] + window_step);
        }
        entries.push(Projective::normalize_batch(&projective));
        for _ in 0..window_bits(w) {
            window_step.double_in_place();
        }
    }
    Tables {
        entries,
        total_offset: offset_total.into_affine(),
    }
});

pub fn entry(window: usize, k: usize) -> Affine<Config> {
    TABLES.entries[window][k]
}
/// `(2^NUM_WINDOWS − 1) · H`, subtracted from the chain-add of the looked-up points.
pub fn total_offset() -> Affine<Config> {
    TABLES.total_offset
}

/// The two 68-bit limbs of one coordinate: axis 0/1 = x limbs (0,1)/(2,3), axis 2/3 = the same of y.
pub fn extract_axis(point: &Affine<Config>, axis: u8) -> [Fr; 2] {
    let coordinate: BigUint = if axis < 2 { point.x } else { point.y }.into_bigint().into();
    let low_limb = 2 * (axis as u64 % 2);
    let mask = (BigUint::from(1u64) << NUM_LIMB_BITS) - 1u64;
    let limb = |i: u64| Fr::from((&coordinate >> (i * NUM_LIMB_BITS)) & &mask);
    [limb(low_limb), limb(low_limb + 1)]
}

pub fn basic_table(id: BasicTableId, table_index: usize, axis: u8, window: usize) -> BasicTable {
    let mut columns = [vec![], vec![], vec![]];
    for k in 0..table_size(window) as usize {
        let [a, b] = extract_axis(&entry(window, k), axis);
        columns[0].push(Fr::from(k as u64));
        columns[1].push(a);
        columns[2].push(b);
    }
    BasicTable {
        id,
        table_index,
        use_twin_keys: false,
        columns,
        lookup_gates: vec![],
    }
}

/// The multi-table chaining one axis of the low (20) or high (18) windows: column 1 accumulates the
/// key in steps of 128, columns 2/3 keep the per-window limbs (step 0).
pub fn multitable(axis: u8, is_lo: bool) -> MultiTable {
    let (num_windows, start) = if is_lo {
        (NUM_WINDOWS_LO, 0)
    } else {
        (NUM_WINDOWS_HI, NUM_WINDOWS_LO)
    };
    let step = Fr::from(TABLE_SIZE_BIG);
    let mut c1 = vec![Fr::from(1u64)];
    let mut c23 = vec![Fr::from(1u64)];
    for i in 1..num_windows {
        c1.push(c1[i - 1] * step);
        c23.push(Fr::from(0u64));
    }
    let windows = start..start + num_windows;
    MultiTable::new(
        [c1, c23.clone(), c23],
        windows.clone().map(table_size).collect(),
        windows
            .clone()
            .map(|w| BasicTableId::Secp256r1FixedBase { axis, window: w as u8 })
            .collect(),
        windows
            .map(|w| TableValues::FixedBase { axis, window: w as u8 })
            .collect(),
    )
}
