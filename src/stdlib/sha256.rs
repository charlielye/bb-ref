//! In-circuit SHA-256 compression (bb `stdlib/hash/sha256/sha256.cpp`): the state words live in
//! sparse (base-16 / base-28) form so that rotations and Ch/Maj become lookups.

use super::field::{Ctx, FieldT};
use super::plookup::{read_accumulators, read_from_1_to_2_table};
use crate::base::field::{u256, FieldLike};
use crate::base::Fr;
use crate::circuit::plookup::sha256::{get_choose_rotation_multipliers, get_majority_rotation_multipliers};
use crate::circuit::plookup::MultiTableId::*;

const ROUND_CONSTANTS: [u64; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98,
    0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8,
    0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
    0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
    0xc67178f2,
];

fn pow16(e: u64) -> Fr {
    Fr::from(16u64).pow_u64(e)
}

/// σ0 = rot7 ⊕ rot18 ⊕ shift3 and σ1 = rot17 ⊕ rot19 ⊕ shift10 over the 3/7/8/14-bit limbs.
fn left_multipliers() -> [Fr; 4] {
    [
        pow16(32 - 7) + pow16(32 - 18),
        pow16(32 - 18 + 3) + Fr::one(),
        pow16(10 - 7) + pow16(32 - 18 + 10) + pow16(10 - 3),
        pow16(18 - 7) + Fr::one() + pow16(18 - 3),
    ]
}
fn right_multipliers() -> [Fr; 4] {
    [
        pow16(32 - 17) + pow16(32 - 19),
        pow16(32 - 17 + 3) + pow16(32 - 19 + 3),
        pow16(32 - 19 + 10) + Fr::one(),
        pow16(18 - 17) + pow16(18 - 10),
    ]
}

fn k(v: Fr) -> FieldT {
    FieldT::constant(v)
}

#[derive(Clone)]
struct SparseWitnessLimbs {
    normal: FieldT,
    sparse_limbs: [FieldT; 4],
    rotated_limb_corrections: [FieldT; 4],
    has_sparse_limbs: bool,
}

impl SparseWitnessLimbs {
    fn new(normal: FieldT) -> Self {
        let z = || k(Fr::zero());
        Self { normal, sparse_limbs: [z(), z(), z(), z()], rotated_limb_corrections: [z(), z(), z(), z()], has_sparse_limbs: false }
    }
}

#[derive(Clone)]
struct SparseValue {
    normal: FieldT,
    sparse: FieldT,
}

impl SparseValue {
    fn new(normal: FieldT) -> Self {
        Self { normal, sparse: k(Fr::zero()) }
    }
}

fn convert_witness(input: &FieldT) -> SparseWitnessLimbs {
    let mut result = SparseWitnessLimbs::new(input.clone());
    let lookup = read_accumulators(Sha256WitnessInput, input);
    result.sparse_limbs = std::array::from_fn(|i| lookup.columns[1][i].clone());
    result.rotated_limb_corrections = std::array::from_fn(|i| lookup.columns[2][i].clone());
    result.has_sparse_limbs = true;
    result
}

fn extend_witness(w_in: &[FieldT; 16]) -> [FieldT; 64] {
    let ctx: Ctx = w_in.iter().find_map(|w| w.ctx.clone()).expect("sha256 inputs must include a witness");
    let mut w_sparse: Vec<SparseWitnessLimbs> = w_in.iter().map(|w| SparseWitnessLimbs::new(w.clone())).collect();
    let (left_mult, right_mult) = (left_multipliers(), right_multipliers());
    for i in 16..64 {
        if !w_sparse[i - 15].has_sparse_limbs {
            w_sparse[i - 15] = convert_witness(&w_sparse[i - 15].normal);
        }
        if !w_sparse[i - 2].has_sparse_limbs {
            w_sparse[i - 2] = convert_witness(&w_sparse[i - 2].normal);
        }
        let (w_left, w_right) = (&w_sparse[i - 15], &w_sparse[i - 2]);
        let left: [FieldT; 4] = std::array::from_fn(|j| w_left.sparse_limbs[j].mul(&k(left_mult[j])));
        let right: [FieldT; 4] = std::array::from_fn(|j| w_right.sparse_limbs[j].mul(&k(right_mult[j])));
        let left_xor_sparse = left[0]
            .add_two(&left[1], &left[2])
            .add_two(&left[3], &w_left.rotated_limb_corrections[1])
            .mul(&k(Fr::from(4u64)));
        let xor_result_sparse = right[0]
            .add_two(&right[1], &right[2])
            .add_two(&right[3], &w_right.rotated_limb_corrections[2])
            .add_two(&w_right.rotated_limb_corrections[3], &left_xor_sparse);
        let xor_result = read_from_1_to_2_table(Sha256WitnessOutput, &xor_result_sparse);
        let w_out_raw = xor_result.add_two(&w_sparse[i - 16].normal, &w_sparse[i - 7].normal);
        let w_out_modded = u256(&w_out_raw.get_value()).0[0] as u32 as u64;
        let w_out = if w_out_raw.is_constant() {
            k(Fr::from(w_out_modded))
        } else {
            let w_out = FieldT::from_witness(&ctx, Fr::from(w_out_modded));
            let inv_pow_two = k(Fr::from(2u64).pow_u64(32).invert());
            let w_out_raw_inv_pow_two = w_out_raw.mul(&inv_pow_two);
            let w_out_inv_pow_two = w_out.mul(&inv_pow_two);
            let divisor = w_out_raw_inv_pow_two.sub(&w_out_inv_pow_two);
            divisor.create_range_constraint(2);
            w_out
        };
        w_sparse.push(SparseWitnessLimbs::new(w_out));
    }
    w_sparse[0].normal.create_range_constraint(32);
    w_sparse[62].normal.create_range_constraint(32);
    w_sparse[63].normal.create_range_constraint(32);
    std::array::from_fn(|i| w_sparse[i].normal.clone())
}

fn map_into_choose_sparse_form(input: &FieldT) -> SparseValue {
    SparseValue { normal: input.clone(), sparse: read_from_1_to_2_table(Sha256ChInput, input) }
}

fn map_into_maj_sparse_form(input: &FieldT) -> SparseValue {
    SparseValue { normal: input.clone(), sparse: read_from_1_to_2_table(Sha256MajInput, input) }
}

/// Σ1(e) + Ch(e, f, g), setting `e.sparse` on the way.
fn choose_with_sigma1(e: &mut SparseValue, f: &SparseValue, g: &SparseValue) -> FieldT {
    let sparse_mult = Fr::from(7u64);
    let lookup = read_accumulators(Sha256ChInput, &e.normal);
    let rotation_coefficients = get_choose_rotation_multipliers();
    let rotation_result = lookup.columns[2][0].clone();
    e.sparse = lookup.columns[1][0].clone();
    let sparse_l2 = lookup.columns[1][2].clone();
    let xor_result = rotation_result.mul(&k(sparse_mult)).add_two(
        &e.sparse.mul(&k(rotation_coefficients[0] * sparse_mult + Fr::one())),
        &sparse_l2.mul(&k(rotation_coefficients[2] * sparse_mult)),
    );
    let choose_result_sparse = xor_result.add_two(&f.sparse.add(&f.sparse), &g.sparse.add(&g.sparse).add(&g.sparse));
    read_from_1_to_2_table(Sha256ChOutput, &choose_result_sparse)
}

/// Σ0(a) + Maj(a, b, c), setting `a.sparse` on the way.
fn majority_with_sigma0(a: &mut SparseValue, b: &SparseValue, c: &SparseValue) -> FieldT {
    let sparse_mult = Fr::from(4u64);
    let lookup = read_accumulators(Sha256MajInput, &a.normal);
    let rotation_coefficients = get_majority_rotation_multipliers();
    let rotation_result = lookup.columns[2][0].clone();
    a.sparse = lookup.columns[1][0].clone();
    let sparse_l1_acc = lookup.columns[1][1].clone();
    let xor_result = rotation_result.mul(&k(sparse_mult)).add_two(
        &a.sparse.mul(&k(rotation_coefficients[0] * sparse_mult + Fr::one())),
        &sparse_l1_acc.mul(&k(rotation_coefficients[1] * sparse_mult)),
    );
    let majority_result_sparse = xor_result.add_two(&b.sparse, &c.sparse);
    read_from_1_to_2_table(Sha256MajOutput, &majority_result_sparse)
}

/// bb `hash_utils::add_normalize_unsafe`: `(a + b) mod 2^32` with the overflow range-constrained.
fn add_normalize_unsafe(a: &FieldT, b: &FieldT, overflow_bits: u64) -> FieldT {
    let sum = u256(&(a.get_value() + b.get_value()));
    let normalized_sum = sum.0[0] as u32 as u64;
    if a.is_constant() && b.is_constant() {
        return k(Fr::from(normalized_sum));
    }
    let ctx = a.ctx.clone().or_else(|| b.ctx.clone()).unwrap();
    let overflow_value = (a.get_value() + b.get_value() - Fr::from(normalized_sum)) * Fr::from(1u64 << 32).invert();
    let overflow = FieldT::from_witness(&ctx, overflow_value);
    let result = a.add_two(b, &overflow.mul(&k(-Fr::from(1u64 << 32))));
    overflow.create_range_constraint(overflow_bits);
    result
}

/// bb `SHA256::sha256_block`: one compression of `input` onto the state `h_init`.
pub fn sha256_block(h_init: &[FieldT; 8], input: &[FieldT; 16]) -> [FieldT; 8] {
    h_init[3].create_range_constraint(32);
    h_init[7].create_range_constraint(32);
    input[0].create_range_constraint(32);
    let mut a = SparseValue::new(h_init[0].clone());
    let mut b = map_into_maj_sparse_form(&h_init[1]);
    let mut c = map_into_maj_sparse_form(&h_init[2]);
    let mut d = SparseValue::new(h_init[3].clone());
    let mut e = SparseValue::new(h_init[4].clone());
    let mut f = map_into_choose_sparse_form(&h_init[5]);
    let mut g = map_into_choose_sparse_form(&h_init[6]);
    let mut h = SparseValue::new(h_init[7].clone());
    let w = extend_witness(input);
    for i in 0..64 {
        let ch = choose_with_sigma1(&mut e, &f, &g);
        let maj = majority_with_sigma0(&mut a, &b, &c);
        let t1 = ch.add_two(&h.normal, &w[i].add(&k(Fr::from(ROUND_CONSTANTS[i]))));
        h = g;
        g = f;
        f = e;
        e = SparseValue::new(add_normalize_unsafe(&d.normal, &t1, 3));
        d = c;
        c = b;
        b = a;
        a = SparseValue::new(add_normalize_unsafe(&t1, &maj, 3));
    }
    a.normal.create_range_constraint(32);
    e.normal.create_range_constraint(32);
    let state = [a, b, c, d, e, f, g, h];
    let output: [FieldT; 8] = std::array::from_fn(|i| add_normalize_unsafe(&state[i].normal, &h_init[i], 1));
    for val in &output {
        val.create_range_constraint(32);
    }
    output
}
