//! The ECCVM (bb `eccvm/`): a Grumpkin-scalar-field (bn254 Fq) circuit proving every BN254 op of
//! the op queue — the transcript of ops, the wNAF point tables, and the Straus MSM rows.

pub mod check;
pub mod prover;
pub mod relations;
pub mod trace;
pub mod verifier;

use crate::base::field::from_hex;
use crate::base::poly::Polynomial;
use crate::base::{Fq, Fr, GrumpkinAffine};

pub const TRACE_OFFSET: usize = 4;
pub const CONST_ECCVM_LOG_N: usize = 15;
pub const FIXED_SIZE: usize = 1 << CONST_ECCVM_LOG_N;
pub const NUM_WNAF_DIGIT_BITS: u32 = 4;
pub const NUM_WNAF_DIGITS_PER_SCALAR: usize = 32;
pub const POINT_TABLE_SIZE: usize = 16;
pub const WNAF_DIGITS_PER_ROW: usize = 4;
pub const ADDITIONS_PER_ROW: usize = 4;
pub const LAST_ADDITION_ROUND: u64 = 31;

/// All ECCVM entities in bb `AllEntities` order: masking, precomputed, witness (wires, then
/// `z_perm`, `lookup_inverses`), shifted.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Ent {
    gemini_masking_poly,
    lagrange_first,
    lagrange_second,
    lagrange_third,
    lagrange_last,
    transcript_add,
    transcript_eq,
    transcript_msm_transition,
    transcript_Px,
    transcript_Py,
    transcript_z1,
    transcript_z2,
    transcript_z1zero,
    transcript_z2zero,
    transcript_op,
    transcript_msm_x,
    transcript_msm_y,
    precompute_point_transition,
    precompute_s1lo,
    precompute_s2hi,
    precompute_s2lo,
    precompute_s3hi,
    precompute_s3lo,
    precompute_s4hi,
    precompute_s4lo,
    precompute_skew,
    msm_size_of_msm,
    msm_add2,
    msm_add3,
    msm_add4,
    msm_x1,
    msm_y1,
    msm_x2,
    msm_y2,
    msm_x3,
    msm_y3,
    msm_x4,
    msm_y4,
    msm_collision_x1,
    msm_collision_x2,
    msm_collision_x3,
    msm_collision_x4,
    msm_lambda1,
    msm_lambda2,
    msm_lambda3,
    msm_lambda4,
    msm_slice1,
    msm_slice2,
    msm_slice3,
    msm_slice4,
    transcript_reset_accumulator,
    lookup_read_counts_0,
    lookup_read_counts_1,
    transcript_base_infinity,
    transcript_base_x_inverse,
    transcript_base_y_inverse,
    transcript_add_x_equal,
    transcript_add_y_equal,
    transcript_add_lambda,
    transcript_msm_intermediate_x,
    transcript_msm_intermediate_y,
    transcript_msm_infinity,
    transcript_msm_x_inverse,
    transcript_msm_count_zero_at_transition,
    transcript_msm_count_at_transition_inverse,
    msm_round_minus_31_inv,
    transcript_mul,
    transcript_msm_count,
    precompute_scalar_sum,
    precompute_s1hi,
    precompute_dx,
    precompute_dy,
    precompute_tx,
    precompute_ty,
    msm_transition,
    msm_add,
    msm_double,
    msm_skew,
    msm_accumulator_x,
    msm_accumulator_y,
    msm_count,
    msm_round,
    msm_add1,
    msm_pc,
    precompute_pc,
    transcript_pc,
    precompute_round,
    precompute_select,
    transcript_accumulator_not_empty,
    transcript_accumulator_x,
    transcript_accumulator_y,
    z_perm,
    lookup_inverses,
    transcript_mul_shift,
    transcript_msm_count_shift,
    precompute_scalar_sum_shift,
    precompute_s1hi_shift,
    precompute_dx_shift,
    precompute_dy_shift,
    precompute_tx_shift,
    precompute_ty_shift,
    msm_transition_shift,
    msm_add_shift,
    msm_double_shift,
    msm_skew_shift,
    msm_accumulator_x_shift,
    msm_accumulator_y_shift,
    msm_count_shift,
    msm_round_shift,
    msm_add1_shift,
    msm_pc_shift,
    precompute_pc_shift,
    transcript_pc_shift,
    precompute_round_shift,
    precompute_select_shift,
    transcript_accumulator_not_empty_shift,
    transcript_accumulator_x_shift,
    transcript_accumulator_y_shift,
    z_perm_shift,
}

pub const NUM_ALL_ENTITIES: usize = 119;
pub const NUM_PRECOMPUTED: usize = 4;
pub const NUM_WITNESS: usize = 88;
pub const NUM_SHIFTED: usize = 26;
/// Index of the first shifted entity; `TO_BE_SHIFTED[i]`'s shift is entity `FIRST_SHIFTED + i`.
pub const FIRST_SHIFTED: usize = NUM_ALL_ENTITIES - NUM_SHIFTED;

use Ent::*;
pub const TO_BE_SHIFTED: [Ent; NUM_SHIFTED] = [
    transcript_mul,
    transcript_msm_count,
    precompute_scalar_sum,
    precompute_s1hi,
    precompute_dx,
    precompute_dy,
    precompute_tx,
    precompute_ty,
    msm_transition,
    msm_add,
    msm_double,
    msm_skew,
    msm_accumulator_x,
    msm_accumulator_y,
    msm_count,
    msm_round,
    msm_add1,
    msm_pc,
    precompute_pc,
    transcript_pc,
    precompute_round,
    precompute_select,
    transcript_accumulator_not_empty,
    transcript_accumulator_x,
    transcript_accumulator_y,
    z_perm,
];

/// The fixed ECCVM verification key: commitments to the four Lagrange polynomials of the fixed-size
/// trace (bb `ECCVMHardcodedVKAndHash`), and its hash.
pub fn fixed_vk() -> [GrumpkinAffine; NUM_PRECOMPUTED] {
    let p = |x: &str, y: &str| GrumpkinAffine::new_unchecked(from_hex(x), from_hex(y));
    [
        p("0x1227d829cc03e51a2cc68ca0e08381c02b78c484f4092a10584ef78381a31968", "0x10b233eb875fed8834f6235ed737946b68c0c7ed258053cd943dcc69212d90d6"),
        p("0x1976c760e4bde34db58394888baeda91f57bcdddf60aec28b721b10aac55f555", "0x26eec8e50bdb2cfc3956e90bd72c9098d4a5de28c1c1c236955d14884a8f498d"),
        p("0x1a96c5eae61aba7353221e65adf123d30255415db00b8063157f2764a3034e26", "0x0d04425c0f370a7aaace3cf41f9b2380079c95fa26f9f83b5fd5e26813dbd289"),
        p("0x23a271e0e1d99d2a526cc8c06df7edf7c86e9cb985e577affb5a64b9daf24401", "0x12a74c457ae1f9bd6076c308f47a006deb82adfd576be1266cde1cdc0d008cd1"),
    ]
}

pub fn fixed_vk_hash() -> Fr {
    from_hex("0x032ece6c493f6e74ca8847127f189f8e759021e53df9820a88985e41e400fde2")
}

/// bb's commitment label of an entity (its name in upper case).
pub fn label(e: Ent) -> String {
    format!("{e:?}").to_uppercase()
}

/// The entity at index `i`.
pub fn ent(i: usize) -> Ent {
    assert!(i < NUM_ALL_ENTITIES);
    // SAFETY: `Ent` is `repr(u8)` with contiguous discriminants `0..NUM_ALL_ENTITIES`.
    unsafe { std::mem::transmute(i as u8) }
}

/// The ECCVM's polynomials, one per entity, all of the fixed dyadic size.
pub struct EccvmPolys {
    pub cols: Vec<Polynomial<Fq>>,
    /// Rows the trace occupies (bb `num_rows`); the rest of the fixed size is padding.
    pub num_rows: usize,
}

impl EccvmPolys {
    pub fn zero(size: usize) -> Self {
        Self { cols: (0..NUM_ALL_ENTITIES).map(|_| Polynomial::zero(size)).collect(), num_rows: size }
    }
    pub fn size(&self) -> usize {
        self.cols[0].len()
    }
    pub fn col(&self, e: Ent) -> &Polynomial<Fq> {
        &self.cols[e as usize]
    }
    pub fn col_mut(&mut self, e: Ent) -> &mut Polynomial<Fq> {
        &mut self.cols[e as usize]
    }
    /// All entity values at row `i` (shifted entities read row `i + 1`).
    pub fn row(&self, i: usize) -> Vec<Fq> {
        self.cols.iter().map(|c| c.coeffs[i]).collect()
    }
    /// Materialize every shifted column from its source (bb `set_shifted`).
    pub fn set_shifted(&mut self) {
        for (k, e) in TO_BE_SHIFTED.iter().enumerate() {
            self.cols[FIRST_SHIFTED + k] = self.cols[*e as usize].shifted();
        }
    }
}
