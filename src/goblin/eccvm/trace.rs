//! ECCVM trace construction (bb `eccvm_circuit_builder.hpp`, `transcript_builder.hpp`,
//! `precomputed_tables_builder.hpp`, `msm_builder.hpp`, and `ECCVMFlavor::ProverPolynomials`).

use super::*;
use crate::base::field::{from_hex, from_u256, u256_shr, FieldLike, U256};
use crate::base::{Fr, G1Affine};
use crate::circuit::op_queue::{EccOpQueue, EccvmOp};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{AdditiveGroup, BigInteger, Zero};
use std::sync::OnceLock;

type Proj = ark_bn254::G1Projective;

/// bb `ECCVM_OFFSET_GENERATOR` (unscaled): the MSM accumulator's starting point.
pub fn offset_generator_base() -> G1Affine {
    G1Affine::new_unchecked(
        from_hex("0x2728608c9bfb52035a3f2f1d18e4c604d4da7611b3e265566265e9b7d36642b2"),
        from_hex("0x0451a4da5a6303859c4755dac222ae1d164db7ca52a19321f46a7b88a64f7742"),
    )
}

/// `2^124 · base`: the offset the transcript adds to every MSM output.
pub fn offset_generator() -> G1Affine {
    static P: OnceLock<G1Affine> = OnceLock::new();
    *P.get_or_init(|| (offset_generator_base() * Fr::from(2u64).pow_u64(124)).into_affine())
}

/// The cube root of unity `β` in Fq of the GLV endomorphism `(x, y) ↦ (βx, y)` (bb stores it in
/// Montgomery form).
pub fn fq_cube_root_of_unity() -> Fq {
    static B: OnceLock<Fq> = OnceLock::new();
    *B.get_or_init(|| {
        let mont: Fq = from_u256(U256::new([0x71930c11d782e155, 0xa6bb947cffbe3323, 0xaa303344d4741444, 0x2c3b3f0d26594943]));
        mont * Fq::from(2u64).pow_u64(256).invert()
    })
}

fn xy(p: &Proj) -> (Fq, Fq) {
    if p.is_zero() {
        (Fq::from(0u64), Fq::from(0u64))
    } else {
        let a = p.into_affine();
        (a.x, a.y)
    }
}

fn affine_xy(p: &G1Affine) -> (Fq, Fq) {
    if p.is_zero() {
        (Fq::from(0u64), Fq::from(0u64))
    } else {
        (p.x, p.y)
    }
}

/// One 128-bit scalar multiplication of the VM (bb `eccvm::ScalarMul`).
#[derive(Clone)]
pub struct ScalarMul {
    pub pc: u32,
    pub scalar: U256,
    pub base_point: G1Affine,
    pub wnaf_digits: [i32; NUM_WNAF_DIGITS_PER_SCALAR],
    pub wnaf_skew: bool,
    /// `[-15P, -13P, ..., -P, P, 3P, ..., 15P, 2P]`
    pub precomputed_table: [G1Affine; POINT_TABLE_SIZE + 1],
}

fn compute_precomputed_table(base: &G1Affine) -> [G1Affine; POINT_TABLE_SIZE + 1] {
    let d2 = base.into_group().double();
    let mut table = vec![Proj::zero(); POINT_TABLE_SIZE + 1];
    table[POINT_TABLE_SIZE] = d2;
    table[POINT_TABLE_SIZE / 2] = base.into_group();
    for i in 1..POINT_TABLE_SIZE / 2 {
        table[i + POINT_TABLE_SIZE / 2] = table[i + POINT_TABLE_SIZE / 2 - 1] + d2;
    }
    for i in 0..POINT_TABLE_SIZE / 2 {
        table[i] = -table[POINT_TABLE_SIZE - 1 - i];
    }
    let affine = Proj::normalize_batch(&table);
    std::array::from_fn(|i| affine[i])
}

/// Base-16 wNAF digits `[a_31, ..., a_0]`, each odd in `[-15, 15]`; even scalars carry a skew.
fn compute_wnaf_digits(mut scalar: U256) -> [i32; NUM_WNAF_DIGITS_PER_SCALAR] {
    let mut output = [0i32; NUM_WNAF_DIGITS_PER_SCALAR];
    let mut previous_slice = 0i32;
    for i in 0..NUM_WNAF_DIGITS_PER_SCALAR {
        let raw_slice = scalar.0[0] & 15;
        let is_even = raw_slice & 1 == 0;
        let mut wnaf_slice = raw_slice as i32;
        if i == 0 && is_even {
            wnaf_slice += 1;
        } else if is_even {
            previous_slice -= 1 << NUM_WNAF_DIGIT_BITS;
            wnaf_slice += 1;
        }
        if i > 0 {
            output[NUM_WNAF_DIGITS_PER_SCALAR - (i - 1) - 1] = previous_slice;
        }
        previous_slice = wnaf_slice;
        scalar = u256_shr(scalar, NUM_WNAF_DIGIT_BITS);
    }
    assert!(scalar.is_zero(), "ECCVM scalars are at most 128 bits");
    output[0] = previous_slice;
    output
}

/// Number of active 128-bit muls contributed by an op (bb counts z1, z2 that are non-zero on a
/// finite base point).
fn num_muls(op: &EccvmOp) -> u32 {
    if !op.op_code.mul || op.base_point.is_zero() {
        return 0;
    }
    (!op.z1.is_zero()) as u32 + (!op.z2.is_zero()) as u32
}

pub fn total_number_of_muls(ops: &[EccvmOp]) -> u32 {
    ops.iter().map(num_muls).sum()
}

/// bb `ECCVMCircuitBuilder::get_msms`: consecutive mul ops form one MSM; `pc` counts down from
/// the total number of muls.
pub fn get_msms(ops: &[EccvmOp]) -> Vec<Vec<ScalarMul>> {
    let mut msms: Vec<Vec<ScalarMul>> = vec![];
    let mut active: Vec<ScalarMul> = vec![];
    let make = |scalar: U256, base_point: G1Affine| ScalarMul {
        pc: 0,
        scalar,
        base_point,
        wnaf_digits: compute_wnaf_digits(scalar),
        wnaf_skew: scalar.0[0] & 1 == 0,
        precomputed_table: compute_precomputed_table(&base_point),
    };
    for op in ops {
        if op.op_code.mul {
            if num_muls(op) > 0 {
                if !op.z1.is_zero() {
                    active.push(make(op.z1, op.base_point));
                }
                if !op.z2.is_zero() {
                    let endo = G1Affine::new_unchecked(op.base_point.x * fq_cube_root_of_unity(), -op.base_point.y);
                    active.push(make(op.z2, endo));
                }
            }
        } else if !active.is_empty() {
            msms.push(std::mem::take(&mut active));
        }
    }
    if !active.is_empty() {
        msms.push(active);
    }
    let mut pc = total_number_of_muls(ops);
    for msm in &mut msms {
        for mul in msm {
            mul.pc = pc;
            pc -= 1;
        }
    }
    assert_eq!(pc, 0);
    msms
}

/// Rows of the MSM table used by one MSM of `size` points (bb `EccvmRowTracker::num_eccvm_msm_rows`).
pub fn num_msm_rows(size: usize) -> usize {
    let rows_per_digit = size.div_ceil(ADDITIONS_PER_ROW);
    (NUM_WNAF_DIGITS_PER_SCALAR + 1) * rows_per_digit + (NUM_WNAF_DIGITS_PER_SCALAR - 1)
}

// ---------------------------------------------------------------------------------------------
// Transcript rows
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Default)]
pub struct TranscriptRow {
    pub msm_infinity: bool,
    pub accumulator_not_empty: bool,
    pub q_add: bool,
    pub q_mul: bool,
    pub q_eq: bool,
    pub q_reset: bool,
    pub msm_transition: bool,
    pub pc: u32,
    pub msm_count: u32,
    pub msm_count_zero_at_transition: bool,
    pub base_x: Fq,
    pub base_y: Fq,
    pub base_infinity: bool,
    pub z1: Fq,
    pub z2: Fq,
    pub z1_zero: bool,
    pub z2_zero: bool,
    pub opcode: u32,
    pub accumulator_x: Fq,
    pub accumulator_y: Fq,
    pub msm_output_x: Fq,
    pub msm_output_y: Fq,
    pub msm_intermediate_x: Fq,
    pub msm_intermediate_y: Fq,
    pub add_x_equal: bool,
    pub add_y_equal: bool,
    pub base_x_inverse: Fq,
    pub base_y_inverse: Fq,
    pub add_lambda: Fq,
    pub msm_x_inverse: Fq,
    pub msm_count_at_transition_inverse: Fq,
}

#[derive(Clone)]
struct VmState {
    pc: u32,
    count: u32,
    accumulator: Proj,
    msm_accumulator: Proj,
    is_accumulator_empty: bool,
}

fn invert_or_zero(v: Fq) -> Fq {
    if Zero::is_zero(&v) {
        v
    } else {
        v.invert()
    }
}

/// bb `ECCVMTranscriptBuilder::compute_rows`; `ops[0]` is the hiding op.
pub fn compute_transcript_rows(ops: &[EccvmOp], total_muls: u32) -> Vec<TranscriptRow> {
    let n = ops.len();
    let offset = offset_generator().into_group();
    let mut rows = vec![TranscriptRow::default(); n + 2];
    let mut state = VmState { pc: total_muls, count: 0, accumulator: Proj::zero(), msm_accumulator: offset, is_accumulator_empty: true };

    let mut acc_trace = vec![Proj::zero(); n];
    let mut msm_acc_trace = vec![Proj::zero(); n];
    let mut intermediate_trace = vec![Proj::zero(); n];
    let mut count_inverse = vec![Fq::from(0u64); n];
    {
        let hiding = &ops[0];
        let row = &mut rows[1];
        (row.base_x, row.base_y) = affine_xy(&hiding.base_point);
        row.q_eq = hiding.op_code.eq;
        row.q_reset = hiding.op_code.reset;
        row.opcode = hiding.op_code.value();
        row.pc = state.pc;
    }
    for i in 1..n {
        let entry = &ops[i];
        let mut updated = state.clone();
        let is_mul = entry.op_code.mul;
        let is_add = entry.op_code.add;
        let z1_zero = if is_mul { entry.z1.is_zero() } else { true };
        let z2_zero = if is_mul { entry.z2.is_zero() } else { true };
        let base_infinity = entry.base_point.is_zero();
        let muls = num_muls(entry);
        updated.pc = state.pc - muls;
        if entry.op_code.reset || entry.op_code.value() == 0 {
            updated.is_accumulator_empty = true;
            updated.accumulator = Proj::zero();
            updated.msm_accumulator = offset;
        }
        let last_row = i == n - 1;
        let next_not_msm = last_row || !ops[i + 1].op_code.mul;
        let is_msm_transition = is_mul && next_not_msm && state.count + muls > 0;
        let current_ongoing_msm = is_mul && !next_not_msm;
        updated.count = if current_ongoing_msm { state.count + muls } else { 0 };
        if is_mul {
            updated.msm_accumulator = state.msm_accumulator + entry.base_point * entry.mul_scalar_full;
        }
        let row = &mut rows[i + 1];
        if is_msm_transition {
            updated.accumulator = if state.is_accumulator_empty { updated.msm_accumulator - offset } else { state.accumulator + updated.msm_accumulator - offset };
            updated.is_accumulator_empty = updated.accumulator.is_zero();
            row.msm_infinity = (updated.msm_accumulator - offset).is_zero();
        }
        if is_add {
            updated.accumulator = if state.is_accumulator_empty { entry.base_point.into_group() } else { state.accumulator + entry.base_point };
            updated.is_accumulator_empty = updated.accumulator.is_zero();
        }
        let active = entry.op_code.add || entry.op_code.mul || entry.op_code.eq;
        row.accumulator_not_empty = !state.is_accumulator_empty;
        row.q_add = entry.op_code.add;
        row.q_mul = entry.op_code.mul;
        row.q_eq = entry.op_code.eq;
        row.q_reset = entry.op_code.reset;
        row.msm_transition = is_msm_transition;
        row.pc = state.pc;
        row.msm_count = state.count;
        row.msm_count_zero_at_transition = state.count + muls == 0 && entry.op_code.mul && next_not_msm;
        (row.base_x, row.base_y) = if active && !base_infinity { affine_xy(&entry.base_point) } else { (Fq::from(0u64), Fq::from(0u64)) };
        row.base_infinity = active && base_infinity;
        row.z1 = if entry.op_code.mul { from_u256(entry.z1) } else { Fq::from(0u64) };
        row.z2 = if entry.op_code.mul { from_u256(entry.z2) } else { Fq::from(0u64) };
        row.z1_zero = entry.z1.is_zero();
        row.z2_zero = entry.z2.is_zero();
        row.opcode = entry.op_code.value();
        let _ = (z1_zero, z2_zero);

        count_inverse[i] = if state.count + muls == 0 { Fq::from(0u64) } else { Fq::from((state.count + muls) as u64) };
        acc_trace[i] = state.accumulator;
        msm_acc_trace[i] = if is_msm_transition { updated.msm_accumulator } else { Proj::zero() };
        intermediate_trace[i] = if is_msm_transition { updated.msm_accumulator - offset } else { Proj::zero() };
        state = updated;
        if is_mul && next_not_msm {
            state.msm_accumulator = offset;
        }
    }
    for i in 0..n {
        let row = &mut rows[i + 1];
        if !acc_trace[i].is_zero() {
            (row.accumulator_x, row.accumulator_y) = xy(&acc_trace[i]);
        }
        if !msm_acc_trace[i].is_zero() {
            (row.msm_output_x, row.msm_output_y) = xy(&msm_acc_trace[i]);
        }
        if !intermediate_trace[i].is_zero() {
            (row.msm_intermediate_x, row.msm_intermediate_y) = xy(&intermediate_trace[i]);
        }
    }
    let offset_x = offset_generator().x;
    for i in 0..n {
        let row = &mut rows[i + 1];
        let is_msm_transition = row.msm_transition;
        let is_add = ops[i].op_code.add;
        if !(is_msm_transition || is_add) {
            count_inverse[i] = Fq::from(0u64);
            continue;
        }
        row.msm_x_inverse = if row.msm_infinity || msm_acc_trace[i].is_zero() { Fq::from(0u64) } else { xy(&msm_acc_trace[i]).0 - offset_x };
        let (lhs_x, lhs_y) = if is_msm_transition { xy(&intermediate_trace[i]) } else { (row.base_x, row.base_y) };
        let (rhs_x, rhs_y) = xy(&acc_trace[i]);
        row.base_x_inverse = invert_or_zero(lhs_x - rhs_x);
        row.base_y_inverse = invert_or_zero(lhs_y - rhs_y);
        row.msm_x_inverse = invert_or_zero(row.msm_x_inverse);

        let vm_point = if is_add { ops[i].base_point.into_group() } else { intermediate_trace[i] };
        let vm_infinity = vm_point.is_zero();
        let acc_infinity = acc_trace[i].is_zero();
        let (vm_x, vm_y) = xy(&vm_point);
        let (acc_x, acc_y) = xy(&acc_trace[i]);
        row.add_x_equal = vm_x == acc_x || (vm_infinity && acc_infinity);
        row.add_y_equal = vm_y == acc_y || (vm_infinity && acc_infinity);
        let (numerator, denominator) = if acc_x == vm_x && acc_y == vm_y && !vm_infinity && !acc_infinity {
            (vm_x * vm_x * Fq::from(3u64), vm_y + vm_y)
        } else if acc_x != vm_x && !vm_infinity && !acc_infinity {
            (acc_y - vm_y, acc_x - vm_x)
        } else {
            (Fq::from(0u64), Fq::from(0u64))
        };
        row.add_lambda = numerator * invert_or_zero(denominator);
    }
    for i in 0..n {
        rows[i + 1].msm_count_at_transition_inverse = invert_or_zero(count_inverse[i]);
    }
    let last = rows.last_mut().unwrap();
    last.pc = state.pc;
    (last.accumulator_x, last.accumulator_y) = xy(&state.accumulator);
    last.accumulator_not_empty = !state.is_accumulator_empty;
    rows
}

// ---------------------------------------------------------------------------------------------
// Point table precomputation rows
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Default)]
pub struct PrecomputeRow {
    pub s: [i32; 8],
    pub skew: bool,
    pub point_transition: bool,
    pub pc: u32,
    pub round: u32,
    pub scalar_sum: u128,
    pub precompute_accumulator: (Fq, Fq),
    pub precompute_double: (Fq, Fq),
}

/// bb `ECCVMPointTablePrecomputationBuilder::compute_rows`: 8 rows per scalar mul, one per 4 wNAF digits.
pub fn compute_precompute_rows(muls: &[ScalarMul]) -> Vec<PrecomputeRow> {
    const ROWS_PER_SCALAR: usize = NUM_WNAF_DIGITS_PER_SCALAR / WNAF_DIGITS_PER_ROW;
    let mut rows = vec![PrecomputeRow::default(); ROWS_PER_SCALAR * muls.len() + 1];
    for (j, entry) in muls.iter().enumerate() {
        let slices = &entry.wnaf_digits;
        let mut scalar_sum: i128 = 0;
        for i in 0..ROWS_PER_SCALAR {
            let mut row = PrecomputeRow::default();
            let d = [slices[i * 4], slices[i * 4 + 1], slices[i * 4 + 2], slices[i * 4 + 3]];
            for k in 0..4 {
                let base2 = (d[k] + 15) / 2;
                row.s[2 * k] = base2 >> 2;
                row.s[2 * k + 1] = base2 & 3;
            }
            let last_row = i == ROWS_PER_SCALAR - 1;
            row.skew = last_row && entry.wnaf_skew;
            row.scalar_sum = scalar_sum as u128;
            let row_chunk = d[3] as i128 + (d[2] as i128) * (1 << 4) + (d[1] as i128) * (1 << 8) + (d[0] as i128) * (1 << 12);
            scalar_sum = (scalar_sum << (NUM_WNAF_DIGIT_BITS as usize * WNAF_DIGITS_PER_ROW)) + row_chunk;
            row.round = i as u32;
            row.point_transition = last_row;
            row.pc = entry.pc;
            if last_row {
                assert_eq!(entry.scalar.0[0] as u128 | ((entry.scalar.0[1] as u128) << 64), (scalar_sum - entry.wnaf_skew as i128) as u128);
            }
            row.precompute_double = affine_xy(&entry.precomputed_table[POINT_TABLE_SIZE]);
            row.precompute_accumulator = affine_xy(&entry.precomputed_table[POINT_TABLE_SIZE - 1 - i]);
            rows[j * ROWS_PER_SCALAR + i + 1] = row;
        }
    }
    rows
}

// ---------------------------------------------------------------------------------------------
// MSM rows
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Default)]
pub struct AddState {
    pub add: bool,
    pub slice: i32,
    pub point: (Fq, Fq),
    pub lambda: Fq,
    pub collision_inverse: Fq,
}

#[derive(Clone, Default)]
pub struct MsmRow {
    pub pc: u32,
    pub msm_size: u32,
    pub msm_count: u32,
    pub msm_round: u32,
    pub msm_transition: bool,
    pub q_add: bool,
    pub q_double: bool,
    pub q_skew: bool,
    pub add_state: [AddState; ADDITIONS_PER_ROW],
    pub accumulator_x: Fq,
    pub accumulator_y: Fq,
}

/// bb `ECCVMMSMMBuilder::compute_rows`: the Straus rows of every MSM plus the point-table read
/// counts (`[0]`: positive slices, `[1]`: negative slices) indexed by `8 * mul_index + table_index`.
pub fn compute_msm_rows(msms: &[Vec<ScalarMul>], total_muls: u32, num_rows: usize) -> (Vec<MsmRow>, [Vec<u64>; 2]) {
    let mut read_counts = [vec![0u64; total_muls as usize * (POINT_TABLE_SIZE / 2)], vec![0u64; total_muls as usize * (POINT_TABLE_SIZE / 2)]];
    let mut update_read_count = |point_idx: usize, slice: i32| {
        let offset = point_idx * 8;
        if slice < 0 {
            read_counts[1][offset + ((slice + 15) / 2) as usize] += 1;
        } else {
            read_counts[0][offset + ((15 - slice) / 2) as usize] += 1;
        }
    };
    let mut pc_values = vec![total_muls as usize];
    for msm in msms {
        pc_values.push(pc_values.last().unwrap() - msm.len());
    }
    assert_eq!(*pc_values.last().unwrap(), 0);
    let rows_per_digit = |size: usize| size.div_ceil(ADDITIONS_PER_ROW);
    let points_in_row = |size: usize, row_idx: usize| if (row_idx + 1) * ADDITIONS_PER_ROW > size { size % ADDITIONS_PER_ROW } else { ADDITIONS_PER_ROW };

    for (msm_idx, msm) in msms.iter().enumerate() {
        let pc = pc_values[msm_idx];
        for digit_idx in 0..NUM_WNAF_DIGITS_PER_SCALAR {
            for row_idx in 0..rows_per_digit(msm.len()) {
                for p in 0..points_in_row(msm.len(), row_idx) {
                    let point_idx = row_idx * ADDITIONS_PER_ROW + p;
                    update_read_count(total_muls as usize - pc + point_idx, msm[point_idx].wnaf_digits[digit_idx]);
                }
            }
            if digit_idx == NUM_WNAF_DIGITS_PER_SCALAR - 1 {
                for row_idx in 0..rows_per_digit(msm.len()) {
                    for p in 0..points_in_row(msm.len(), row_idx) {
                        let point_idx = row_idx * ADDITIONS_PER_ROW + p;
                        update_read_count(total_muls as usize - pc + point_idx, if msm[point_idx].wnaf_skew { -1 } else { -15 });
                    }
                }
            }
        }
    }

    let offset = offset_generator_base().into_group();
    let mut rows = vec![MsmRow::default(); num_rows];
    // Accumulator after each row (index 0: before the first MSM) and the pending slope computations.
    let mut accumulator_trace = vec![offset; num_rows - 1];
    struct Op {
        p1: Proj,
        p2: (Fq, Fq),
        is_double: bool,
    }
    let mut ops: Vec<Op> = Vec::with_capacity((num_rows - 2) * ADDITIONS_PER_ROW);
    let mut row_index = 1;
    for (msm_idx, msm) in msms.iter().enumerate() {
        let mut accumulator = offset;
        let size = msm.len();
        let start_pc = pc_values[msm_idx];
        for digit_idx in 0..NUM_WNAF_DIGITS_PER_SCALAR {
            for row_idx in 0..rows_per_digit(size) {
                let row = &mut rows[row_index];
                let offset_idx = row_idx * ADDITIONS_PER_ROW;
                row.msm_transition = digit_idx == 0 && row_idx == 0;
                for p in 0..ADDITIONS_PER_ROW {
                    let st = &mut row.add_state[p];
                    st.add = points_in_row(size, row_idx) > p;
                    let slice = if st.add { msm[offset_idx + p].wnaf_digits[digit_idx] } else { 0 };
                    st.slice = if st.add { (slice + 15) / 2 } else { 0 };
                    st.point = if st.add { affine_xy(&msm[offset_idx + p].precomputed_table[st.slice as usize]) } else { (Fq::from(0u64), Fq::from(0u64)) };
                    let p1 = accumulator;
                    if st.add {
                        accumulator += msm[offset_idx + p].precomputed_table[st.slice as usize];
                    }
                    ops.push(Op { p1, p2: st.point, is_double: false });
                }
                accumulator_trace[row_index] = accumulator;
                row.q_add = true;
                row.msm_round = digit_idx as u32;
                row.msm_size = size as u32;
                row.msm_count = offset_idx as u32;
                row.pc = start_pc as u32;
                row_index += 1;
            }
            if digit_idx < NUM_WNAF_DIGITS_PER_SCALAR - 1 {
                let row = &mut rows[row_index];
                row.msm_round = digit_idx as u32 + 1;
                row.msm_size = size as u32;
                row.q_double = true;
                row.pc = start_pc as u32;
                for _ in 0..ADDITIONS_PER_ROW {
                    let p1 = accumulator;
                    accumulator = accumulator.double();
                    ops.push(Op { p1, p2: (Fq::from(0u64), Fq::from(0u64)), is_double: true });
                }
                accumulator_trace[row_index] = accumulator;
                row_index += 1;
            } else {
                for row_idx in 0..rows_per_digit(size) {
                    let row = &mut rows[row_index];
                    let offset_idx = row_idx * ADDITIONS_PER_ROW;
                    for p in 0..ADDITIONS_PER_ROW {
                        let st = &mut row.add_state[p];
                        st.add = points_in_row(size, row_idx) > p;
                        st.slice = if st.add && msm[offset_idx + p].wnaf_skew { 7 } else { 0 };
                        st.point = if st.add { affine_xy(&msm[offset_idx + p].precomputed_table[st.slice as usize]) } else { (Fq::from(0u64), Fq::from(0u64)) };
                        let add_predicate = st.add && msm[offset_idx + p].wnaf_skew;
                        let p1 = accumulator;
                        if add_predicate {
                            accumulator += msm[offset_idx + p].precomputed_table[st.slice as usize];
                        }
                        ops.push(Op { p1, p2: st.point, is_double: false });
                    }
                    row.q_skew = true;
                    row.msm_round = digit_idx as u32 + 1;
                    row.msm_size = size as u32;
                    row.msm_count = offset_idx as u32;
                    row.pc = start_pc as u32;
                    accumulator_trace[row_index] = accumulator;
                    row_index += 1;
                }
            }
        }
    }
    assert_eq!(row_index, num_rows - 1);
    // Slopes: every op's (p1, p2) is affine by now.
    let mut op_iter = ops.iter();
    for (row_index, row) in rows.iter_mut().enumerate().take(num_rows - 1).skip(1) {
        (row.accumulator_x, row.accumulator_y) = xy(&accumulator_trace[row_index - 1]);
        let (skew_row, add_row) = (row.q_skew, row.q_add);
        for st in row.add_state.iter_mut() {
            let op = op_iter.next().unwrap();
            let (x1, y1) = xy(&op.p1);
            if op.is_double {
                let inverse = invert_or_zero(y1 + y1);
                st.lambda = (x1 + x1 + x1) * x1 * inverse;
                st.collision_inverse = Fq::from(0u64);
            } else {
                let inverse = invert_or_zero(op.p2.0 - x1);
                let active = if skew_row { st.add && st.slice == 7 } else { add_row && st.add };
                st.collision_inverse = if active { inverse } else { Fq::from(0u64) };
                st.lambda = if active { (op.p2.1 - y1) * inverse } else { Fq::from(0u64) };
            }
        }
    }
    let last = rows.last_mut().unwrap();
    last.msm_transition = true;
    (last.accumulator_x, last.accumulator_y) = xy(accumulator_trace.last().unwrap());
    (rows, read_counts)
}

// ---------------------------------------------------------------------------------------------
// Polynomials
// ---------------------------------------------------------------------------------------------

impl EccOpQueue {
    /// The ECCVM's op list: the hiding op followed by every merged subtable's ops (bb `get_eccvm_ops`).
    pub fn get_eccvm_ops(&self) -> Vec<EccvmOp> {
        let hiding = self.hiding_op.clone().expect("the hiding op must be set before building the ECCVM");
        std::iter::once(hiding).chain(self.eccvm_ops.tables.iter().flatten().cloned()).collect()
    }
}

fn b(v: bool) -> Fq {
    Fq::from(v as u64)
}

impl EccvmPolys {
    /// bb `ECCVMFlavor::ProverPolynomials(builder)` without the ZK masking rows: the full witness
    /// of the fixed-size ECCVM for the op queue's ops.
    pub fn from_op_queue(q: &EccOpQueue) -> Self {
        let ops = q.get_eccvm_ops();
        let total_muls = total_number_of_muls(&ops);
        let transcript_rows = compute_transcript_rows(&ops, total_muls);
        let msms = get_msms(&ops);
        let flattened: Vec<ScalarMul> = msms.iter().flatten().cloned().collect();
        let precompute_rows = compute_precompute_rows(&flattened);
        let num_msm_rows_total = 2 + msms.iter().map(|m| num_msm_rows(m.len())).sum::<usize>();
        let (msm_rows, read_counts) = compute_msm_rows(&msms, total_muls, num_msm_rows_total);
        let num_rows = transcript_rows.len().max(precompute_rows.len()).max(msm_rows.len()) + TRACE_OFFSET;
        assert!(num_rows <= FIXED_SIZE, "ECCVM circuit exceeds its fixed size");

        let mut polys = EccvmPolys::zero(FIXED_SIZE);
        let mut set = |e: Ent, i: usize, v: Fq| polys.cols[e as usize].coeffs[TRACE_OFFSET + i] = v;
        set(lagrange_first, 0, Fq::one());
        set(lagrange_second, 1, Fq::one());
        set(lagrange_third, 2, Fq::one());
        let round_minus_31_inv = |round: u32| if round as u64 == LAST_ADDITION_ROUND { Fq::from(0u64) } else { (Fq::from(round as u64) - Fq::from(LAST_ADDITION_ROUND)).invert() };
        for i in 0..read_counts[0].len() {
            set(lookup_read_counts_0, i + 1, Fq::from(read_counts[0][i]));
            set(lookup_read_counts_1, i + 1, Fq::from(read_counts[1][i]));
        }
        for (i, r) in transcript_rows.iter().enumerate() {
            set(transcript_accumulator_not_empty, i, b(r.accumulator_not_empty));
            set(transcript_add, i, b(r.q_add));
            set(transcript_mul, i, b(r.q_mul));
            set(transcript_eq, i, b(r.q_eq));
            set(transcript_reset_accumulator, i, b(r.q_reset));
            set(transcript_msm_transition, i, b(r.msm_transition));
            set(transcript_pc, i, Fq::from(r.pc as u64));
            set(transcript_msm_count, i, Fq::from(r.msm_count as u64));
            set(transcript_Px, i, r.base_x);
            set(transcript_Py, i, r.base_y);
            set(transcript_z1, i, r.z1);
            set(transcript_z2, i, r.z2);
            set(transcript_z1zero, i, b(r.z1_zero));
            set(transcript_z2zero, i, b(r.z2_zero));
            set(transcript_op, i, Fq::from(r.opcode as u64));
            set(transcript_accumulator_x, i, r.accumulator_x);
            set(transcript_accumulator_y, i, r.accumulator_y);
            set(transcript_msm_x, i, r.msm_output_x);
            set(transcript_msm_y, i, r.msm_output_y);
            set(transcript_base_infinity, i, b(r.base_infinity));
            set(transcript_base_x_inverse, i, r.base_x_inverse);
            set(transcript_base_y_inverse, i, r.base_y_inverse);
            set(transcript_add_x_equal, i, b(r.add_x_equal));
            set(transcript_add_y_equal, i, b(r.add_y_equal));
            set(transcript_add_lambda, i, r.add_lambda);
            set(transcript_msm_intermediate_x, i, r.msm_intermediate_x);
            set(transcript_msm_intermediate_y, i, r.msm_intermediate_y);
            set(transcript_msm_infinity, i, b(r.msm_infinity));
            set(transcript_msm_x_inverse, i, r.msm_x_inverse);
            set(transcript_msm_count_zero_at_transition, i, b(r.msm_count_zero_at_transition));
            set(transcript_msm_count_at_transition_inverse, i, r.msm_count_at_transition_inverse);
        }
        for (i, r) in precompute_rows.iter().enumerate() {
            set(precompute_select, i, b(i != 0));
            set(precompute_pc, i, Fq::from(r.pc as u64));
            set(precompute_point_transition, i, b(r.point_transition));
            set(precompute_round, i, Fq::from(r.round as u64));
            set(precompute_scalar_sum, i, Fq::from(r.scalar_sum));
            let s = |k: usize| Fq::from(r.s[k] as u64);
            set(precompute_s1hi, i, s(0));
            set(precompute_s1lo, i, s(1));
            set(precompute_s2hi, i, s(2));
            set(precompute_s2lo, i, s(3));
            set(precompute_s3hi, i, s(4));
            set(precompute_s3lo, i, s(5));
            set(precompute_s4hi, i, s(6));
            set(precompute_s4lo, i, s(7));
            set(precompute_skew, i, Fq::from(if r.skew { 7u64 } else { 0 }));
            set(precompute_dx, i, r.precompute_double.0);
            set(precompute_dy, i, r.precompute_double.1);
            set(precompute_tx, i, r.precompute_accumulator.0);
            set(precompute_ty, i, r.precompute_accumulator.1);
        }
        for (i, r) in msm_rows.iter().enumerate() {
            set(msm_transition, i, b(r.msm_transition));
            set(msm_add, i, b(r.q_add));
            set(msm_double, i, b(r.q_double));
            set(msm_skew, i, b(r.q_skew));
            set(msm_accumulator_x, i, r.accumulator_x);
            set(msm_accumulator_y, i, r.accumulator_y);
            set(msm_pc, i, Fq::from(r.pc as u64));
            set(msm_size_of_msm, i, Fq::from(r.msm_size as u64));
            set(msm_count, i, Fq::from(r.msm_count as u64));
            set(msm_round, i, Fq::from(r.msm_round as u64));
            set(msm_round_minus_31_inv, i, round_minus_31_inv(r.msm_round));
            let adds = [msm_add1, msm_add2, msm_add3, msm_add4];
            let xs = [msm_x1, msm_x2, msm_x3, msm_x4];
            let ys = [msm_y1, msm_y2, msm_y3, msm_y4];
            let cols = [msm_collision_x1, msm_collision_x2, msm_collision_x3, msm_collision_x4];
            let lambdas = [msm_lambda1, msm_lambda2, msm_lambda3, msm_lambda4];
            let slices = [msm_slice1, msm_slice2, msm_slice3, msm_slice4];
            for k in 0..ADDITIONS_PER_ROW {
                let st = &r.add_state[k];
                set(adds[k], i, b(st.add));
                set(xs[k], i, st.point.0);
                set(ys[k], i, st.point.1);
                set(cols[k], i, st.collision_inverse);
                set(lambdas[k], i, st.lambda);
                set(slices[k], i, Fq::from(st.slice as u64));
            }
        }
        polys.cols[lagrange_last as usize].coeffs[FIXED_SIZE - 1] = Fq::one();
        polys.set_shifted();
        polys
    }
}
