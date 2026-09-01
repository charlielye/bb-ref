//! The shared Blake2s/Blake3s mixing function `G` and round function over the BLAKE XOR-rotate
//! plookup tables (bb `stdlib/hash/blake2s/blake_util.hpp` + `hash_utils.hpp`).

use super::field::FieldT;
use super::plookup::get_lookup_accumulators;
use crate::base::field::u256;
use crate::base::Fr;
use crate::circuit::plookup::MultiTableId;

pub const BLAKE_STATE_SIZE: usize = 16;

pub const MSG_SCHEDULE_BLAKE3: [[usize; 16]; 7] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8],
    [3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1],
    [10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6],
    [12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4],
    [9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7],
    [11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13],
];

pub const MSG_SCHEDULE_BLAKE2: [[usize; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

/// bb `hash_utils::add_normalize_unsafe`: `(a + b) mod 2^32` with the (range-constrained) overflow
/// word witnessed out. "Unsafe" = the caller relies on a later lookup to range-check the result.
pub fn add_normalize_unsafe(a: &FieldT, b: &FieldT, overflow_bits: usize) -> FieldT {
    let ctx = a.ctx.clone().or_else(|| b.ctx.clone());
    // Both inputs are (possibly slightly overflowed) 32-bit words, so the field sum is the
    // integer sum.
    let sum = u256(&(a.get_value() + b.get_value()));
    let normalized_sum = sum.0[0] as u32 as u64;
    if a.is_constant() && b.is_constant() {
        return FieldT::constant(Fr::from(normalized_sum));
    }
    let overflow_value = Fr::from((sum.0[0] >> 32) | (sum.0[1] << 32));
    let overflow = FieldT::from_witness(ctx.as_ref().unwrap(), overflow_value);
    let result = a.add_two(b, &overflow.mul(&FieldT::constant(-Fr::from(1u64 << 32))));
    overflow.create_range_constraint(overflow_bits as u64);
    result
}

fn constant(v: u64) -> FieldT {
    FieldT::constant(Fr::from(v))
}

/// bb `blake_util::g`: the core mixing step — adds, XORs and right-rotates via the BLAKE tables.
pub fn g(state: &mut [FieldT; BLAKE_STATE_SIZE], a: usize, b: usize, c: usize, d: usize, x: &FieldT, y: &FieldT) {
    // a = a + b + x
    state[a] = state[a].add_two(&state[b], x);

    // d = (d ^ a).ror(16): the table's third column holds the rotated value scaled by 2^{-16}.
    let lookup_1 = get_lookup_accumulators(MultiTableId::BlakeXorRotate16, &state[d], &state[a], true);
    state[d] = lookup_1.columns[2][0].mul(&constant(1 << 16));

    // c = c + d
    state[c] = state[c].add(&state[d]);

    // b = (b ^ c).ror(12), derived from the plain XOR table: with u split into 6-bit slices,
    // ROTR_12(u) = C3[2] + (C3[0] - 2^{12}·C3[2]) · 2^{20}.
    let lookup_2 = get_lookup_accumulators(MultiTableId::BlakeXor, &state[b], &state[c], true);
    let mut lookup_output = lookup_2.columns[2][2].clone();
    let t2_term = constant(1 << 12).mul(&lookup_2.columns[2][2]);
    lookup_output = lookup_output.add(&lookup_2.columns[2][0].sub(&t2_term).mul(&constant(1 << 20)));
    state[b] = lookup_output;

    // a = a + b + y
    state[a] = add_normalize_unsafe(&state[a], &state[b].add(y), 3);

    // d = (d ^ a).ror(8)
    let lookup_3 = get_lookup_accumulators(MultiTableId::BlakeXorRotate8, &state[d], &state[a], true);
    state[d] = lookup_3.columns[2][0].mul(&constant(1 << 24));

    // c = c + d
    state[c] = add_normalize_unsafe(&state[c], &state[d], 3);

    // b = (b ^ c).ror(7)
    let lookup_4 = get_lookup_accumulators(MultiTableId::BlakeXorRotate7, &state[b], &state[c], true);
    state[b] = lookup_4.columns[2][0].mul(&constant(1 << 25));
}

/// bb `blake_util::round_fn` (`which_blake`: false → Blake2, true → Blake3).
pub fn round_fn(
    state: &mut [FieldT; BLAKE_STATE_SIZE],
    msg: &[FieldT; BLAKE_STATE_SIZE],
    round: usize,
    which_blake: bool,
) {
    let schedule = if which_blake {
        &MSG_SCHEDULE_BLAKE3[round]
    } else {
        &MSG_SCHEDULE_BLAKE2[round]
    };

    // Mix the columns.
    g(state, 0, 4, 8, 12, &msg[schedule[0]].clone(), &msg[schedule[1]].clone());
    g(state, 1, 5, 9, 13, &msg[schedule[2]].clone(), &msg[schedule[3]].clone());
    g(
        state,
        2,
        6,
        10,
        14,
        &msg[schedule[4]].clone(),
        &msg[schedule[5]].clone(),
    );
    g(
        state,
        3,
        7,
        11,
        15,
        &msg[schedule[6]].clone(),
        &msg[schedule[7]].clone(),
    );

    // Mix the rows.
    g(
        state,
        0,
        5,
        10,
        15,
        &msg[schedule[8]].clone(),
        &msg[schedule[9]].clone(),
    );
    g(
        state,
        1,
        6,
        11,
        12,
        &msg[schedule[10]].clone(),
        &msg[schedule[11]].clone(),
    );
    g(
        state,
        2,
        7,
        8,
        13,
        &msg[schedule[12]].clone(),
        &msg[schedule[13]].clone(),
    );
    g(
        state,
        3,
        4,
        9,
        14,
        &msg[schedule[14]].clone(),
        &msg[schedule[15]].clone(),
    );
}
