//! In-circuit Blake3 (bb `stdlib/hash/blake3s/blake3s.cpp`), single-chunk (≤ 1024 bytes): the
//! Blake2 mixing core with Blake3's schedule, flags and output XOF.

use super::blake_util::{self, BLAKE_STATE_SIZE};
use super::byte_array::ByteArray;
use super::field::FieldT;
use super::plookup::get_lookup_accumulators;
use crate::base::Fr;
use crate::circuit::plookup::MultiTableId::BlakeXor;

const IV: [u64; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

const CHUNK_START: u8 = 1 << 0;
const CHUNK_END: u8 = 1 << 1;
const ROOT: u8 = 1 << 3;

const BLAKE3_OUT_LEN: usize = 32;
const BLAKE3_BLOCK_LEN: usize = 64;
const BLAKE3_CHUNK_LEN: usize = 1024;
const BLAKE3_CV_WORDS: usize = 8;

fn constant(v: u64) -> FieldT {
    FieldT::constant(Fr::from(v))
}

struct Blake3Hasher {
    cv: [FieldT; BLAKE3_CV_WORDS],
    buf: ByteArray,
    buf_len: usize,
    blocks_compressed: u8,
    flags: u8,
}

fn maybe_start_flag(hasher: &Blake3Hasher) -> u8 {
    if hasher.blocks_compressed == 0 {
        CHUNK_START
    } else {
        0
    }
}

fn compress_pre(
    cv: &[FieldT; BLAKE3_CV_WORDS],
    block: &ByteArray,
    block_len: u8,
    flags: u8,
) -> [FieldT; BLAKE_STATE_SIZE] {
    let block_words: [FieldT; BLAKE_STATE_SIZE] = std::array::from_fn(|i| block.slice(i * 4, 4).reverse().to_field());
    let mut state: [FieldT; BLAKE_STATE_SIZE] = std::array::from_fn(|i| match i {
        0..=7 => cv[i].clone(),
        8..=11 => constant(IV[i - 8]),
        12 | 13 => constant(0),
        14 => constant(block_len as u64),
        _ => constant(flags as u64),
    });
    for round in 0..7 {
        blake_util::round_fn(&mut state, &block_words, round, true);
    }
    state
}

fn compress_in_place(cv: &mut [FieldT; BLAKE3_CV_WORDS], block: &ByteArray, block_len: u8, flags: u8) {
    let state = compress_pre(cv, block, block_len, flags);
    // A malicious prover could overflow rows of the state; the XOR reads constrain the outputs to
    // 32 bits, so the overflow is harmless.
    for i in 0..(BLAKE_STATE_SIZE >> 1) {
        let lookup = get_lookup_accumulators(BlakeXor, &state[i], &state[i + 8], true);
        cv[i] = lookup.columns[2][0].clone();
    }
}

fn compress_xof(cv: &[FieldT; BLAKE3_CV_WORDS], block: &ByteArray, block_len: u8, flags: u8, out: &mut ByteArray) {
    let state = compress_pre(cv, block, block_len, flags);
    for i in 0..(BLAKE_STATE_SIZE >> 1) {
        let lookup_1 = get_lookup_accumulators(BlakeXor, &state[i], &state[i + 8], true);
        out.write_at(&ByteArray::from_field(&lookup_1.columns[2][0], 4).reverse(), i * 4);
        let lookup_2 = get_lookup_accumulators(BlakeXor, &state[i + 8], &cv[i], true);
        out.write_at(
            &ByteArray::from_field(&lookup_2.columns[2][0], 4).reverse(),
            (i + 8) * 4,
        );
    }
}

fn hasher_update(hasher: &mut Blake3Hasher, input: &ByteArray) {
    let mut input_len = input.len();
    if input_len == 0 {
        return;
    }
    let mut start_counter = 0;
    while input_len > BLAKE3_BLOCK_LEN {
        let flags = hasher.flags | maybe_start_flag(hasher);
        let mut cv = hasher.cv.clone();
        compress_in_place(
            &mut cv,
            &input.slice(start_counter, BLAKE3_BLOCK_LEN),
            BLAKE3_BLOCK_LEN as u8,
            flags,
        );
        hasher.cv = cv;
        hasher.blocks_compressed += 1;
        start_counter += BLAKE3_BLOCK_LEN;
        input_len -= BLAKE3_BLOCK_LEN;
    }
    let take = (BLAKE3_BLOCK_LEN - hasher.buf_len).min(input_len);
    let input_slice = input.slice(start_counter, take);
    hasher.buf.write_at(&input_slice, hasher.buf_len);
    hasher.buf_len += take;
}

fn hasher_finalize(hasher: &Blake3Hasher) -> ByteArray {
    let block_flags = hasher.flags | maybe_start_flag(hasher) | CHUNK_END;
    let mut wide_buf = ByteArray::constant_padding(BLAKE3_BLOCK_LEN, 0);
    compress_xof(
        &hasher.cv,
        &hasher.buf,
        hasher.buf_len as u8,
        block_flags | ROOT,
        &mut wide_buf,
    );
    wide_buf.slice(0, BLAKE3_OUT_LEN)
}

/// bb `Blake3s::hash`: 32-byte digest of `input` (≤ 1024 bytes).
pub fn hash(input: &ByteArray) -> ByteArray {
    assert!(
        input.len() <= BLAKE3_CHUNK_LEN,
        "blake3 inputs are capped at 1024 bytes"
    );
    let mut hasher = Blake3Hasher {
        cv: std::array::from_fn(|i| constant(IV[i])),
        buf: ByteArray::constant_padding(BLAKE3_BLOCK_LEN, 0),
        buf_len: 0,
        blocks_compressed: 0,
        flags: 0,
    };
    hasher_update(&mut hasher, input);
    hasher_finalize(&hasher)
}
