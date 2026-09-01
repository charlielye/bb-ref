//! In-circuit Blake2s (bb `stdlib/hash/blake2s/blake2s.cpp`): state words as `FieldT`s, XORs and
//! rotations via the BLAKE plookup tables.

use super::blake_util::{self, BLAKE_STATE_SIZE};
use super::byte_array::ByteArray;
use super::field::FieldT;
use super::plookup::get_lookup_accumulators;
use crate::base::field::u256;
use crate::base::Fr;
use crate::circuit::plookup::MultiTableId::BlakeXor;

const BLAKE2S_IV: [u64; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

/// The IV with the parameter block (digest length 32, fanout/depth 1) folded into `h_0`.
const INITIAL_H: [u64; 8] = [
    0x6b08e647, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const BLAKE2S_BLOCKBYTES: usize = 64;

struct Blake2sState {
    h: [FieldT; 8],
    t: [FieldT; 2],
    f: [FieldT; 2],
}

fn constant(v: u64) -> FieldT {
    FieldT::constant(Fr::from(v))
}

/// The counter words are circuit constants, so the 32-bit carry is computed out-of-circuit.
fn increment_counter(s: &mut Blake2sState, inc: u32) {
    assert!(s.t[0].is_constant());
    assert!(s.t[1].is_constant());
    s.t[0] = s.t[0].add(&constant(inc as u64));
    let to_inc = (u256(&s.t[0].get_value()).0[0] as u32) < inc;
    s.t[1] = s.t[1].add(&constant(to_inc as u64));
}

fn compress(s: &mut Blake2sState, input: &ByteArray) {
    let m: [FieldT; BLAKE_STATE_SIZE] = std::array::from_fn(|i| input.slice(i * 4, 4).reverse().to_field());
    let mut v: [FieldT; BLAKE_STATE_SIZE] = std::array::from_fn(|i| {
        if i < 8 {
            s.h[i].clone()
        } else {
            constant(BLAKE2S_IV[i - 8])
        }
    });

    let lookup_1 = get_lookup_accumulators(BlakeXor, &s.t[0], &constant(BLAKE2S_IV[4]), true);
    v[12] = lookup_1.columns[2][0].clone();
    let lookup_2 = get_lookup_accumulators(BlakeXor, &s.t[1], &constant(BLAKE2S_IV[5]), true);
    v[13] = lookup_2.columns[2][0].clone();
    let lookup_3 = get_lookup_accumulators(BlakeXor, &s.f[0], &constant(BLAKE2S_IV[6]), true);
    v[14] = lookup_3.columns[2][0].clone();
    let lookup_4 = get_lookup_accumulators(BlakeXor, &s.f[1], &constant(BLAKE2S_IV[7]), true);
    v[15] = lookup_4.columns[2][0].clone();

    for round in 0..10 {
        blake_util::round_fn(&mut v, &m, round, false);
    }

    // (v0..v3) and (v8..v11) may be > 2^32 here; the XOR reads below constrain the outputs to
    // 32 bits, so no explicit normalization is needed.
    for i in 0..8 {
        let lookup_a = get_lookup_accumulators(BlakeXor, &s.h[i], &v[i], true);
        let lookup_b = get_lookup_accumulators(BlakeXor, &lookup_a.columns[2][0], &v[i + 8], true);
        s.h[i] = lookup_b.columns[2][0].clone();
    }
}

fn blake2s(s: &mut Blake2sState, input: &ByteArray) {
    let mut offset = 0;
    let mut size = input.len();

    while size > BLAKE2S_BLOCKBYTES {
        increment_counter(s, BLAKE2S_BLOCKBYTES as u32);
        compress(s, &input.slice(offset, BLAKE2S_BLOCKBYTES));
        offset += BLAKE2S_BLOCKBYTES;
        size -= BLAKE2S_BLOCKBYTES;
    }

    // Last block: remaining input plus constant zero padding.
    s.f[0] = constant(u32::MAX as u64);
    let mut final_block = input.slice_from(offset);
    final_block.write(&ByteArray::constant_padding(BLAKE2S_BLOCKBYTES - size, 0));
    increment_counter(s, size as u32);
    compress(s, &final_block);
}

/// bb `Blake2s::hash`: 32-byte digest of `input`.
pub fn hash(input: &ByteArray) -> ByteArray {
    let mut s = Blake2sState {
        h: std::array::from_fn(|i| constant(INITIAL_H[i])),
        t: [constant(0), constant(0)],
        f: [constant(0), constant(0)],
    };
    blake2s(&mut s, input);
    let mut result = ByteArray::constant_padding(0, 0);
    for h in &s.h {
        result.write(&ByteArray::from_field(h, 4).reverse());
    }
    result
}
