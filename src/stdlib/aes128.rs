//! In-circuit AES-128 CBC encryption (bb `stdlib/encryption/aes128/aes128.cpp`): state bytes live
//! in sparse base-9 form so XORs become additions; the S-box, normalization and byte↔sparse
//! conversions are plookup reads.

use super::field::{Ctx, FieldT};
use super::plookup::{read_accumulators, read_from_1_to_2_table, read_pair_from_table};
use crate::base::field::u256;
use crate::base::Fr;
use crate::circuit::aes_tables::{from_sparse, sparse, SBOX};
use crate::circuit::plookup::MultiTableId::{AesInput, AesNormalize, AesSbox};

const BLOCK_SIZE: usize = 16;
const EXTENDED_KEY_LENGTH: usize = 176;
const NUM_ROUNDS: usize = 10;
const COLUMN_SIZE: usize = 4;

type BytePair = (FieldT, FieldT);

fn normalize_sparse_form(byte: &FieldT) -> FieldT {
    read_from_1_to_2_table(AesNormalize, byte)
}

fn apply_aes_sbox_map(input: &FieldT) -> BytePair {
    read_pair_from_table(AesSbox, input)
}

/// bb `convert_into_sparse_bytes`: one AES_INPUT read decomposes a 128-bit block into 16
/// sparse-form bytes (most significant byte first in the result).
fn convert_into_sparse_bytes(ctx: &Ctx, block_data: &FieldT) -> [FieldT; BLOCK_SIZE] {
    let mut block_data_copy = block_data.clone();
    if block_data.is_constant() {
        block_data_copy.convert_constant_to_fixed_witness(ctx);
    }
    let lookup = read_accumulators(AesInput, &block_data_copy);
    std::array::from_fn(|i| lookup.columns[1][BLOCK_SIZE - 1 - i].clone())
}

/// bb `convert_from_sparse_bytes`: witness the packed byte value and constrain it against a fresh
/// AES_INPUT decomposition.
fn convert_from_sparse_bytes(ctx: &Ctx, sparse_bytes: &mut [FieldT]) -> FieldT {
    let mut accumulator = Fr::from(0u64);
    for sparse_byte in sparse_bytes.iter() {
        let byte = from_sparse(u256(&sparse_byte.get_value()).0[0]);
        accumulator = accumulator * Fr::from(256u64) + Fr::from(byte as u64);
    }
    let result = FieldT::from_witness(ctx, accumulator);
    let lookup = read_accumulators(AesInput, &result);
    for i in 0..BLOCK_SIZE {
        sparse_bytes[BLOCK_SIZE - 1 - i].assert_equal(&lookup.columns[1][i]);
    }
    result
}

/// bb `expand_key` (FIPS 197 §5.2): 11 round keys as 176 sparse-form bytes, with digit-count
/// bookkeeping deciding when a byte is renormalized.
fn expand_key(ctx: &Ctx, key: &FieldT) -> [FieldT; EXTENDED_KEY_LENGTH] {
    const ROUND_CONSTANTS: [u8; 11] = [0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];
    let sparse_round_constants: [FieldT; 11] =
        std::array::from_fn(|i| FieldT::constant(Fr::from(sparse(ROUND_CONSTANTS[i]))));

    let sparse_key = convert_into_sparse_bytes(ctx, key);
    let mut round_key: [FieldT; EXTENDED_KEY_LENGTH] = std::array::from_fn(|_| FieldT::constant(Fr::from(0u64)));
    let mut add_counts = [1u64; EXTENDED_KEY_LENGTH];

    round_key[..16].clone_from_slice(&sparse_key);

    for i in 4..44 {
        let k = (i - 1) * 4;
        let mut temp_add_counts = [add_counts[k], add_counts[k + 1], add_counts[k + 2], add_counts[k + 3]];
        let mut temp = [
            round_key[k].clone(),
            round_key[k + 1].clone(),
            round_key[k + 2].clone(),
            round_key[k + 3].clone(),
        ];

        if i & 0x03 == 0 {
            temp.rotate_left(1);
            temp[0] = apply_aes_sbox_map(&temp[0]).0;
            temp[1] = apply_aes_sbox_map(&temp[1]).0;
            temp[2] = apply_aes_sbox_map(&temp[2]).0;
            temp[3] = apply_aes_sbox_map(&temp[3]).0;
            temp[0] = temp[0].add(&sparse_round_constants[i >> 2]);
            temp_add_counts[0] += 1;
        }

        let j = i * 4;
        let k = (i - 4) * 4;
        for c in 0..4 {
            round_key[j + c] = round_key[k + c].add(&temp[c]);
            add_counts[j + c] = add_counts[k + c] + temp_add_counts[c];
        }

        const TARGET: u64 = 3;
        for c in 0..4 {
            let byte_index = j + c;
            if add_counts[byte_index] > TARGET || (add_counts[byte_index] > 1 && (byte_index & 12) == 12) {
                round_key[byte_index] = normalize_sparse_form(&round_key[byte_index]);
                add_counts[byte_index] = 1;
            }
        }
    }
    round_key
}

/// FIPS 197 §5.1.2: circular right shift of matrix row `i` by `i`.
fn shift_rows(state: &mut [BytePair]) {
    let temp = state[1].clone();
    state[1] = state[5].clone();
    state[5] = state[9].clone();
    state[9] = state[13].clone();
    state[13] = temp;

    state.swap(2, 10);
    state.swap(6, 14);

    let temp = state[3].clone();
    state[3] = state[15].clone();
    state[15] = state[11].clone();
    state[11] = state[7].clone();
    state[7] = temp;
}

/// FIPS 197 §5.1.3–5.1.4: `(2 3 1 1)`-matrix column mix plus the round key, on sparse S-box pairs
/// `(S(x), 3·S(x))`, using `2·x = 3·x ⊕ x`.
fn mix_column_and_add_round_key(column_pairs: &mut [BytePair], round_key: &[FieldT], round: usize, column: usize) {
    let t0 = column_pairs[0].0.add_two(&column_pairs[3].0, &column_pairs[1].1);
    let t1 = column_pairs[1].0.add_two(&column_pairs[2].0, &column_pairs[3].1);

    let r0 = t0.add_two(&column_pairs[2].0, &column_pairs[0].1);
    let r1 = t0.add_two(&column_pairs[1].0, &column_pairs[2].1);
    let r2 = t1.add_two(&column_pairs[0].0, &column_pairs[2].1);
    let r3 = t1.add_two(&column_pairs[0].1, &column_pairs[3].0);

    let key_offset = round * BLOCK_SIZE + column * COLUMN_SIZE;
    column_pairs[0].0 = r0.add(&round_key[key_offset]);
    column_pairs[1].0 = r1.add(&round_key[key_offset + 1]);
    column_pairs[2].0 = r2.add(&round_key[key_offset + 2]);
    column_pairs[3].0 = r3.add(&round_key[key_offset + 3]);
}

fn mix_columns_and_add_round_key(state_pairs: &mut [BytePair], round_key: &[FieldT], round: usize) {
    for column in 0..4 {
        mix_column_and_add_round_key(
            &mut state_pairs[column * COLUMN_SIZE..(column + 1) * COLUMN_SIZE],
            round_key,
            round,
            column,
        );
    }
}

fn sub_bytes(state_pairs: &mut [BytePair]) {
    for pair in state_pairs.iter_mut() {
        *pair = apply_aes_sbox_map(&pair.0);
    }
}

fn add_round_key(sparse_state: &mut [BytePair], sparse_round_key: &[FieldT], round: usize) {
    let key_offset = round * BLOCK_SIZE;
    for i in (0..BLOCK_SIZE).step_by(COLUMN_SIZE) {
        for j in 0..COLUMN_SIZE {
            sparse_state[i + j].0 = sparse_state[i + j].0.add(&sparse_round_key[key_offset + i + j]);
        }
    }
}

fn xor_with_iv(state: &mut [BytePair], iv: &[FieldT]) {
    for i in 0..BLOCK_SIZE {
        state[i].0 = state[i].0.add(&iv[i]);
    }
}

fn aes128_cipher(state: &mut [BytePair], sparse_round_key: &[FieldT]) {
    add_round_key(state, sparse_round_key, 0);
    for pair in state.iter_mut() {
        pair.0 = normalize_sparse_form(&pair.0);
    }

    for round in 1..NUM_ROUNDS {
        sub_bytes(state);
        shift_rows(state);
        mix_columns_and_add_round_key(state, sparse_round_key, round);
        for pair in state.iter_mut() {
            pair.0 = normalize_sparse_form(&pair.0);
        }
    }

    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, sparse_round_key, NUM_ROUNDS);
}

/// Native AES-128 CBC (FIPS 197 + CBC chaining), for the all-constants path and witness values.
fn native_cbc(input: &mut [u8], iv: &[u8; 16], key: &[u8; 16]) {
    let xtime = |a: u8| (a << 1) ^ (((a >> 7) & 1) * 0x1b);
    // Key schedule.
    let mut w = [0u8; EXTENDED_KEY_LENGTH];
    w[..16].copy_from_slice(key);
    const RCON: [u8; 11] = [0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];
    for i in 4..44 {
        let mut t = [
            w[(i - 1) * 4],
            w[(i - 1) * 4 + 1],
            w[(i - 1) * 4 + 2],
            w[(i - 1) * 4 + 3],
        ];
        if i % 4 == 0 {
            t.rotate_left(1);
            for b in t.iter_mut() {
                *b = SBOX[*b as usize];
            }
            t[0] ^= RCON[i / 4];
        }
        for c in 0..4 {
            w[i * 4 + c] = w[(i - 4) * 4 + c] ^ t[c];
        }
    }
    let mut chain = *iv;
    for block in input.chunks_mut(16) {
        let mut s = [0u8; 16];
        for i in 0..16 {
            s[i] = block[i] ^ chain[i] ^ w[i];
        }
        for round in 1..=10 {
            for b in s.iter_mut() {
                *b = SBOX[*b as usize];
            }
            // shift_rows on the column-major state layout.
            let t = s[1];
            s[1] = s[5];
            s[5] = s[9];
            s[9] = s[13];
            s[13] = t;
            s.swap(2, 10);
            s.swap(6, 14);
            let t = s[3];
            s[3] = s[15];
            s[15] = s[11];
            s[11] = s[7];
            s[7] = t;
            if round != 10 {
                for c in 0..4 {
                    let col: [u8; 4] = s[c * 4..c * 4 + 4].try_into().unwrap();
                    let all = col[0] ^ col[1] ^ col[2] ^ col[3];
                    for r in 0..4 {
                        s[c * 4 + r] = col[r] ^ all ^ xtime(col[r] ^ col[(r + 1) % 4]);
                    }
                }
            }
            for i in 0..16 {
                s[i] ^= w[round * 16 + i];
            }
        }
        block.copy_from_slice(&s);
        chain = s;
    }
}

fn block_bytes(v: &FieldT) -> [u8; 16] {
    let value = u256(&v.get_value());
    std::array::from_fn(|i| ((value >> (8 * (15 - i)) as u32).0[0] & 0xff) as u8)
}

/// bb `aes128::encrypt_buffer_cbc`: CBC encryption of 16-byte blocks packed big-endian into
/// field elements.
pub fn encrypt_buffer_cbc(input: &[FieldT], iv: &FieldT, key: &FieldT) -> Vec<FieldT> {
    let all_constants = key.is_constant() && iv.is_constant() && input.iter().all(|b| b.is_constant());
    if all_constants {
        let mut bytes: Vec<u8> = input.iter().flat_map(|b| block_bytes(b)).collect();
        native_cbc(&mut bytes, &block_bytes(iv), &block_bytes(key));
        return bytes
            .chunks(16)
            .map(|block| {
                let mut v = Fr::from(0u64);
                for byte in block {
                    v = v * Fr::from(256u64) + Fr::from(*byte as u64);
                }
                FieldT::constant(v)
            })
            .collect();
    }

    let ctx = key
        .ctx
        .clone()
        .or_else(|| iv.ctx.clone())
        .or_else(|| input.iter().find_map(|b| b.ctx.clone()))
        .expect("aes128 with no witness inputs");

    let round_key = expand_key(&ctx, key);
    let num_blocks = input.len();

    let mut sparse_state: Vec<BytePair> = Vec::with_capacity(num_blocks * BLOCK_SIZE);
    for block in input {
        for byte in convert_into_sparse_bytes(&ctx, block) {
            sparse_state.push((byte, FieldT::constant(Fr::from(0u64))));
        }
    }

    let mut sparse_iv = convert_into_sparse_bytes(&ctx, iv);

    for i in 0..num_blocks {
        let round_state = &mut sparse_state[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE];
        xor_with_iv(round_state, &sparse_iv);
        aes128_cipher(round_state, &round_key);
        for j in 0..BLOCK_SIZE {
            sparse_iv[j] = round_state[j].0.clone();
        }
    }

    let mut sparse_output: Vec<FieldT> = sparse_state.iter().map(|pair| normalize_sparse_form(&pair.0)).collect();

    (0..num_blocks)
        .map(|i| convert_from_sparse_bytes(&ctx, &mut sparse_output[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE]))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::{Builder, EccOpQueue};
    use num_bigint::BigUint;
    use std::cell::RefCell;
    use std::rc::Rc;

    fn block(ctx: &Ctx, hex: &str) -> FieldT {
        FieldT::from_witness(ctx, Fr::from(BigUint::parse_bytes(hex.as_bytes(), 16).unwrap()))
    }

    /// NIST SP 800-38A F.2.1 (CBC-AES128, first block) — the value pin against the standard.
    #[test]
    fn matches_nist_cbc_kat() {
        let ctx = Rc::new(RefCell::new(Builder::new_mega(Rc::new(
            RefCell::new(EccOpQueue::new()),
        ))));
        let input = vec![block(&ctx, "6bc1bee22e409f96e93d7e117393172a")];
        let iv = block(&ctx, "000102030405060708090a0b0c0d0e0f");
        let key = block(&ctx, "2b7e151628aed2a6abf7158809cf4f3c");
        let out = encrypt_buffer_cbc(&input, &iv, &key);
        let expected = Fr::from(BigUint::parse_bytes(b"7649abac8119b246cee98e9b12e9197d", 16).unwrap());
        assert_eq!(out[0].get_value(), expected);
        assert!(ctx.borrow().failed.is_none());
    }
}
