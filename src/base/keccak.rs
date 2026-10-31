//! Keccak-256 transcript hashing (bb `crypto::Keccak` + `KeccakTranscript`): each transcript word
//! is serialized as 32 big-endian bytes, the concatenation is keccak-256 hashed, and the 32-byte
//! digest is interpreted big-endian and reduced mod the bn254 scalar field.

use super::field::{u256, Fr, U256};
use super::poseidon2::Hasher;
use ark_ff::PrimeField;

/// Keccak-f[1600] (FIPS 202).
pub fn keccak_f1600(state: &mut [u64; 25]) {
    const RC: [u64; 24] = [
        0x0000000000000001,
        0x0000000000008082,
        0x800000000000808a,
        0x8000000080008000,
        0x000000000000808b,
        0x0000000080000001,
        0x8000000080008081,
        0x8000000000008009,
        0x000000000000008a,
        0x0000000000000088,
        0x0000000080008009,
        0x000000008000000a,
        0x000000008000808b,
        0x800000000000008b,
        0x8000000000008089,
        0x8000000000008003,
        0x8000000000008002,
        0x8000000000000080,
        0x000000000000800a,
        0x800000008000000a,
        0x8000000080008081,
        0x8000000000008080,
        0x0000000080000001,
        0x8000000080008008,
    ];
    const ROT: [u32; 25] = [
        0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
    ];
    for rc in RC {
        let c: [u64; 5] = std::array::from_fn(|x| (0..5).fold(0, |acc, y| acc ^ state[y * 5 + x]));
        let d: [u64; 5] = std::array::from_fn(|x| c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1));
        for i in 0..25 {
            state[i] ^= d[i % 5];
        }
        let mut b = [0u64; 25];
        for y in 0..5 {
            for x in 0..5 {
                b[((2 * x + 3 * y) % 5) * 5 + y] = state[y * 5 + x].rotate_left(ROT[y * 5 + x]);
            }
        }
        for y in 0..5 {
            for x in 0..5 {
                state[y * 5 + x] = b[y * 5 + x] ^ (!b[y * 5 + (x + 1) % 5] & b[y * 5 + (x + 2) % 5]);
            }
        }
        state[0] ^= rc;
    }
}

/// Keccak-256 over bytes (rate 136, `0x01 … 0x80` padding, little-endian lanes).
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    const RATE: usize = 136;
    let mut state = [0u64; 25];
    let mut padded = data.to_vec();
    padded.push(0x01);
    while padded.len() % RATE != 0 {
        padded.push(0x00);
    }
    let last = padded.len() - 1;
    padded[last] |= 0x80;
    for block in padded.chunks(RATE) {
        for (i, lane) in block.chunks(8).enumerate() {
            state[i] ^= u64::from_le_bytes(lane.try_into().unwrap());
        }
        keccak_f1600(&mut state);
    }
    let mut out = [0u8; 32];
    for i in 0..4 {
        out[i * 8..(i + 1) * 8].copy_from_slice(&state[i].to_le_bytes());
    }
    out
}

pub fn u256_to_bytes_be(v: &U256) -> [u8; 32] {
    use ark_ff::BigInteger;
    v.to_bytes_be().try_into().unwrap()
}

pub struct Keccak256;

impl Hasher<U256> for Keccak256 {
    fn hash(input: &[U256]) -> U256 {
        let mut buffer = Vec::with_capacity(input.len() * 32);
        for word in input {
            buffer.extend_from_slice(&u256_to_bytes_be(word));
        }
        let digest = keccak256(&buffer);
        // bb interprets the digest as a big-endian integer and reduces mod r ("losing 2 bits").
        u256(&Fr::from_be_bytes_mod_order(&digest))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keccak256_empty_vector() {
        let d = keccak256(b"");
        assert_eq!(
            hex::encode(d),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
    }
}
