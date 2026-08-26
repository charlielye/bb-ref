//! Poseidon2 over the BN254 scalar field (t = 4), and the sponge used as the transcript / VK hash.

use super::field::{from_hex, Fr};
use super::poseidon2_params as params;
use crate::base::field::FieldLike;
use std::sync::OnceLock;

pub trait Hasher<F: FieldLike> {
    fn hash(input: &[F]) -> F;
}

pub struct Poseidon2;

struct Constants {
    round_constants: [[Fr; 4]; 64],
    diag_minus_one: [Fr; 4],
}

fn constants() -> &'static Constants {
    static C: OnceLock<Constants> = OnceLock::new();
    C.get_or_init(|| Constants {
        round_constants: params::ROUND_CONSTANTS.map(|r| r.map(from_hex::<Fr>)),
        diag_minus_one: params::INTERNAL_MATRIX_DIAGONAL_MINUS_ONE.map(from_hex::<Fr>),
    })
}

/// MDS matrix [[5,7,1,3],[4,6,1,1],[1,3,5,7],[1,1,4,6]] applied in place.
pub fn matrix_multiplication_external(s: &mut [Fr; 4]) {
    let t0 = s[0] + s[1];
    let t1 = s[2] + s[3];
    let mut t2 = s[1] + s[1];
    t2 += t1;
    let mut t3 = s[3] + s[3];
    t3 += t0;
    let mut t4 = t1 + t1;
    t4 += t4;
    t4 += t3;
    let mut t5 = t0 + t0;
    t5 += t5;
    t5 += t2;
    let t6 = t3 + t5;
    let t7 = t2 + t4;
    *s = [t6, t5, t7, t4];
}

pub fn matrix_multiplication_internal(s: &mut [Fr; 4]) {
    let diag_minus_one = &constants().diag_minus_one;
    let sum = s[0] + s[1] + s[2] + s[3];
    for i in 0..4 {
        s[i] *= diag_minus_one[i];
        s[i] += sum;
    }
}

pub fn sbox(x: &mut Fr) {
    let x4 = x.sqr().sqr();
    *x *= x4;
}

/// The per-round constants, indexed `[round][state element]`.
pub fn round_constants() -> &'static [[Fr; 4]; 64] {
    &constants().round_constants
}

pub fn permutation(state: &mut [Fr; 4]) {
    let c = constants();
    let rounds_f_beginning = params::ROUNDS_F / 2;
    let p_end = rounds_f_beginning + params::ROUNDS_P;
    let num_rounds = params::ROUNDS_F + params::ROUNDS_P;

    matrix_multiplication_external(state);
    for i in 0..rounds_f_beginning {
        for j in 0..4 {
            state[j] += c.round_constants[i][j];
        }
        state.iter_mut().for_each(sbox);
        matrix_multiplication_external(state);
    }
    for i in rounds_f_beginning..p_end {
        state[0] += c.round_constants[i][0];
        sbox(&mut state[0]);
        matrix_multiplication_internal(state);
    }
    for i in p_end..num_rounds {
        for j in 0..4 {
            state[j] += c.round_constants[i][j];
        }
        state.iter_mut().for_each(sbox);
        matrix_multiplication_external(state);
    }
}

/// Duplex sponge with rate 3, capacity 1 and IV = input_length << 64.
impl Hasher<Fr> for Poseidon2 {
    fn hash(input: &[Fr]) -> Fr {
        const RATE: usize = 3;
        let mut state = [Fr::zero(); 4];
        state[RATE] = Fr::from((input.len() as u128) << 64);
        let mut cache = [Fr::zero(); RATE];
        let mut cache_size = 0;
        let duplex = |state: &mut [Fr; 4], cache: &mut [Fr; RATE]| {
            for i in 0..RATE {
                state[i] += cache[i];
            }
            permutation(state);
            *cache = [Fr::zero(); RATE];
        };
        for x in input {
            if cache_size == RATE {
                duplex(&mut state, &mut cache);
                cache[0] = *x;
                cache_size = 1;
            } else {
                cache[cache_size] = *x;
                cache_size += 1;
            }
        }
        duplex(&mut state, &mut cache);
        state[0]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permutation_test_vector() {
        let mut s = params::TEST_VECTOR_INPUT.map(from_hex::<Fr>);
        permutation(&mut s);
        assert_eq!(s, params::TEST_VECTOR_OUTPUT.map(from_hex::<Fr>));
    }

    #[test]
    fn hash_consistency_check() {
        // crypto/poseidon2/poseidon2.test.cpp HashConsistencyCheck
        let a = from_hex::<Fr>("0x9a807b615c4d3e2fa0b1c2d3e4f56789fedcba9876543210abcdef0123456789");
        let r = Poseidon2::hash(&[a, a, a, a]);
        assert_eq!(r, from_hex::<Fr>("0x2f43a0f83b51a6f5fc839dea0ecec74947637802a579fa9841930a25a0bcec11"));
    }
}
