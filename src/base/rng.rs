//! Randomness source for ZK provers. A replayable tape can be substituted to reproduce bb's proofs.

use super::field::{Fq, Fr, U256};
use ark_ff::{BigInteger, PrimeField, UniformRand};

pub trait Rng {
    /// A uniformly random 256-bit integer (bb `RNG::get_random_uint256`).
    fn next_u256(&mut self) -> U256;

    /// bb `field::random_element()`: `lo + 2^256 * hi` for two independent u256 draws, each reduced mod p.
    fn fr(&mut self) -> Fr {
        random_field_from(self.next_u256(), self.next_u256())
    }
    fn fq(&mut self) -> Fq {
        random_field_from(self.next_u256(), self.next_u256())
    }
}

/// bb `field::random_element()` for any field: `lo + 2^256 * hi` from two u256 draws.
pub fn random_field<F: PrimeField>(rng: &mut dyn Rng) -> F {
    random_field_from(rng.next_u256(), rng.next_u256())
}

fn random_field_from<F: PrimeField>(lo: U256, hi: U256) -> F {
    let pow_2_256 = F::from(2u64).pow([256u64]);
    F::from_le_bytes_mod_order(&lo.to_bytes_le()) + pow_2_256 * F::from_le_bytes_mod_order(&hi.to_bytes_le())
}

/// OS randomness.
pub struct OsRng;
impl Rng for OsRng {
    fn next_u256(&mut self) -> U256 {
        let mut rng = rand::thread_rng();
        U256::new(std::array::from_fn(|_| u64::rand(&mut rng)))
    }
}

/// Replays bb's CSPRNG byte stream (`BB_RNG_TAPE_OUT` in the patched `numeric/random/engine.cpp`):
/// each u256 draw is 32 little-endian bytes. Panics when exhausted.
pub struct TapeRng {
    bytes: Vec<u8>,
    pos: usize,
}
impl TapeRng {
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { bytes, pos: 0 }
    }
    pub fn remaining(&self) -> usize {
        self.bytes.len() - self.pos
    }
}
impl Rng for TapeRng {
    fn next_u256(&mut self) -> U256 {
        assert!(self.pos + 32 <= self.bytes.len(), "RNG tape exhausted");
        let c = &self.bytes[self.pos..self.pos + 32];
        self.pos += 32;
        U256::new(std::array::from_fn(|i| {
            u64::from_le_bytes(c[8 * i..8 * i + 8].try_into().unwrap())
        }))
    }
}
