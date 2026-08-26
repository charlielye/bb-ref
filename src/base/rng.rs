//! Randomness source for ZK provers. A replayable tape can be substituted to reproduce bb's proofs.

use super::field::{Fq, Fr, U256};
use ark_ff::{BigInteger, PrimeField, UniformRand};

pub trait Rng {
    /// A uniformly random 256-bit integer (bb `RNG::get_random_uint256`).
    fn next_u256(&mut self) -> U256;

    /// bb `field::random_element()`: `lo + 2^256 * hi` for two independent u256 draws, each reduced mod p.
    fn fr(&mut self) -> Fr {
        random_field(self.next_u256(), self.next_u256())
    }
    fn fq(&mut self) -> Fq {
        random_field(self.next_u256(), self.next_u256())
    }
}

fn random_field<F: PrimeField>(lo: U256, hi: U256) -> F {
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

/// Replays a recorded sequence of u256 draws (32-byte big-endian each), panicking when exhausted.
pub struct TapeRng {
    draws: Vec<U256>,
    pos: usize,
}
impl TapeRng {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        assert_eq!(bytes.len() % 32, 0);
        let draws = bytes
            .chunks(32)
            .map(|c| U256::new(std::array::from_fn(|i| u64::from_be_bytes(c[24 - 8 * i..32 - 8 * i].try_into().unwrap()))))
            .collect();
        Self { draws, pos: 0 }
    }
}
impl Rng for TapeRng {
    fn next_u256(&mut self) -> U256 {
        let v = self.draws[self.pos];
        self.pos += 1;
        v
    }
}
