//! Randomness source for ZK provers. bb's proofs are reproduced either by replaying a recorded tape of
//! its CSPRNG or by seeding both sides' `mt19937_64` (bb's debug engine, `BB_RNG_SEED`).

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

/// `std::mt19937_64`.
pub struct Mt19937_64 {
    mt: [u64; 312],
    index: usize,
}

impl Mt19937_64 {
    pub fn new(seed: u64) -> Self {
        let mut mt = [0u64; 312];
        mt[0] = seed;
        for i in 1..312 {
            mt[i] = 6364136223846793005u64.wrapping_mul(mt[i - 1] ^ (mt[i - 1] >> 62)).wrapping_add(i as u64);
        }
        Self { mt, index: 312 }
    }
    fn twist(&mut self) {
        for i in 0..312 {
            let x = (self.mt[i] & 0xFFFF_FFFF_8000_0000) | (self.mt[(i + 1) % 312] & 0x7FFF_FFFF);
            let mut xa = x >> 1;
            if x & 1 == 1 {
                xa ^= 0xB502_6F5A_A966_19E9;
            }
            self.mt[i] = self.mt[(i + 156) % 312] ^ xa;
        }
        self.index = 0;
    }
    pub fn next_u64(&mut self) -> u64 {
        if self.index >= 312 {
            self.twist();
        }
        let mut y = self.mt[self.index];
        self.index += 1;
        y ^= (y >> 29) & 0x5555_5555_5555_5555;
        y ^= (y << 17) & 0x71D6_7FFF_EDA6_0000;
        y ^= (y << 37) & 0xFFF7_EEE0_0000_0000;
        y ^= y >> 43;
        y
    }
}

/// bb `numeric::get_debug_randomness(seed)`: `mt19937_64`, a u256 being four draws (low limb first).
pub struct DebugRng(pub Mt19937_64);

impl DebugRng {
    pub fn new(seed: u64) -> Self {
        Self(Mt19937_64::new(seed))
    }
}

impl Rng for DebugRng {
    fn next_u256(&mut self) -> U256 {
        let a = self.0.next_u64();
        let b = self.0.next_u64();
        let c = self.0.next_u64();
        let d = self.0.next_u64();
        U256::new([a, b, c, d])
    }
}

/// The prover's randomness: bb's seeded debug engine when `BB_RNG_SEED` is set (as for bb itself with
/// the fixture engine patch), OS randomness otherwise.
pub fn from_env() -> Box<dyn Rng> {
    if let Ok(path) = std::env::var("BB_RNG_TAPE_IN") {
        return Box::new(TapeRng::from_bytes(std::fs::read(path).expect("BB_RNG_TAPE_IN")));
    }
    match std::env::var("BB_RNG_SEED") {
        Ok(seed) => Box::new(DebugRng::new(seed.parse().expect("BB_RNG_SEED must be a u64"))),
        Err(_) => Box::new(OsRng),
    }
}
