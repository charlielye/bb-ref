//! Randomness source for ZK provers. bb's proofs are reproduced either by replaying a recorded tape of
//! its CSPRNG or by seeding both sides' `mt19937_64` (bb's debug engine, `BB_RNG_SEED`).

use super::field::{from_limbs_mod_order, Fq, Fr, U256};
use ark_ff::{PrimeField, UniformRand};

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

/// `2^256` is three squarings of `2^32`: a few multiplications instead of a 256-step `pow` and
/// the byte-at-a-time `from_le_bytes_mod_order`.
fn random_field_from<F: PrimeField>(lo: U256, hi: U256) -> F {
    let pow_2_256 = F::from(1u64 << 32).square().square().square();
    from_limbs_mod_order::<F>(lo.0) + pow_2_256 * from_limbs_mod_order::<F>(hi.0)
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
            mt[i] = 6364136223846793005u64
                .wrapping_mul(mt[i - 1] ^ (mt[i - 1] >> 62))
                .wrapping_add(i as u64);
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

/// The process-global witness-randomness source, mirroring bb's `numeric::get_randomness()` global
/// engine: stdlib gadgets that bb feeds from the implicit engine (e.g. `mask_points`' random offset)
/// draw from here, so a seed set on both sides keeps witnesses byte-equal. Defaults to OS randomness.
static GLOBAL: std::sync::Mutex<Option<Box<dyn Rng + Send>>> = std::sync::Mutex::new(None);

pub fn set_global(rng: Box<dyn Rng + Send>) {
    *GLOBAL.lock().unwrap() = Some(rng);
}
/// Sets the global source from `BB_RNG_SEED`/`BB_RNG_TAPE_IN`, like `from_env`.
pub fn set_global_from_env() {
    if std::env::var("BB_RNG_TAPE_IN").is_ok() || std::env::var("BB_RNG_SEED").is_ok() {
        set_global(from_env_boxed());
    }
}
fn from_env_boxed() -> Box<dyn Rng + Send> {
    if let Ok(path) = std::env::var("BB_RNG_TAPE_IN") {
        return Box::new(TapeRng::from_bytes(std::fs::read(path).expect("BB_RNG_TAPE_IN")));
    }
    match std::env::var("BB_RNG_SEED") {
        Ok(seed) => Box::new(DebugRng::new(seed.parse().expect("BB_RNG_SEED must be a u64"))),
        Err(_) => Box::new(OsRng),
    }
}
/// An `Rng` that delegates every draw to the process-global source, so one tape set via
/// `set_global` can serve bb's single interleaved draw sequence (witness gap-fill, in-circuit
/// masking, random claims, prover) in order.
pub struct GlobalProxy;
impl Rng for GlobalProxy {
    fn next_u256(&mut self) -> U256 {
        global_next_u256()
    }
}

/// Draws taken from the global source, for diagnosing reproducibility. bb's engine is a single
/// process-global that is never reset, so a command that draws when bb's would not advances the
/// stream and changes every later proof in the same session.
pub static GLOBAL_DRAWS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

thread_local! {
    /// Set while this thread runs work ahead of its turn (`detached`): whether it tried to draw.
    static DETACHED: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
}

/// Runs `f` with this thread's global draws replaced by throwaway OS draws, and reports whether it
/// made any: work done ahead of its turn on another thread must not take from the shared stream,
/// whose order fixes the proof bytes, so the caller discards such a result and redoes it in turn.
pub fn detached<T>(f: impl FnOnce() -> T) -> (T, bool) {
    DETACHED.with(|d| d.set(Some(false)));
    let out = f();
    (out, DETACHED.with(|d| d.take()) == Some(true))
}

pub fn global_next_u256() -> U256 {
    if DETACHED.with(|d| d.get().map(|_| d.set(Some(true)))).is_some() {
        return OsRng.next_u256();
    }
    GLOBAL_DRAWS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut g = GLOBAL.lock().unwrap();
    match g.as_mut() {
        Some(rng) => rng.next_u256(),
        None => OsRng.next_u256(),
    }
}
/// bb `field::random_element(engine)` from the global source.
pub fn global_field<F: PrimeField>() -> F {
    random_field_from(global_next_u256(), global_next_u256())
}

/// bb `group::element::random_element()` (hash-to-curve path) reduced to affine: sample x until
/// `x³ + ax + b` is square (root = `pow((q+1)/4)`, valid only for `q ≡ 3 mod 4` like bn254), then
/// draw (and discard) the projective z randomization so the draw ledger matches bb's.
pub fn global_random_affine<P: ark_ec::short_weierstrass::SWCurveConfig>() -> ark_ec::short_weierstrass::Affine<P>
where
    P::BaseField: PrimeField,
{
    use ark_ff::{Field, Zero};
    let modulus: num_bigint::BigUint = P::BaseField::MODULUS.into();
    assert_eq!(
        &modulus % 4u64,
        num_bigint::BigUint::from(3u64),
        "sqrt convention needs q ≡ 3 mod 4"
    );
    let exponent: num_bigint::BigUint = (&modulus + 1u64) >> 2;
    let limbs = exponent.to_u64_digits();
    loop {
        let x: P::BaseField = global_field();
        let mut yy = x.square() * x + P::COEFF_B;
        if !P::COEFF_A.is_zero() {
            yy += x * P::COEFF_A;
        }
        let y = yy.pow(&limbs);
        if y.square() == yy {
            let _z: P::BaseField = global_field();
            return ark_ec::short_weierstrass::Affine::<P>::new_unchecked(x, y);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The C++ standard's own KAT: the 10000th output of a default-seeded (5489) `mt19937_64`
    /// is 9981545732273789042. Seeded parity with bb rests entirely on this generator.
    #[test]
    fn mt19937_64_matches_the_cpp_standard_kat() {
        let mut mt = Mt19937_64::new(5489);
        for _ in 0..9999 {
            mt.next_u64();
        }
        assert_eq!(mt.next_u64(), 9981545732273789042);
    }

    /// bb packs four u64 draws into a u256 low limb first.
    #[test]
    fn debug_rng_packs_four_draws_low_limb_first() {
        let mut raw = Mt19937_64::new(7);
        let expected = [raw.next_u64(), raw.next_u64(), raw.next_u64(), raw.next_u64()];
        let u = DebugRng::new(7).next_u256();
        assert_eq!(u, U256::new(expected));
    }

    #[test]
    fn tape_rng_replays_32_le_bytes_per_draw() {
        let mut bytes = vec![0u8; 64];
        bytes[0] = 1; // limb 0 = 1
        bytes[40] = 2; // second draw, limb 1 = 2
        let mut tape = TapeRng::from_bytes(bytes);
        assert_eq!(tape.remaining(), 64);
        assert_eq!(tape.next_u256(), U256::new([1, 0, 0, 0]));
        assert_eq!(tape.next_u256(), U256::new([0, 2, 0, 0]));
        assert_eq!(tape.remaining(), 0);
    }

    #[test]
    #[should_panic(expected = "RNG tape exhausted")]
    fn tape_exhaustion_panics() {
        let mut tape = TapeRng::from_bytes(vec![0u8; 16]);
        let _ = tape.next_u256();
    }

    /// `random_element()` must produce valid group elements while consuming bb's draw pattern.
    #[test]
    fn random_affine_is_on_curve() {
        for _ in 0..4 {
            let p = global_random_affine::<crate::base::G1Config>();
            assert!(p.is_on_curve());
        }
    }
}
