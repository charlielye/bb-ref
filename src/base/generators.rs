//! bb `grumpkin::g1::derive_generators`: deterministic Grumpkin generators from a domain
//! separator — BLAKE3 of the separator, then `hash ‖ index ‖ attempt ‖ {0,1}` hashed to the x
//! coordinate (bb `affine_element::hash_to_curve`), the sign bit choosing the root.

use super::field::u256;
use super::{Fr, GrumpkinAffine};
use ark_ec::short_weierstrass::SWCurveConfig;
use ark_ff::{Field, PrimeField};

pub fn derive_generators(domain_separator: &[u8], num_generators: usize, starting_index: usize) -> Vec<GrumpkinAffine> {
    assert!(!domain_separator.is_empty());
    let mut preimage = [0u8; 64];
    preimage[..32].copy_from_slice(blake3::hash(domain_separator).as_bytes());
    (starting_index..starting_index + num_generators)
        .map(|i| {
            preimage[32..36].copy_from_slice(&(i as u32).to_be_bytes());
            hash_to_curve(&preimage)
        })
        .collect()
}

fn hash_to_curve(seed: &[u8]) -> GrumpkinAffine {
    let mut target = seed.to_vec();
    target.extend_from_slice(&[0, 0]);
    for attempt in 0..=u8::MAX {
        target[seed.len()] = attempt;
        target[seed.len() + 1] = 0;
        let hash_hi = *blake3::hash(&target).as_bytes();
        target[seed.len() + 1] = 1;
        let hash_lo = *blake3::hash(&target).as_bytes();
        let mut wide = [0u8; 64];
        wide[..32].copy_from_slice(&hash_hi);
        wide[32..].copy_from_slice(&hash_lo);
        let x = Fr::from_be_bytes_mod_order(&wide);
        let sign_bit = hash_hi[0] > 127;
        if let Some(p) = derive_from_x_coordinate(x, sign_bit) {
            return p;
        }
    }
    unreachable!("hash_to_curve: no curve point after 256 attempts")
}

fn derive_from_x_coordinate(x: Fr, sign_bit: bool) -> Option<GrumpkinAffine> {
    let yy = x.square() * x + ark_grumpkin::GrumpkinConfig::COEFF_B;
    let mut y = yy.sqrt()?;
    if (u256(&y).0[0] & 1 == 1) != sign_bit {
        y = -y;
    }
    Some(GrumpkinAffine::new_unchecked(x, y))
}

/// bb `generator_data<Grumpkin>::precomputed_generators`: the default-domain generators
/// (`DEFAULT_DOMAIN_SEPARATOR`), whose first two have fixed-base lookup tables in bb.
pub fn default_generators(n: usize) -> Vec<GrumpkinAffine> {
    derive_generators(b"DEFAULT_DOMAIN_SEPARATOR", n, 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::field::from_hex;

    /// bb `generator_data.test.cpp` expected default generators 0 and 1.
    #[test]
    fn matches_bb_precomputed_generators() {
        let g = default_generators(2);
        assert_eq!(
            g[0].x,
            from_hex::<Fr>("0x083e7911d835097629f0067531fc15cafd79a89beecb39903f69572c636f4a5a")
        );
        assert_eq!(
            g[0].y,
            from_hex::<Fr>("0x1a7f5efaad7f315c25a918f30cc8d7333fccab7ad7c90f14de81bcc528f9935d")
        );
        assert_eq!(
            g[1].x,
            from_hex::<Fr>("0x054aa86a73cb8a34525e5bbed6e43ba1198e860f5f3950268f71df4591bde402")
        );
        assert_eq!(
            g[1].y,
            from_hex::<Fr>("0x209dcfbf2cfb57f9f6046f44d71ac6faf87254afc7407c04eb621a6287cac126")
        );
        assert!(g.iter().all(|p| p.is_on_curve()));
    }
}
