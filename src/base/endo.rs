//! GLV endomorphism scalar decomposition (bb `split_into_endomorphism_scalars`, the 128-bit
//! Babai-rounding path): k ≡ k1 - k2·λ (mod r) with k1, k2 < 2^129, so an n-point 254-bit MSM
//! becomes a 2n-point 129-bit one — half the Pippenger windows, half the schedule entries.
//! λ·(x, y) = (β·x, y) with λ, β the matched cube roots of unity in the scalar and base field.
//!
//! The g1/g2/b1/b2 lattice constants and both cube roots are bb's (bn254 Fr/Fq); the cube roots
//! are stored canonically so they are valid under any stored Montgomery domain.

use super::field::NativeField;
use crate::base::{Fq, Fr};
use ark_ff::{BigInt, PrimeField};

/// Scalar fields with a fast endomorphism split; the same fields serve as base fields, where
/// `cube_root` is the matching β.
pub trait EndoField: NativeField {
    /// floor(b1 · 2^256 / r), 192 bits.
    const ENDO_G1: [u64; 4];
    /// floor(b2 · 2^256 / r), 129 bits.
    const ENDO_G2: [u64; 4];
    /// -b1 (the lattice vector, made positive), 128 bits.
    const ENDO_MINUS_B1: [u64; 4];
    /// b2, 128 bits.
    const ENDO_B2: [u64; 4];
    /// A primitive cube root of unity (λ as a field element).
    fn cube_root() -> Self;
}

impl EndoField for Fr {
    const ENDO_G1: [u64; 4] = [0x7a7bd9d4391eb18d, 0x4ccef014a773d2cf, 2, 0];
    const ENDO_G2: [u64; 4] = [0xd91d232ec7e0b3d7, 2, 0, 0];
    const ENDO_MINUS_B1: [u64; 4] = [0x8211bbeb7d4f1128, 0x6f4d8248eeb859fc, 0, 0];
    const ENDO_B2: [u64; 4] = [0x89d3256894d213e3, 0, 0, 0];
    fn cube_root() -> Self {
        static L: std::sync::LazyLock<Fr> = std::sync::LazyLock::new(|| {
            Fr::from_bigint(BigInt([
                0x8b17ea66b99c90dd,
                0x5bfc41088d8daaa7,
                0xb3c4d79d41a91758,
                0x0,
            ]))
            .unwrap()
        });
        *L
    }
}

impl EndoField for Fq {
    const ENDO_G1: [u64; 4] = [0x7a7bd9d4391eb18d, 0x4ccef014a773d2cf, 2, 0];
    const ENDO_G2: [u64; 4] = [0xd91d232ec7e0b3d2, 2, 0, 0];
    const ENDO_MINUS_B1: [u64; 4] = [0x8211bbeb7d4f1129, 0x6f4d8248eeb859fc, 0, 0];
    const ENDO_B2: [u64; 4] = [0x89d3256894d213e2, 0, 0, 0];
    fn cube_root() -> Self {
        static L: std::sync::LazyLock<Fq> = std::sync::LazyLock::new(|| {
            Fq::from_bigint(BigInt([
                0x5763473177fffffe,
                0xd4f263f1acdb5c4f,
                0x59e26bcea0d48bac,
                0x0,
            ]))
            .unwrap()
        });
        *L
    }
}

#[inline]
fn mul512(a: &[u64; 4], b: &[u64; 4]) -> [u64; 8] {
    let mut out = [0u64; 8];
    for i in 0..4 {
        let mut carry = 0u128;
        for j in 0..4 {
            let t = (a[i] as u128) * (b[j] as u128) + (out[i + j] as u128) + carry;
            out[i + j] = t as u64;
            carry = t >> 64;
        }
        out[i + 4] = carry as u64;
    }
    out
}

#[inline]
fn sub256(a: &[u64; 4], b: &[u64; 4]) -> ([u64; 4], bool) {
    let mut out = [0u64; 4];
    let mut borrow = false;
    for i in 0..4 {
        let (v1, b1) = a[i].overflowing_sub(b[i]);
        let (v2, b2) = v1.overflowing_sub(borrow as u64);
        out[i] = v2;
        borrow = b1 | b2;
    }
    (out, borrow)
}

#[inline]
fn add256(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let mut out = [0u64; 4];
    let mut carry = false;
    for i in 0..4 {
        let (v1, c1) = a[i].overflowing_add(b[i]);
        let (v2, c2) = v1.overflowing_add(carry as u64);
        out[i] = v2;
        carry = c1 | c2;
    }
    out
}

#[inline]
fn geq(a: &[u64; 4], b: &[u64; 4]) -> bool {
    for i in (0..4).rev() {
        if a[i] != b[i] {
            return a[i] > b[i];
        }
    }
    true
}

/// k ≡ k1 - k2·λ (mod r); both halves < 2^129 (bb's negative-k2 fix keeps the rare slightly
/// negative k2 positive). Returned as low-128-bit pairs.
pub fn glv_split<F: EndoField>(k: &F) -> ([u64; 2], [u64; 2]) {
    let raw: [u64; 4] = k.into_bigint().0;
    if raw[2] == 0 && raw[3] == 0 && raw[1] >> 63 == 0 {
        return ([raw[0], raw[1]], [0, 0]);
    }
    let r: [u64; 4] = F::MODULUS.0;
    // c1 = (g2·k) >> 256, c2 = (g1·k) >> 256; q1 = (c1·(-b1)) mod 2^256, q2 = (c2·b2) mod 2^256.
    let c1: [u64; 4] = mul512(&F::ENDO_G2, &raw)[4..8].try_into().unwrap();
    let c2: [u64; 4] = mul512(&F::ENDO_G1, &raw)[4..8].try_into().unwrap();
    let q1: [u64; 4] = mul512(&c1, &F::ENDO_MINUS_B1)[0..4].try_into().unwrap();
    let q2: [u64; 4] = mul512(&c2, &F::ENDO_B2)[0..4].try_into().unwrap();
    // t1 = q2 - q1 (mod r).
    let (mut t1, borrow) = sub256(&q2, &q1);
    if borrow {
        t1 = add256(&t1, &r);
    }
    if geq(&t1, &r) {
        (t1, _) = sub256(&t1, &r);
    }
    // Slightly negative k2 shows up as a ~254-bit t1: shift k2 by +|b1| (k1 moves by -a1).
    if t1[2] != 0 || t1[3] != 0 {
        t1 = add256(&t1, &F::ENDO_MINUS_B1);
        if geq(&t1, &r) {
            (t1, _) = sub256(&t1, &r);
        }
    }
    // k1 = k + λ·k2 (mod r).
    let t2 = (F::from_bigint(BigInt(t1)).unwrap() * F::cube_root() + *k)
        .into_bigint()
        .0;
    debug_assert!(t2[2] == 0 && t2[3] == 0, "k1 exceeds 128 bits");
    debug_assert!(t1[2] == 0 && t1[3] == 0, "k2 exceeds 128 bits");
    ([t2[0], t2[1]], [t1[0], t1[1]])
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;

    fn check_split<F: EndoField>() {
        let mut rng = ark_std::test_rng();
        for i in 0..2000 {
            let k = if i == 0 { F::ZERO } else { F::rand(&mut rng) };
            let (k1, k2) = glv_split(&k);
            let f1 = F::from_bigint(BigInt([k1[0], k1[1], 0, 0])).unwrap();
            let f2 = F::from_bigint(BigInt([k2[0], k2[1], 0, 0])).unwrap();
            assert_eq!(f1 - f2 * F::cube_root(), k, "split identity, iter {i}");
        }
    }

    #[test]
    fn split_identity() {
        check_split::<Fr>();
        check_split::<Fq>();
    }

    /// λ·P = (β·x, y) with λ the scalar-field root and β the base-field root, on both curves.
    #[test]
    fn endo_maps() {
        use ark_ec::{AffineRepr, CurveGroup};
        let g = ark_bn254::G1Affine::generator();
        let lg = (g * Fr::cube_root()).into_affine();
        assert_eq!(lg, ark_bn254::G1Affine::new_unchecked(g.x * Fq::cube_root(), g.y));
        let g = ark_grumpkin::Affine::generator();
        let lg = (g * Fq::cube_root()).into_affine();
        assert_eq!(lg, ark_grumpkin::Affine::new_unchecked(g.x * Fr::cube_root(), g.y));
    }
}
