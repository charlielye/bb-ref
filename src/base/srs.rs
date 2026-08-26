//! Structured reference string: Aztec's BN254 trusted setup (`~/.bb-crs`), plus the Grumpkin SRS
//! used by IPA.

use super::group::{G1Affine, G2Affine, G2Points, GrumpkinAffine};
use super::poly::Poly;
use ark_ec::{CurveGroup, VariableBaseMSM};
use super::field::{from_bytes_be, Fq, Fr};
use ark_ec::AffineRepr;
use std::io::Read;
use std::path::PathBuf;

/// `$CRS_PATH`, else `$HOME/.bb-crs` (bb `bb_crs_path`).
pub fn crs_dir() -> PathBuf {
    if let Ok(p) = std::env::var("CRS_PATH") {
        return PathBuf::from(p);
    }
    PathBuf::from(std::env::var("HOME").expect("HOME not set")).join(".bb-crs")
}

/// The first `n` monomial points `[tau^i]_1` from `bn254_g1.dat` (raw 64-byte affine points, x then y,
/// big-endian). The first point is the generator (1, 2).
pub fn load_bn254_g1(n: usize) -> Vec<G1Affine> {
    let path = crs_dir().join("bn254_g1.dat");
    let mut f = std::fs::File::open(&path).unwrap_or_else(|e| panic!("cannot open {}: {e}", path.display()));
    let mut buf = vec![0u8; n * 64];
    f.read_exact(&mut buf).unwrap_or_else(|e| panic!("CRS file too small for {n} points: {e}"));
    let points: Vec<G1Affine> = buf
        .chunks(64)
        .map(|c| G1Affine::new_unchecked(from_bytes_be::<Fq>(&c[0..32]), from_bytes_be::<Fq>(&c[32..64])))
        .collect();
    assert_eq!(points[0], G1Affine::generator(), "unexpected first CRS point");
    points
}

/// The Grumpkin SRS from `grumpkin_g1.flat.dat` (same raw 64-byte layout, coordinates in bn254 Fr).
pub fn load_grumpkin_g1(n: usize) -> Vec<GrumpkinAffine> {
    let path = crs_dir().join("grumpkin_g1.flat.dat");
    let mut f = std::fs::File::open(&path).unwrap_or_else(|e| panic!("cannot open {}: {e}", path.display()));
    let mut buf = vec![0u8; n * 64];
    f.read_exact(&mut buf).unwrap_or_else(|e| panic!("CRS file too small for {n} points: {e}"));
    buf.chunks(64)
        .map(|c| GrumpkinAffine::new_unchecked(from_bytes_be::<Fr>(&c[0..32]), from_bytes_be::<Fr>(&c[32..64])))
        .collect()
}

/// The trusted-setup `[x]_2`, pinned in bb at `srs/factories/bn254_crs_data.hpp`
/// (x.c0, x.c1, y.c0, y.c1; 32 big-endian bytes each).
const BN254_G2_X_BYTES: [u8; 128] = [0x01, 0x18, 0xc4, 0xd5, 0xb8, 0x37, 0xbc, 0xc2, 0xbc, 0x89, 0xb5, 0xb3, 0x98, 0xb5, 0x97, 0x4e, 0x9f, 0x59, 0x44, 0x07, 0x3b, 0x32, 0x07, 0x8b, 0x7e, 0x23, 0x1f, 0xec, 0x93, 0x88, 0x83, 0xb0, 0x26, 0x0e, 0x01, 0xb2, 0x51, 0xf6, 0xf1, 0xc7, 0xe7, 0xff, 0x4e, 0x58, 0x07, 0x91, 0xde, 0xe8, 0xea, 0x51, 0xd8, 0x7a, 0x35, 0x8e, 0x03, 0x8b, 0x4e, 0xfe, 0x30, 0xfa, 0xc0, 0x93, 0x83, 0xc1, 0x22, 0xfe, 0xbd, 0xa3, 0xc0, 0xc0, 0x63, 0x2a, 0x56, 0x47, 0x5b, 0x42, 0x14, 0xe5, 0x61, 0x5e, 0x11, 0xe6, 0xdd, 0x3f, 0x96, 0xe6, 0xce, 0xa2, 0x85, 0x4a, 0x87, 0xd4, 0xda, 0xcc, 0x5e, 0x55, 0x04, 0xfc, 0x63, 0x69, 0xf7, 0x11, 0x0f, 0xe3, 0xd2, 0x51, 0x56, 0xc1, 0xbb, 0x9a, 0x72, 0x85, 0x9c, 0xf2, 0xa0, 0x46, 0x41, 0xf9, 0x9b, 0xa4, 0xee, 0x41, 0x3c, 0x80, 0xda, 0x6a, 0x5f, 0xe4];

/// `[[1]_2, [x]_2]` for the KZG pairing check.
pub fn bn254_g2() -> G2Points {
    let b = &BN254_G2_X_BYTES;
    let fq2 = |lo: &[u8], hi: &[u8]| ark_bn254::Fq2::new(from_bytes_be::<Fq>(lo), from_bytes_be::<Fq>(hi));
    let x = G2Affine::new_unchecked(fq2(&b[0..32], &b[32..64]), fq2(&b[64..96], &b[96..128]));
    assert!(x.is_on_curve() && x.is_in_correct_subgroup_assuming_on_curve(), "bad pinned G2 point");
    [G2Affine::generator(), x]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn g2_is_valid() {
        let _ = bn254_g2();
    }

    #[test]
    fn g1_prefix_loads() {
        let pts = load_bn254_g1(4);
        assert!(pts.iter().all(|p| p.is_on_curve()));
    }
}

/// KZG commitment key: the first `n` (rounded up to even, as bb does) SRS points.
pub struct CommitmentKey {
    pub points: Vec<G1Affine>,
}

impl CommitmentKey {
    pub fn new(num_points: usize) -> Self {
        let n = (num_points + 1) & !1usize;
        Self { points: load_bn254_g1(n) }
    }

    /// `sum_i coeffs[i] * [tau^i]_1`.
    pub fn commit(&self, p: &Poly) -> G1Affine {
        let k = p.end_index();
        assert!(k <= self.points.len(), "polynomial needs {k} SRS points, key has {}", self.points.len());
        ark_bn254::G1Projective::msm_unchecked(&self.points[..k], &p.coeffs[..k]).into_affine()
    }
}
