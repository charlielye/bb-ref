//! Structured reference string: Aztec's BN254 trusted setup (`~/.bb-crs`), plus the Grumpkin SRS
//! used by IPA.

use super::field::FieldLike;
use super::field::{from_bytes_be, Fq, Fr};
use super::group::{G1Affine, G2Affine, G2Points, GrumpkinAffine};
use super::poly::Polynomial;
use ark_ec::AffineRepr;
use ark_ec::{CurveGroup, VariableBaseMSM};
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
///
/// Montgomery-converting 2 x 8.4M coordinates dominates a full-size load and recurs on every
/// one-shot CLI prove, so the converted form is cached next to the source (bb keeps the same
/// cache as `bn254_g1.mont`): raw little-endian Montgomery limbs, 64 bytes per point.
pub fn load_bn254_g1(n: usize) -> Vec<G1Affine> {
    use rayon::prelude::*;
    let mont_path = crs_dir().join("bn254_g1.ark.mont");
    if let Ok(f) = std::fs::File::open(&mont_path) {
        if f.metadata().map_or(0, |m| m.len()) >= (n * 64) as u64 {
            let mut buf = vec![0u8; n * 64];
            let mut f = f;
            f.read_exact(&mut buf).expect("short read on Montgomery SRS cache");
            let limbs = |c: &[u8]| {
                let mut l = [0u64; 4];
                for (k, w) in c.chunks(8).enumerate() {
                    l[k] = u64::from_le_bytes(w.try_into().unwrap());
                }
                unsafe { std::mem::transmute::<[u64; 4], Fq>(l) }
            };
            let points: Vec<G1Affine> = buf
                .par_chunks(64)
                .map(|c| G1Affine::new_unchecked(limbs(&c[0..32]), limbs(&c[32..64])))
                .collect();
            assert_eq!(points[0], G1Affine::generator(), "corrupt Montgomery SRS cache");
            return points;
        }
    }
    let path = crs_dir().join("bn254_g1.dat");
    let mut f = std::fs::File::open(&path).unwrap_or_else(|e| panic!("cannot open {}: {e}", path.display()));
    let mut buf = vec![0u8; n * 64];
    f.read_exact(&mut buf)
        .unwrap_or_else(|e| panic!("CRS file too small for {n} points: {e}"));
    let points: Vec<G1Affine> = buf
        .par_chunks(64)
        .map(|c| G1Affine::new_unchecked(from_bytes_be::<Fq>(&c[0..32]), from_bytes_be::<Fq>(&c[32..64])))
        .collect();
    assert_eq!(points[0], G1Affine::generator(), "unexpected first CRS point");
    // Best-effort cache write (atomic rename; concurrent losers overwrite with identical bytes).
    // Only grow the cache: a smaller load must not truncate a bigger one.
    if std::fs::metadata(&mont_path).map_or(0, |m| m.len()) < (n * 64) as u64 {
        let mut out: Vec<u8> = Vec::with_capacity(n * 64);
        for p in &points {
            for f in [&p.x, &p.y] {
                let l = unsafe { &*(f as *const Fq as *const [u64; 4]) };
                for w in l {
                    out.extend_from_slice(&w.to_le_bytes());
                }
            }
        }
        let tmp = mont_path.with_extension("mont.tmp");
        if std::fs::write(&tmp, &out).is_ok() {
            let _ = std::fs::rename(&tmp, &mont_path);
        }
    }
    points
}

/// The Grumpkin SRS from `grumpkin_g1_v2.flat.dat` (same raw 64-byte layout, coordinates in bn254 Fr).
pub fn load_grumpkin_g1(n: usize) -> Vec<GrumpkinAffine> {
    let path = crs_dir().join("grumpkin_g1_v2.flat.dat");
    let mut f = std::fs::File::open(&path).unwrap_or_else(|e| panic!("cannot open {}: {e}", path.display()));
    let mut buf = vec![0u8; n * 64];
    f.read_exact(&mut buf)
        .unwrap_or_else(|e| panic!("CRS file too small for {n} points: {e}"));
    buf.chunks(64)
        .map(|c| GrumpkinAffine::new_unchecked(from_bytes_be::<Fr>(&c[0..32]), from_bytes_be::<Fr>(&c[32..64])))
        .collect()
}

/// The trusted-setup `[x]_2`, pinned in bb at `srs/factories/bn254_crs_data.hpp`
/// (x.c0, x.c1, y.c0, y.c1; 32 big-endian bytes each).
const BN254_G2_X_BYTES: [u8; 128] = [
    0x01, 0x18, 0xc4, 0xd5, 0xb8, 0x37, 0xbc, 0xc2, 0xbc, 0x89, 0xb5, 0xb3, 0x98, 0xb5, 0x97, 0x4e, 0x9f, 0x59, 0x44,
    0x07, 0x3b, 0x32, 0x07, 0x8b, 0x7e, 0x23, 0x1f, 0xec, 0x93, 0x88, 0x83, 0xb0, 0x26, 0x0e, 0x01, 0xb2, 0x51, 0xf6,
    0xf1, 0xc7, 0xe7, 0xff, 0x4e, 0x58, 0x07, 0x91, 0xde, 0xe8, 0xea, 0x51, 0xd8, 0x7a, 0x35, 0x8e, 0x03, 0x8b, 0x4e,
    0xfe, 0x30, 0xfa, 0xc0, 0x93, 0x83, 0xc1, 0x22, 0xfe, 0xbd, 0xa3, 0xc0, 0xc0, 0x63, 0x2a, 0x56, 0x47, 0x5b, 0x42,
    0x14, 0xe5, 0x61, 0x5e, 0x11, 0xe6, 0xdd, 0x3f, 0x96, 0xe6, 0xce, 0xa2, 0x85, 0x4a, 0x87, 0xd4, 0xda, 0xcc, 0x5e,
    0x55, 0x04, 0xfc, 0x63, 0x69, 0xf7, 0x11, 0x0f, 0xe3, 0xd2, 0x51, 0x56, 0xc1, 0xbb, 0x9a, 0x72, 0x85, 0x9c, 0xf2,
    0xa0, 0x46, 0x41, 0xf9, 0x9b, 0xa4, 0xee, 0x41, 0x3c, 0x80, 0xda, 0x6a, 0x5f, 0xe4,
];

/// `[[1]_2, [x]_2]` for the KZG pairing check.
pub fn bn254_g2() -> G2Points {
    let b = &BN254_G2_X_BYTES;
    let fq2 = |lo: &[u8], hi: &[u8]| ark_bn254::Fq2::new(from_bytes_be::<Fq>(lo), from_bytes_be::<Fq>(hi));
    let x = G2Affine::new_unchecked(fq2(&b[0..32], &b[32..64]), fq2(&b[64..96], &b[96..128]));
    assert!(
        x.is_on_curve() && x.is_in_correct_subgroup_assuming_on_curve(),
        "bad pinned G2 point"
    );
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

/// A sized view into an SRS point pool. Keys constructed from the preloaded global pool share it
/// (an Arc clone); keys built outside a server share nothing and own their exact slice. Deref to
/// `[G]` keeps every `key.points[..]` call site oblivious.
pub struct PointsView<G> {
    pool: std::sync::Arc<Vec<G>>,
    len: usize,
}

impl<G> std::ops::Deref for PointsView<G> {
    type Target = [G];
    fn deref(&self) -> &[G] {
        &self.pool[..self.len]
    }
}

/// KZG commitment key: the first `n` (rounded up to even, as bb does) SRS points.
/// Monomial commitment key `[tau^i]` over either curve (bb `CommitmentKey<Curve>`).
pub struct Ck<G: AffineRepr> {
    pub points: PointsView<G>,
}

/// The SRS pools a long-lived server loads once at startup and hands to its handler (bb memoizes
/// its CRS globally; here the server owns it and threads it down — no globals). Keys are Arc views
/// into the pools, so handing one out is free.
#[derive(Clone)]
pub struct Srs {
    bn254: std::sync::Arc<Vec<G1Affine>>,
    grumpkin: std::sync::Arc<Vec<GrumpkinAffine>>,
}

impl Default for Srs {
    /// Empty pools: every key request falls back to an exact on-demand load. The behavior of a
    /// process that never preloads (tests, one-shot CLI commands).
    fn default() -> Self {
        Self {
            bn254: std::sync::Arc::new(vec![]),
            grumpkin: std::sync::Arc::new(vec![]),
        }
    }
}

impl Srs {
    /// `bn254_n` must cover the largest circuit served (2^23 for the rollup root); an oversized
    /// request later falls back to a private exact load rather than failing.
    pub fn load(bn254_n: usize, grumpkin_n: usize) -> Self {
        Self {
            bn254: std::sync::Arc::new(load_bn254_g1(bn254_n)),
            grumpkin: std::sync::Arc::new(load_grumpkin_g1(grumpkin_n)),
        }
    }

    pub fn bn254_key(&self, num_points: usize) -> CommitmentKey {
        let n = (num_points + 1) & !1usize;
        if self.bn254.len() >= n {
            Ck {
                points: PointsView {
                    pool: self.bn254.clone(),
                    len: n,
                },
            }
        } else {
            CommitmentKey::new(num_points)
        }
    }

    pub fn grumpkin_key(&self, num_points: usize) -> GrumpkinKey {
        if self.grumpkin.len() >= num_points {
            Ck {
                points: PointsView {
                    pool: self.grumpkin.clone(),
                    len: num_points,
                },
            }
        } else {
            GrumpkinKey::new(num_points)
        }
    }
}

impl<G: super::msm::BatchMsm> Ck<G>
where
    G::ScalarField: FieldLike,
{
    /// Commit to many polynomials with bounded MSM concurrency (bb `batch_commit`): each MSM is
    /// internally parallel, so a few at a time saturate the cores while capping the live
    /// per-MSM scratch that an unbounded fan-out multiplies.
    pub fn batch_commit(&self, polys: &[&Polynomial<G::ScalarField>]) -> Vec<G>
    where
        G: Send + Sync,
        G::ScalarField: Send + Sync,
    {
        use std::sync::atomic::{AtomicUsize, Ordering};
        const CONCURRENT_MSMS: usize = 8;
        let mut out: Vec<Option<G>> = vec![None; polys.len()];
        let slots = super::msm::SendPtr(out.as_mut_ptr());
        let slots = &slots; // capture the Sync wrapper, not the raw pointer field
        let next = AtomicUsize::new(0);
        rayon::scope(|s| {
            for _ in 0..CONCURRENT_MSMS.min(polys.len()) {
                s.spawn(|_| loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    if i >= polys.len() {
                        break;
                    }
                    let c = self.commit(polys[i]);
                    unsafe { *slots.0.add(i) = Some(c) };
                });
            }
        });
        out.into_iter().map(Option::unwrap).collect()
    }

    /// `sum_i coeffs[i] * [tau^i]`.
    pub fn commit(&self, p: &Polynomial<G::ScalarField>) -> G {
        let k = p.end_index();
        assert!(
            k <= self.points.len(),
            "polynomial needs {k} SRS points, key has {}",
            self.points.len()
        );
        G::batch_msm(&self.points[..k], &p.coeffs[..k]).into_affine()
    }
}

pub type CommitmentKey = Ck<G1Affine>;
impl CommitmentKey {
    pub fn new(num_points: usize) -> Self {
        let n = (num_points + 1) & !1usize;
        Self {
            points: PointsView {
                pool: std::sync::Arc::new(load_bn254_g1(n)),
                len: n,
            },
        }
    }
    /// A key that cannot commit (for IVC state that is only ever verified against, never proven).
    pub fn empty() -> Self {
        Self {
            points: PointsView {
                pool: std::sync::Arc::new(vec![]),
                len: 0,
            },
        }
    }
}

/// The Grumpkin key used by the ECCVM's IPA.
pub type GrumpkinKey = Ck<GrumpkinAffine>;
impl GrumpkinKey {
    pub fn new(num_points: usize) -> Self {
        Self {
            points: PointsView {
                pool: std::sync::Arc::new(load_grumpkin_g1(num_points)),
                len: num_points,
            },
        }
    }
}

#[cfg(test)]
mod pool_tests {
    use super::*;

    /// Server-loaded pools hand out Arc views (rounded up to even, as bb sizes its keys); a
    /// request past the pool falls back to an exact private load instead of failing.
    #[test]
    fn pooled_keys_round_and_fall_back() {
        if crate::testutil::crs_or_skip().is_none() {
            return;
        }
        let srs = Srs::load(6, 4);
        assert_eq!(srs.bn254_key(3).points.len(), 4, "rounded up to even, from the pool");
        assert_eq!(srs.bn254_key(8).points.len(), 8, "past the pool: exact private load");
        assert_eq!(srs.grumpkin_key(4).points.len(), 4);
        assert_eq!(srs.grumpkin_key(6).points.len(), 6);
        assert_eq!(
            Srs::default().bn254_key(2).points.len(),
            2,
            "empty pool always falls back"
        );
        assert_eq!(CommitmentKey::empty().points.len(), 0);
    }
}
