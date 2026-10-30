//! Structured reference string: Aztec's BN254 trusted setup (`~/.bb-crs`), plus the Grumpkin SRS
//! used by IPA.

use super::field::FieldLike;
use super::field::{from_bytes_be, Fq, Fr};
use super::group::{G1Affine, G2Affine, G2Points, GrumpkinAffine};
use super::poly::Polynomial;
use ark_ec::AffineRepr;
use ark_ec::CurveGroup;
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
/// one-shot CLI prove, so the converted form is cached next to the source in bb's cache format,
/// `bn254_g1.mont`: raw little-endian Montgomery limbs, 64 bytes per point. bb reduces coordinates
/// only to `[0, 2p)`, so they are canonicalised on load; bb-ref writes canonical ones, which bb
/// reads unchanged. One file thus serves both, including from a read-only `~/.bb-crs`.
pub fn load_bn254_g1(n: usize) -> Vec<G1Affine> {
    use rayon::prelude::*;
    let mont_path = crs_dir().join("bn254_g1.mont");
    if let Some(points) = read_mont_cache(&mont_path, n) {
        return points;
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
        write_mont_cache(&mont_path, &points);
    }
    points
}

/// Write `points` as the Montgomery-limb cache: canonical limbs in the shared 2^256-domain format
/// (see [`read_mont_cache`]), via an atomic rename (concurrent losers write the same points).
fn write_mont_cache(path: &std::path::Path, points: &[G1Affine]) {
    let mut out: Vec<u8> = Vec::with_capacity(points.len() * 64);
    let unfix = crate::base::wasm::stored_to_shared();
    for p in points {
        for f in [&p.x, &p.y] {
            let f = match unfix {
                Some(u) => *f * u,
                None => *f,
            };
            let l = unsafe { &*(&f as *const Fq as *const [u64; 4]) };
            for w in l {
                out.extend_from_slice(&w.to_le_bytes());
            }
        }
    }
    let tmp = path.with_extension("mont.tmp");
    if std::fs::write(&tmp, &out).is_ok() {
        let _ = std::fs::rename(&tmp, path);
    }
}

/// `n` points from the Montgomery-limb SRS cache, if it holds that many. Coordinates in `[p, 2p)`
/// (bb's coarse reduction) are brought into `[0, p)`.
fn read_mont_cache(path: &std::path::Path, n: usize) -> Option<Vec<G1Affine>> {
    use ark_ff::PrimeField;
    use rayon::prelude::*;
    let mut f = std::fs::File::open(path).ok()?;
    if f.metadata().map_or(0, |m| m.len()) < (n * 64) as u64 {
        return None;
    }
    let mut buf = vec![0u8; n * 64];
    f.read_exact(&mut buf).expect("short read on Montgomery SRS cache");
    // The caches hold 2^256-domain Montgomery limbs (the shared cross-target format).
    let fix = crate::base::wasm::shared_to_stored();
    let p = Fq::MODULUS.0;
    let limbs = |c: &[u8]| {
        let mut l = [0u64; 4];
        for (k, w) in c.chunks(8).enumerate() {
            l[k] = u64::from_le_bytes(w.try_into().unwrap());
        }
        if (0..4).rev().map(|k| l[k].cmp(&p[k])).find(|o| o.is_ne()) != Some(std::cmp::Ordering::Less) {
            let mut borrow = false;
            for k in 0..4 {
                let (d, b1) = l[k].overflowing_sub(p[k]);
                let (d, b2) = d.overflowing_sub(borrow as u64);
                l[k] = d;
                borrow = b1 || b2;
            }
        }
        let v = unsafe { std::mem::transmute::<[u64; 4], Fq>(l) };
        match fix {
            Some(f) => v * f,
            None => v,
        }
    };
    let points: Vec<G1Affine> = buf
        .par_chunks(64)
        .map(|c| G1Affine::new_unchecked(limbs(&c[0..32]), limbs(&c[32..64])))
        .collect();
    assert_eq!(points[0], G1Affine::generator(), "corrupt Montgomery SRS cache {}", path.display());
    Some(points)
}

/// The Grumpkin SRS from `grumpkin_g1_v2.flat.dat` (same raw 64-byte layout, coordinates in bn254 Fr).
/// As bb's loader, the chunks covering the prefix are read whole and checked against their pins.
pub fn load_grumpkin_g1(n: usize) -> Vec<GrumpkinAffine> {
    assert!(n > 0 && n <= GRUMPKIN_NUM_POINTS, "Grumpkin CRS point count must be between 1 and {GRUMPKIN_NUM_POINTS}");
    let path = crs_dir().join("grumpkin_g1_v2.flat.dat");
    let mut f = std::fs::File::open(&path).unwrap_or_else(|e| panic!("cannot open {}: {e}", path.display()));
    let mut buf = vec![0u8; n.div_ceil(GRUMPKIN_CHUNK_BYTES / 64) * GRUMPKIN_CHUNK_BYTES];
    f.read_exact(&mut buf)
        .unwrap_or_else(|e| panic!("CRS file too small for {n} points: {e}"));
    verify_grumpkin_chunks(&buf).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    buf[..n * 64].chunks(64).map(grumpkin_from_raw).collect()
}

// The pins bb authenticates SRS bytes against (`srs/factories/bn254_g1_chunk_hashes.hpp`,
// `bn254_crs_data.hpp`, `grumpkin_crs_data.hpp`): SHA-256 of every 2^17-point chunk of the
// compressed BN254 G1 setup, of the G2 point's 128 bytes, of each 2^16-point Grumpkin v2 chunk, and
// the raw bytes of tau·G.
const BN254_G1_CHUNK_HASHES: &[u8] = include_bytes!("srs_pins/bn254_g1_chunk_hashes.bin");
const BN254_G1_SECOND: &[u8; 64] = include_bytes!("srs_pins/bn254_g1_second.bin");
const BN254_G2_SHA256: &[u8; 32] = include_bytes!("srs_pins/bn254_g2_sha256.bin");
const GRUMPKIN_G1_CHUNK_HASHES: &[u8; 128] = include_bytes!("srs_pins/grumpkin_g1_chunk_hashes.bin");
const BN254_CHUNK_BYTES: usize = (1 << 17) * 32;
const BN254_FULL_CHUNKS: usize = 762;
/// bb `GRUMPKIN_G1_NUM_POINTS`: the pinned Grumpkin CRS, four chunks of 2^16 points.
pub const GRUMPKIN_NUM_POINTS: usize = 1 << 18;
const GRUMPKIN_CHUNK_BYTES: usize = (GRUMPKIN_NUM_POINTS / 4) * 64;

fn sha256(b: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(b).into()
}

/// bb `verify_grumpkin_crs_integrity`: one to four complete chunks, each matching its pin.
pub fn verify_grumpkin_chunks(data: &[u8]) -> Result<(), String> {
    if data.is_empty() || data.len() > GRUMPKIN_NUM_POINTS * 64 || data.len() % GRUMPKIN_CHUNK_BYTES != 0 {
        return Err("Grumpkin CRS must contain complete pinned chunks (1 to 4 chunks)".into());
    }
    for (c, chunk) in data.chunks(GRUMPKIN_CHUNK_BYTES).enumerate() {
        if sha256(chunk)[..] != GRUMPKIN_G1_CHUNK_HASHES[c * 32..(c + 1) * 32] {
            return Err(format!("grumpkin g1 SHA-256 mismatch at chunk {c}"));
        }
    }
    Ok(())
}

fn g1_from_raw(c: &[u8]) -> G1Affine {
    G1Affine::new_unchecked(from_bytes_be::<Fq>(&c[0..32]), from_bytes_be::<Fq>(&c[32..64]))
}

/// bb `affine_element::from_compressed`: x in the low 255 bits, y's parity in the top bit; a
/// non-canonical x or a non-residue decodes to (0, 0), as bb's does.
fn g1_from_compressed(c: &[u8]) -> G1Affine {
    use ark_ff::{BigInteger, Field, PrimeField};
    let mut x_bytes: [u8; 32] = c.try_into().unwrap();
    let y_bit = x_bytes[0] >> 7 == 1;
    x_bytes[0] &= 0x7f;
    let zero = G1Affine::new_unchecked(Fq::from(0u64), Fq::from(0u64));
    let mut limbs = [0u64; 4];
    for (i, w) in x_bytes.chunks(8).enumerate() {
        limbs[3 - i] = u64::from_be_bytes(w.try_into().unwrap());
    }
    let x_int = super::field::U256::new(limbs);
    if x_int >= Fq::MODULUS {
        return zero;
    }
    let x = Fq::from_bigint(x_int).unwrap();
    let Some(mut y) = (x.square() * x + Fq::from(3u64)).sqrt() else {
        return zero;
    };
    if y.into_bigint().is_odd() != y_bit {
        y = -y;
    }
    G1Affine::new_unchecked(x, y)
}

fn g1_to_raw(p: &G1Affine, out: &mut [u8]) {
    out[0..32].copy_from_slice(&super::field::to_bytes_be(&p.x));
    out[32..64].copy_from_slice(&super::field::to_bytes_be(&p.y));
}

/// bb `SrsInitSrs::execute`: authenticate and decode the BN254 points a client pushes. Compressed
/// input (32 bytes a point) must be whole chunks matching the pins and is returned uncompressed for
/// the caller to cache; uncompressed input is trusted apart from its first two points. The G2 point
/// must be the canonical `[x]_2`.
pub fn bn254_from_ingress(num_points: u32, points_buf: &[u8], g2_point: &[u8]) -> Result<(Vec<G1Affine>, Vec<u8>), String> {
    use rayon::prelude::*;
    let n = num_points as usize;
    let bytes_per_point = if n > 0 { points_buf.len() / n } else { 0 };
    if bytes_per_point != 64 && bytes_per_point != 32 {
        return Err(format!(
            "SrsInitSrs: invalid points_buf size. Expected 32 or 64 bytes per point, got {bytes_per_point}"
        ));
    }
    let mut uncompressed = vec![];
    let points: Vec<G1Affine> = if bytes_per_point == 64 {
        points_buf[..n * 64].par_chunks(64).map(g1_from_raw).collect()
    } else {
        if points_buf.is_empty() || points_buf.len() % BN254_CHUNK_BYTES != 0 {
            return Err(format!(
                "SrsInitSrs: compressed points_buf size {} must be a positive multiple of {BN254_CHUNK_BYTES}",
                points_buf.len()
            ));
        }
        let chunks = (points_buf.len() / BN254_CHUNK_BYTES).min(BN254_FULL_CHUNKS);
        for (i, chunk) in points_buf.chunks(BN254_CHUNK_BYTES).take(chunks).enumerate() {
            if sha256(chunk)[..] != BN254_G1_CHUNK_HASHES[i * 32..(i + 1) * 32] {
                return Err(format!("SrsInitSrs: g1 compressed chunk {i} SHA-256 mismatch"));
            }
        }
        let points: Vec<G1Affine> = points_buf[..n * 32].par_chunks(32).map(g1_from_compressed).collect();
        uncompressed = vec![0u8; n * 64];
        uncompressed.par_chunks_mut(64).zip(points.par_iter()).for_each(|(o, p)| g1_to_raw(p, o));
        points
    };
    if n >= 1 && points[0] != G1Affine::generator() {
        return Err("SrsInitSrs: g1_points[0] is not the canonical BN254 generator".into());
    }
    if n >= 2 && points[1] != g1_from_raw(BN254_G1_SECOND) {
        return Err("SrsInitSrs: g1_points[1] does not match the canonical trusted-setup tau·G".into());
    }
    // The hash pin fixes the bytes to the canonical [x]_2, which is a valid prime-order point.
    if sha256(g2_point) != *BN254_G2_SHA256 {
        return Err("SrsInitSrs: g2_point bytes do not match the canonical Aztec [x]_2 SHA-256".into());
    }
    Ok((points, uncompressed))
}

/// bb `SrsInitGrumpkinSrs::execute`: the first `num_points` of an authenticated Grumpkin buffer.
pub fn grumpkin_from_ingress(num_points: u32, points_buf: &[u8]) -> Result<Vec<GrumpkinAffine>, String> {
    let n = num_points as usize;
    if n == 0 || n > GRUMPKIN_NUM_POINTS {
        return Err("SrsInitGrumpkinSrs: point count is outside the pinned Grumpkin CRS".into());
    }
    if points_buf.len() < n * 64 {
        return Err(format!(
            "SrsInitGrumpkinSrs: points_buf too small ({} bytes) for num_points={n} (need {})",
            points_buf.len(),
            n * 64
        ));
    }
    verify_grumpkin_chunks(points_buf)?;
    Ok(points_buf[..n * 64].chunks(64).map(grumpkin_from_raw).collect())
}

/// The Grumpkin SRS's first point (the head of pinned chunk 0): the ECCVM's Shplonk base point
/// (bb `VerifierCommitmentKey::get_g1_identity`), which a verifier needs without the setup at hand.
pub fn grumpkin_g1_first() -> GrumpkinAffine {
    grumpkin_from_raw(include_bytes!("srs_pins/grumpkin_g1_first.bin"))
}

fn grumpkin_from_raw(c: &[u8]) -> GrumpkinAffine {
    GrumpkinAffine::new_unchecked(from_bytes_be::<Fr>(&c[0..32]), from_bytes_be::<Fr>(&c[32..64]))
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
    let fq2 = |lo: &[u8], hi: &[u8]| ark_bn254::Fq2::new(from_bytes_be::<ark_bn254::Fq>(lo), from_bytes_be::<ark_bn254::Fq>(hi));
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

    /// The cache as bb writes it (coordinates in `[0, 2p)`) decodes to the `.dat` points. Skipped
    /// where no cache exists.
    #[test]
    fn bb_mont_cache_matches_dat() {
        let mont = crs_dir().join("bn254_g1.mont");
        let n = 1 << 16;
        let Some(points) = read_mont_cache(&mont, n) else {
            eprintln!("no {} with {n} points; skipped", mont.display());
            return;
        };
        let mut raw = vec![0u8; n * 64];
        std::fs::File::open(crs_dir().join("bn254_g1.dat")).unwrap().read_exact(&mut raw).unwrap();
        for (i, c) in raw.chunks(64).enumerate() {
            let p = G1Affine::new_unchecked(from_bytes_be::<Fq>(&c[0..32]), from_bytes_be::<Fq>(&c[32..64]));
            assert_eq!(points[i], p, "point {i}");
        }
        // What bb-ref writes reads back to the same points.
        let dir = std::env::temp_dir().join(format!("bbref-srs-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("bn254_g1.mont");
        write_mont_cache(&path, &points);
        assert_eq!(read_mont_cache(&path, n).unwrap(), points);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The ingress path against the real setup files: one compressed chunk decompresses to exactly
    /// the uncompressed setup's points, a flipped byte is rejected, and Grumpkin chunks authenticate.
    #[test]
    fn ingress_authenticates_and_decompresses() {
        let dir = crs_dir();
        let (Ok(comp), Ok(raw), Ok(grum)) = (
            std::fs::read(dir.join("bn254_g1_compressed.dat")),
            std::fs::read(dir.join("bn254_g1.dat")),
            std::fs::read(dir.join("grumpkin_g1_v2.flat.dat")),
        ) else {
            eprintln!("skipping: no CRS files");
            return;
        };
        let g2: Vec<u8> = BN254_G2_X_BYTES.to_vec();
        let n = 1 << 17;
        let chunk = &comp[..BN254_CHUNK_BYTES];
        let (points, out) = bn254_from_ingress(n as u32, chunk, &g2).unwrap();
        assert_eq!(out, raw[..n * 64]);
        assert_eq!(points[12345], g1_from_raw(&raw[12345 * 64..12346 * 64]));
        let (points64, out64) = bn254_from_ingress(n as u32, &raw[..n * 64], &g2).unwrap();
        assert!(out64.is_empty() && points64 == points);
        let mut bad = chunk.to_vec();
        bad[1000] ^= 1;
        assert!(bn254_from_ingress(n as u32, &bad, &g2).unwrap_err().contains("chunk 0 SHA-256 mismatch"));
        let mut bad_g2 = g2.clone();
        bad_g2[5] ^= 1;
        assert!(bn254_from_ingress(n as u32, chunk, &bad_g2).is_err());
        assert!(bn254_from_ingress(n as u32, &chunk[..chunk.len() - 32], &g2).is_err());

        let g = grumpkin_from_ingress(1 << 16, &grum[..GRUMPKIN_CHUNK_BYTES]).unwrap();
        assert_eq!(g[0], grumpkin_g1_first());
        assert_eq!(g, load_grumpkin_g1(1 << 16));
        assert!(grumpkin_from_ingress(1 << 16, &grum[..GRUMPKIN_CHUNK_BYTES - 64]).is_err());
        let mut bad = grum[..GRUMPKIN_CHUNK_BYTES].to_vec();
        bad[7] ^= 1;
        assert!(grumpkin_from_ingress(16, &bad).unwrap_err().contains("chunk 0"));
    }

    #[test]
    fn g1_prefix_loads() {
        let pts = load_bn254_g1(4);
        assert!(pts.iter().all(|p| p.is_on_curve()));
    }
}

/// A sized view into an SRS point pool. Keys constructed from a server pool share it
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
    /// GLV companion points `(beta * x, -y)`, built once per key on wasm (where the per-entry
    /// multiply at gather is the visible cost) and shared by every commit through this key;
    /// only the first `glv_threshold()` points, the most a GLV MSM reads.
    phi: PhiTable<G>,
}

/// The lazily built φ table, never waited on. Commits run inside rayon jobs and the table is
/// built with rayon, so a thread blocked on the build can be the builder itself: while its
/// `par_iter` waits it steals a sibling commit job, which would block on the cell it is filling
/// — a deadlock (seen on wasm as every thread parked in `Once::call`/`wait_until_cold` during
/// `batch_commit`). So one thread builds and every other commit, re-entrant ones included, runs
/// without the table until it is ready; the MSM computes φ at gather time then, same result.
#[derive(Default)]
struct PhiTable<G> {
    cell: std::sync::OnceLock<Vec<G>>,
    building: std::sync::atomic::AtomicBool,
}

impl<G> PhiTable<G> {
    fn get_or_build(&self, build: impl FnOnce() -> Vec<G>) -> Option<&[G]> {
        use std::sync::atomic::Ordering;
        if self.cell.get().is_none() && !self.building.swap(true, Ordering::Acquire) {
            // Sole builder: `set` cannot block or lose.
            let _ = self.cell.set(build());
        }
        self.cell.get().map(Vec::as_slice)
    }
}

/// The SRS pools a long-lived server loads once, on the first key request, and hands to its
/// handler (bb memoizes its CRS globally; here the server owns it and threads it down — no
/// globals). Keys are Arc views into the pools, so handing one out is free. Loading on first use
/// rather than at startup keeps a process that never commits (bb.js spawns one per AVM call,
/// whose work is bb's own) at bb's startup cost instead of a 2^23-point load.
#[derive(Clone)]
pub struct Srs {
    bn254: Pool<G1Affine>,
    grumpkin: Pool<GrumpkinAffine>,
}

/// A point pool of `n` points, loaded by `load` on first use (`n == 0`: empty).
#[derive(Clone)]
struct Pool<G> {
    cell: std::sync::Arc<std::sync::OnceLock<std::sync::Arc<Vec<G>>>>,
    n: usize,
    load: fn(usize) -> Vec<G>,
}

impl<G> Pool<G> {
    fn new(n: usize, load: fn(usize) -> Vec<G>) -> Self {
        Self { cell: Default::default(), n, load }
    }
    fn filled(points: Vec<G>) -> Self {
        let n = points.len();
        let cell = std::sync::OnceLock::new();
        let _ = cell.set(std::sync::Arc::new(points));
        Self { cell: std::sync::Arc::new(cell), n, load: |_| vec![] }
    }
    /// The pool if it can serve `k` points (loading it then, once), else `None`.
    fn serving(&self, k: usize) -> Option<&std::sync::Arc<Vec<G>>> {
        (self.n >= k).then(|| self.cell.get_or_init(|| std::sync::Arc::new((self.load)(self.n))))
    }
}

impl Default for Srs {
    /// Empty pools: every key request falls back to an exact on-demand load. The behavior of a
    /// process that never preloads (tests, one-shot CLI commands).
    fn default() -> Self {
        Self {
            bn254: Pool::new(0, load_bn254_g1),
            grumpkin: Pool::new(0, load_grumpkin_g1),
        }
    }
}

impl Srs {
    /// Pools of `bn254_n` and `grumpkin_n` points, each loaded whole on its first key request.
    /// `bn254_n` must cover the largest circuit served (2^23 for the rollup root); an oversized
    /// request falls back to a private exact load rather than failing.
    pub fn lazy(bn254_n: usize, grumpkin_n: usize) -> Self {
        Self {
            bn254: Pool::new(bn254_n, load_bn254_g1),
            grumpkin: Pool::new(grumpkin_n, load_grumpkin_g1),
        }
    }

    /// Serve BN254 keys from `points` (bb `init_bn254_mem_crs_factory`); larger requests still
    /// fall back to an exact load.
    pub fn set_bn254(&mut self, points: Vec<G1Affine>) {
        self.bn254 = Pool::filled(points);
    }

    /// Serve Grumpkin keys from `points` (bb `init_grumpkin_mem_crs_factory`).
    pub fn set_grumpkin(&mut self, points: Vec<GrumpkinAffine>) {
        self.grumpkin = Pool::filled(points);
    }

    pub fn bn254_key(&self, num_points: usize) -> CommitmentKey {
        let n = (num_points + 1) & !1usize;
        match self.bn254.serving(n) {
            Some(pool) => Ck {
                points: PointsView { pool: pool.clone(), len: n },
                phi: PhiTable::default(),
            },
            None => CommitmentKey::new(num_points),
        }
    }

    pub fn grumpkin_key(&self, num_points: usize) -> GrumpkinKey {
        match self.grumpkin.serving(num_points) {
            Some(pool) => Ck {
                points: PointsView { pool: pool.clone(), len: num_points },
                phi: PhiTable::default(),
            },
            None => GrumpkinKey::new(num_points),
        }
    }
}

/// BBREF_DEDUP=0 disables the duplicate-scalar pre-pass (A/B).
fn dedup_enabled() -> bool {
    static V: std::sync::LazyLock<bool> =
        std::sync::LazyLock::new(|| std::env::var("BBREF_DEDUP").map(|v| v != "0").unwrap_or(true));
    *V
}

/// Smallest polynomial the dedup pre-pass considers (BBREF_DEDUP_MIN overrides, default 512 — the
/// ECCVM's ~3,000-row wire polynomials measured 0.207 -> 0.190 s with the gate at or below 1024).
fn dedup_min_len() -> usize {
    static V: std::sync::LazyLock<usize> = std::sync::LazyLock::new(|| {
        std::env::var("BBREF_DEDUP_MIN").ok().and_then(|s| s.parse().ok()).unwrap_or(512)
    });
    *V
}

/// Sample the first nonzero coefficients: dedup pays only when a large share repeats. A prefix
/// misses repeats past a varying head, as in the translator's `z_perm` (varying over its first
/// ~27k rows, long constant runs after), so runs of equal neighbours are counted over the whole.
fn duplicate_heavy<F: FieldLike>(coeffs: &[F]) -> bool {
    prefix_duplicate_heavy(coeffs) || run_heavy(coeffs)
}

/// At least a quarter of the nonzero coefficients equal their predecessor, estimated from 4,096
/// neighbour pairs spread evenly (a pair sample is unbiased for runs, as a value sample is not
/// for scattered duplicates).
fn run_heavy<F: FieldLike>(coeffs: &[F]) -> bool {
    let (mut nonzero, mut repeats) = (0usize, 0usize);
    for i in (1..coeffs.len()).step_by((coeffs.len() / 4096).max(1)) {
        if !coeffs[i].is_zero() {
            nonzero += 1;
            repeats += (coeffs[i] == coeffs[i - 1]) as usize;
        }
    }
    nonzero >= 512 && repeats * 4 >= nonzero
}

fn prefix_duplicate_heavy<F: FieldLike>(coeffs: &[F]) -> bool {
    use std::collections::HashSet;
    assert_eq!(std::mem::size_of::<F>(), 32);
    let mut seen: HashSet<[u64; 4], LimbHashBuilder> = HashSet::default();
    let mut sample = 0usize;
    for s in coeffs {
        if s.is_zero() {
            continue;
        }
        seen.insert(unsafe { std::mem::transmute_copy::<F, [u64; 4]>(s) });
        sample += 1;
        if sample == 2048 {
            break;
        }
    }
    sample >= 512 && seen.len() * 4 < sample * 3
}

/// Hash of a field element's limbs: the low limb is already well mixed for field elements and
/// small values, and the map compares full keys on collision.
#[derive(Default)]
pub struct LimbHasher(u64);
pub type LimbHashBuilder = std::hash::BuildHasherDefault<LimbHasher>;
impl std::hash::Hasher for LimbHasher {
    fn finish(&self) -> u64 {
        self.0
    }
    fn write(&mut self, bytes: &[u8]) {
        for chunk in bytes.chunks(8) {
            let mut b = [0u8; 8];
            b[..chunk.len()].copy_from_slice(chunk);
            self.write_u64(u64::from_le_bytes(b));
        }
    }
    fn write_u64(&mut self, x: u64) {
        self.0 = (self.0.rotate_left(23) ^ x).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    }
}

impl<G: super::msm::BatchMsm> Ck<G>
where
    G::ScalarField: FieldLike,
{
    /// Commit to many polynomials with bounded MSM concurrency (bb `batch_commit`): each MSM is
    /// internally parallel, so a few at a time saturate the cores while capping the live
    /// per-MSM scratch that an unbounded fan-out multiplies. The bound keeps that scratch (~64 B
    /// per point: scalars, histograms, schedules) within bb's 32 MiB batch budget: 8 MSMs at once
    /// up to 2^16 points, 4 at 2^17, one from 2^19.
    pub fn batch_commit(&self, polys: &[&Polynomial<G::ScalarField>]) -> Vec<G>
    where
        G: Send + Sync,
        G::ScalarField: Send + Sync,
    {
        use std::sync::atomic::{AtomicUsize, Ordering};
        const CONCURRENT_MSMS: usize = 8;
        let n = polys.iter().map(|p| p.end_index()).max().unwrap_or(0);
        let concurrent = ((32 << 20) / (64 * n.max(1))).clamp(1, CONCURRENT_MSMS);
        let mut out: Vec<Option<G>> = vec![None; polys.len()];
        let slots = super::msm::SendPtr(out.as_mut_ptr());
        let slots = &slots; // capture the Sync wrapper, not the raw pointer field
        let next = AtomicUsize::new(0);
        rayon::scope(|s| {
            for _ in 0..concurrent.min(polys.len()) {
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
        crate::scope!("CommitmentKey::commit");
        let k = p.end_index();
        assert!(
            k <= self.points.len(),
            "polynomial needs {k} SRS points, key has {}",
            self.points.len()
        );
        let (s, coeffs) = (p.start.min(k), &p.coeffs[..k.saturating_sub(p.start)]);
        let t0 = std::env::var_os("BBREF_COMMIT_TIMING").map(|_| std::time::Instant::now());
        let c = if s == 0 && dedup_enabled() && k >= dedup_min_len() && duplicate_heavy(coeffs) {
            self.commit_dedup(coeffs).into_affine()
        } else {
            let phi = if crate::base::wasm::GLV_PHI_TABLE {
                // Only a GLV MSM (at most the threshold's points) reads the table.
                let n = self.points.len().min(crate::base::msm::glv_threshold());
                self.phi.get_or_build(|| G::phi_table(&self.points[..n])).and_then(|t| t.get(s..k))
            } else {
                None
            };
            G::batch_msm_with_phi(&self.points[s..k], coeffs, phi).into_affine()
        };
        if let Some(t0) = t0 {
            use ark_ff::{BigInteger, PrimeField};
            let ms = t0.elapsed().as_secs_f64() * 1e3;
            let mut nnz = 0usize;
            let mut hist = [0usize; 5]; // <=32, <=64, <=128, <=192, <=254 bits
            for s in coeffs {
                if s.is_zero() {
                    continue;
                }
                nnz += 1;
                let b = s.into_bigint().num_bits();
                hist[match b {
                    0..=32 => 0,
                    33..=64 => 1,
                    65..=128 => 2,
                    129..=192 => 3,
                    _ => 4,
                }] += 1;
            }
            eprintln!("[commit] {k} pts nnz={nnz} bits<=32/64/128/192/254: {hist:?}  {ms:.1} ms");
        }
        c
    }

    /// Commit to a polynomial whose coefficients repeat heavily (witness wires: values 0, 1 and
    /// small constants recur thousands of times). Equal scalars land in the same bucket of every
    /// Pippenger window, so their points are summed once up front and the MSM runs over the
    /// distinct scalars only (bb's dedup pre-pass). Exact: the same group element.
    fn commit_dedup(&self, coeffs: &[G::ScalarField]) -> G::Group {
        use std::collections::HashMap;
        assert_eq!(std::mem::size_of::<G::ScalarField>(), 32);
        let key = |s: &G::ScalarField| unsafe { std::mem::transmute_copy::<G::ScalarField, [u64; 4]>(s) };
        let mut map: HashMap<[u64; 4], u32, LimbHashBuilder> =
            HashMap::with_capacity_and_hasher(coeffs.len() / 2, Default::default());
        let mut reps: Vec<u32> = Vec::new();
        let mut counts: Vec<u32> = Vec::new();
        let mut cluster_of: Vec<(u32, u32)> = Vec::with_capacity(coeffs.len());
        for (i, s) in coeffs.iter().enumerate() {
            if s.is_zero() {
                continue;
            }
            let id = *map.entry(key(s)).or_insert_with(|| {
                reps.push(i as u32);
                counts.push(0);
                (reps.len() - 1) as u32
            });
            counts[id as usize] += 1;
            cluster_of.push((i as u32, id));
        }
        // The points of every repeated scalar, grouped by scalar and summed batched-affine;
        // singletons keep their SRS point.
        let mut slot: Vec<u32> = vec![u32::MAX; reps.len()];
        let mut lens: Vec<u32> = Vec::new();
        for (id, &c) in counts.iter().enumerate() {
            if c > 1 {
                slot[id] = lens.len() as u32;
                lens.push(c);
            }
        }
        let mut fill: Vec<u32> = lens.iter().scan(0, |at, &l| Some(std::mem::replace(at, *at + l))).collect();
        let mut grouped = vec![G::zero(); lens.iter().sum::<u32>() as usize];
        for &(i, id) in &cluster_of {
            let sl = slot[id as usize];
            if sl != u32::MAX {
                grouped[fill[sl as usize] as usize] = self.points[i as usize];
                fill[sl as usize] += 1;
            }
        }
        let sums = G::sum_runs(&grouped, &lens);
        let points: Vec<G> = (0..reps.len())
            .map(|id| {
                let sl = slot[id];
                if sl == u32::MAX { self.points[reps[id] as usize] } else { sums[sl as usize] }
            })
            .collect();
        let scalars: Vec<G::ScalarField> = reps.iter().map(|&i| coeffs[i as usize]).collect();
        if std::env::var_os("BBREF_COMMIT_TIMING").is_some() {
            eprintln!("[dedup] nnz={} distinct={} merged_clusters={}", cluster_of.len(), reps.len(), sums.len());
        }
        let phi = (crate::base::wasm::GLV_PHI_TABLE && points.len() <= crate::base::msm::glv_threshold())
            .then(|| G::phi_table(&points));
        G::batch_msm_with_phi(&points, &scalars, phi.as_deref())
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
            phi: PhiTable::default(),
        }
    }
    /// A key that cannot commit (for IVC state that is only ever verified against, never proven).
    pub fn empty() -> Self {
        Self {
            points: PointsView {
                pool: std::sync::Arc::new(vec![]),
                len: 0,
            },
            phi: PhiTable::default(),
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
            phi: PhiTable::default(),
        }
    }
}

#[cfg(test)]
mod pool_tests {
    use super::*;

    /// A commit re-entering the φ build (rayon work stealing inside the build's `par_iter`) gets
    /// no table instead of blocking on the cell its own thread is filling.
    #[test]
    fn phi_build_reentry_does_not_block() {
        let t = PhiTable::<u64>::default();
        let got = t.get_or_build(|| {
            assert!(t.get_or_build(|| unreachable!()).is_none());
            vec![7]
        });
        assert_eq!(got, Some(&[7u64][..]));
        assert_eq!(t.get_or_build(|| unreachable!()), Some(&[7u64][..]));
    }

    /// Server pools load on the first key request and hand out Arc views of the one load (rounded
    /// up to even, as bb sizes its keys); a request past the pool falls back to an exact private
    /// load instead of failing.
    #[test]
    fn pooled_keys_load_lazily_round_and_fall_back() {
        if crate::testutil::crs_or_skip().is_none() {
            return;
        }
        let srs = Srs::lazy(6, 4);
        assert!(srs.bn254.cell.get().is_none(), "nothing loaded before a key is asked for");
        assert_eq!(srs.bn254_key(3).points.len(), 4, "rounded up to even, from the pool");
        assert!(std::sync::Arc::ptr_eq(&srs.bn254_key(2).points.pool, &srs.clone().bn254_key(6).points.pool));
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
