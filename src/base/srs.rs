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
            // The cache holds 2^256-domain Montgomery limbs (the shared cross-target format).
            let fix = crate::base::wasm::shared_to_stored();
            let limbs = |c: &[u8]| {
                let mut l = [0u64; 4];
                for (k, w) in c.chunks(8).enumerate() {
                    l[k] = u64::from_le_bytes(w.try_into().unwrap());
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
        // Written in the shared 2^256-domain format (see the reader above).
        let unfix = crate::base::wasm::stored_to_shared();
        for p in &points {
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
                phi: PhiTable::default(),
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
                phi: PhiTable::default(),
            }
        } else {
            GrumpkinKey::new(num_points)
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

/// Sample the first nonzero coefficients: dedup pays only when a large share repeats.
fn duplicate_heavy<F: FieldLike>(coeffs: &[F]) -> bool {
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
