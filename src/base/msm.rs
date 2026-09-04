//! Pippenger MSM with batched-affine bucket accumulation (bb `scalar_multiplication_fast`, minimal
//! port: signed Booth digits, counting-sort schedules, pair tree-reduction sharing one Montgomery
//! inversion per batch, segmented running-sum bucket reduce; no GLV, no dedup pre-pass).
//!
//! Affine addition costs ~6 muls plus an amortized share of one inversion, against ~14 for the
//! Jacobian adds inside arkworks' `msm_unchecked` — that difference is most of bb's MSM advantage.
//! Unlike bb's unsafe path this handles equal, inverse, and infinity pairs exactly, so it serves
//! verifier-side batch_muls as well as SRS commitments.

use ark_ec::short_weierstrass::{Affine, Projective, SWCurveConfig};
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{AdditiveGroup, Field, PrimeField, Zero};
use rayon::prelude::*;

/// Minimum chunk size for the stage-4 tree jobs.
const MIN_CHUNK: usize = 384;

/// Points per thread below which arkworks' MSM wins: the batched-affine advantage needs enough
/// points per bucket, and the schedule machinery has fixed costs. Swept on the canonical wasm
/// flow (BBREF_MSM_MIN_PTS 128/32/8/4/2/1 -> 6.05/6.02/5.94/5.97/5.97/5.94 s): the packed
/// pippenger wins down to tiny sizes, plateauing at 8.
const MIN_PTS_PER_THREAD: usize = 8;

/// In-place batched inversion of nonzero elements (Montgomery's trick), with the prefix-product
/// scratch reused across calls. ark's `serial_batch_inversion_and_mul` allocates its scratch and
/// filters zeros on every call; the tree denominators are nonzero by construction and this runs
/// tens of millions of elements per prove.
fn batch_invert_nonzero<F: ark_ff::Field>(v: &mut [F], prod: &mut Vec<F>) {
    if v.is_empty() {
        return;
    }
    prod.clear();
    let mut acc = F::one();
    for x in v.iter() {
        acc *= x;
        prod.push(acc);
    }
    let mut inv = acc.inverse().expect("zero denominator in batched inversion");
    for i in (1..v.len()).rev() {
        let prev = v[i];
        v[i] = inv * prod[i - 1];
        inv *= prev;
    }
    v[0] = inv;
}

/// Raw pointer wrapper for the column-major digit scatter: each rayon task writes a disjoint cell.
pub struct SendPtr<T>(pub *mut T);
unsafe impl<T> Send for SendPtr<T> {}
unsafe impl<T> Sync for SendPtr<T> {}

/// Points-per-thread gate below which the arkworks MSM takes over; overridable for crossover
/// sweeps via BBREF_MSM_MIN_PTS.
fn min_pts_per_thread() -> usize {
    static V: std::sync::LazyLock<usize> = std::sync::LazyLock::new(|| {
        std::env::var("BBREF_MSM_MIN_PTS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(MIN_PTS_PER_THREAD)
    });
    *V
}

pub fn msm<P: SWCurveConfig>(points: &[Affine<P>], scalars: &[P::ScalarField]) -> Projective<P>
where
    P::BaseField: crate::honk::quadf::QuadConsts + crate::base::endo::EndoField,
    P::ScalarField: crate::base::endo::EndoField,
{
    msm_with_phi(points, scalars, None)
}

/// `msm` with an optional precomputed endomorphism table `phi[i] = (beta * x_i, -y_i)` covering
/// `points` (an SRS-backed caller amortizes it across many MSMs); without it the phi point is
/// formed at gather, one base-field multiply per schedule entry.
pub fn msm_with_phi<P: SWCurveConfig>(
    points: &[Affine<P>],
    scalars: &[P::ScalarField],
    phi_table: Option<&[Affine<P>]>,
) -> Projective<P>
where
    P::BaseField: crate::honk::quadf::QuadConsts + crate::base::endo::EndoField,
    P::ScalarField: crate::base::endo::EndoField,
{
    let n = points.len().min(scalars.len());
    // Mostly-zero inputs (masking polys, sorted range columns, sparse selectors) compact to their
    // support first, so the cost is per-nonzero, not per-length, and the window size fits the real
    // problem (bb routes these through `commit_sparse` for the same reason).
    if n >= 1024 && scalars.iter().take(64).filter(|s| s.is_zero()).count() >= 8 {
        let nnz = (0..n)
            .into_par_iter()
            .filter(|&i| !scalars[i].is_zero() && !points[i].is_zero())
            .count();
        if nnz * 2 < n {
            let (cp, cs): (Vec<Affine<P>>, Vec<P::ScalarField>) = (0..n)
                .filter(|&i| !scalars[i].is_zero() && !points[i].is_zero())
                .map(|i| (points[i], scalars[i]))
                .unzip();
            return msm_with_phi(&cp, &cs, None);
        }
    }
    if n < min_pts_per_thread() * rayon::current_num_threads() {
        if std::env::var_os("BBREF_MSM_STATS").is_some() {
            eprintln!("[msm-stats] small n={n}");
        }
        return small_msm(&points[..n], &scalars[..n]);
    }
    // GLV: each scalar splits as k = k1 - k2*lambda with 128-bit halves (bb's Babai path), so
    // the MSM runs 2n virtual points — P_i under k1 and (beta*x, -y) under k2 — over 129-bit
    // sub-scalars: half the windows, half the schedule entries. Entry bit 30 marks the
    // endomorphism half, bit 31 the Booth digit sign.
    const PHI: u32 = 1 << 30;
    let subs: Vec<([u64; 2], [u64; 2])> = scalars[..n].par_iter().map(crate::base::endo::glv_split).collect();
    let c = window_bits(2 * n);
    let half = 1usize << (c - 1);
    let num_windows = 129usize.div_ceil(c);

    // bb's stage layout: every O(n) pass is parallel across scalar-range tasks, windows together.
    // Digits are decoded twice (count pass, scatter pass) instead of materialized — cheaper than
    // streaming an n x windows matrix through memory.
    let tasks = rayon::current_num_threads().clamp(1, n.div_ceil(2048));
    let task_ranges: Vec<std::ops::Range<usize>> = (0..tasks)
        .map(|t| t * n.div_ceil(tasks)..((t + 1) * n.div_ceil(tasks)).min(n))
        .collect();
    let stride = half + 1; // per-window histogram row: bucket magnitudes 1..=half
    fn decode(limbs: &[u64; 2], c: usize, half: usize, num_windows: usize, mut f: impl FnMut(usize, i32)) {
        if limbs[0] == 0 && limbs[1] == 0 {
            return;
        }
        let mut carry = 0u64;
        for w in 0..num_windows {
            let raw = extract_bits(limbs, w * c, c) + carry;
            let d = if raw > half as u64 {
                carry = 1;
                raw as i32 - (1i32 << c)
            } else {
                carry = 0;
                raw as i32
            };
            if d != 0 {
                f(w, d);
            }
        }
    }

    let timing = std::env::var("BBREF_MSM_TIMING").is_ok();
    let mut t0 = std::time::Instant::now();
    let mut mark = |name: &str| {
        if timing {
            eprintln!("[msm {name}] {:.2} ms", t0.elapsed().as_secs_f64() * 1e3);
            t0 = std::time::Instant::now();
        }
    };

    // Stage 1: per-task, per-window bucket histograms, one flat (task, window, bucket) array so
    // stage 2 can prefix-sum window columns in parallel.
    let cell = |t: usize, w: usize, b: usize| (t * num_windows + w) * stride + b;
    let mut counts: Vec<u32> = vec![0; tasks * num_windows * stride];
    {
        let ptr = SendPtr(counts.as_mut_ptr());
        task_ranges.par_iter().enumerate().for_each(|(t, r)| {
            let ptr = &ptr;
            for i in r.clone() {
                if !points[i].is_zero() {
                    let bump = |w: usize, d: i32| unsafe {
                        *ptr.0.add(cell(t, w, d.unsigned_abs() as usize)) += 1;
                    };
                    decode(&subs[i].0, c, half, num_windows, bump);
                    decode(&subs[i].1, c, half, num_windows, bump);
                }
            }
        });
    }

    mark("1 histogram");
    // Stage 2: exclusive prefix sums turn the histograms into absolute scatter cursors;
    // bucket_starts[w][b-1] is bucket b's schedule offset (last entry: window length), which
    // stage 4 uses to recover an entry's bucket from its rank. Windows are independent columns.
    let bucket_starts: Vec<Vec<u32>> = {
        let ptr = SendPtr(counts.as_mut_ptr());
        (0..num_windows)
            .into_par_iter()
            .map(|w| {
                let ptr = &ptr;
                let mut starts = Vec::with_capacity(half + 1);
                let mut acc = 0u32;
                for b in 1..=half {
                    starts.push(acc);
                    for t in 0..tasks {
                        unsafe {
                            let p = ptr.0.add(cell(t, w, b));
                            let v = *p;
                            *p = acc;
                            acc += v;
                        }
                    }
                }
                starts.push(acc);
                starts
            })
            .collect()
    };
    let window_len = |w: usize| *bucket_starts[w].last().unwrap() as usize;

    mark("2 prefix");
    // Stage 3: scatter schedule entries (point index | sign bit), bucket-contiguous per window.
    let schedules: Vec<Vec<u32>> = (0..num_windows)
        .map(|w| {
            let mut v = Vec::with_capacity(window_len(w));
            unsafe { v.set_len(window_len(w)) };
            v
        })
        .collect();
    {
        let ptrs: Vec<SendPtr<u32>> = schedules.iter().map(|s| SendPtr(s.as_ptr() as *mut u32)).collect();
        let ptrs = &ptrs;
        let cur = SendPtr(counts.as_mut_ptr());
        task_ranges.par_iter().enumerate().for_each(|(t, r)| {
            let cur = &cur;
            for i in r.clone() {
                if !points[i].is_zero() {
                    let scatter = |phi: u32| {
                        move |w: usize, d: i32| unsafe {
                            let slot = cur.0.add(cell(t, w, d.unsigned_abs() as usize));
                            let entry = i as u32 | phi | if d < 0 { 1u32 << 31 } else { 0 };
                            *ptrs[w].0.add(*slot as usize) = entry;
                            *slot += 1;
                        }
                    };
                    decode(&subs[i].0, c, half, num_windows, scatter(0));
                    decode(&subs[i].1, c, half, num_windows, scatter(PHI));
                }
            }
        });
    }

    mark("3 scatter");
    if std::env::var_os("BBREF_MSM_STATS").is_some() {
        let entries: usize = schedules.iter().map(|s| s.len()).sum();
        eprintln!("[msm-stats] n={n} c={c} windows={num_windows} entries={entries}");
    }
    // Stage 4: tree-reduce, parallel over (window, schedule chunk): a chunk of a bucket-sorted
    // schedule is itself bucket-sorted, so chunks reduce independently; the survivors concatenate
    // in order and a few more levels merge the buckets that straddled chunk boundaries.
    // A chunk must span several points per bucket or the local trees find no pairs and all the
    // reduction work lands on the sequential per-window merge.
    let chunk_len = (8 * half)
        .max(n / (2 * rayon::current_num_threads()).max(1))
        .max(MIN_CHUNK);
    let jobs: Vec<(usize, usize)> = (0..num_windows)
        .flat_map(|w| (0..(schedules[w].len().div_ceil(chunk_len)).max(1)).map(move |k| (w, k)))
        .collect();
    // Points are gathered in bounded blocks and each block tree-reduced before the next is
    // touched, so a job's live scratch is one block plus its (bucket-count-bounded) survivors —
    // gathering a whole 2^20-entry slice as 80-byte pairs costs GBs across concurrent MSMs.
    const GATHER_BLOCK: usize = 1 << 16;
    let beta = <P::BaseField as crate::base::endo::EndoField>::cube_root();
    let survivors: Vec<(Vec<u32>, Vec<Affine<P>>)> = jobs
        .par_iter()
        .map_init(
            // Per-rayon-split scratch, reused across jobs and tree levels, at full capacity up
            // front: growth reallocation of these buffers (and the per-job survivor vectors
            // below) was most of the prover's large-allocation churn, which is what glibc pays
            // page refaults for.
            || {
                let g = GATHER_BLOCK.min(chunk_len);
                (
                    Vec::with_capacity(g),
                    Vec::with_capacity(g),
                    Vec::with_capacity(g),
                    TreeScratch::<P>::with_capacity(g),
                )
            },
            |(block_p, run_id, run_len, scratch), &(w, k)| {
                let sched = &schedules[w];
                let job_start = (k * chunk_len).min(sched.len());
                let job_end = ((k + 1) * chunk_len).min(sched.len());
                // The entry's bucket is its rank's position in the per-window bucket offsets, tracked
                // incrementally since the schedule is sorted.
                let starts = &bucket_starts[w];
                let mut b = starts.partition_point(|&s| s as usize <= job_start) - 1;
                // Survivors per gather block are bounded by the bucket count; one exact
                // allocation instead of doubling growth.
                let cap = (job_end - job_start).min(2 * half * (job_end - job_start).div_ceil(GATHER_BLOCK).max(1));
                let (mut work_b, mut work_p): (Vec<u32>, Vec<Affine<P>>) =
                    (Vec::with_capacity(cap), Vec::with_capacity(cap));
                for (block_start, chunk) in (job_start..job_end)
                    .step_by(GATHER_BLOCK)
                    .zip(sched[job_start..job_end].chunks(GATHER_BLOCK))
                {
                    block_p.clear();
                    run_id.clear();
                    run_len.clear();
                    let (mut cur, mut cnt) = (u32::MAX, 0u32);
                    for (j, &e) in chunk.iter().enumerate() {
                        while starts[b + 1] as usize <= block_start + j {
                            b += 1;
                        }
                        let i = (e & 0x3fff_ffff) as usize;
                        if b as u32 != cur {
                            if cnt > 0 {
                                run_id.push(cur);
                                run_len.push(cnt);
                            }
                            cur = b as u32;
                            cnt = 1;
                        } else {
                            cnt += 1;
                        }
                        let mut pt = points[i];
                        if e & PHI != 0 {
                            pt = match phi_table {
                                Some(t) => t[i],
                                None => Affine::<P>::new_unchecked(beta * pt.x, -pt.y),
                            };
                        }
                        block_p.push(if e >> 31 == 1 { -pt } else { pt });
                    }
                    if cnt > 0 {
                        run_id.push(cur);
                        run_len.push(cnt);
                    }
                    tree_reduce(run_id, run_len, block_p, scratch);
                    work_b.extend_from_slice(run_id);
                    work_p.extend_from_slice(block_p);
                }
                // Block-boundary buckets appear in two blocks' survivors; one more reduction over
                // the (still bucket-sorted) concatenation settles them.
                runs_from_ids(&work_b, run_id, run_len);
                tree_reduce(run_id, run_len, &mut work_p, scratch);
                work_b.clear();
                work_b.extend_from_slice(run_id);
                (work_b, work_p)
            },
        )
        .collect();

    mark("4 tree");
    // Stage 5: per window, concatenate chunk survivors (still bucket-sorted), merge boundary
    // buckets, and reduce buckets to the window sum.
    let mut per_window: Vec<Vec<(Vec<u32>, Vec<Affine<P>>)>> = (0..num_windows).map(|_| Vec::new()).collect();
    for (&(w, _), s) in jobs.iter().zip(survivors) {
        per_window[w].push(s);
    }
    let window_sums: Vec<Projective<P>> = per_window
        .into_par_iter()
        .map(|parts| {
            let mut work_b: Vec<u32> = Vec::with_capacity(parts.iter().map(|(b, _)| b.len()).sum());
            let mut work_p: Vec<Affine<P>> = Vec::with_capacity(work_b.capacity());
            for (b, p) in parts {
                work_b.extend_from_slice(&b);
                work_p.extend_from_slice(&p);
            }
            if work_b.is_empty() {
                return Projective::<P>::zero();
            }
            let (mut run_id, mut run_len) = (Vec::new(), Vec::new());
            let mut scratch = TreeScratch::<P>::with_capacity(work_b.len().min(4096));
            runs_from_ids(&work_b, &mut run_id, &mut run_len);
            tree_reduce(&mut run_id, &mut run_len, &mut work_p, &mut scratch);
            bucket_reduce::<P>(&run_id, &work_p, half)
        })
        .collect();

    mark("5 bucketreduce");
    // Horner walk, high window to low: acc = acc * 2^c + W_w.
    let mut acc = Projective::<P>::zero();
    for w in (0..num_windows).rev() {
        if acc.is_zero() {
            acc = window_sums[w];
            continue;
        }
        for _ in 0..c {
            acc.double_in_place();
        }
        acc += window_sums[w];
    }
    acc
}

/// bb `choose_window_bits` over the GLV-doubled 129-bit problem: minimize
/// rounds * (4n + 12 * buckets), n already doubled by the caller.
fn window_bits(n: usize) -> usize {
    (4..=16)
        .min_by_key(|&c| 129usize.div_ceil(c) * (4 * n + 12 * (1usize << (c - 1))))
        .unwrap()
}

pub(crate) fn extract_bits(limbs: &[u64], start: usize, len: usize) -> u64 {
    let limb = start / 64;
    if limb >= limbs.len() {
        return 0;
    }
    let shift = start % 64;
    let mut v = limbs[limb] >> shift;
    if shift + len > 64 && limb + 1 < limbs.len() {
        v |= limbs[limb + 1] << (64 - shift);
    }
    v & ((1u64 << len) - 1)
}

/// Per-job scratch for `tree_reduce`, reused across jobs and levels. The scalar vectors serve
/// the native tree and the packed tree's scalar tail; the packed staging exists on wasm+simd128
/// builds only.
pub(crate) struct TreeScratch<P: SWCurveConfig> {
    dens: Vec<P::BaseField>,
    prod: Vec<P::BaseField>,
    #[cfg(all(target_family = "wasm", target_feature = "simd128"))]
    packed: packed_tree::PackedScratch<P>,
}

impl<P: SWCurveConfig> TreeScratch<P>
where
    P::BaseField: crate::honk::quadf::QuadConsts,
{
    fn with_capacity(cap: usize) -> Self {
        TreeScratch {
            dens: Vec::with_capacity(cap),
            prod: Vec::with_capacity(cap),
            #[cfg(all(target_family = "wasm", target_feature = "simd128"))]
            packed: packed_tree::PackedScratch::with_capacity(cap),
        }
    }
}

/// Reduce a bucket-sorted point array to at most one point per bucket: repeated levels of
/// adjacent-pair batched-affine additions through one inversion per level. On wasm+simd128 the
/// chord additions run four pairs per lane group through the packed 29-bit kernels; elsewhere
/// (and for the packed path's stragglers) the scalar two-pass level runs. On return every
/// surviving run has length 1, so `run_id`/`ps` are the (bucket, point) survivors.
fn tree_reduce<P: SWCurveConfig>(
    run_id: &mut Vec<u32>,
    run_len: &mut Vec<u32>,
    ps: &mut Vec<Affine<P>>,
    s: &mut TreeScratch<P>,
) where
    P::BaseField: crate::honk::quadf::QuadConsts,
{
    #[cfg(all(target_family = "wasm", target_feature = "simd128"))]
    {
        packed_tree::tree_reduce(run_id, run_len, ps, s);
    }
    #[cfg(not(all(target_family = "wasm", target_feature = "simd128")))]
    {
        tree_reduce_scalar(run_id, run_len, ps, &mut s.dens, &mut s.prod);
    }
}

/// The scalar tree level loop (see `tree_reduce`): the same-bucket runs are described by the
/// parallel `run_id`/`run_len` arrays and updated arithmetically, so the inner loops never touch
/// per-element bucket ids — no id compares, no id compaction, no tag lists (a pair's
/// chord/double/infinity case is re-derived from the coordinates in the apply pass). Sequential:
/// the caller's schedule chunks are the parallel unit.
#[cfg_attr(all(target_family = "wasm", target_feature = "simd128"), allow(dead_code))]
fn tree_reduce_scalar<P: SWCurveConfig>(
    run_id: &mut Vec<u32>,
    run_len: &mut Vec<u32>,
    ps: &mut Vec<Affine<P>>,
    dens: &mut Vec<P::BaseField>,
    prod: &mut Vec<P::BaseField>,
) {
    loop {
        // Pass 1: denominators for every adjacent same-bucket pair, positions implicit.
        dens.clear();
        let mut i = 0usize;
        let mut any = false;
        for &k in run_len.iter() {
            let k = k as usize;
            for j in 0..k / 2 {
                let (a, b) = (&ps[i + 2 * j], &ps[i + 2 * j + 1]);
                if a.x == b.x {
                    if a.y == b.y {
                        dens.push(a.y.double());
                    } // else: inverse pair, sums to infinity — no denominator, dropped in pass 2
                } else {
                    dens.push(b.x - a.x);
                }
            }
            any |= k >= 2;
            i += k;
        }
        if !any {
            return;
        }
        batch_invert_nonzero(dens, prod);
        // Pass 2: apply the additions, compacting points and runs in place (the write cursor
        // never passes the read cursor). Every slot holds a finite point: zero points never enter
        // the schedule and inverse pairs are dropped, so in-place x/y writes keep slots finite.
        let mut inv = dens.iter();
        let (mut out, mut i, mut out_run) = (0usize, 0usize, 0usize);
        for r in 0..run_len.len() {
            let k = run_len[r] as usize;
            let mut new_k = 0u32;
            for j in 0..k / 2 {
                let at = i + 2 * j;
                let (ax, ay) = (ps[at].x, ps[at].y);
                let (bx, by) = (ps[at + 1].x, ps[at + 1].y);
                if ax == bx && ay != by {
                    continue;
                }
                let d = *inv.next().unwrap();
                let lambda = if ax == bx {
                    let xx = ax.square();
                    (xx.double() + xx) * d
                } else {
                    (by - ay) * d
                };
                let x3 = lambda.square() - ax - bx;
                ps[out].x = x3;
                ps[out].y = lambda * (ax - x3) - ay;
                out += 1;
                new_k += 1;
            }
            if k % 2 == 1 {
                ps[out] = ps[i + k - 1];
                out += 1;
                new_k += 1;
            }
            i += k;
            if new_k > 0 {
                run_id[out_run] = run_id[r];
                run_len[out_run] = new_k;
                out_run += 1;
            }
        }
        run_id.truncate(out_run);
        run_len.truncate(out_run);
        ps.truncate(out);
    }
}

/// The wasm+simd128 tree level: pair classification and run bookkeeping stay scalar (bb keeps
/// its schedule AoS for the same reason — packed layouts can't index conditional pairing
/// cheaply), while the chord additions drain through the packed 29-bit SIMD kernels, four
/// pairs per lane group with one batched inversion per level per lane. Doublings (duplicate
/// points inside one bucket) and the <4-pair tail take the scalar path; inverse pairs
/// annihilate. This is bb's Stage-6a `tree_reduce_in_place` + `drain_batch` shape.
#[cfg(all(target_family = "wasm", target_feature = "simd128"))]
mod packed_tree {
    use super::*;
    use crate::honk::quadf::QuadConsts;
    use ark_ff::fields::models::fp::montgomery_backend::quad261::{self, QuadFp};

    pub(crate) struct PackedScratch<P: SWCurveConfig> {
        // Chord staging, coordinate-separated so groups of four pack straight from memory.
        ax: Vec<P::BaseField>,
        ay: Vec<P::BaseField>,
        bx: Vec<P::BaseField>,
        by: Vec<P::BaseField>,
        dest: Vec<u32>,
        dbl_dest: Vec<u32>,
        #[cfg(feature = "bbkernel")]
        ox: Vec<P::BaseField>,
        #[cfg(feature = "bbkernel")]
        oy: Vec<P::BaseField>,
        #[cfg(feature = "bbkernel")]
        cscratch: Vec<P::BaseField>,
        // Packed operands and batched-inversion chain, one entry per lane group.
        qax: Vec<QuadFp>,
        qbx: Vec<QuadFp>,
        qden: Vec<QuadFp>,
        qprod: Vec<QuadFp>,
    }

    impl<P: SWCurveConfig> PackedScratch<P>
    where
        P::BaseField: QuadConsts,
    {
        pub(crate) fn with_capacity(cap: usize) -> Self {
            let half = cap / 2 + 1;
            PackedScratch {
                ax: Vec::with_capacity(half),
                ay: Vec::with_capacity(half),
                bx: Vec::with_capacity(half),
                by: Vec::with_capacity(half),
                dest: Vec::with_capacity(half),
                dbl_dest: Vec::new(),
                #[cfg(feature = "bbkernel")]
                ox: Vec::new(),
                #[cfg(feature = "bbkernel")]
                oy: Vec::new(),
                #[cfg(feature = "bbkernel")]
                cscratch: Vec::new(),
                qax: Vec::with_capacity(half / 4 + 1),
                qbx: Vec::with_capacity(half / 4 + 1),
                qden: Vec::with_capacity(half / 4 + 1),
                qprod: Vec::with_capacity(half / 4 + 1),
            }
        }
    }

    pub(crate) fn tree_reduce<P: SWCurveConfig>(
        run_id: &mut Vec<u32>,
        run_len: &mut Vec<u32>,
        ps: &mut Vec<Affine<P>>,
        s: &mut TreeScratch<P>,
    ) where
        P::BaseField: QuadConsts,
    {
        loop {
            let p = &mut s.packed;
            p.ax.clear();
            p.ay.clear();
            p.bx.clear();
            p.by.clear();
            p.dest.clear();
            p.dbl_dest.clear();
            let mut any = false;
            // Classify and compact in one pass. The write cursor never passes the read cursor
            // (each read pair yields at most one output slot), so chord results scattered after
            // the walk land on slots already read this level.
            let (mut out, mut i, mut out_run) = (0usize, 0usize, 0usize);
            for r in 0..run_len.len() {
                let k = run_len[r] as usize;
                let mut new_k = 0u32;
                for j in 0..k / 2 {
                    let at = i + 2 * j;
                    let (a, b) = (ps[at], ps[at + 1]);
                    if a.x == b.x {
                        if a.y != b.y {
                            continue; // inverse pair, sums to infinity — dropped
                        }
                        ps[out] = a;
                        p.dbl_dest.push(out as u32);
                    } else {
                        p.ax.push(a.x);
                        p.ay.push(a.y);
                        p.bx.push(b.x);
                        p.by.push(b.y);
                        p.dest.push(out as u32);
                    }
                    out += 1;
                    new_k += 1;
                }
                if k % 2 == 1 {
                    ps[out] = ps[i + k - 1];
                    out += 1;
                    new_k += 1;
                }
                any |= k >= 2;
                i += k;
                if new_k > 0 {
                    run_id[out_run] = run_id[r];
                    run_len[out_run] = new_k;
                    out_run += 1;
                }
            }
            if !any {
                return;
            }
            drain::<P>(s, ps);
            run_id.truncate(out_run);
            run_len.truncate(out_run);
            ps.truncate(out);
        }
    }

    /// Apply the level's queued additions: packed lane groups of four chords, then the scalar
    /// tail (chord stragglers + doublings) through one shared scalar batched inversion.
    fn drain<P: SWCurveConfig>(s: &mut TreeScratch<P>, ps: &mut [Affine<P>])
    where
        P::BaseField: QuadConsts,
    {
        // The bb-kernel drain loses its isolated 1t rung to the QuadFp chain below (~+15%/pair)
        // but wins the real flow at 8t (6.11 vs 6.23 s canonical) — flow-verified, kept.
        #[cfg(feature = "bbkernel")]
        if drain_bbk::<P>(s, ps) {
            return;
        }
        let p = &mut s.packed;
        let groups = p.ax.len() / 4;
        if groups > 0 {
            // The wasm stored form is the 2^261 Montgomery domain, which the quad261 multiply
            // is closed over — the whole level is plain Montgomery arithmetic on packed stored
            // bytes, one scalar batched inversion per level.
            let kc = <P::BaseField as QuadConsts>::kc();
            #[inline(always)]
            fn pack4<F>(v: &[F], g: usize) -> QuadFp {
                // Fp<_, 4> is repr-equivalent to its 4x64 stored limbs.
                QuadFp::pack(unsafe { &*(v.as_ptr().add(4 * g) as *const [[u64; 4]; 4]) })
            }
            p.qax.clear();
            p.qbx.clear();
            p.qden.clear();
            p.qprod.clear();
            for g in 0..groups {
                let (qax, qbx) = (pack4(&p.ax, g), pack4(&p.bx, g));
                let den = quad261::sub(&qbx, &qax, &kc.c);
                let acc = match p.qprod.last() {
                    Some(prev) => quad261::mont_mul(prev, &den, &kc.c),
                    None => den,
                };
                p.qprod.push(acc);
                p.qden.push(den);
                p.qax.push(qax);
                p.qbx.push(qbx);
            }
            // One scalar batched inversion for the level: the four lanes of the total product,
            // inverted together, each scaled by 2^10 to seed the constant-exponent unwind.
            let seed = {
                let total = p.qprod[groups - 1].unpack(&kc.modulus);
                let mut lanes: [P::BaseField; 4] =
                    core::array::from_fn(|l| unsafe { core::mem::transmute_copy(&total[l]) });
                let mut acc = lanes[0];
                let mut pref = [acc; 4];
                for l in 1..4 {
                    acc *= lanes[l];
                    pref[l] = acc;
                }
                let mut inv = acc.inverse().expect("zero denominator in packed tree inversion");
                for l in (1..4).rev() {
                    let prev = lanes[l];
                    lanes[l] = inv * pref[l - 1];
                    inv *= prev;
                }
                lanes[0] = inv;
                let stored: [[u64; 4]; 4] = core::array::from_fn(|l| unsafe { core::mem::transmute_copy(&lanes[l]) });
                QuadFp::pack(&stored)
            };
            let mut inv = seed;
            for g in (1..groups).rev() {
                let d = quad261::mont_mul(&inv, &p.qprod[g - 1], &kc.c);
                inv = quad261::mont_mul(&inv, &p.qden[g], &kc.c);
                p.qden[g] = d;
            }
            p.qden[0] = inv;
            for g in 0..groups {
                let (qay, qby) = (pack4(&p.ay, g), pack4(&p.by, g));
                let (qax, qbx) = (p.qax[g], p.qbx[g]);
                let dy = quad261::sub(&qby, &qay, &kc.c);
                let l = quad261::mont_mul(&dy, &p.qden[g], &kc.c);
                let x3 = quad261::sub(
                    &quad261::sub(&quad261::mont_mul(&l, &l, &kc.c), &qax, &kc.c),
                    &qbx,
                    &kc.c,
                );
                let y3 = quad261::sub(
                    &quad261::mont_mul(&l, &quad261::sub(&qax, &x3, &kc.c), &kc.c),
                    &qay,
                    &kc.c,
                );
                let (xs, ys) = (x3.unpack(&kc.modulus), y3.unpack(&kc.modulus));
                for l in 0..4 {
                    let d = p.dest[4 * g + l] as usize;
                    let (x, y): (P::BaseField, P::BaseField) =
                        unsafe { (core::mem::transmute_copy(&xs[l]), core::mem::transmute_copy(&ys[l])) };
                    ps[d] = Affine::<P>::new_unchecked(x, y);
                }
            }
        }
        // Scalar tail: leftover chords and all doublings, one shared batched inversion.
        s.dens.clear();
        for t in groups * 4..p.ax.len() {
            s.dens.push(p.bx[t] - p.ax[t]);
        }
        for &d in &p.dbl_dest {
            s.dens.push(ps[d as usize].y.double());
        }
        if s.dens.is_empty() {
            return;
        }
        batch_invert_nonzero(&mut s.dens, &mut s.prod);
        let mut inv = s.dens.iter();
        for t in groups * 4..p.ax.len() {
            let d = *inv.next().unwrap();
            let lambda = (p.by[t] - p.ay[t]) * d;
            let x3 = lambda.square() - p.ax[t] - p.bx[t];
            let y3 = lambda * (p.ax[t] - x3) - p.ay[t];
            ps[p.dest[t] as usize] = Affine::<P>::new_unchecked(x3, y3);
        }
        for &dst in &p.dbl_dest {
            let d = *inv.next().unwrap();
            let (x, y) = (ps[dst as usize].x, ps[dst as usize].y);
            let xx = x.square();
            let lambda = (xx.double() + xx) * d;
            let x3 = lambda.square() - x.double();
            let y3 = lambda * (x - x3) - y;
            ps[dst as usize] = Affine::<P>::new_unchecked(x3, y3);
        }
    }


    /// Drain through bb's clang-compiled chord kernels (feature `bbkernel`): phase 1 builds the
    /// denominators and five-lane product chains, the single inversion of the lane totals runs
    /// here (ark), phase 2 unwinds and applies. Staging is padded to the kernel width with a
    /// repeated valid pair (outputs ignored); doublings run the scalar batched path. Returns
    /// false for base fields without a kernel.
    #[cfg(feature = "bbkernel")]
    fn drain_bbk<P: SWCurveConfig>(s: &mut TreeScratch<P>, ps: &mut [Affine<P>]) -> bool
    where
        P::BaseField: QuadConsts,
    {
        use crate::base::packed::bbk;
        use core::any::TypeId;
        type C1 = unsafe extern "C" fn(*const u64, *const u64, usize, *mut u64, *mut u64);
        type C2 = unsafe extern "C" fn(
            *const u64,
            *const u64,
            *const u64,
            *const u64,
            usize,
            *mut u64,
            *const u64,
            *const u64,
            *const u32,
            *mut u64,
        );
        let (c1, c2): (C1, C2) = if TypeId::of::<P::BaseField>() == TypeId::of::<crate::base::Fr>() {
            (bbk::bbref_chord1_fr, bbk::bbref_chord2s_fr)
        } else if TypeId::of::<P::BaseField>() == TypeId::of::<ark_bn254::Fq>() {
            (bbk::bbref_chord1_fq, bbk::bbref_chord2s_fq)
        } else {
            return false;
        };
        let p = &mut s.packed;
        if !p.ax.is_empty() {
            let w = unsafe { bbk::bbref_chord_width() };
            while p.ax.len() % w != 0 {
                p.ax.push(p.ax[0]);
                p.ay.push(p.ay[0]);
                p.bx.push(p.bx[0]);
                p.by.push(p.by[0]);
            }
            while p.dest.len() < p.ax.len() {
                p.dest.push(p.dest[0]);
            }
            let n = p.ax.len();
            p.cscratch.resize(2 * n, p.ax[0]);
            let (dx, prod) = p.cscratch.split_at_mut(n);
            unsafe {
                c1(
                    p.ax.as_ptr() as *const u64,
                    p.bx.as_ptr() as *const u64,
                    n,
                    dx.as_mut_ptr() as *mut u64,
                    prod.as_mut_ptr() as *mut u64,
                )
            };
            // One inversion for the whole level: the last w chain products, batched.
            let mut lane_inv: Vec<P::BaseField> = prod[n - w..].to_vec();
            batch_invert_nonzero(&mut lane_inv, &mut s.prod);
            // Phase 2 scatters {x3, y3} straight into ps by dest index (Affine is 64-byte {x,y}).
            unsafe {
                c2(
                    p.ax.as_ptr() as *const u64,
                    p.ay.as_ptr() as *const u64,
                    p.bx.as_ptr() as *const u64,
                    p.by.as_ptr() as *const u64,
                    n,
                    dx.as_mut_ptr() as *mut u64,
                    prod.as_ptr() as *const u64,
                    lane_inv.as_ptr() as *const u64,
                    p.dest.as_ptr(),
                    ps.as_mut_ptr() as *mut u64,
                )
            };
        }
        // Doublings through the scalar batched path.
        s.dens.clear();
        for &d in &p.dbl_dest {
            s.dens.push(ps[d as usize].y.double());
        }
        if !s.dens.is_empty() {
            batch_invert_nonzero(&mut s.dens, &mut s.prod);
            let mut inv = s.dens.iter();
            for &dst in &p.dbl_dest {
                let d = *inv.next().unwrap();
                let (x, y) = (ps[dst as usize].x, ps[dst as usize].y);
                let xx = x.square();
                let lambda = (xx.double() + xx) * d;
                let x3 = lambda.square() - x.double();
                let y3 = lambda * (x - x3) - y;
                ps[dst as usize] = Affine::<P>::new_unchecked(x3, y3);
            }
        }
        true
    }
}

/// Adds each pair sharing one field inversion across the batch. `None` = point at infinity.
fn batch_affine_add<P: SWCurveConfig>(pairs: Vec<(Affine<P>, Affine<P>)>) -> Vec<Option<Affine<P>>> {
    #[derive(Clone, Copy)]
    enum Kind {
        Add,
        Double,
        Inf,
        Lhs,
        Rhs,
    }
    let mut kinds = Vec::with_capacity(pairs.len());
    let mut dens: Vec<P::BaseField> = Vec::with_capacity(pairs.len());
    for (a, b) in &pairs {
        let kind = if a.is_zero() {
            Kind::Rhs
        } else if b.is_zero() {
            Kind::Lhs
        } else if a.x == b.x {
            if a.y == b.y {
                dens.push(a.y.double());
                Kind::Double
            } else {
                Kind::Inf
            }
        } else {
            dens.push(b.x - a.x);
            Kind::Add
        };
        kinds.push(kind);
    }
    ark_ff::serial_batch_inversion_and_mul(&mut dens, &<P::BaseField as ark_ff::One>::one());
    let mut inv = dens.into_iter();
    pairs
        .iter()
        .zip(kinds)
        .map(|(&(a, b), kind)| {
            let lambda = match kind {
                Kind::Rhs => return Some(b),
                Kind::Lhs => return Some(a),
                Kind::Inf => return None,
                Kind::Add => (b.y - a.y) * inv.next().unwrap(),
                Kind::Double => {
                    let xx = a.x.square();
                    (xx.double() + xx) * inv.next().unwrap()
                }
            };
            let x3 = lambda.square() - a.x - b.x;
            let y3 = lambda * (a.x - x3) - a.y;
            Some(Affine::<P>::new_unchecked(x3, y3))
        })
        .collect()
}

/// `sum_b (b+1) * B_b` over singleton buckets: segmented double running sums, the affine chain
/// steps batched across segments, segment totals recombined in projective.

/// Rebuild `run_id`/`run_len` from a bucket-sorted id array (used where per-block survivors are
/// concatenated: block-boundary buckets become one run again).
fn runs_from_ids(ids: &[u32], run_id: &mut Vec<u32>, run_len: &mut Vec<u32>) {
    run_id.clear();
    run_len.clear();
    let (mut cur, mut cnt) = (u32::MAX, 0u32);
    for &b in ids {
        if b != cur {
            if cnt > 0 {
                run_id.push(cur);
                run_len.push(cnt);
            }
            cur = b;
            cnt = 1;
        } else {
            cnt += 1;
        }
    }
    if cnt > 0 {
        run_id.push(cur);
        run_len.push(cnt);
    }
}

fn bucket_reduce<P: SWCurveConfig>(bs: &[u32], ps: &[Affine<P>], num_buckets: usize) -> Projective<P> {
    // Wider = bigger inversion batches and fewer chain steps; the projective recombine at the end
    // costs ~2 ops per segment, so segments stay well below the bucket count.
    let segments = (num_buckets / 16).clamp(1, 1024).next_power_of_two();
    let seg_len = num_buckets.div_ceil(segments);
    let mut bucket_of: Vec<Option<Affine<P>>> = vec![None; seg_len * segments];
    for (b, p) in bs.iter().zip(ps) {
        bucket_of[*b as usize] = Some(*p);
    }
    let mut running: Vec<Option<Affine<P>>> = vec![None; segments];
    let mut acc: Vec<Option<Affine<P>>> = vec![None; segments];
    let (mut dens, mut kinds) = (Vec::with_capacity(segments), Vec::with_capacity(segments));
    for t in (0..seg_len).rev() {
        super::fold::pass_add(&mut running, |j| bucket_of[j * seg_len + t], &mut dens, &mut kinds);
        super::fold::pass_add(&mut acc, |j| running[j], &mut dens, &mut kinds);
    }
    // window = sum_j acc_j + seg_len * sum_j j * running_j, both cheap in projective.
    let mut total: Projective<P> = acc.iter().flatten().map(|p| p.into_group()).sum();
    let mut j_weighted = Projective::<P>::zero();
    let mut suffix = Projective::<P>::zero();
    for j in (1..segments).rev() {
        suffix += running[j].map_or(Projective::<P>::zero(), |p| p.into_group());
        j_weighted += suffix;
    }
    // num_buckets and segments are both powers of two, so seg_len is too.
    assert!(seg_len.is_power_of_two());
    for _ in 0..seg_len.trailing_zeros() {
        j_weighted.double_in_place();
    }
    total += j_weighted;
    total
}

/// `lhs[i] += rhs[i]` with the affine additions batched through one inversion.
fn batch_add_assign<P: SWCurveConfig>(lhs: &mut [Option<Affine<P>>], rhs: &[Option<Affine<P>>]) {
    let idx: Vec<usize> = (0..lhs.len())
        .filter(|&i| rhs[i].is_some() && lhs[i].is_some())
        .collect();
    let sums = batch_affine_add::<P>(idx.iter().map(|&i| (lhs[i].unwrap(), rhs[i].unwrap())).collect());
    for (k, &i) in idx.iter().enumerate() {
        lhs[i] = sums[k];
    }
    for i in 0..lhs.len() {
        if lhs[i].is_none() && rhs[i].is_some() {
            lhs[i] = rhs[i];
        }
    }
}

/// Small-input fallback. NOT arkworks' `msm_unchecked`: ark's parallel MSM builds a brand-new
/// rayon thread pool per chunk per call (`msm_chunks` in ark-ec) — 1,526 thread spawns per chonk
/// proof, which costs ~0.75s of clone() natively and multiplies under wasm-on-workers runtimes
/// where a thread is a web worker. A plain serial Pippenger per chunk on the global pool does
/// the same math with zero pool churn.
fn small_msm<P: SWCurveConfig>(points: &[Affine<P>], scalars: &[P::ScalarField]) -> Projective<P> {
    let n = points.len().min(scalars.len());
    if n == 0 {
        return Projective::<P>::zero();
    }
    let threads = rayon::current_num_threads().clamp(1, n.div_ceil(64));
    if threads == 1 {
        return serial_pippenger(&points[..n], &scalars[..n]);
    }
    let chunk = n.div_ceil(threads);
    points[..n]
        .par_chunks(chunk)
        .zip(scalars[..n].par_chunks(chunk))
        .map(|(p, s)| serial_pippenger(p, s))
        .sum()
}

/// Textbook unsigned-window Pippenger, single-threaded, Jacobian buckets.
fn serial_pippenger<P: SWCurveConfig>(points: &[Affine<P>], scalars: &[P::ScalarField]) -> Projective<P> {
    let n = points.len();
    let c = if n < 32 { 3 } else { (n.ilog2() as usize * 69 / 100) + 2 };
    let num_windows = 256usize.div_ceil(c);
    let mut window_sums = Vec::with_capacity(num_windows);
    let mut buckets: Vec<Projective<P>> = vec![Projective::<P>::zero(); (1 << c) - 1];
    for w in 0..num_windows {
        for b in buckets.iter_mut() {
            *b = Projective::<P>::zero();
        }
        for (p, s) in points.iter().zip(scalars) {
            let limbs = s.into_bigint();
            let d = extract_bits(limbs.as_ref(), w * c, c) as usize;
            if d != 0 {
                buckets[d - 1] += p;
            }
        }
        let mut running = Projective::<P>::zero();
        let mut acc = Projective::<P>::zero();
        for b in buckets.iter().rev() {
            running += b;
            acc += &running;
        }
        window_sums.push(acc);
    }
    let mut total = Projective::<P>::zero();
    for w in (0..num_windows).rev() {
        for _ in 0..c {
            total.double_in_place();
        }
        total += &window_sums[w];
    }
    total
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::VariableBaseMSM;
    use ark_ff::UniformRand;

    fn check<P: SWCurveConfig>(n: usize, tweak: impl Fn(&mut Vec<Affine<P>>, &mut Vec<P::ScalarField>))
    where
        P::BaseField: crate::honk::quadf::QuadConsts + crate::base::endo::EndoField,
        P::ScalarField: crate::base::endo::EndoField,
    {
        let mut rng = ark_std::test_rng();
        let mut points =
            Projective::<P>::normalize_batch(&(0..n).map(|_| Projective::<P>::rand(&mut rng)).collect::<Vec<_>>());
        let mut scalars: Vec<P::ScalarField> = (0..n).map(|_| P::ScalarField::rand(&mut rng)).collect();
        tweak(&mut points, &mut scalars);
        assert_eq!(
            msm(&points, &scalars),
            Projective::<P>::msm_unchecked(&points, &scalars),
            "n={n}"
        );
    }

    #[test]
    fn matches_ark() {
        for n in [1, 100, 1000, 5000, 70000] {
            check::<ark_bn254::g1::Config>(n, |_, _| ());
            check::<ark_grumpkin::GrumpkinConfig>(n, |_, _| ());
        }
    }

    #[test]
    fn edge_cases() {
        // Zero scalars, tiny scalars, duplicate points (equal pairs in one bucket), inverse points,
        // and infinity inputs must all agree with ark.
        check::<ark_bn254::g1::Config>(1000, |points, scalars| {
            for i in 0..200 {
                scalars[i] = ark_ff::Zero::zero();
            }
            for i in 200..300 {
                scalars[i] = ark_bn254::Fr::from((i % 7) as u64);
            }
            for i in 300..400 {
                points[i] = points[0];
                scalars[i] = scalars[0];
            }
            for i in 400..450 {
                points[i] = -points[1];
                scalars[i] = scalars[1];
            }
            for i in 450..470 {
                points[i] = AffineRepr::zero();
            }
        });
    }
}

/// The MSM entry point for code generic over `AffineRepr` (the commitment key).
pub trait BatchMsm: AffineRepr {
    fn batch_msm(points: &[Self], scalars: &[Self::ScalarField]) -> Self::Group;
    /// `batch_msm` with a precomputed endomorphism table covering `points`.
    fn batch_msm_with_phi(points: &[Self], scalars: &[Self::ScalarField], phi: Option<&[Self]>) -> Self::Group;
    /// The GLV companion table `phi[i] = (beta * x_i, -y_i)`.
    fn phi_table(points: &[Self]) -> Vec<Self>;
}

impl<P: SWCurveConfig> BatchMsm for Affine<P>
where
    P::BaseField: crate::honk::quadf::QuadConsts + crate::base::endo::EndoField,
    P::ScalarField: crate::base::endo::EndoField,
{
    fn batch_msm(points: &[Self], scalars: &[Self::ScalarField]) -> Projective<P> {
        msm(points, scalars)
    }
    fn batch_msm_with_phi(points: &[Self], scalars: &[Self::ScalarField], phi: Option<&[Self]>) -> Projective<P> {
        msm_with_phi(points, scalars, phi)
    }
    fn phi_table(points: &[Self]) -> Vec<Self> {
        let beta = <P::BaseField as crate::base::endo::EndoField>::cube_root();
        points
            .par_iter()
            .map(|p| {
                if p.is_zero() {
                    *p
                } else {
                    Affine::<P>::new_unchecked(beta * p.x, -p.y)
                }
            })
            .collect()
    }
}
