//! Pippenger MSM with batched-affine bucket accumulation (bb `scalar_multiplication_fast`, minimal
//! port: signed Booth digits, counting-sort schedules, pair tree-reduction sharing one Montgomery
//! inversion per batch, segmented running-sum bucket reduce; no GLV, no dedup pre-pass).
//!
//! Affine addition costs ~6 muls plus an amortized share of one inversion, against ~14 for the
//! Jacobian adds inside arkworks' `msm_unchecked` — that difference is most of bb's MSM advantage.
//! Unlike bb's unsafe path this handles equal, inverse, and infinity pairs exactly, so it serves
//! verifier-side batch_muls as well as SRS commitments.

use ark_ec::short_weierstrass::{Affine, Projective, SWCurveConfig};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{AdditiveGroup, Field, PrimeField, Zero};
use rayon::prelude::*;

/// Minimum chunk size for the stage-4 tree jobs.

/// Points per thread below which arkworks' MSM wins: the batched-affine advantage needs enough
/// points per bucket, and the schedule machinery has fixed costs. Swept on the canonical wasm
/// flow (BBREF_MSM_MIN_PTS 128/32/8/4/2/1 -> 6.05/6.02/5.94/5.97/5.97/5.94 s): the packed
/// pippenger wins down to tiny sizes, plateauing at 8.
const MIN_PTS_PER_THREAD: usize = 8;

/// In-place batched inversion of nonzero elements (Montgomery's trick), with the prefix-product
/// scratch reused across calls. ark's `serial_batch_inversion_and_mul` allocates its scratch and
/// filters zeros on every call; the tree denominators are nonzero by construction and this runs
/// tens of millions of elements per prove.
pub(crate) fn batch_invert_nonzero<F: ark_ff::Field>(v: &mut [F], prod: &mut Vec<F>) {
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
    P::BaseField: crate::base::wasm::QuadConsts + crate::base::endo::EndoField,
    P::ScalarField: crate::base::endo::EndoField,
{
    msm_with_phi(points, scalars, None)
}

/// bb `GLV_SMALL_N_THRESHOLD`: above this many points the doubled point count (2n gathers, 2n
/// schedule entries) outweighs halving the windows, so the MSM runs on full-width scalars
/// instead (and never reads a φ table). The crossover is platform-specific: measured at 2^16 on
/// wasm; natively at 2^12 (8t, bbbench: full-width 2^13 3.59 -> 3.41 ms and 2^15 10.3 -> 9.2 ms
/// without GLV on the IFMA drain, neutral without IFMA). bb's own constants are 2^16 / 2^13.
/// BBREF_GLV_LOG2 overrides.
pub fn glv_threshold() -> usize {
    static GLV_LOG2: std::sync::OnceLock<u32> = std::sync::OnceLock::new();
    1usize
        << *GLV_LOG2.get_or_init(|| {
            std::env::var("BBREF_GLV_LOG2")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(crate::base::wasm::MSM_DEFAULT_LOG2)
        })
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
    P::BaseField: crate::base::wasm::QuadConsts + crate::base::endo::EndoField,
    P::ScalarField: crate::base::endo::EndoField,
{
    crate::scope!("MSM::batch_multi_scalar_mul");
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
    let full: Vec<[u64; 4]> = scalars[..n].par_iter().map(|s| s.into_bigint().0).collect();
    // Scalars of at most 128 bits already have GLV's window count: splitting only doubles the points.
    let use_glv = n <= glv_threshold() && full.iter().any(|k| k[2] | k[3] != 0);
    // Working sub-scalars: GLV gives two 128-bit halves per point (k1 against P, k2 against the
    // endomorphism image), otherwise one full-width scalar per point.
    let subs: Vec<([u64; 2], [u64; 2])> = if use_glv {
        scalars[..n].par_iter().map(crate::base::endo::glv_split).collect()
    } else {
        Vec::new()
    };
    // bb Phase 1 scalar profile: the window count tracks the largest *actual* working scalar
    // (not the nominal bound) and the window size is chosen for the *nonzero* working scalar
    // count. Commit polynomials are full of short scalars (selectors, small witness values),
    // for which this cuts the rounds — and every per-round pass — several-fold.
    let bit_len = |l: &[u64]| -> usize {
        for (k, limb) in l.iter().enumerate().rev() {
            if *limb != 0 {
                return 64 * k + (64 - limb.leading_zeros() as usize);
            }
        }
        0
    };
    let (effective_bits, n_active) = if use_glv {
        subs.par_iter()
            .map(|(k1, k2)| {
                let (b1, b2) = (bit_len(k1), bit_len(k2));
                (b1.max(b2), (b1 != 0) as usize + (b2 != 0) as usize)
            })
            .reduce(|| (0usize, 0usize), |a, b| (a.0.max(b.0), a.1 + b.1))
    } else {
        full.par_iter()
            .map(|k| {
                let b = bit_len(k);
                (b, (b != 0) as usize)
            })
            .reduce(|| (0usize, 0usize), |a, b| (a.0.max(b.0), a.1 + b.1))
    };
    if n_active == 0 {
        return Projective::<P>::zero();
    }
    let c = choose_window_bits(n_active, effective_bits);
    let half = 1usize << (c - 1);
    // Carry-Booth recoding over uniform c-bit windows needs `windows * c >= bits + 1` so the
    // final carry out is zero (bb's Constantine recoder budgets bits + 2 for the same reason).
    let num_windows = (effective_bits + 1).div_ceil(c);

    // bb's stage layout: every O(n) pass is parallel across scalar-range tasks, windows together.
    // Digits are decoded twice (count pass, scatter pass) instead of materialized — cheaper than
    // streaming an n x windows matrix through memory.
    let tasks = rayon::current_num_threads().clamp(1, n.div_ceil(2048));
    let task_ranges: Vec<std::ops::Range<usize>> = (0..tasks)
        .map(|t| t * n.div_ceil(tasks)..((t + 1) * n.div_ceil(tasks)).min(n))
        .collect();
    let stride = half + 1; // per-window histogram row: bucket magnitudes 1..=half
    fn decode(limbs: &[u64], c: usize, half: usize, num_windows: usize, mut f: impl FnMut(usize, i32)) {
        if limbs.iter().all(|&l| l == 0) {
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

    // Scope names mirror bb's `MSM::*` BB_BENCH scopes so the two phase tables line up.
    let sched_scope = crate::base::bench::Scope::new("MSM::build_point_schedule");

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
                    let mut bump = |w: usize, d: i32| unsafe {
                        *ptr.0.add(cell(t, w, d.unsigned_abs() as usize)) += 1;
                    };
                    if use_glv {
                        decode(&subs[i].0, c, half, num_windows, &mut bump);
                        decode(&subs[i].1, c, half, num_windows, &mut bump);
                    } else {
                        decode(&full[i], c, half, num_windows, &mut bump);
                    }
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
                    if use_glv {
                        decode(&subs[i].0, c, half, num_windows, scatter(0));
                        decode(&subs[i].1, c, half, num_windows, scatter(PHI));
                    } else {
                        decode(&full[i], c, half, num_windows, scatter(0));
                    }
                }
            }
        });
    }

    mark("3 scatter");
    drop(sched_scope);
    // Digits, histograms and cursors are dead once scattered; only the schedules feed the tree.
    drop((full, subs, counts));
    let bucket_scope = crate::base::bench::Scope::new("MSM::batch_accumulate_into_buckets");
    if std::env::var_os("BBREF_MSM_STATS").is_some() {
        let entries: usize = schedules.iter().map(|s| s.len()).sum();
        eprintln!(
            "[msm-stats] n={n} active={n_active} bits={effective_bits} c={c} windows={num_windows} entries={entries}"
        );
    }
    // bb Stage 5: each window's schedule is cut into `threads` chunks by schedule index and every
    // chunk's bucket range [lo, hi] is recorded (a bucket run straddling a cut yields one partial on
    // each side; Stage 6b merges them). Entry `pos` belongs to digit `partition_point(start <= pos)`
    // over the per-window bucket offsets, digits numbered 1..=half.
    let threads = rayon::current_num_threads().max(1);
    let digit_of = |w: usize, pos: usize| -> usize { bucket_starts[w].partition_point(|&st| st as usize <= pos) };
    struct WinChunks {
        start: Vec<usize>,
        lo: Vec<usize>,
        hi: Vec<usize>,
    }
    let chunks: Vec<WinChunks> = (0..num_windows)
        .map(|w| {
            let m = window_len(w);
            let mut start = vec![0usize; threads + 1];
            let (mut lo, mut hi) = (vec![half + 1; threads], vec![0usize; threads]);
            for t in 0..threads {
                start[t] = t * m / threads;
            }
            start[threads] = m;
            for t in 0..threads {
                if start[t] < start[t + 1] {
                    lo[t] = digit_of(w, start[t]);
                    hi[t] = digit_of(w, start[t + 1] - 1);
                }
            }
            WinChunks { start, lo, hi }
        })
        .collect();

    // bb Stage 6a: per thread and window, walk the chunk in sub-chunks, tree-reduce each (pairs
    // same-digit neighbours), and densify the survivors into a slot array indexed by digit − lo.
    // A slot already populated by an earlier sub-chunk (the digit's run was split) goes to an
    // overflow list that one tree reduce per window folds back in. Output: per-(thread, window)
    // dense partials with a presence bitmap — no second survivor tree per job or per window.
    const SUBCHUNK: usize = crate::base::wasm::MSM_SUBCHUNK;
    #[cfg(target_arch = "x86_64")]
    const GATHER_PREFETCH: usize = 16;
    struct Partial<P: SWCurveConfig> {
        lo: usize,
        dense: Vec<Affine<P>>,
        present: Vec<u8>,
    }
    let beta = <P::BaseField as crate::base::endo::EndoField>::cube_root();
    s6a_timing::reset();
    let partials: Vec<Vec<Partial<P>>> = (0..threads)
        .into_par_iter()
        .map(|t| {
            let mut block_p: Vec<Affine<P>> = Vec::with_capacity(SUBCHUNK);
            let mut run_id: Vec<u32> = Vec::with_capacity(SUBCHUNK);
            let mut run_len: Vec<u32> = Vec::with_capacity(SUBCHUNK);
            let mut scratch = TreeScratch::<P>::with_capacity(SUBCHUNK);
            (0..num_windows)
                .map(|w| {
                    let ch = &chunks[w];
                    let (cs_lo, cs_hi) = (ch.start[t], ch.start[t + 1]);
                    if cs_lo == cs_hi {
                        return Partial {
                            lo: 0,
                            dense: Vec::new(),
                            present: Vec::new(),
                        };
                    }
                    let (my_lo, my_hi) = (ch.lo[t], ch.hi[t]);
                    let width = my_hi - my_lo + 1;
                    let mut dense = vec![Affine::<P>::zero(); width];
                    let mut present = vec![0u8; width];
                    let mut overflow: Vec<(u32, Affine<P>)> = Vec::new();
                    let sched = &schedules[w];
                    let bs = &bucket_starts[w];
                    // 0-based bucket cursor: bs[b] <= pos < bs[b + 1]; the digit is b + 1.
                    let mut b = bs.partition_point(|&st| st as usize <= cs_lo) - 1;
                    let mut pos = cs_lo;
                    let (mut tg, mut tt, mut td) = (0u64, 0u64, 0u64);
                    let now = || std::time::Instant::now();
                    while pos < cs_hi {
                        let end = (pos + SUBCHUNK).min(cs_hi);
                        let t_g = timing.then(now);
                        block_p.clear();
                        run_id.clear();
                        run_len.clear();
                        let (mut cur, mut cnt) = (u32::MAX, 0u32);
                        for j in pos..end {
                            while bs[b + 1] as usize <= j {
                                b += 1;
                            }
                            // The point loads are random over the SRS; prefetching a few entries
                            // ahead keeps more of them in flight than the branchy loop does.
                            #[cfg(target_arch = "x86_64")]
                            if let Some(&f) = sched.get(j + GATHER_PREFETCH) {
                                let k = (f & 0x3fff_ffff) as usize;
                                let p = match phi_table {
                                    Some(tbl) if f & PHI != 0 => &tbl[k],
                                    _ => &points[k],
                                };
                                unsafe {
                                    use std::arch::x86_64::{_mm_prefetch, _MM_HINT_T0};
                                    _mm_prefetch(p as *const Affine<P> as *const i8, _MM_HINT_T0);
                                }
                            }
                            let e = sched[j];
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
                                    Some(tbl) => tbl[i],
                                    None => Affine::<P>::new_unchecked(beta * pt.x, -pt.y),
                                };
                            }
                            block_p.push(if e >> 31 == 1 { -pt } else { pt });
                        }
                        if cnt > 0 {
                            run_id.push(cur);
                            run_len.push(cnt);
                        }
                        if let Some(t) = t_g {
                            tg += t.elapsed().as_nanos() as u64;
                        }
                        let t_t = timing.then(now);
                        tree_reduce(&mut run_id, &mut run_len, &mut block_p, &mut scratch);
                        if let Some(t) = t_t {
                            tt += t.elapsed().as_nanos() as u64;
                        }
                        let t_d = timing.then(now);
                        let mut idx = 0;
                        for r in 0..run_id.len() {
                            for _ in 0..run_len[r] {
                                let slot = run_id[r] as usize + 1 - my_lo;
                                if present[slot] != 0 {
                                    overflow.push((slot as u32, block_p[idx]));
                                } else {
                                    dense[slot] = block_p[idx];
                                    present[slot] = 1;
                                }
                                idx += 1;
                            }
                        }
                        if let Some(t) = t_d {
                            td += t.elapsed().as_nanos() as u64;
                        }
                        pos = end;
                    }
                    // Overflow entries arrive slot-sorted (sub-chunks walk digits in order), so each
                    // slot's head + partials are consecutive: one tree reduce settles them all.
                    if !overflow.is_empty() {
                        block_p.clear();
                        run_id.clear();
                        run_len.clear();
                        let mut k = 0;
                        while k < overflow.len() {
                            let slot = overflow[k].0;
                            block_p.push(dense[slot as usize]);
                            let mut c = 1u32;
                            while k < overflow.len() && overflow[k].0 == slot {
                                block_p.push(overflow[k].1);
                                c += 1;
                                k += 1;
                            }
                            run_id.push(slot);
                            run_len.push(c);
                        }
                        tree_reduce(&mut run_id, &mut run_len, &mut block_p, &mut scratch);
                        let mut idx = 0;
                        for r in 0..run_id.len() {
                            for _ in 0..run_len[r] {
                                dense[run_id[r] as usize] = block_p[idx];
                                idx += 1;
                            }
                        }
                        // A slot whose entries cancelled to infinity has no survivor.
                        let mut seen = vec![false; width];
                        for &id in run_id.iter() {
                            seen[id as usize] = true;
                        }
                        for (slot, _) in overflow.iter() {
                            if !seen[*slot as usize] {
                                present[*slot as usize] = 0;
                            }
                        }
                    }
                    crate::base::msm::s6a_timing::add(tg, tt, td);
                    Partial {
                        lo: my_lo,
                        dense,
                        present,
                    }
                })
                .collect()
        })
        .collect();

    if timing {
        eprintln!("[msm 4a] {}", s6a_timing::report());
    }
    mark("4 tree");
    drop(bucket_scope);
    // Stage 6b reads only the partials: free the schedules before it allocates its columns.
    drop((schedules, chunks, bucket_starts));
    let reduce_scope = crate::base::bench::Scope::new("MSM::accumulate_buckets");
    // bb Stage 6b: rebalanced tasks own uniform digit ranges [lo_d, hi_d] over 1..=half. Each task
    // gathers the contributing threads' partials for every window into a column (SoA) layout with a
    // power-of-two stride (a seam digit shared by two threads is merged projectively), then runs
    // the recursive affine bucket reduction across all windows at once, giving each window's
    // (R = Σ B_d, L = Σ (d − lo + 1) B_d); the window's weighted sum is L + (lo − 1) R.
    let active_digits = half;
    let lo_part: Vec<usize> = (0..=threads).map(|t| 1 + t * active_digits / threads).collect();
    let max_per_task = (0..threads)
        .map(|t| lo_part[t + 1].saturating_sub(lo_part[t]))
        .max()
        .unwrap_or(1);
    let stride = max_per_task.max(2).next_power_of_two();
    let per_task: Vec<Vec<Projective<P>>> = (0..threads)
        .into_par_iter()
        .map(|tp| {
            let (lo_d, hi_d) = (lo_part[tp], lo_part[tp + 1] - 1);
            let mut sums = vec![Projective::<P>::zero(); num_windows];
            if lo_d > hi_d {
                return sums;
            }
            let mut dx = vec![P::BaseField::zero(); num_windows * stride];
            let mut dy = vec![P::BaseField::zero(); num_windows * stride];
            let mut present = vec![0u8; num_windows * stride];
            let mut infos: Vec<BucketChunkInfo> = vec![BucketChunkInfo::default(); num_windows];
            for w in 0..num_windows {
                let base = w * stride;
                let mut has = false;
                for t in 0..threads {
                    let pt = &partials[t][w];
                    if pt.present.is_empty() {
                        continue;
                    }
                    let (cl, ch) = (pt.lo, pt.lo + pt.dense.len() - 1);
                    let (dlo, dhi) = (lo_d.max(cl), hi_d.min(ch));
                    if dlo > dhi {
                        continue;
                    }
                    for d in dlo..=dhi {
                        let ss = d - cl;
                        if pt.present[ss] == 0 {
                            continue;
                        }
                        let ds = base + (d - lo_d);
                        if present[ds] == 0 {
                            dx[ds] = pt.dense[ss].x;
                            dy[ds] = pt.dense[ss].y;
                            present[ds] = 1;
                        } else {
                            let merged =
                                (Affine::<P>::new_unchecked(dx[ds], dy[ds]).into_group() + pt.dense[ss]).into_affine();
                            if merged.is_zero() {
                                present[ds] = 0;
                            } else {
                                dx[ds] = merged.x;
                                dy[ds] = merged.y;
                            }
                        }
                        has = true;
                    }
                }
                if has {
                    let m = hi_d - lo_d + 1;
                    infos[w] = BucketChunkInfo {
                        empty: false,
                        lo: lo_d as u32,
                        buckets_padded: m.max(1).next_power_of_two(),
                    };
                }
            }
            if infos.iter().all(|i| i.empty) {
                return sums;
            }
            let (rs, ls) = recursive_affine_bucket_reduce::<P>(&mut dx, &mut dy, &mut present, stride, &infos);
            for w in 0..num_windows {
                if infos[w].empty {
                    continue;
                }
                // chunk_contribution: L + (lo − 1)·R by double-and-add on the small factor.
                let mut acc = ls[w];
                let mut k = infos[w].lo - 1;
                let mut pw = rs[w];
                while k != 0 {
                    if k & 1 != 0 {
                        acc += pw;
                    }
                    k >>= 1;
                    if k != 0 {
                        pw.double_in_place();
                    }
                }
                sums[w] = acc;
            }
            sums
        })
        .collect();
    // bb Stage 7: per-window sum of the task partials.
    let window_sums: Vec<Projective<P>> = (0..num_windows)
        .map(|w| per_task.iter().fold(Projective::<P>::zero(), |a, s| a + s[w]))
        .collect();

    mark("5 bucketreduce");
    drop(reduce_scope);
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

/// Per-window metadata for `recursive_affine_bucket_reduce` (bb `AffineBucketChunkInfo`).
#[derive(Clone, Copy)]
struct BucketChunkInfo {
    empty: bool,
    lo: u32,
    buckets_padded: usize,
}
impl Default for BucketChunkInfo {
    fn default() -> Self {
        BucketChunkInfo {
            empty: true,
            lo: 0,
            buckets_padded: 0,
        }
    }
}

/// bb `try_filter_pair`: queue `dst += src` as a batched affine add unless it is an identity or
/// coincidence case, which are settled inline (copy / doubling / cancel to infinity).
#[inline(always)]
fn try_filter_pair<P: SWCurveConfig>(
    dx: &mut [P::BaseField],
    dy: &mut [P::BaseField],
    present: &mut [u8],
    dst: usize,
    src: usize,
    reals: &mut Vec<(u32, u32)>,
) {
    if present[src] == 0 {
        return;
    }
    if present[dst] == 0 {
        dx[dst] = dx[src];
        dy[dst] = dy[src];
        present[dst] = 1;
        return;
    }
    if dx[dst] == dx[src] {
        if dy[dst] == dy[src] {
            let d = Affine::<P>::new_unchecked(dx[dst], dy[dst])
                .into_group()
                .double()
                .into_affine();
            dx[dst] = d.x;
            dy[dst] = d.y;
        } else {
            present[dst] = 0;
        }
        return;
    }
    reals.push((dst as u32, src as u32));
}

/// bb `batch_affine_add_indexed_scalar`: `buckets[dst] += buckets[src]` over the column view for
/// every pair, one field inversion for the batch (Montgomery's trick). Pairs are pre-filtered:
/// distinct x, distinct dsts disjoint from srcs. With `chords` (AVX-512 IFMA) the pairs are
/// gathered into the eight-lane drain and the sums scattered back.
fn batch_affine_add_indexed<P: SWCurveConfig>(
    dx: &mut [P::BaseField],
    dy: &mut [P::BaseField],
    pairs: &[(u32, u32)],
    scratch: &mut Vec<P::BaseField>,
    chords: Option<&mut crate::base::ifma::Chords<P::BaseField>>,
) where
    P::BaseField: crate::base::field::NativeField,
{
    if pairs.is_empty() {
        return;
    }
    if let Some(q) = chords {
        q.clear();
        for &(d, sidx) in pairs {
            let (d, sidx) = (d as usize, sidx as usize);
            q.push(dx[sidx], dy[sidx], dx[d], dy[d]);
        }
        q.run(false);
        for (k, &(d, _)) in pairs.iter().enumerate() {
            (dx[d as usize], dy[d as usize]) = (q.ax[k], q.ay[k]);
        }
        return;
    }
    if crate::base::wasm::try_batch_add_indexed(dx, dy, pairs) {
        return;
    }
    scratch.clear();
    scratch.resize(pairs.len(), P::BaseField::zero());
    let mut acc = <P::BaseField as ark_ff::One>::one();
    for (i, &(d, sidx)) in pairs.iter().enumerate() {
        let (d, sidx) = (d as usize, sidx as usize);
        scratch[i] = dx[sidx] + dx[d];
        dx[d] -= dx[sidx];
        dy[d] -= dy[sidx];
        dy[d] *= acc;
        acc *= dx[d];
    }
    acc = acc.inverse().expect("batch_affine_add_indexed: zero denominator");
    for (i, &(d, sidx)) in pairs.iter().enumerate().rev() {
        let (d, sidx) = (d as usize, sidx as usize);
        dy[d] *= acc;
        acc *= dx[d];
        dx[d] = dy[d].square() - scratch[i];
        let tmp = (dx[sidx] - dx[d]) * dy[d];
        dy[d] = tmp - dy[sidx];
    }
}

/// bb `batch_affine_double_indexed_scalar`: `buckets[i] = 2 buckets[i]` for every index, one
/// inversion for the batch. Indices are pre-filtered (present, distinct).
fn batch_affine_double_indexed<P: SWCurveConfig>(
    dx: &mut [P::BaseField],
    dy: &mut [P::BaseField],
    idx: &[u32],
    scratch: &mut Vec<P::BaseField>,
) where
    P::BaseField: crate::base::field::NativeField,
{
    if idx.is_empty() || crate::base::wasm::try_batch_double_indexed(dx, dy, idx) {
        return;
    }
    scratch.clear();
    scratch.resize(idx.len(), P::BaseField::zero());
    let mut acc = <P::BaseField as ark_ff::One>::one();
    for (i, &k) in idx.iter().enumerate() {
        let k = k as usize;
        let xx = dx[k].square();
        scratch[i] = (xx + xx + xx) * acc;
        acc *= dy[k].double();
    }
    acc = acc.inverse().expect("batch_affine_double_indexed: zero denominator");
    for (i, &k) in idx.iter().enumerate().rev() {
        let k = k as usize;
        scratch[i] *= acc;
        acc *= dy[k].double();
        let tx = dx[k];
        dx[k] = scratch[i].square() - dx[k].double();
        dy[k] = scratch[i] * (tx - dx[k]) - dy[k];
    }
}

/// bb `recursive_affine_bucket_reduce_strided` (Mitschabaude, ZPrize 2022): for every window's
/// dense slot row `[w*stride, w*stride + buckets_padded)` compute `R = Σ_d B_d` and
/// `L = Σ_d (d − lo + 1) B_d` with batched affine adds/doublings shared across all windows at
/// each step. Phase A: suffix sums within sub-partitions of length L0; B: log-recombine the
/// sub-partition sums into slot 0 (= R); C: doublings priming D; D: flat tree-add to slot 0 (= L),
/// finishing in Jacobian once a level's batch would be smaller than the inversion is worth.
fn recursive_affine_bucket_reduce<P: SWCurveConfig>(
    dx: &mut [P::BaseField],
    dy: &mut [P::BaseField],
    present: &mut [u8],
    stride: usize,
    infos: &[BucketChunkInfo],
) -> (Vec<Projective<P>>, Vec<Projective<P>>)
where
    P::BaseField: crate::base::field::NativeField,
{
    let nw = infos.len();
    let mut rs = vec![Projective::<P>::zero(); nw];
    let mut ls = vec![Projective::<P>::zero(); nw];
    let pt = |dx: &[P::BaseField], dy: &[P::BaseField], i: usize| Affine::<P>::new_unchecked(dx[i], dy[i]).into_group();
    if stride <= 2 {
        for w in 0..nw {
            if infos[w].empty {
                continue;
            }
            let base = w * stride;
            for i in 0..infos[w].buckets_padded {
                if present[base + i] == 0 {
                    continue;
                }
                let p = pt(dx, dy, base + i);
                rs[w] += p;
                ls[w] += p;
                if i == 1 {
                    ls[w] += p;
                }
            }
        }
        return (rs, ls);
    }
    let c_log = stride.trailing_zeros() as usize;
    let c0 = (c_log / 2).clamp(1, c_log - 1);
    let l0 = 1usize << c0;
    let mut reals: Vec<(u32, u32)> = Vec::new();
    let mut dbls: Vec<u32> = Vec::new();
    let mut scratch: Vec<P::BaseField> = Vec::new();
    let mut chords = crate::base::ifma::available::<P::BaseField>().then(crate::base::ifma::Chords::default);
    // Phase A: per-sub-partition suffix sums.
    for l in (1..l0).rev() {
        reals.clear();
        for w in 0..nw {
            if infos[w].empty {
                continue;
            }
            let (m, base) = (infos[w].buckets_padded, w * stride);
            if m < l0 {
                if l < m {
                    try_filter_pair::<P>(dx, dy, present, base + l - 1, base + l, &mut reals);
                }
            } else {
                for d in 0..(m >> c0) {
                    try_filter_pair::<P>(dx, dy, present, base + d * l0 + l - 1, base + d * l0 + l, &mut reals);
                }
            }
        }
        batch_affine_add_indexed::<P>(dx, dy, &reals, &mut scratch, chords.as_mut());
    }
    // Phase B: log-recombine sub-partition sums into slot 0.
    let mut l1 = l0;
    while l1 < stride {
        reals.clear();
        let step = 2 * l1;
        for w in 0..nw {
            if infos[w].empty || step > infos[w].buckets_padded {
                continue;
            }
            let base = w * stride;
            for d in 0..(infos[w].buckets_padded / step) {
                try_filter_pair::<P>(dx, dy, present, base + 2 * d * l1, base + (2 * d + 1) * l1, &mut reals);
            }
        }
        batch_affine_add_indexed::<P>(dx, dy, &reals, &mut scratch, chords.as_mut());
        l1 *= 2;
    }
    for w in 0..nw {
        if !infos[w].empty && present[w * stride] != 0 {
            rs[w] = pt(dx, dy, w * stride);
        }
    }
    // Phase C: doublings — c0 chained on every slot d*l0 (d >= 1), then one per hierarchy level.
    dbls.clear();
    for w in 0..nw {
        if infos[w].empty {
            continue;
        }
        let (m, base) = (infos[w].buckets_padded, w * stride);
        let my_d = if m >= l0 { m >> c0 } else { 0 };
        for d in 1..my_d {
            if present[base + d * l0] != 0 {
                dbls.push((base + d * l0) as u32);
            }
        }
    }
    if !dbls.is_empty() {
        for _ in 0..c0 {
            batch_affine_double_indexed::<P>(dx, dy, &dbls, &mut scratch);
        }
    }
    let mut l1 = 2 * l0;
    while l1 < stride {
        dbls.clear();
        for w in 0..nw {
            if infos[w].empty || l1 >= infos[w].buckets_padded {
                continue;
            }
            let base = w * stride;
            for d in 1..(infos[w].buckets_padded / l1) {
                if present[base + d * l1] != 0 {
                    dbls.push((base + d * l1) as u32);
                }
            }
        }
        batch_affine_double_indexed::<P>(dx, dy, &dbls, &mut scratch);
        l1 *= 2;
    }
    // Phase D: flat tree-add; bail to Jacobian when a level's batch drops below the breakeven.
    const BATCH_AFFINE_BREAKEVEN: usize = 32;
    let mut m = 1usize;
    while m < stride {
        if nw * (stride / (2 * m)) < BATCH_AFFINE_BREAKEVEN {
            break;
        }
        reals.clear();
        let step = 2 * m;
        for w in 0..nw {
            if infos[w].empty || m >= infos[w].buckets_padded {
                continue;
            }
            let base = w * stride;
            let mut pos = 0;
            while pos + m < infos[w].buckets_padded {
                try_filter_pair::<P>(dx, dy, present, base + pos, base + pos + m, &mut reals);
                pos += step;
            }
        }
        batch_affine_add_indexed::<P>(dx, dy, &reals, &mut scratch, chords.as_mut());
        m *= 2;
    }
    for w in 0..nw {
        if infos[w].empty {
            continue;
        }
        let base = w * stride;
        let mut pos = 0;
        while pos < infos[w].buckets_padded {
            if present[base + pos] != 0 {
                ls[w] += pt(dx, dy, base + pos);
            }
            pos += m;
        }
    }
    (rs, ls)
}

/// bb `choose_window_bits`: minimize `rounds * (4 * n_active + 12 * buckets)` with
/// `rounds = ceil((num_bits + 2) / c)` and `buckets = 2^(c-1) + 1` (signed digits halve the
/// bucket count), c in [2, 20). The 12/4 weight prices a bucket at ~3 point visits.
fn choose_window_bits(n_active: usize, num_bits: usize) -> usize {
    (2..20)
        .min_by_key(|&c| {
            let rounds = (num_bits + 2).div_ceil(c) as u64;
            let buckets = (1u64 << (c - 1)) + 1;
            rounds * (4 * n_active as u64 + 12 * buckets)
        })
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
/// the scalar tree and the packed tree's scalar tail; `packed` is the wasm+simd128 staging (an
/// empty stand-in elsewhere); `chords` the scalar tree's AVX-512 IFMA queue where available.
pub(crate) struct TreeScratch<P: SWCurveConfig> {
    dens: Vec<P::BaseField>,
    prod: Vec<P::BaseField>,
    packed: crate::base::wasm::PackedTree<P>,
    chords: Option<crate::base::ifma::Chords<P::BaseField>>,
}

impl<P: SWCurveConfig> TreeScratch<P>
where
    P::BaseField: crate::base::wasm::QuadConsts,
{
    fn with_capacity(cap: usize) -> Self {
        TreeScratch {
            dens: Vec::with_capacity(cap),
            prod: Vec::with_capacity(cap),
            packed: crate::base::wasm::PackedTree::with_capacity(cap),
            chords: crate::base::ifma::available::<P::BaseField>().then(Default::default),
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
    P::BaseField: crate::base::wasm::QuadConsts,
{
    if !s.packed.try_reduce(run_id, run_len, ps, &mut s.dens, &mut s.prod) {
        tree_reduce_scalar(run_id, run_len, ps, &mut s.dens, &mut s.prod, s.chords.as_mut());
    }
}

/// One point per run of consecutive `ps` (`run_len[r]` points each; the identity where a run
/// cancels): batched-affine tree reductions over fixed-size pieces in parallel (a run cut by a
/// piece boundary leaves a partial on each side), then one more over the pieces' survivors.
fn sum_runs<P: SWCurveConfig>(ps: &[Affine<P>], run_len: &[u32]) -> Vec<Affine<P>>
where
    P::BaseField: crate::base::wasm::QuadConsts,
{
    const PIECE: usize = 4096;
    let mut run_start = Vec::with_capacity(run_len.len() + 1);
    run_start.push(0usize);
    for &l in run_len {
        run_start.push(run_start.last().unwrap() + l as usize);
    }
    assert_eq!(*run_start.last().unwrap(), ps.len());
    let reduce = |ids: &mut Vec<u32>, lens: &mut Vec<u32>, pts: &mut Vec<Affine<P>>| {
        tree_reduce(ids, lens, pts, &mut TreeScratch::with_capacity(pts.len()));
    };
    let partials: Vec<(Vec<u32>, Vec<Affine<P>>)> = (0..ps.len().div_ceil(PIECE))
        .into_par_iter()
        .map(|k| {
            let (lo, hi) = (k * PIECE, ((k + 1) * PIECE).min(ps.len()));
            let (mut ids, mut lens) = (Vec::new(), Vec::new());
            let mut r = run_start.partition_point(|&st| st <= lo) - 1;
            while run_start[r] < hi {
                ids.push(r as u32);
                lens.push((run_start[r + 1].min(hi) - run_start[r].max(lo)) as u32);
                r += 1;
            }
            let mut pts = ps[lo..hi].to_vec();
            reduce(&mut ids, &mut lens, &mut pts);
            (ids, pts)
        })
        .collect();
    let (mut ids, mut lens, mut pts) = (Vec::new(), Vec::new(), Vec::new());
    for (pid, pp) in partials {
        for (i, p) in pid.into_iter().zip(pp) {
            if ids.last() == Some(&i) {
                *lens.last_mut().unwrap() += 1;
            } else {
                ids.push(i);
                lens.push(1);
            }
            pts.push(p);
        }
    }
    reduce(&mut ids, &mut lens, &mut pts);
    let mut out = vec![Affine::<P>::zero(); run_len.len()];
    for (i, p) in ids.into_iter().zip(pts) {
        out[i as usize] = p;
    }
    out
}

/// The scalar tree level loop (see `tree_reduce`): the same-bucket runs are described by the
/// parallel `run_id`/`run_len` arrays and updated arithmetically, so the inner loops never touch
/// per-element bucket ids — no id compares, no id compaction, no tag lists (a pair's
/// chord/double/infinity case is re-derived from the coordinates in the apply pass). Sequential:
/// the caller's schedule chunks are the parallel unit. With `chords` (AVX-512 IFMA), the chord
/// additions run eight lanes wide in `ifma::Chords::run` and only doublings take the scalar pass.
fn tree_reduce_scalar<P: SWCurveConfig>(
    run_id: &mut Vec<u32>,
    run_len: &mut Vec<u32>,
    ps: &mut Vec<Affine<P>>,
    dens: &mut Vec<P::BaseField>,
    prod: &mut Vec<P::BaseField>,
    mut chords: Option<&mut crate::base::ifma::Chords<P::BaseField>>,
) where
    P::BaseField: crate::base::field::NativeField,
{
    loop {
        // Pass 1: denominators for every adjacent same-bucket pair, positions implicit.
        dens.clear();
        if let Some(q) = chords.as_mut() {
            q.clear();
        }
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
                } else if let Some(q) = chords.as_mut() {
                    q.push(a.x, a.y, b.x, b.y);
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
        if let Some(q) = chords.as_mut() {
            q.run(false);
        }
        let mut chord = 0;
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
                if let (Some(q), false) = (chords.as_ref(), ax == bx) {
                    (ps[out].x, ps[out].y) = (q.ax[chord], q.ay[chord]);
                    chord += 1;
                    out += 1;
                    new_k += 1;
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
/// Stage 6a sub-timing (BBREF_MSM_TIMING): gather / tree_reduce / densify nanoseconds summed
/// across workers, printed from the driver at the "4 tree" mark.
pub mod s6a_timing {
    use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
    pub static GATHER: AtomicU64 = AtomicU64::new(0);
    pub static TREE: AtomicU64 = AtomicU64::new(0);
    pub static DENSIFY: AtomicU64 = AtomicU64::new(0);
    pub fn reset() {
        GATHER.store(0, Relaxed);
        TREE.store(0, Relaxed);
        DENSIFY.store(0, Relaxed);
    }
    pub fn add(g: u64, t: u64, d: u64) {
        GATHER.fetch_add(g, Relaxed);
        TREE.fetch_add(t, Relaxed);
        DENSIFY.fetch_add(d, Relaxed);
    }
    pub fn report() -> String {
        format!(
            "gather {:.0}ms tree {:.0}ms densify {:.0}ms (sum over workers)",
            GATHER.load(Relaxed) as f64 / 1e6,
            TREE.load(Relaxed) as f64 / 1e6,
            DENSIFY.load(Relaxed) as f64 / 1e6
        )
    }
}


/// `sum_b (b+1) * B_b` over singleton buckets: segmented double running sums, the affine chain
/// steps batched across segments, segment totals recombined in projective.

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
    // Pippenger's per-window cost (bucket reset, reduction, c doublings) is paid 86 times at c = 3,
    // which is ~1ms even for a handful of points; the flow commits hundreds of such polynomials.
    // A shared doubling chain with a per-point wNAF table is O(254 + n*~50) group ops instead.
    if n <= tiny_msm_max() {
        return tiny_msm_wnaf(&points[..n], &scalars[..n]);
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

fn tiny_msm_max() -> usize {
    static V: std::sync::LazyLock<usize> = std::sync::LazyLock::new(|| {
        std::env::var("BBREF_TINY_MSM_MAX").ok().and_then(|s| s.parse().ok()).unwrap_or(128)
    });
    *V
}

/// Width-5 wNAF over every point with one shared doubling chain: 254 doublings plus, per point,
/// 8 odd multiples and ~51 signed additions. Exact for scalars up to 256 bits.
fn tiny_msm_wnaf<P: SWCurveConfig>(points: &[Affine<P>], scalars: &[P::ScalarField]) -> Projective<P> {
    const W: usize = 5;
    let n = points.len();
    // Odd multiples 1P, 3P, ..., 15P per point.
    let tables: Vec<[Projective<P>; 8]> = points
        .iter()
        .map(|p| {
            let p1: Projective<P> = (*p).into();
            let p2 = p1.double();
            let mut t = [p1; 8];
            for i in 1..8 {
                t[i] = t[i - 1] + p2;
            }
            t
        })
        .collect();
    // wNAF digits, most significant first, as (position, signed digit) lists per point.
    let mut digits: Vec<Vec<i8>> = Vec::with_capacity(n);
    let mut max_len = 0usize;
    for s in scalars {
        let mut limbs: Vec<u64> = s.into_bigint().as_ref().to_vec();
        let mut out: Vec<i8> = Vec::with_capacity(260);
        let is_zero = |l: &[u64]| l.iter().all(|&x| x == 0);
        let shr1 = |l: &mut [u64]| {
            for i in 0..l.len() {
                let hi = if i + 1 < l.len() { l[i + 1] << 63 } else { 0 };
                l[i] = (l[i] >> 1) | hi;
            }
        };
        let sub_small = |l: &mut [u64], v: u64| {
            let (r, b) = l[0].overflowing_sub(v);
            l[0] = r;
            let mut borrow = b;
            let mut i = 1;
            while borrow && i < l.len() {
                let (r, b) = l[i].overflowing_sub(1);
                l[i] = r;
                borrow = b;
                i += 1;
            }
        };
        let add_small = |l: &mut [u64], v: u64| {
            let (r, c) = l[0].overflowing_add(v);
            l[0] = r;
            let mut carry = c;
            let mut i = 1;
            while carry && i < l.len() {
                let (r, c) = l[i].overflowing_add(1);
                l[i] = r;
                carry = c;
                i += 1;
            }
        };
        while !is_zero(&limbs) {
            if limbs[0] & 1 == 1 {
                let m = (limbs[0] & ((1 << W) - 1)) as i64;
                let d = if m >= (1 << (W - 1)) { m - (1 << W) } else { m };
                if d > 0 {
                    sub_small(&mut limbs, d as u64);
                } else {
                    add_small(&mut limbs, (-d) as u64);
                }
                out.push(d as i8);
            } else {
                out.push(0);
            }
            shr1(&mut limbs);
        }
        max_len = max_len.max(out.len());
        digits.push(out);
    }
    let mut acc = Projective::<P>::zero();
    for pos in (0..max_len).rev() {
        acc.double_in_place();
        for (i, ds) in digits.iter().enumerate() {
            if let Some(&d) = ds.get(pos) {
                if d > 0 {
                    acc += &tables[i][(d as usize) / 2];
                } else if d < 0 {
                    acc -= &tables[i][((-d) as usize) / 2];
                }
            }
        }
    }
    acc
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
        P::BaseField: crate::base::wasm::QuadConsts + crate::base::endo::EndoField,
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

    /// Runs of every length, across piece boundaries, with repeated and cancelling points.
    #[test]
    fn sum_runs_matches_projective() {
        use crate::base::G1Config as C;
        let mut rng = ark_std::test_rng();
        let base: Vec<Affine<C>> = (0..64).map(|_| Projective::<C>::rand(&mut rng).into_affine()).collect();
        let lens: Vec<u32> = [1u32, 2, 3, 5, 9000, 1, 4100, 7, 2, 2, 300].to_vec();
        let mut ps = Vec::new();
        for (r, &l) in lens.iter().enumerate() {
            for j in 0..l as usize {
                // Run 8: P, -P (cancels); run 9: P, P (doubling); others: mixed repeats.
                ps.push(match r {
                    8 => if j == 0 { base[0] } else { -base[0] },
                    9 => base[1],
                    _ => base[(j * 7 + r) % base.len()],
                });
            }
        }
        let sums = sum_runs(&ps, &lens);
        let mut at = 0;
        for (r, &l) in lens.iter().enumerate() {
            let want: Projective<C> = ps[at..at + l as usize].iter().map(|p| p.into_group()).sum();
            assert_eq!(sums[r], want.into_affine(), "run {r}");
            at += l as usize;
        }
    }

    #[test]
    fn matches_ark() {
        for n in [1, 100, 1000, 5000, 70000] {
            check::<crate::base::G1Config>(n, |_, _| ());
            check::<crate::base::GrumpkinConfig>(n, |_, _| ());
        }
    }

    #[test]
    fn edge_cases() {
        // Zero scalars, tiny scalars, duplicate points (equal pairs in one bucket), inverse points,
        // and infinity inputs must all agree with ark.
        check::<crate::base::G1Config>(1000, |points, scalars| {
            for i in 0..200 {
                scalars[i] = ark_ff::Zero::zero();
            }
            for i in 200..300 {
                scalars[i] = crate::base::Fr::from((i % 7) as u64);
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
    /// One sum per run of consecutive points (`sum_runs`).
    fn sum_runs(points: &[Self], run_len: &[u32]) -> Vec<Self>;
}

impl<P: SWCurveConfig> BatchMsm for Affine<P>
where
    P::BaseField: crate::base::wasm::QuadConsts + crate::base::endo::EndoField,
    P::ScalarField: crate::base::endo::EndoField,
{
    fn batch_msm(points: &[Self], scalars: &[Self::ScalarField]) -> Projective<P> {
        msm(points, scalars)
    }
    fn batch_msm_with_phi(points: &[Self], scalars: &[Self::ScalarField], phi: Option<&[Self]>) -> Projective<P> {
        msm_with_phi(points, scalars, phi)
    }
    fn sum_runs(points: &[Self], run_len: &[u32]) -> Vec<Self> {
        sum_runs(points, run_len)
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
