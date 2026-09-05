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
    // bb Phase 1 scalar profile: the window count tracks the largest *actual* working scalar
    // (not the 128-bit GLV bound) and the window size is chosen for the *nonzero* working
    // scalar count. Commit polynomials are full of short scalars (selectors, small witness
    // values), for which this cuts the rounds — and every per-round pass — several-fold.
    let bit_len = |l: &[u64; 2]| -> usize {
        if l[1] != 0 {
            128 - l[1].leading_zeros() as usize
        } else if l[0] != 0 {
            64 - l[0].leading_zeros() as usize
        } else {
            0
        }
    };
    let (effective_bits, n_active) = subs
        .par_iter()
        .map(|(k1, k2)| {
            let (b1, b2) = (bit_len(k1), bit_len(k2));
            (b1.max(b2), (b1 != 0) as usize + (b2 != 0) as usize)
        })
        .reduce(|| (0usize, 0usize), |a, b| (a.0.max(b.0), a.1 + b.1));
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
    const SUBCHUNK: usize = 2048;
    struct Partial<P: SWCurveConfig> {
        lo: usize,
        dense: Vec<Affine<P>>,
        present: Vec<u8>,
    }
    let beta = <P::BaseField as crate::base::endo::EndoField>::cube_root();
    #[cfg(all(feature = "bbkernel", target_family = "wasm", target_feature = "simd128"))]
    let bbk6a = {
        use crate::base::packed::bbk;
        use core::any::TypeId;
        type RC = unsafe extern "C" fn(
            *const u64,
            *const u64,
            *const u64,
            *const u32,
            usize,
            usize,
            *const u32,
            *mut usize,
            *mut u64,
            *mut u32,
            *mut u64,
            *mut u32,
        ) -> usize;
        type TR = unsafe extern "C" fn(*mut u64, *mut u32, usize, *mut u64, *mut u32) -> usize;
        if TypeId::of::<P::BaseField>() == TypeId::of::<crate::base::Fr>() {
            Some((bbk::bbref_reduce_chunk_fr as RC, bbk::bbref_tree_reduce_fr as TR))
        } else if TypeId::of::<P::BaseField>() == TypeId::of::<ark_bn254::Fq>() {
            Some((bbk::bbref_reduce_chunk_fq as RC, bbk::bbref_tree_reduce_fq as TR))
        } else {
            None
        }
    };
    s6a_timing::reset();
    let max_chunk_len = chunks
        .iter()
        .flat_map(|c| (0..threads).map(move |t| c.start[t + 1] - c.start[t]))
        .max()
        .unwrap_or(0);
    let partials: Vec<Vec<Partial<P>>> = (0..threads)
        .into_par_iter()
        .map(|t| {
            // bb's 6a inner loop, compiled from bb source and linked in: gather + tree_reduce +
            // batched-affine drain over bb's ThreadScratch shape, one call per sub-chunk. Only the
            // densify + overflow bookkeeping stays in Rust (bb keeps that in the same function; the
            // split is the linkage boundary, not an algorithmic change).
            #[cfg(all(feature = "bbkernel", target_family = "wasm", target_feature = "simd128"))]
            if let Some((rc, tr)) = if std::env::var_os("BBREF_NO_C6A").is_some() {
                None
            } else {
                bbk6a
            } {
                use crate::base::packed::bbk;
                let cap = SUBCHUNK.max(2 * (max_chunk_len / SUBCHUNK + 2));
                let mut cpts: Vec<Affine<P>> = vec![Affine::<P>::zero(); cap];
                let mut cbk: Vec<u32> = vec![0u32; cap];
                let (vf, pack_cap, bcap) =
                    unsafe { (bbk::bbref_vf_size(), bbk::bbref_pack_cap(), bbk::bbref_batch_capacity()) };
                let mut packed: Vec<core::mem::MaybeUninit<u64>> =
                    Vec::with_capacity((8 * pack_cap * vf).div_ceil(8) + 32);
                packed.resize((8 * pack_cap * vf).div_ceil(8) + 32, core::mem::MaybeUninit::uninit());
                let mut pair_dest: Vec<u32> = vec![0u32; bcap];
                let phi_ptr: *const u64 = match phi_table {
                    Some(tbl) => tbl.as_ptr() as *const u64,
                    None => core::ptr::null(),
                };
                let beta_v = <P::BaseField as crate::base::endo::EndoField>::cube_root();
                let beta_ptr = &beta_v as *const P::BaseField as *const u64;
                return (0..num_windows)
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
                        let bs = &bucket_starts[w];
                        let mut b: usize = bs.partition_point(|&st| st as usize <= cs_lo) - 1;
                        let mut pos = cs_lo;
                        while pos < cs_hi {
                            let end = (pos + SUBCHUNK).min(cs_hi);
                            let len = unsafe {
                                rc(
                                    points.as_ptr() as *const u64,
                                    phi_ptr,
                                    beta_ptr,
                                    schedules[w].as_ptr(),
                                    pos,
                                    end,
                                    bs.as_ptr(),
                                    &mut b,
                                    cpts.as_mut_ptr() as *mut u64,
                                    cbk.as_mut_ptr(),
                                    packed.as_mut_ptr() as *mut u64,
                                    pair_dest.as_mut_ptr(),
                                )
                            };
                            for k in 0..len {
                                let slot = cbk[k] as usize + 1 - my_lo;
                                if present[slot] != 0 {
                                    overflow.push((slot as u32, cpts[k]));
                                } else {
                                    dense[slot] = cpts[k];
                                    present[slot] = 1;
                                }
                            }
                            pos = end;
                        }
                        if !overflow.is_empty() {
                            let mut n = 0usize;
                            let mut k = 0;
                            while k < overflow.len() {
                                let slot = overflow[k].0;
                                cpts[n] = dense[slot as usize];
                                cbk[n] = slot;
                                n += 1;
                                while k < overflow.len() && overflow[k].0 == slot {
                                    cpts[n] = overflow[k].1;
                                    cbk[n] = slot;
                                    n += 1;
                                    k += 1;
                                }
                            }
                            let len = unsafe {
                                tr(
                                    cpts.as_mut_ptr() as *mut u64,
                                    cbk.as_mut_ptr(),
                                    n,
                                    packed.as_mut_ptr() as *mut u64,
                                    pair_dest.as_mut_ptr(),
                                )
                            };
                            let mut seen = vec![false; width];
                            for k in 0..len {
                                dense[cbk[k] as usize] = cpts[k];
                                seen[cbk[k] as usize] = true;
                            }
                            for (slot, _) in overflow.iter() {
                                if !seen[*slot as usize] {
                                    present[*slot as usize] = 0;
                                }
                            }
                        }
                        Partial {
                            lo: my_lo,
                            dense,
                            present,
                        }
                    })
                    .collect();
            }
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
/// distinct x, distinct dsts disjoint from srcs.
fn batch_affine_add_indexed<P: SWCurveConfig>(
    dx: &mut [P::BaseField],
    dy: &mut [P::BaseField],
    pairs: &[(u32, u32)],
    scratch: &mut Vec<P::BaseField>,
) {
    if pairs.is_empty() {
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
) {
    if idx.is_empty() {
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
) -> (Vec<Projective<P>>, Vec<Projective<P>>) {
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
        batch_affine_add_indexed::<P>(dx, dy, &reals, &mut scratch);
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
        batch_affine_add_indexed::<P>(dx, dy, &reals, &mut scratch);
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
        batch_affine_add_indexed::<P>(dx, dy, &reals, &mut scratch);
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
        // Opaque byte scratch for the C drain kernels (packed VectorFields); the kernel writes
        // every word before reading it, so growth is left uninitialized rather than filled.
        #[cfg(feature = "bbkernel")]
        cscratch: Vec<core::mem::MaybeUninit<u64>>,
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
        type C1 = unsafe extern "C" fn(*const u64, *const u64, *const u64, *const u64, usize, *mut u64, *mut u64);
        type C2 = unsafe extern "C" fn(usize, *mut u64, *const u64, *const u32, *mut u64);
        let (c1, c2): (C1, C2) = if TypeId::of::<P::BaseField>() == TypeId::of::<crate::base::Fr>() {
            (bbk::bbref_chord1p_fr, bbk::bbref_chord2p_fr)
        } else if TypeId::of::<P::BaseField>() == TypeId::of::<ark_bn254::Fq>() {
            (bbk::bbref_chord1p_fq, bbk::bbref_chord2p_fq)
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
            // Stream the level through the kernels in fixed chunks (bb's BATCH_CAPACITY shape):
            // one small scratch, allocated once and reused, stays cache-resident. A level-sized
            // scratch was 3.6x the old footprint and paid memory-growth/page-fault churn on every
            // rayon split — a flow loss the per-chord rung could not see. Six packed VectorFields
            // per W-block, sized from the kernel's own sizeof (the 5-wide VF carries a scalar lane
            // beside the four SIMD lanes).
            let batch = (4096 / w) * w;
            // Sized for this level's chunk, capped at the batch: small MSMs (the flow has
            // thousands) keep a small scratch; a fixed batch-sized buffer per TreeScratch paid
            // ~1 MB of first-touch page faults per instance.
            let words = (6 * (n.min(batch) / w) * unsafe { bbk::bbref_vf_size() }).div_ceil(8) + 32;
            if p.cscratch.len() < words {
                p.cscratch.resize(words, core::mem::MaybeUninit::uninit());
            }
            let mut lane: Vec<P::BaseField> = vec![p.ax[0]; w];
            let mut off = 0;
            while off < n {
                let m = batch.min(n - off);
                unsafe {
                    c1(
                        p.ax.as_ptr().add(off) as *const u64,
                        p.ay.as_ptr().add(off) as *const u64,
                        p.bx.as_ptr().add(off) as *const u64,
                        p.by.as_ptr().add(off) as *const u64,
                        m,
                        p.cscratch.as_mut_ptr() as *mut u64,
                        lane.as_mut_ptr() as *mut u64,
                    )
                };
                // One inversion per chunk: the w lane chain totals, batched.
                batch_invert_nonzero(&mut lane, &mut s.prod);
                // Phase 2 reads the packed intermediates and scatters {x3, y3} into ps by dest.
                unsafe {
                    c2(
                        m,
                        p.cscratch.as_mut_ptr() as *mut u64,
                        lane.as_ptr() as *const u64,
                        p.dest.as_ptr().add(off),
                        ps.as_mut_ptr() as *mut u64,
                    )
                };
                off += m;
            }
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

    /// Isolates bb's linked Stage-6a tree (`bbref_tree_reduce_*`) from the gather: build a
    /// bucket-sorted block of distinct points, reduce it with the C kernel, and compare each
    /// bucket's survivor against an ark sum.
    #[cfg(all(feature = "bbkernel", target_family = "wasm", target_feature = "simd128"))]
    #[test]
    fn c_tree_reduce_matches_ark() {
        use crate::base::packed::bbk;
        use ark_ec::CurveGroup;
        use ark_std::UniformRand;
        type P = ark_bn254::g1::Config;
        let mut rng = ark_std::test_rng();
        for &(nbuckets, per) in &[(1usize, 2usize), (1, 3), (3, 1), (5, 4), (7, 9), (13, 37), (2, 600)] {
            let mut pts: Vec<Affine<P>> = Vec::new();
            let mut bks: Vec<u32> = Vec::new();
            let mut expect: Vec<Projective<P>> = Vec::new();
            for b in 0..nbuckets {
                let mut acc = Projective::<P>::zero();
                for _ in 0..per {
                    let p = ark_bn254::G1Projective::rand(&mut rng).into_affine();
                    pts.push(p);
                    bks.push(b as u32);
                    acc += p;
                }
                expect.push(acc);
            }
            let n = pts.len();
            let (vf, pack_cap, bcap) =
                unsafe { (bbk::bbref_vf_size(), bbk::bbref_pack_cap(), bbk::bbref_batch_capacity()) };
            let mut packed: Vec<core::mem::MaybeUninit<u64>> =
                vec![core::mem::MaybeUninit::uninit(); (8 * pack_cap * vf).div_ceil(8) + 32];
            let mut pair_dest: Vec<u32> = vec![0u32; bcap];
            let len = unsafe {
                bbk::bbref_tree_reduce_fq(
                    pts.as_mut_ptr() as *mut u64,
                    bks.as_mut_ptr(),
                    n,
                    packed.as_mut_ptr() as *mut u64,
                    pair_dest.as_mut_ptr(),
                )
            };
            assert_eq!(len, nbuckets, "survivor count (nbuckets={nbuckets}, per={per})");
            for k in 0..len {
                assert_eq!(bks[k] as usize, k, "survivor bucket order");
                assert_eq!(
                    pts[k].into_group(),
                    expect[k],
                    "bucket {k} sum (nbuckets={nbuckets}, per={per})"
                );
            }
        }
    }

    /// Isolates bb's linked `bbref_reduce_chunk_*` gather: a hand-built bucket-sorted schedule
    /// over known points, with and without a phi table, compared against an ark reference that
    /// decodes the same entries.
    #[cfg(all(feature = "bbkernel", target_family = "wasm", target_feature = "simd128"))]
    #[test]
    fn c_reduce_chunk_gather_matches_ark() {
        use crate::base::endo::EndoField;
        use crate::base::packed::bbk;
        use ark_ec::CurveGroup;
        use ark_std::UniformRand;
        type P = ark_bn254::g1::Config;
        const PHI_BIT: u32 = 1 << 30;
        let mut rng = ark_std::test_rng();
        let npts = 64usize;
        let points: Vec<Affine<P>> = (0..npts)
            .map(|_| ark_bn254::G1Projective::rand(&mut rng).into_affine())
            .collect();
        let beta = <ark_bn254::Fq as EndoField>::cube_root();
        let phi: Vec<Affine<P>> = points
            .iter()
            .map(|p| Affine::<P>::new_unchecked(beta * p.x, -p.y))
            .collect();

        // Three buckets with 3, 5 and 2 entries, each entry exercising a phi/sign combination.
        let per = [3usize, 5, 2];
        let mut sched: Vec<u32> = Vec::new();
        let mut bstarts: Vec<u32> = vec![0];
        let mut idx = 0usize;
        for &c in per.iter() {
            for j in 0..c {
                let pi = (idx % npts) as u32;
                let f = (j % 4) as u32;
                sched.push(pi | if f & 1 != 0 { PHI_BIT } else { 0 } | if f & 2 != 0 { 1 << 31 } else { 0 });
                idx += 1;
            }
            bstarts.push(sched.len() as u32);
        }
        let decode = |e: u32, table: bool| -> Affine<P> {
            let i = (e & 0x3fff_ffff) as usize;
            let mut pt = points[i];
            if e & PHI_BIT != 0 {
                pt = if table {
                    phi[i]
                } else {
                    Affine::<P>::new_unchecked(beta * pt.x, -pt.y)
                };
            }
            if e >> 31 == 1 {
                -pt
            } else {
                pt
            }
        };

        for table in [false, true] {
            let mut expect: Vec<Projective<P>> = Vec::new();
            for b in 0..per.len() {
                let mut acc = Projective::<P>::zero();
                for e in &sched[bstarts[b] as usize..bstarts[b + 1] as usize] {
                    acc += decode(*e, table);
                }
                expect.push(acc);
            }
            let (vf, pack_cap, bcap) =
                unsafe { (bbk::bbref_vf_size(), bbk::bbref_pack_cap(), bbk::bbref_batch_capacity()) };
            let mut packed: Vec<core::mem::MaybeUninit<u64>> =
                vec![core::mem::MaybeUninit::uninit(); (8 * pack_cap * vf).div_ceil(8) + 32];
            let mut pair_dest: Vec<u32> = vec![0u32; bcap];
            let mut cpts: Vec<Affine<P>> = vec![Affine::<P>::zero(); sched.len()];
            let mut cbk: Vec<u32> = vec![0u32; sched.len()];
            let mut b_cursor: usize = 0;
            let phi_ptr: *const u64 = if table {
                phi.as_ptr() as *const u64
            } else {
                core::ptr::null()
            };
            let len = unsafe {
                bbk::bbref_reduce_chunk_fq(
                    points.as_ptr() as *const u64,
                    phi_ptr,
                    &beta as *const ark_bn254::Fq as *const u64,
                    sched.as_ptr(),
                    0,
                    sched.len(),
                    bstarts.as_ptr(),
                    &mut b_cursor,
                    cpts.as_mut_ptr() as *mut u64,
                    cbk.as_mut_ptr(),
                    packed.as_mut_ptr() as *mut u64,
                    pair_dest.as_mut_ptr(),
                )
            };
            assert_eq!(len, per.len(), "survivor count (table={table})");
            for k in 0..len {
                assert_eq!(cbk[k] as usize, k, "survivor bucket (table={table})");
                assert_eq!(cpts[k].into_group(), expect[k], "bucket {k} (table={table})");
            }
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
