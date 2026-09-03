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

/// Points per thread below which arkworks' MSM wins (bb gates its pippenger the same way): the
/// batched-affine advantage needs enough points per bucket, and the schedule machinery has fixed
/// costs. Measured crossover: 2^15 at 32 threads, at or below 2^14 at 16 (msmbench sweeps).
const MIN_PTS_PER_THREAD: usize = 1024;

/// Raw pointer wrapper for the column-major digit scatter: each rayon task writes a disjoint cell.
pub struct SendPtr<T>(pub *mut T);
unsafe impl<T> Send for SendPtr<T> {}
unsafe impl<T> Sync for SendPtr<T> {}

pub fn msm<P: SWCurveConfig>(points: &[Affine<P>], scalars: &[P::ScalarField]) -> Projective<P> {
    let n = points.len().min(scalars.len());
    // Mostly-zero inputs (masking polys, sorted range columns, sparse selectors) compact to their
    // support first, so the cost is per-nonzero, not per-length, and the window size fits the real
    // problem (bb routes these through `commit_sparse` for the same reason).
    if n >= 1024 {
        let nnz = (0..n)
            .into_par_iter()
            .filter(|&i| !scalars[i].is_zero() && !points[i].is_zero())
            .count();
        if nnz * 2 < n {
            let (cp, cs): (Vec<Affine<P>>, Vec<P::ScalarField>) = (0..n)
                .filter(|&i| !scalars[i].is_zero() && !points[i].is_zero())
                .map(|i| (points[i], scalars[i]))
                .unzip();
            return msm(&cp, &cs);
        }
    }
    if n < MIN_PTS_PER_THREAD * rayon::current_num_threads() {
        return small_msm(&points[..n], &scalars[..n]);
    }
    let c = window_bits(n);
    let half = 1usize << (c - 1);
    let num_windows = 256usize.div_ceil(c);

    // bb's stage layout: every O(n) pass is parallel across scalar-range tasks, windows together.
    // Digits are decoded twice (count pass, scatter pass) instead of materialized — cheaper than
    // streaming an n x windows matrix through memory.
    let tasks = rayon::current_num_threads().clamp(1, n.div_ceil(2048));
    let task_ranges: Vec<std::ops::Range<usize>> = (0..tasks)
        .map(|t| t * n.div_ceil(tasks)..((t + 1) * n.div_ceil(tasks)).min(n))
        .collect();
    let stride = half + 1; // per-window histogram row: bucket magnitudes 1..=half
    fn decode<F: PrimeField>(s: &F, c: usize, half: usize, num_windows: usize, mut f: impl FnMut(usize, i32)) {
        let limbs = s.into_bigint();
        let mut carry = 0u64;
        for w in 0..num_windows {
            let raw = extract_bits(limbs.as_ref(), w * c, c) + carry;
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
                    decode(&scalars[i], c, half, num_windows, |w, d| unsafe {
                        *ptr.0.add(cell(t, w, d.unsigned_abs() as usize)) += 1;
                    });
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
                    decode(&scalars[i], c, half, num_windows, |w, d| unsafe {
                        let slot = cur.0.add(cell(t, w, d.unsigned_abs() as usize));
                        let entry = i as u32 | if d < 0 { 1u32 << 31 } else { 0 };
                        *ptrs[w].0.add(*slot as usize) = entry;
                        *slot += 1;
                    });
                }
            }
        });
    }

    mark("3 scatter");
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
    let survivors: Vec<Vec<(u32, Affine<P>)>> = jobs
        .par_iter()
        .map_init(
            // Per-rayon-split scratch, reused across jobs and tree levels: the gather block and
            // the tree pair/denominator buffers dominate the prover's allocation churn otherwise.
            || (Vec::new(), Vec::new(), Vec::new()),
            |(block, pairs, dens), &(w, k)| {
                let sched = &schedules[w];
                let job_start = (k * chunk_len).min(sched.len());
                let job_end = ((k + 1) * chunk_len).min(sched.len());
                // The entry's bucket is its rank's position in the per-window bucket offsets, tracked
                // incrementally since the schedule is sorted.
                let starts = &bucket_starts[w];
                let mut b = starts.partition_point(|&s| s as usize <= job_start) - 1;
                let mut work: Vec<(u32, Affine<P>)> = Vec::new();
                for (block_start, chunk) in (job_start..job_end)
                    .step_by(GATHER_BLOCK)
                    .zip(sched[job_start..job_end].chunks(GATHER_BLOCK))
                {
                    block.clear();
                    for (j, &e) in chunk.iter().enumerate() {
                        while starts[b + 1] as usize <= block_start + j {
                            b += 1;
                        }
                        let i = (e & 0x7fff_ffff) as usize;
                        let p = if e >> 31 == 1 { -points[i] } else { points[i] };
                        block.push((b as u32, p));
                    }
                    while tree_level(block, pairs, dens) {}
                    work.extend_from_slice(block);
                }
                while tree_level(&mut work, pairs, dens) {}
                work
            },
        )
        .collect();

    mark("4 tree");
    // Stage 5: per window, concatenate chunk survivors (still bucket-sorted), merge boundary
    // buckets, and reduce buckets to the window sum.
    let mut per_window: Vec<Vec<Vec<(u32, Affine<P>)>>> = (0..num_windows).map(|_| Vec::new()).collect();
    for (&(w, _), s) in jobs.iter().zip(survivors) {
        per_window[w].push(s);
    }
    let window_sums: Vec<Projective<P>> = per_window
        .into_par_iter()
        .map(|parts| {
            let mut work = parts.concat();
            if work.is_empty() {
                return Projective::<P>::zero();
            }
            let (mut pairs, mut dens) = (Vec::new(), Vec::new());
            while tree_level(&mut work, &mut pairs, &mut dens) {}
            bucket_reduce::<P>(&work, half)
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

/// bb `choose_window_bits`: minimize rounds * (4n + 12 * buckets).
fn window_bits(n: usize) -> usize {
    (4..=16)
        .min_by_key(|&c| 256usize.div_ceil(c) * (4 * n + 12 * (1usize << (c - 1))))
        .unwrap()
}

fn extract_bits(limbs: &[u64], start: usize, len: usize) -> u64 {
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

/// One tree level, in place: adjacent same-bucket pairs are batch-added through a single
/// level-wide inversion, survivors compact to the front. Returns false when every bucket is down
/// to one point (no pair found). Sequential: the caller's schedule chunks are the parallel unit.
fn tree_level<P: SWCurveConfig>(
    work: &mut Vec<(u32, Affine<P>)>,
    pairs: &mut Vec<(u32, u32)>,
    dens: &mut Vec<P::BaseField>,
) -> bool {
    // Pass 1: pick pairs, collect the batched denominators (None = pair sums to infinity).
    pairs.clear();
    dens.clear();
    let mut i = 0;
    while i + 1 < work.len() {
        let ((ba, a), (bb, b)) = (work[i], work[i + 1]);
        if ba != bb {
            i += 1;
            continue;
        }
        if a.x == b.x && a.y != b.y {
            // Inverse points: mark by an impossible index; nothing enters the batch.
            pairs.push((u32::MAX, i as u32));
        } else {
            dens.push(if a.x == b.x { a.y.double() } else { b.x - a.x });
            pairs.push((i as u32, i as u32));
        }
        i += 2;
    }
    if pairs.is_empty() {
        return false;
    }
    ark_ff::batch_inversion(dens);
    // Pass 2: apply sums and compact survivors to the front in one walk.
    let mut inv = dens.iter();
    let mut pair_it = pairs.iter().copied().peekable();
    let (mut out, mut i) = (0usize, 0usize);
    while i < work.len() {
        match pair_it.peek() {
            Some(&(tag, at)) if at as usize == i => {
                pair_it.next();
                let ((_, a), (_, b)) = (work[i], work[i + 1]);
                i += 2;
                if tag == u32::MAX {
                    continue; // infinity: pair contributes nothing
                }
                let lambda = if a.x == b.x {
                    let xx = a.x.square();
                    (xx.double() + xx) * inv.next().unwrap()
                } else {
                    (b.y - a.y) * inv.next().unwrap()
                };
                let x3 = lambda.square() - a.x - b.x;
                work[out] = (work[i - 2].0, Affine::<P>::new_unchecked(x3, lambda * (a.x - x3) - a.y));
                out += 1;
            }
            _ => {
                work[out] = work[i];
                out += 1;
                i += 1;
            }
        }
    }
    work.truncate(out);
    true
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
    ark_ff::batch_inversion(&mut dens);
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
fn bucket_reduce<P: SWCurveConfig>(work: &[(u32, Affine<P>)], num_buckets: usize) -> Projective<P> {
    // Wider = bigger inversion batches and fewer chain steps; the projective recombine at the end
    // costs ~2 ops per segment, so segments stay well below the bucket count.
    let segments = (num_buckets / 16).clamp(1, 1024).next_power_of_two();
    let seg_len = num_buckets.div_ceil(segments);
    let mut bucket_of: Vec<Option<Affine<P>>> = vec![None; seg_len * segments];
    for &(b, p) in work {
        bucket_of[b as usize] = Some(p);
    }
    let mut running: Vec<Option<Affine<P>>> = vec![None; segments];
    let mut acc: Vec<Option<Affine<P>>> = vec![None; segments];
    for t in (0..seg_len).rev() {
        let step: Vec<Option<Affine<P>>> = (0..segments).map(|j| bucket_of[j * seg_len + t]).collect();
        batch_add_assign(&mut running, &step);
        batch_add_assign(&mut acc, &running.clone());
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

fn small_msm<P: SWCurveConfig>(points: &[Affine<P>], scalars: &[P::ScalarField]) -> Projective<P> {
    Projective::<P>::msm_unchecked(points, scalars)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::VariableBaseMSM;
    use ark_ff::UniformRand;

    fn check<P: SWCurveConfig>(n: usize, tweak: impl Fn(&mut Vec<Affine<P>>, &mut Vec<P::ScalarField>)) {
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
}

impl<P: SWCurveConfig> BatchMsm for Affine<P> {
    fn batch_msm(points: &[Self], scalars: &[Self::ScalarField]) -> Projective<P> {
        msm(points, scalars)
    }
}
