//! Drain-kernel rung: bb's chord kernel (chord1 + one inversion + chord2s, the committed MSM
//! drain shape) on n staged pairs, vs the same linked VectorField multiply streaming through
//! `bbref_axpy_fq`. Reports ns per chord and per mul-equivalent (5 muls/chord). Answers where a
//! ~26 ns/mul kernel becomes ~60 ns/mul inside the drain. wasm + bbkernel only.
fn main() {
    #[cfg(all(target_family = "wasm", target_feature = "simd128", feature = "bbkernel"))]
    run();
    #[cfg(not(all(target_family = "wasm", target_feature = "simd128", feature = "bbkernel")))]
    println!("chordbench requires wasm32 +simd128 --features bbkernel");
}

#[cfg(all(target_family = "wasm", target_feature = "simd128", feature = "bbkernel"))]
fn run() {
    use ark_bn254::{Fq, G1Affine, G1Projective};
    use ark_ec::CurveGroup;
    use ark_std::UniformRand;
    use bb_ref::base::packed::bbk;
    use std::hint::black_box;
    use std::time::Instant;

    let log_n: usize = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(14);
    let n = 1usize << log_n; // pairs
    let mut rng = ark_std::test_rng();
    let pts: Vec<G1Affine> = G1Projective::normalize_batch(
        &(0..2 * n).map(|_| G1Projective::rand(&mut rng)).collect::<Vec<_>>(),
    );
    let w = unsafe { bbk::bbref_chord_width() };
    let np = n.div_ceil(w) * w;
    // Stage exactly as the drain does (coordinate-separated, padded with pair 0).
    let mut ax = Vec::with_capacity(np);
    let mut ay = Vec::with_capacity(np);
    let mut bx = Vec::with_capacity(np);
    let mut by = Vec::with_capacity(np);
    let mut dst: Vec<u32> = Vec::with_capacity(np);
    for k in 0..np {
        let (a, b) = (pts[2 * (k % n)], pts[2 * (k % n) + 1]);
        ax.push(a.x);
        ay.push(a.y);
        bx.push(b.x);
        by.push(b.y);
        dst.push((k % n) as u32);
    }
    let mut out: Vec<G1Affine> = vec![pts[0]; n];
    let mut scratch: Vec<Fq> = vec![Fq::from(0u64); 2 * np];
    let reps = (1usize << 22) / n;

    // Correctness on one call.
    {
        let (dx, prod) = scratch.split_at_mut(np);
        unsafe { bbk::bbref_chord1_fq(ax.as_ptr() as _, bx.as_ptr() as _, np, dx.as_mut_ptr() as _, prod.as_mut_ptr() as _) };
        let mut lane_inv: Vec<Fq> = prod[np - w..].to_vec();
        ark_ff::batch_inversion(&mut lane_inv);
        unsafe {
            bbk::bbref_chord2s_fq(ax.as_ptr() as _, ay.as_ptr() as _, bx.as_ptr() as _, by.as_ptr() as _, np,
                dx.as_mut_ptr() as _, prod.as_ptr() as _, lane_inv.as_ptr() as _, dst.as_ptr(), out.as_mut_ptr() as _)
        };
        for k in 0..n.min(64) {
            let exp = (pts[2 * k] + pts[2 * k + 1]).into_affine();
            assert_eq!(out[k], exp, "chord {k}");
        }
        println!("chord cross-check OK (n={n}, W={w})");
    }

    let t = Instant::now();
    let (mut t1, mut tinv, mut t2) = (0u128, 0u128, 0u128);
    for _ in 0..reps {
        let (dx, prod) = scratch.split_at_mut(np);
        let s0 = Instant::now();
        unsafe { bbk::bbref_chord1_fq(ax.as_ptr() as _, bx.as_ptr() as _, np, dx.as_mut_ptr() as _, prod.as_mut_ptr() as _) };
        let s1 = Instant::now();
        let mut lane_inv: Vec<Fq> = prod[np - w..].to_vec();
        ark_ff::batch_inversion(&mut lane_inv);
        let s2 = Instant::now();
        unsafe {
            bbk::bbref_chord2s_fq(ax.as_ptr() as _, ay.as_ptr() as _, bx.as_ptr() as _, by.as_ptr() as _, np,
                dx.as_mut_ptr() as _, prod.as_ptr() as _, lane_inv.as_ptr() as _, dst.as_ptr(), out.as_mut_ptr() as _)
        };
        let s3 = Instant::now();
        t1 += (s1 - s0).as_nanos();
        tinv += (s2 - s1).as_nanos();
        t2 += (s3 - s2).as_nanos();
    }
    black_box(&out);
    let tot = t.elapsed().as_nanos() as f64 / (reps * n) as f64;
    println!("OLD total:    {tot:7.1} ns/chord  = {:5.1} ns/mul-eq (6 muls/chord)", tot / 6.0);
    println!("  chord1:     {:7.1} ns/chord", t1 as f64 / (reps * n) as f64);
    println!("  invert:     {:7.1} ns/chord (1 per call, amortized)", tinv as f64 / (reps * n) as f64);
    println!("  chord2s:    {:7.1} ns/chord", t2 as f64 / (reps * n) as f64);

    // Packed-intermediate variant (chord1p/chord2p): 4 packs + 2 unpacks per block.
    let vfb = unsafe { bbk::bbref_vf_size() };
    println!("sizeof(VectorField) = {vfb} B");
    let mut pscratch: Vec<Fq> = vec![Fq::from(0u64); (6 * (np / w) * vfb).div_ceil(32) + 16];
    let mut lane: Vec<Fq> = vec![Fq::from(0u64); w];
    let mut out2: Vec<G1Affine> = vec![pts[0]; n];
    unsafe {
        bbk::bbref_chord1p_fq(ax.as_ptr() as _, ay.as_ptr() as _, bx.as_ptr() as _, by.as_ptr() as _, np, pscratch.as_mut_ptr() as _, lane.as_mut_ptr() as _);
    }
    ark_ff::batch_inversion(&mut lane);
    unsafe { bbk::bbref_chord2p_fq(np, pscratch.as_mut_ptr() as _, lane.as_ptr() as _, dst.as_ptr(), out2.as_mut_ptr() as _) };
    for k in 0..n.min(64) {
        assert_eq!(out2[k], (pts[2 * k] + pts[2 * k + 1]).into_affine(), "packed chord {k}");
    }
    println!("packed chord cross-check OK");
    let t = Instant::now();
    let (mut q1, mut qinv, mut q2) = (0u128, 0u128, 0u128);
    for _ in 0..reps {
        let s0 = Instant::now();
        unsafe {
            bbk::bbref_chord1p_fq(ax.as_ptr() as _, ay.as_ptr() as _, bx.as_ptr() as _, by.as_ptr() as _, np, pscratch.as_mut_ptr() as _, lane.as_mut_ptr() as _);
        }
        let s1 = Instant::now();
        ark_ff::batch_inversion(&mut lane);
        let s2 = Instant::now();
        unsafe { bbk::bbref_chord2p_fq(np, pscratch.as_mut_ptr() as _, lane.as_ptr() as _, dst.as_ptr(), out2.as_mut_ptr() as _) };
        let s3 = Instant::now();
        q1 += (s1 - s0).as_nanos();
        qinv += (s2 - s1).as_nanos();
        q2 += (s3 - s2).as_nanos();
    }
    black_box(&out2);
    let tot2 = t.elapsed().as_nanos() as f64 / (reps * n) as f64;
    println!("PACKED total: {tot2:7.1} ns/chord  = {:5.1} ns/mul-eq (6 muls/chord)", tot2 / 6.0);
    println!("  chord1p:    {:7.1} ns/chord", q1 as f64 / (reps * n) as f64);
    println!("  invert:     {:7.1} ns/chord", qinv as f64 / (reps * n) as f64);
    println!("  chord2p:    {:7.1} ns/chord", q2 as f64 / (reps * n) as f64);

    // Reference: same VectorField mul streaming (axpy = 1 mul + 1 add + load/store per elt).
    let mut d: Vec<Fq> = (0..n).map(|_| Fq::rand(&mut rng)).collect();
    let a: Vec<Fq> = (0..n).map(|_| Fq::rand(&mut rng)).collect();
    let sc = Fq::rand(&mut rng);
    let t = Instant::now();
    for _ in 0..reps {
        unsafe { bbk::bbref_axpy_fq(d.as_mut_ptr() as _, a.as_ptr() as _, &sc as *const Fq as _, n) };
    }
    black_box(&d);
    println!("axpy ref:     {:7.1} ns/elt (1 mul + 1 add + ld/st)", t.elapsed().as_nanos() as f64 / (reps * n) as f64);
}
