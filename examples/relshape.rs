//! Probe: quad261 mul throughput in a relation-shaped context (many QuadF locals, interleaved
//! add/sub, per-op kc() access, ~20 ops per element over many columns) vs the tight-loop shape.

fn main() {
    #[cfg(all(target_family = "wasm", target_feature = "simd128"))]
    run();
    #[cfg(not(all(target_family = "wasm", target_feature = "simd128")))]
    println!("wasm only");
}

#[cfg(all(target_family = "wasm", target_feature = "simd128"))]
fn run() {
    use ark_ff::UniformRand;
    use bb_ref::base::Fr;
    use bb_ref::honk::quadf::QuadF;
    use std::hint::black_box;
    use std::time::Instant;

    let mut rng = ark_std::test_rng();
    const NCOLS: usize = 24;
    const NG: usize = 2048;
    // Column-major table of packed quads, like the sumcheck row table.
    let cols: Vec<Vec<QuadF<Fr>>> = (0..NCOLS)
        .map(|_| {
            (0..NG)
                .map(|_| {
                    let l: [Fr; 4] = core::array::from_fn(|_| Fr::rand(&mut rng));
                    QuadF::lanes(l[0], l[1], l[2], l[3])
                })
                .collect()
        })
        .collect();
    let reps = 200;

    // Relation-shaped: per group, read ~24 columns, do a mix of muls/adds/subs producing a few
    // accumulators (about 16 muls + 14 add/sub per group).
    let t = Instant::now();
    let mut acc0 = cols[0][0];
    let mut acc1 = cols[1][0];
    for _ in 0..reps {
        for g in 0..NG {
            let w = |j: usize| cols[j][g];
            let a = (w(0) + &w(1)) * &(w(2) + &w(3));
            let b = (w(4) - &w(5)) * &w(6);
            let c = w(7) * &w(8) * &w(9);
            let d = (w(10) + &w(11)) * &(w(12) - &w(13));
            let e = w(14) * &w(15);
            let f = (w(16) + &w(17)) * &w(18);
            let h = w(19) * &w(20) * &w(21);
            let i = (w(22) - &w(23)) * &a;
            let s1 = b * &c + &(d * &e);
            let s2 = f * &h + &i;
            acc0 += &(s1 * &s2);
            acc1 += &(s1 + &s2);
        }
    }
    black_box((acc0.hsum(), acc1.hsum()));
    let muls_per_group = 16.0;
    println!(
        "relation-shaped: {:.1} ns/quad-mul-equivalent ({} muls + ~14 addsub per group)",
        t.elapsed().as_nanos() as f64 / (reps * NG) as f64 / muls_per_group,
        muls_per_group
    );

    // Tight loop, same total muls, one call site.
    let mut arr: Vec<QuadF<Fr>> = cols[0].clone();
    let b = cols[1][0];
    let t = Instant::now();
    for _ in 0..(reps * 16) {
        for q in arr.iter_mut() {
            *q = *q * &b;
        }
    }
    black_box(arr[0].hsum());
    println!(
        "tight loop:      {:.1} ns/quad-mul",
        t.elapsed().as_nanos() as f64 / (reps * 16 * NG) as f64
    );
}
