//! L0/L1 wasm kernel rungs, matched against bb's `fr_bench`/`vector_field_bench`/
//! `add_scaled_bench`: array THROUGHPUT (`c[i] = a[i] op b`) over independent elements —
//! dependency-chain benches understate wasm SIMD by 4-8x. The wasm stored form is the 2^261
//! Montgomery domain, so the packed kernels run directly on stored bytes. wasm+simd128 only.

fn main() {
    #[cfg(all(target_family = "wasm", target_feature = "simd128"))]
    run();
    #[cfg(not(all(target_family = "wasm", target_feature = "simd128")))]
    println!("quadbench requires wasm32 with +simd128");
}

#[cfg(all(target_family = "wasm", target_feature = "simd128"))]
const NQ: usize = 4096;

#[cfg(all(target_family = "wasm", target_feature = "simd128"))]
fn run() {
    use ark_ff::fields::models::fp::montgomery_backend::quad261::{self, QuadFp};
    use ark_ff::UniformRand;
    use bb_ref::base::Fr;
    use bb_ref::honk::quadf::{QuadConsts, QuadF};
    use std::hint::black_box;
    use std::time::Instant;

    let n: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(16_000_000);
    let mut rng = ark_std::test_rng();
    let kc = <Fr as QuadConsts>::kc();
    let stored = |x: Fr| -> [u64; 4] { unsafe { core::mem::transmute::<Fr, [u64; 4]>(x) } };
    let unstored = |l: [u64; 4]| -> Fr { unsafe { core::mem::transmute::<[u64; 4], Fr>(l) } };

    // Cross-checks: packed mul/add/sub on stored bytes agree with ark ops.
    for _ in 0..2000 {
        let xs: [Fr; 4] = core::array::from_fn(|_| Fr::rand(&mut rng));
        let ys: [Fr; 4] = core::array::from_fn(|_| Fr::rand(&mut rng));
        let qa = QuadFp::pack(&[stored(xs[0]), stored(xs[1]), stored(xs[2]), stored(xs[3])]);
        let qb = QuadFp::pack(&[stored(ys[0]), stored(ys[1]), stored(ys[2]), stored(ys[3])]);
        let qm = quad261::mont_mul(&qa, &qb, &kc.c).unpack(&kc.modulus);
        let qs = quad261::add(&qa, &qb, &kc.c).unpack(&kc.modulus);
        let qd = quad261::sub(&qa, &qb, &kc.c).unpack(&kc.modulus);
        for l in 0..4 {
            assert_eq!(unstored(qm[l]), xs[l] * ys[l], "mul lane {l}");
            assert_eq!(unstored(qs[l]), xs[l] + ys[l], "add lane {l}");
            assert_eq!(unstored(qd[l]), xs[l] - ys[l], "sub lane {l}");
        }
    }
    println!("cross-checks OK");

    fn mk_quads<R: ark_std::rand::Rng>(rng: &mut R) -> Vec<QuadFp> {
        let stored = |x: Fr| -> [u64; 4] { unsafe { core::mem::transmute::<Fr, [u64; 4]>(x) } };
        (0..NQ)
            .map(|_| {
                let xs: [Fr; 4] = core::array::from_fn(|_| Fr::rand(rng));
                QuadFp::pack(&[stored(xs[0]), stored(xs[1]), stored(xs[2]), stored(xs[3])])
            })
            .collect()
    }
    let reps = (n / (NQ * 4)).max(1);
    let per_elt = |t: std::time::Duration, r: usize| t.as_nanos() as f64 / (r * NQ * 4) as f64;

    // L0: scalar mul/add (the mont_mul_261 kernel through ark ops).
    let mut sarr: Vec<Fr> = (0..NQ * 4).map(|_| Fr::rand(&mut rng)).collect();
    let y = Fr::rand(&mut rng);
    let t = Instant::now();
    for _ in 0..reps {
        for x in sarr.iter_mut() {
            *x *= y;
        }
    }
    black_box(sarr[0]);
    println!("scalar mul:  {:6.2} ns/elt", per_elt(t.elapsed(), reps));

    let t = Instant::now();
    for _ in 0..reps {
        for x in sarr.iter_mut() {
            *x += y;
        }
    }
    black_box(sarr[0]);
    println!("scalar add:  {:6.2} ns/elt", per_elt(t.elapsed(), reps));

    // L0: packed mul/add/sub.
    let mut arr = mk_quads(&mut rng);
    let ys: [Fr; 4] = core::array::from_fn(|_| Fr::rand(&mut rng));
    let qb = QuadFp::pack(&[stored(ys[0]), stored(ys[1]), stored(ys[2]), stored(ys[3])]);
    let t = Instant::now();
    for _ in 0..reps {
        for q in arr.iter_mut() {
            *q = quad261::mont_mul(q, &qb, &kc.c);
        }
    }
    black_box(arr[0].unpack(&kc.modulus));
    println!("packed mul:  {:6.2} ns/elt", per_elt(t.elapsed(), reps));

    let mut arr2 = mk_quads(&mut rng);
    let t = Instant::now();
    for _ in 0..reps {
        for q in arr2.iter_mut() {
            *q = quad261::add(q, &qb, &kc.c);
        }
    }
    black_box(arr2[0].unpack(&kc.modulus));
    println!("packed add:  {:6.2} ns/elt", per_elt(t.elapsed(), reps));

    let mut arr3 = mk_quads(&mut rng);
    let t = Instant::now();
    for _ in 0..reps {
        for q in arr3.iter_mut() {
            *q = quad261::sub(q, &qb, &kc.c);
        }
    }
    black_box(arr3[0].unpack(&kc.modulus));
    println!("packed sub:  {:6.2} ns/elt", per_elt(t.elapsed(), reps));

    // L0: pack transpose throughput (packed add on top so the pack isn't dead-coded).
    let flat: Vec<Fr> = (0..NQ * 4).map(|_| Fr::rand(&mut rng)).collect();
    let mut acc = arr[0];
    let t = Instant::now();
    for _ in 0..reps {
        for g in 0..NQ {
            let q = QuadFp::pack(unsafe { &*(flat.as_ptr().add(4 * g) as *const [[u64; 4]; 4]) });
            acc = quad261::add(&acc, &q, &kc.c);
        }
    }
    black_box(acc.unpack(&kc.modulus));
    println!("pack+add:    {:6.2} ns/elt", per_elt(t.elapsed(), reps));

    // L0: q1s1 shape — one scalar mul interleaved with one quad mul per block of 5 elements
    // (bb VectorField's 5-wide trick: the integer unit works in parallel with SIMD).
    let mut arr5q = mk_quads(&mut rng);
    let mut arr5s: Vec<Fr> = (0..NQ).map(|_| Fr::rand(&mut rng)).collect();
    let t = Instant::now();
    for _ in 0..reps {
        for (q, sc) in arr5q.iter_mut().zip(arr5s.iter_mut()) {
            *q = quad261::mont_mul(q, &qb, &kc.c);
            *sc *= y;
        }
    }
    black_box((arr5q[0].unpack(&kc.modulus), arr5s[0]));
    println!(
        "q1s1 mul:    {:6.2} ns/elt",
        t.elapsed().as_nanos() as f64 / (reps * NQ * 5) as f64
    );

    // L0: QuadF wrapper mul (the relation-body call shape: per-op kc(), 144B temporaries).
    let mut warr: Vec<QuadF<Fr>> = (0..NQ)
        .map(|_| {
            let xs: [Fr; 4] = core::array::from_fn(|_| Fr::rand(&mut rng));
            QuadF::lanes(xs[0], xs[1], xs[2], xs[3])
        })
        .collect();
    let wb = QuadF::lanes(ys[0], ys[1], ys[2], ys[3]);
    let t = Instant::now();
    for _ in 0..reps {
        for q in warr.iter_mut() {
            *q = *q * &wb;
        }
    }
    black_box(warr[0].hsum());
    println!("QuadF mul:   {:6.2} ns/elt", per_elt(t.elapsed(), reps));

    // L1: bb's clang-compiled q1s1 kernels linked in (csrc/bb_kernel.o), same slices as axpy.
    #[cfg(feature = "bbkernel")]
    {
        unsafe extern "C" {
            fn bbref_axpy_fr(dst: *mut u64, src: *const u64, scalar: *const u64, n: usize);
        }
        // Cross-check vs ark ops on our stored bytes.
        for n in [1usize, 4, 5, 23] {
            let mut d: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
            let a: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
            let sc = Fr::rand(&mut rng);
            let expect: Vec<Fr> = d.iter().zip(&a).map(|(x, y)| *x + *y * sc).collect();
            unsafe {
                bbref_axpy_fr(d.as_mut_ptr() as *mut u64, a.as_ptr() as *const u64, &sc as *const Fr as *const u64, n)
            };
            assert_eq!(d, expect, "bb axpy n={n}");
        }
        println!("bb kernel cross-checks OK");
        let mut d: Vec<Fr> = (0..NQ * 4).map(|_| Fr::rand(&mut rng)).collect();
        let a: Vec<Fr> = (0..NQ * 4).map(|_| Fr::rand(&mut rng)).collect();
        let sc = Fr::rand(&mut rng);
        let t = Instant::now();
        for _ in 0..reps {
            unsafe {
                bbref_axpy_fr(
                    d.as_mut_ptr() as *mut u64,
                    a.as_ptr() as *const u64,
                    &sc as *const Fr as *const u64,
                    NQ * 4,
                )
            };
        }
        black_box(d[0]);
        println!("bb axpy:     {:6.2} ns/elt", per_elt(t.elapsed(), reps));
    }

    // L1: axpy and one full fold ladder (matched against bb add_scaled_bench / fold loops).
    let mut dst: Vec<Fr> = (0..1 << 16).map(|_| Fr::rand(&mut rng)).collect();
    let src: Vec<Fr> = (0..1 << 16).map(|_| Fr::rand(&mut rng)).collect();
    let s = Fr::rand(&mut rng);
    let r1 = (n / (1 << 18)).max(1);
    let t = Instant::now();
    for _ in 0..r1 {
        assert!(bb_ref::base::packed::try_axpy(&mut dst, &src, &s));
    }
    black_box(dst[0]);
    println!(
        "axpy:        {:6.2} ns/elt",
        t.elapsed().as_nanos() as f64 / (r1 * (1 << 16)) as f64
    );

    let u = Fr::rand(&mut rng);
    let mut folds = 0usize;
    let t = Instant::now();
    for _ in 0..r1 {
        let mut v = src.clone();
        while v.len() > 1 {
            assert!(bb_ref::base::packed::try_fold_halve(&mut v, &u));
            folds += v.len();
        }
        black_box(v[0]);
    }
    println!(
        "fold:        {:6.2} ns/out (incl clone)",
        t.elapsed().as_nanos() as f64 / folds as f64
    );
}
