//! quad256 array-THROUGHPUT benchmark: `c[i] = a[i] * b` over independent quads — the real loop
//! shape. Dependency-chain benches understate wasm SIMD throughput by 4–8× (measured on bb's
//! VectorField: 132 ns/elt chain latency vs ~16 ns/elt in-loop). wasm+simd128 only.

fn main() {
    #[cfg(all(target_family = "wasm", target_feature = "simd128"))]
    run();
    #[cfg(not(all(target_family = "wasm", target_feature = "simd128")))]
    println!("quadbench requires wasm32 with +simd128");
}

#[cfg(all(target_family = "wasm", target_feature = "simd128"))]
fn run() {
    use ark_ff::fields::models::fp::montgomery_backend::{quad256, wasm_mont};
    use ark_ff::{PrimeField, UniformRand};
    use bb_ref::base::Fr;
    use std::hint::black_box;
    use std::time::Instant;

    let n: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(16_000_000);
    let mut rng = ark_std::test_rng();
    let modulus: [u64; 4] = Fr::MODULUS.as_ref().try_into().unwrap();
    let p29 = wasm_mont::to29(&modulus);
    let inv = wasm_mont::inv29(p29[0]);
    let stored = |x: Fr| -> [u64; 4] { unsafe { core::mem::transmute::<Fr, [u64; 4]>(x) } };

    for _ in 0..2000 {
        let xs: [Fr; 4] = core::array::from_fn(|_| Fr::rand(&mut rng));
        let ys: [Fr; 4] = core::array::from_fn(|_| Fr::rand(&mut rng));
        let qa = quad256::QuadFp::pack(&[stored(xs[0]), stored(xs[1]), stored(xs[2]), stored(xs[3])]);
        let qb = quad256::QuadFp::pack(&[stored(ys[0]), stored(ys[1]), stored(ys[2]), stored(ys[3])]);
        let qr = quad256::mont_mul(&qa, &qb, &p29, inv).unpack(&modulus);
        for l in 0..4 {
            assert_eq!(qr[l], stored(xs[l] * ys[l]), "quad256 lane {l}");
        }
    }
    println!("quad256 cross-check OK");

    const NQ: usize = 4096;
    let mut arr: Vec<quad256::QuadFp> = (0..NQ)
        .map(|_| {
            let xs: [Fr; 4] = core::array::from_fn(|_| Fr::rand(&mut rng));
            quad256::QuadFp::pack(&[stored(xs[0]), stored(xs[1]), stored(xs[2]), stored(xs[3])])
        })
        .collect();
    let ys: [Fr; 4] = core::array::from_fn(|_| Fr::rand(&mut rng));
    let qb = quad256::QuadFp::pack(&[stored(ys[0]), stored(ys[1]), stored(ys[2]), stored(ys[3])]);
    let reps = (n / (NQ * 4)).max(1);
    let t = Instant::now();
    for _ in 0..reps {
        for q in arr.iter_mut() {
            *q = quad256::mont_mul(q, &qb, &p29, inv);
        }
    }
    black_box(arr[0].unpack(&modulus));
    println!(
        "quad256 array mul: {:.2} ns/element",
        t.elapsed().as_nanos() as f64 / (reps * NQ * 4) as f64
    );

    {
        use ark_ff::fields::models::fp::montgomery_backend::quad261;
        use ark_ff::fields::models::fp::montgomery_backend::wasm_mont::FR_RINV29;
        let qc = quad261::Consts::new(&FR_RINV29, &p29, inv);
        // Correctness: with b pre-scaled by 32, quad261 (÷2^261) lands exactly in the 2^256
        // domain: stored(a) * stored(32b) / 2^261 = stored(a*b).
        for _ in 0..2000 {
            let xs: [Fr; 4] = core::array::from_fn(|_| Fr::rand(&mut rng));
            let y = Fr::rand(&mut rng);
            let y32 = y * Fr::from(32u64);
            let qa = quad261::QuadFp::pack(&[stored(xs[0]), stored(xs[1]), stored(xs[2]), stored(xs[3])]);
            let qb = quad261::QuadFp::pack(&[stored(y32); 4]);
            let qr = quad261::mont_mul(&qa, &qb, &qc).unpack(&modulus);
            for l in 0..4 {
                assert_eq!(qr[l], stored(xs[l] * y), "quad261 lane {l}");
            }
        }
        println!("quad261 cross-check OK");
        // add/sub on naturally-coarse values (mont_mul outputs), vs ark
        let twop29: [u32; 9] = {
            let mut t = [0u32; 9];
            let mut c = 0u64;
            for i in 0..9 {
                let v = 2 * (p29[i]) + c;
                t[i] = (v & ((1u64 << 29) - 1)) as u32;
                c = v >> 29;
            }
            t
        };
        for i in 0..3000 {
            let xs: [Fr; 4] = core::array::from_fn(|_| Fr::rand(&mut rng));
            let ys: [Fr; 4] = core::array::from_fn(|_| Fr::rand(&mut rng));
            let z = Fr::rand(&mut rng);
            let z32 = z * Fr::from(32u64);
            let qz = quad261::QuadFp::pack(&[stored(z32); 4]);
            // coarse operands: products (coarse range outputs)
            let qa = quad261::mont_mul(&quad261::QuadFp::pack(&[stored(xs[0]), stored(xs[1]), stored(xs[2]), stored(xs[3])]), &qz, &qc);
            let qb2 = quad261::mont_mul(&quad261::QuadFp::pack(&[stored(ys[0]), stored(ys[1]), stored(ys[2]), stored(ys[3])]), &qz, &qc);
            let sum = quad261::add(&qa, &qb2, &twop29, &qc).unpack(&modulus);
            let dif = quad261::sub(&qa, &qb2, &twop29, &qc).unpack(&modulus);
            for l in 0..4 {
                assert_eq!(sum[l], stored(xs[l] * z + ys[l] * z), "add lane {l} iter {i}");
                assert_eq!(dif[l], stored(xs[l] * z - ys[l] * z), "sub lane {l} iter {i}");
            }
        }
        println!("quad261 add/sub cross-check OK");
        let ys: [Fr; 4] = core::array::from_fn(|_| Fr::rand(&mut rng));
        let qb = quad261::QuadFp::pack(&[stored(ys[0]), stored(ys[1]), stored(ys[2]), stored(ys[3])]);
        let mut arr2: Vec<quad261::QuadFp> = (0..NQ)
            .map(|_| {
                let xs: [Fr; 4] = core::array::from_fn(|_| Fr::rand(&mut rng));
                quad261::QuadFp::pack(&[stored(xs[0]), stored(xs[1]), stored(xs[2]), stored(xs[3])])
            })
            .collect();
        let t = Instant::now();
        for _ in 0..reps {
            for q in arr2.iter_mut() {
                *q = quad261::mont_mul(q, &qb, &qc);
            }
        }
        black_box(arr2[0].unpack(&modulus));
        println!(
            "quad261 array mul: {:.2} ns/element",
            t.elapsed().as_nanos() as f64 / (reps * NQ * 4) as f64
        );
    }
    let mut sarr: Vec<Fr> = (0..NQ * 4).map(|_| Fr::rand(&mut rng)).collect();
    let y = Fr::rand(&mut rng);
    let t = Instant::now();
    for _ in 0..reps {
        for x in sarr.iter_mut() {
            *x *= y;
        }
    }
    black_box(sarr[0]);
    println!(
        "scalar array mul: {:.2} ns/element",
        t.elapsed().as_nanos() as f64 / (reps * NQ * 4) as f64
    );
}
