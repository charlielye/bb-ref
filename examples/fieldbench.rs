//! Field mul/sqr/add microbenchmark: serial dependency chain, reports ns/op.

use ark_ff::{AdditiveGroup, Field, UniformRand};
use bb_ref::base::Fr;
use std::hint::black_box;
use std::time::Instant;

fn main() {
    let n: u64 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(20_000_000);
    let mut rng = ark_std::test_rng();
    let mut a = Fr::rand(&mut rng);
    let b = Fr::rand(&mut rng);

    {
        // Cross-validate ark's (possibly wasm-specialized) mul against the independent m29 core.
        use ark_ff::{BigInteger, PrimeField};
        use bb_ref::base::mont29 as m29;
        let mut rng2 = ark_std::test_rng();
        for _ in 0..20_000 {
            let x = Fr::rand(&mut rng2);
            let y = Fr::rand(&mut rng2);
            let conv = |v: Fr| {
                let l: [u64; 4] = v.into_bigint().as_ref().try_into().unwrap();
                m29::reduce(&m29::mont_mul(&m29::from_u64x4(&l), &m29::FR_R2, &m29::FR_P, m29::FR_INV), &m29::FR_P)
            };
            let want = m29::reduce(&m29::mont_mul(&conv(x), &conv(y), &m29::FR_P, m29::FR_INV), &m29::FR_P);
            assert_eq!(conv(x * y), want, "ark mul cross-check failed");
            assert_eq!(conv(x.square()), m29::reduce(&m29::mont_mul(&conv(x), &conv(x), &m29::FR_P, m29::FR_INV), &m29::FR_P));
        }
        println!("ark-vs-m29 cross-check OK");
    }
    {
        use bb_ref::base::mont29::{add as m29_add, mont_mul, mont_mul_u, FR_INV, FR_P, FR_R2};
        let mut ma = mont_mul(&[1, 0, 0, 0, 0, 0, 0, 0, 0], &FR_R2, &FR_P, FR_INV);
        let mb = mont_mul(&[7, 0, 0, 0, 0, 0, 0, 0, 0], &FR_R2, &FR_P, FR_INV);
        let t = Instant::now();
        for _ in 0..n {
            ma = mont_mul(&ma, &mb, &FR_P, FR_INV);
        }
        black_box(ma);
        println!("m29 mul: {:.2} ns/op", t.elapsed().as_nanos() as f64 / n as f64);
        let t = Instant::now();
        for _ in 0..n {
            ma = mont_mul_u(&ma, &mb, &FR_P, FR_INV);
        }
        black_box(ma);
        println!("m29 mul-unrolled: {:.2} ns/op", t.elapsed().as_nanos() as f64 / n as f64);
        let t = Instant::now();
        for _ in 0..n {
            ma = m29_add(&ma, &mb, &FR_P);
        }
        black_box(ma);
        println!("m29 add: {:.2} ns/op", t.elapsed().as_nanos() as f64 / n as f64);
        // Throughput: four independent chains expose instruction-level parallelism.
        let mut c = [ma, mb, mont_mul(&ma, &mb, &FR_P, FR_INV), mont_mul(&mb, &mb, &FR_P, FR_INV)];
        let t = Instant::now();
        for _ in 0..n / 4 {
            c[0] = mont_mul(&c[0], &mb, &FR_P, FR_INV);
            c[1] = mont_mul(&c[1], &mb, &FR_P, FR_INV);
            c[2] = mont_mul(&c[2], &mb, &FR_P, FR_INV);
            c[3] = mont_mul(&c[3], &mb, &FR_P, FR_INV);
        }
        black_box(c);
        println!("m29 mul x4-ilp: {:.2} ns/op", t.elapsed().as_nanos() as f64 / n as f64);
    }
    {
        let mut rng = ark_std::test_rng();
        let mut c: [Fr; 4] = core::array::from_fn(|_| Fr::rand(&mut rng));
        let b = Fr::rand(&mut rng);
        let t = Instant::now();
        for _ in 0..n / 4 {
            for x in c.iter_mut() {
                *x *= b;
            }
        }
        black_box(c);
        println!("ark mul x4-ilp: {:.2} ns/op", t.elapsed().as_nanos() as f64 / n as f64);
    }
    #[cfg(all(target_family = "wasm", target_feature = "simd128"))]
    {
        use bb_ref::base::mont29::{mont_mul, quad, FR_INV, FR_P, FR_R2};
        let to_m = |v: u64| {
            let mut raw = [0u32; 9];
            raw[0] = (v & ((1 << 29) - 1)) as u32;
            raw[1] = (v >> 29) as u32;
            mont_mul(&raw, &FR_R2, &FR_P, FR_INV)
        };
        let e = [to_m(3), to_m(1u64 << 40), to_m(12345678901), to_m(7)];
        let f = [to_m(11), to_m(13), to_m(1u64 << 50), to_m(999999999999)];
        let (qa, qb) = (quad::Quad::pack(&e), quad::Quad::pack(&f));
        let qr = quad::mont_mul(&qa, &qb, &FR_P, FR_INV).unpack();
        for l in 0..4 {
            use bb_ref::base::mont29::reduce;
            assert_eq!(
                reduce(&qr[l], &FR_P),
                reduce(&mont_mul(&e[l], &f[l], &FR_P, FR_INV), &FR_P),
                "quad lane {l} mismatch"
            );
        }
        println!("quad correctness OK");
        let mut qa = qa;
        let t = Instant::now();
        for _ in 0..n / 4 {
            qa = quad::mont_mul(&qa, &qb, &FR_P, FR_INV);
        }
        black_box(qa.unpack());
        println!("m29 quad mul: {:.2} ns/element", t.elapsed().as_nanos() as f64 / n as f64);
        let qr2 = quad::mont_mul_u(&quad::Quad::pack(&e), &qb, &FR_P, FR_INV).unpack();
        let qr1 = quad::mont_mul(&quad::Quad::pack(&e), &qb, &FR_P, FR_INV).unpack();
        for l in 0..4 {
            use bb_ref::base::mont29::reduce;
            assert_eq!(reduce(&qr2[l], &FR_P), reduce(&qr1[l], &FR_P), "unrolled quad lane {l}");
        }
        let mut qa2 = quad::Quad::pack(&e);
        let t = Instant::now();
        for _ in 0..n / 4 {
            qa2 = quad::mont_mul_u(&qa2, &qb, &FR_P, FR_INV);
        }
        black_box(qa2.unpack());
        println!("m29 quad mul unrolled: {:.2} ns/element", t.elapsed().as_nanos() as f64 / n as f64);
        // mix5: 1 scalar + 4 quad per call
        let (mr, qr3) = quad::mont_mul_mix5(&e[0], &f[0], &quad::Quad::pack(&e), &qb, &FR_P, FR_INV);
        {
            use bb_ref::base::mont29::reduce;
            assert_eq!(reduce(&mr, &FR_P), reduce(&mont_mul(&e[0], &f[0], &FR_P, FR_INV), &FR_P), "mix5 scalar");
            let qq = qr3.unpack();
            let q1 = quad::mont_mul(&quad::Quad::pack(&e), &qb, &FR_P, FR_INV).unpack();
            for l in 0..4 { assert_eq!(reduce(&qq[l], &FR_P), reduce(&q1[l], &FR_P), "mix5 lane {l}"); }
        }
        let (mut sa5, mut qa5) = (e[0], quad::Quad::pack(&e));
        let t = Instant::now();
        for _ in 0..n / 5 {
            let (s2, q2) = quad::mont_mul_mix5(&sa5, &f[0], &qa5, &qb, &FR_P, FR_INV);
            sa5 = s2;
            qa5 = q2;
        }
        black_box((sa5, qa5.unpack()));
        println!("m29 mix5 mul: {:.2} ns/element", t.elapsed().as_nanos() as f64 / n as f64);
    }
    for (name, f) in [
        ("mul", (|a: &mut Fr, b: &Fr| *a *= b) as fn(&mut Fr, &Fr)),
        ("sqr", |a, _| *a = a.square()),
        ("add", |a, b| *a += b),
    ] {
        let t = Instant::now();
        for _ in 0..n {
            f(&mut a, &b);
        }
        black_box(a);
        println!("{name}: {:.2} ns/op", t.elapsed().as_nanos() as f64 / n as f64);
        if a == Fr::ZERO {
            a += b;
        }
    }
}
