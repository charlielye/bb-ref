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
