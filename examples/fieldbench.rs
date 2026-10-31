//! Fr vs Fq throughput on the stored representation: ECCVM, IPA and the translator run entirely
//! over Fq (Grumpkin's scalar field), so a slow Fq path would show up as an ECCVM-wide deficit.
//! Array throughput (independent elements).
use bb_ref::base::{Fq, Fr};
use std::hint::black_box;
use std::time::Instant;

fn bench<F: Copy + std::ops::MulAssign + std::ops::AddAssign + ark_ff::UniformRand>(name: &str, n: usize) {
    let mut rng = ark_std::test_rng();
    let mut a: Vec<F> = (0..4096).map(|_| F::rand(&mut rng)).collect();
    let b = F::rand(&mut rng);
    let reps = n / 4096;
    let t = Instant::now();
    for _ in 0..reps {
        for x in a.iter_mut() {
            *x *= b;
        }
    }
    black_box(&a);
    let mul = t.elapsed().as_nanos() as f64 / (reps * 4096) as f64;
    let t = Instant::now();
    for _ in 0..reps {
        for x in a.iter_mut() {
            *x += b;
        }
    }
    black_box(&a);
    let add = t.elapsed().as_nanos() as f64 / (reps * 4096) as f64;
    println!("{name}: mul {mul:6.2} ns/elt   add {add:5.2} ns/elt");
}

fn main() {
    let n: usize = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(8_000_000);
    bench::<Fr>("Fr", n);
    bench::<Fq>("Fq", n);
}
