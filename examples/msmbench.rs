//! Isolated MSM comparison: base::msm::msm vs ark msm_unchecked. Usage: msmbench <log_n> [iters]

use ark_ec::{CurveGroup, VariableBaseMSM};
use ark_ff::{UniformRand, Zero};
use std::time::Instant;

fn main() {
    let log_n: usize = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(17);
    let iters: usize = std::env::args().nth(2).and_then(|s| s.parse().ok()).unwrap_or(5);
    let n = 1usize << log_n;
    let mut rng = ark_std::test_rng();
    let points = ark_bn254::G1Projective::normalize_batch(
        &(0..n)
            .map(|_| ark_bn254::G1Projective::rand(&mut rng))
            .collect::<Vec<_>>(),
    );
    let scalars: Vec<ark_bn254::Fr> = (0..n).map(|_| ark_bn254::Fr::rand(&mut rng)).collect();

    for (name, f) in [
        (
            "ours",
            (|p: &[_], s: &[_]| bb_ref::base::msm::msm(p, s)) as fn(&[_], &[_]) -> _,
        ),
        ("ark ", |p, s| ark_bn254::G1Projective::msm_unchecked(p, s)),
    ] {
        let mut best = f64::MAX;
        let mut r = f(&points, &scalars);
        for _ in 0..iters {
            let t = Instant::now();
            r = f(&points, &scalars);
            best = best.min(t.elapsed().as_secs_f64() * 1e3);
        }
        assert!(!r.is_zero());
        println!("{name} 2^{log_n}: {best:.2} ms");
    }
}
