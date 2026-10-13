//! K dense polynomials of size 2^n committed via `batch_commit` versus K sequential `commit`s:
//! how much our concurrent-independent-MSM batching buys, and what a true batched pass (bb's
//! `batch_multi_scalar_mul`, one pass over the points shared by K scalar streams) could gain.
use ark_ff::UniformRand;
use bb_ref::base::poly::Polynomial;
use bb_ref::base::{CommitmentKey, Fr};
use std::time::Instant;

fn main() {
    let log_n: usize = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(15);
    let k: usize = std::env::args().nth(2).and_then(|s| s.parse().ok()).unwrap_or(10);
    let n = 1usize << log_n;
    let ck = CommitmentKey::new(n);
    let mut rng = ark_std::test_rng();
    let polys: Vec<Polynomial<Fr>> =
        (0..k).map(|_| Polynomial::from_coeffs((0..n).map(|_| Fr::rand(&mut rng)).collect())).collect();
    let refs: Vec<&Polynomial<Fr>> = polys.iter().collect();
    for _ in 0..2 {
        let _ = ck.batch_commit(&refs);
    }
    let t = Instant::now();
    let a = ck.batch_commit(&refs);
    let batch_ms = t.elapsed().as_secs_f64() * 1e3;
    let t = Instant::now();
    let b: Vec<_> = refs.iter().map(|p| ck.commit(p)).collect();
    let seq_ms = t.elapsed().as_secs_f64() * 1e3;
    assert_eq!(a, b);
    println!("K={k} 2^{log_n}: batch_commit {batch_ms:7.1} ms   sequential {seq_ms:7.1} ms   per-poly {:5.1} ms", seq_ms / k as f64);
}
