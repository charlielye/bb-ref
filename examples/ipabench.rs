//! Matched against bb's `ipa_bench` `ipa_open/15`: one classical IPA opening proof of a random
//! degree-2^15 polynomial over Grumpkin (b = powers of a random evaluation point).
use ark_ff::UniformRand;
use bb_ref::base::poly::Polynomial;
use bb_ref::base::{Fq, GrumpkinKey, NativeTranscript};
use bb_ref::goblin::ipa::inner_product_prove;
use std::time::Instant;

fn main() {
    let log_n: usize = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(15);
    let iters: usize = std::env::args().nth(2).and_then(|s| s.parse().ok()).unwrap_or(3);
    let n = 1usize << log_n;
    let ck = GrumpkinKey::new(n);
    let mut rng = ark_std::test_rng();
    let poly = Polynomial::from_coeffs((0..n).map(|_| Fq::rand(&mut rng)).collect());
    let x = Fq::rand(&mut rng);
    let mut b = Vec::with_capacity(n);
    let mut p = Fq::from(1u64);
    for _ in 0..n {
        b.push(p);
        p *= x;
    }
    for it in 0..iters + 1 {
        let mut t = NativeTranscript::new();
        t.send("IPA:x", &x);
        let t0 = Instant::now();
        inner_product_prove(&ck, &poly, b.clone(), &mut t);
        let ms = t0.elapsed().as_secs_f64() * 1e3;
        if it > 0 {
            println!("ipa_open 2^{log_n}: {ms:7.1} ms");
        }
    }
}
