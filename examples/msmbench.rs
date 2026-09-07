//! Isolated MSM comparison: base::msm::msm vs ark msm_unchecked. Usage: msmbench <log_n> [iters] [scalar_bits]

use ark_ec::{CurveGroup, VariableBaseMSM};
use ark_ff::{UniformRand, Zero};
use std::time::Instant;

fn main() {
    let log_n: usize = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(17);
    let iters: usize = std::env::args().nth(2).and_then(|s| s.parse().ok()).unwrap_or(5);
    let n = 1usize << log_n;
    let mut rng = ark_std::test_rng();
    let points = bb_ref::base::G1Projective::normalize_batch(
        &(0..n)
            .map(|_| bb_ref::base::G1Projective::rand(&mut rng))
            .collect::<Vec<_>>(),
    );
    let bits: u32 = std::env::args().nth(3).and_then(|s| s.parse().ok()).unwrap_or(254);
    let scalars: Vec<bb_ref::base::Fr> = (0..n)
        .map(|_| {
            use ark_ff::PrimeField;
            let mut b = bb_ref::base::Fr::rand(&mut rng).into_bigint();
            for (k, limb) in b.0.iter_mut().enumerate() {
                let lo = (k * 64) as u32;
                if lo >= bits {
                    *limb = 0;
                } else if bits - lo < 64 {
                    *limb &= (1u64 << (bits - lo)) - 1;
                }
            }
            bb_ref::base::Fr::from_bigint(b).unwrap()
        })
        .collect();

    let skip_ark = std::env::var_os("BBREF_MSMBENCH_NO_ARK").is_some();
    for (name, f) in [
        (
            "ours",
            (|p: &[_], s: &[_]| bb_ref::base::msm::msm(p, s)) as fn(&[_], &[_]) -> _,
        ),
        ("ark ", |p, s| bb_ref::base::G1Projective::msm_unchecked(p, s)),
    ] {
        if skip_ark && name == "ark " {
            continue;
        }
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
