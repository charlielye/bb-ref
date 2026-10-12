//! Isolated MSM comparison over SRS points: base::msm::msm, CommitmentKey::commit (with its
//! duplicate-scalar pre-pass) and ark msm_unchecked.
//! Usage: msmbench <log_n> [iters] [scalar_bits] [profile]
//! Profiles (bb pippenger_bench's PippengerSparsity): dense; dense80 (20% zero); dup (20% zero,
//! 25% one scalar A, 5% one scalar B, 50% unique).

use ark_ec::{CurveGroup, VariableBaseMSM};
use ark_ff::{UniformRand, Zero};
use ark_std::rand::Rng;
use std::time::Instant;

fn main() {
    let arg = |i: usize| std::env::args().nth(i);
    let log_n: usize = arg(1).and_then(|s| s.parse().ok()).unwrap_or(17);
    let iters: usize = arg(2).and_then(|s| s.parse().ok()).unwrap_or(5);
    let bits: u32 = arg(3).and_then(|s| s.parse().ok()).unwrap_or(254);
    let profile = arg(4).unwrap_or("dense".into());
    let n = 1usize << log_n;
    let mut rng = ark_std::test_rng();
    let ck = bb_ref::base::CommitmentKey::new(n);
    let points = &ck.points[..n];
    let random = |rng: &mut dyn ark_std::rand::RngCore| {
        use ark_ff::PrimeField;
        let mut b = bb_ref::base::Fr::rand(&mut *rng).into_bigint();
        for (k, limb) in b.0.iter_mut().enumerate() {
            let lo = (k * 64) as u32;
            if lo >= bits {
                *limb = 0;
            } else if bits - lo < 64 {
                *limb &= (1u64 << (bits - lo)) - 1;
            }
        }
        bb_ref::base::Fr::from_bigint(b).unwrap()
    };
    let (a, b) = (random(&mut rng), random(&mut rng));
    let scalars: Vec<bb_ref::base::Fr> = (0..n)
        .map(|_| {
            let r: f64 = rng.gen();
            match profile.as_str() {
                "dense80" if r < 0.2 => bb_ref::base::Fr::zero(),
                "dup" if r < 0.2 => bb_ref::base::Fr::zero(),
                "dup" if r < 0.45 => a,
                "dup" if r < 0.5 => b,
                _ => random(&mut rng),
            }
        })
        .collect();
    let poly = bb_ref::base::poly::Polynomial::from_coeffs(scalars.clone());

    let skip_ark = std::env::var_os("BBREF_MSMBENCH_NO_ARK").is_some();
    let runs: [(&str, Box<dyn Fn() -> bb_ref::base::G1Projective>); 3] = [
        ("msm   ", Box::new(|| bb_ref::base::msm::msm(points, &scalars))),
        ("commit", Box::new(|| ck.commit(&poly).into())),
        (
            "ark   ",
            Box::new(|| bb_ref::base::G1Projective::msm_unchecked(points, &scalars)),
        ),
    ];
    for (name, f) in runs.iter() {
        if skip_ark && name.starts_with("ark") {
            continue;
        }
        let mut best = f64::MAX;
        let mut r = f();
        for _ in 0..iters {
            let t = Instant::now();
            r = f();
            best = best.min(t.elapsed().as_secs_f64() * 1e3);
        }
        assert!(!r.is_zero());
        let _ = r.into_affine();
        println!("{name} {profile} {bits}b 2^{log_n}: {best:.2} ms");
    }
}
