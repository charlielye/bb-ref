//! L3 rung: sumcheck round-0 univariate over a synthetic no-skip MegaZK table, matched to bb's
//! `sumcheck_iteration_bench` `MegaZK/compute_univariate_round0/<log_n>` (each column filled with
//! the nonzero constant `idx + 3`, gate challenges `idx + 7`, so no skip logic fires on either
//! side). Usage: roundbench [log_n] [iters] [active_pct] — active_pct < 100 zeroes the table
//! outside that leading fraction (the mostly-skippable real-trace shape; skip machinery cost).

use ark_ff::UniformRand;
use bb_ref::base::poly::Polynomial;
use bb_ref::base::Fr;
use bb_ref::honk::flavor::MEGA_ZK;
use bb_ref::honk::relations::RelationParams;
use bb_ref::honk::sumcheck::{alpha_powers, HonkRelations, RelationSet, RoundProver};
use std::time::Instant;

fn main() {
    let log_n: usize = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(17);
    let iters: usize = std::env::args().nth(2).and_then(|s| s.parse().ok()).unwrap_or(4);
    let n = 1usize << log_n;
    let layout = MEGA_ZK.layout();
    let rels = HonkRelations {
        flavor: &MEGA_ZK,
        layout: &layout,
    };
    let active_pct: usize = std::env::args().nth(3).and_then(|s| s.parse().ok()).unwrap_or(100);
    let active = n * active_pct / 100;
    let polys: Vec<Polynomial<Fr>> = (0..layout.unshifted.len())
        .map(|i| {
            let mut coeffs = vec![Fr::from(0u64); n];
            for c in coeffs[..active].iter_mut() {
                *c = Fr::from(i as u64 + 3);
            }
            Polynomial::from_coeffs(coeffs)
        })
        .collect();
    let shifted: Vec<usize> = layout.shifted.iter().map(|e| layout.idx(*e)).collect();
    let mut rng = ark_std::test_rng();
    let mut params = RelationParams::<Fr>::default();
    params.beta = Fr::rand(&mut rng);
    params.gamma = Fr::rand(&mut rng);
    params.public_input_delta = Fr::rand(&mut rng);
    params.eta = Fr::rand(&mut rng);
    params.eta_two = Fr::rand(&mut rng);
    params.eta_three = Fr::rand(&mut rng);
    let betas: Vec<Fr> = (0..log_n as u64).map(|i| Fr::from(i + 7)).collect();
    let alphas = alpha_powers(&Fr::rand(&mut rng), RelationSet::<Fr>::total_subrelations(&rels) - 1);
    let d = layout.batched_len;
    println!(
        "MegaZK round0 2^{log_n}: {} relations, {} subrelations, {} cols (+{} shifts), d={d}",
        RelationSet::<Fr>::num_relations(&rels),
        RelationSet::<Fr>::total_subrelations(&rels),
        layout.unshifted.len(),
        shifted.len(),
    );
    // Warm-up + timed iterations; a fresh RoundProver per iteration (round 0 reads borrowed
    // columns, nothing folds).
    for it in 0..iters + 1 {
        let mut state = RoundProver::new(n, &polys, &shifted, true, MEGA_ZK.trace_offset, n, None);
        let t = Instant::now();
        let uni = state.univariate(&rels, &params, &betas, &Fr::from(1u64), &alphas, d);
        let ms = t.elapsed().as_secs_f64() * 1e3;
        std::hint::black_box(uni);
        if it > 0 {
            println!("round0: {ms:.1} ms");
        }
    }
}
