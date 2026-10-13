//! L3 rung: the *whole* sumcheck round loop, matched to bb's `sumcheck_iteration_bench`
//! `MegaZK/loop_static_blocks/<log_n>`, as opposed to `roundbench` which times round 0 alone.
//!
//! Exists because the round-0 rung and the real flow disagree: on round 0 we beat bb, while the
//! flow's folding sumcheck is 1.32x bb. The knobs here are the ways the flow's configuration
//! differs from the dense single-round rung, so they can be swept one at a time to find which one
//! flips the result.
//!
//! Usage: loopbench [log_n] [iters] [active_pct] [virtual_log_n]
//!   active_pct    < 100 zeroes the table outside that leading fraction (real traces are mostly
//!                 skippable, the synthetic rung is not).
//!   virtual_log_n > log_n adds the rounds a folded instance runs past its own size, which every
//!                 instance in a Chonk group does because the group shares one round count.

use ark_ff::UniformRand;
use bb_ref::base::poly::Polynomial;
use bb_ref::base::Fr;
use bb_ref::honk::flavor::MEGA_ZK;
use bb_ref::honk::relations::RelationParams;
use bb_ref::honk::sumcheck::{alpha_powers, HonkRelations, RelationSet, RoundProver};
use std::time::Instant;

fn main() {
    let arg = |i: usize| std::env::args().nth(i).and_then(|s| s.parse::<usize>().ok());
    let log_n = arg(1).unwrap_or(17);
    let iters = arg(2).unwrap_or(3);
    let active_pct = arg(3).unwrap_or(100);
    let virtual_log_n = arg(4).unwrap_or(log_n);
    let n = 1usize << log_n;
    let layout = MEGA_ZK.layout();
    let rels = HonkRelations {
        flavor: &MEGA_ZK,
        layout: &layout,
    };
    // `frag` reproduces bb's `make_active_blocks(round_size, fragmented=true)`: 18 active blocks
    // separated by gaps, the shape a real Chonk trace has, rather than one leading prefix.
    let frag = std::env::var_os("BBREF_FRAG").is_some();
    let blocks: Vec<(usize, usize)> = if frag {
        const NUM_BLOCKS: usize = 18;
        let total_pairs = n / 2;
        let active_pairs = (total_pairs * active_pct / 100).max(NUM_BLOCKS);
        let inactive_pairs = total_pairs - active_pairs;
        let (base_block, extra_block) = (active_pairs / NUM_BLOCKS, active_pairs % NUM_BLOCKS);
        let (base_gap, extra_gap) = (inactive_pairs / NUM_BLOCKS, inactive_pairs % NUM_BLOCKS);
        let mut v = Vec::with_capacity(NUM_BLOCKS);
        let mut cursor = 0usize;
        for b in 0..NUM_BLOCKS {
            cursor += base_gap + usize::from(b < extra_gap);
            let pairs = base_block + usize::from(b < extra_block);
            v.push((cursor * 2, pairs * 2));
            cursor += pairs;
        }
        v
    } else {
        vec![(0, n * active_pct / 100)]
    };
    let polys: Vec<Polynomial<Fr>> = (0..layout.unshifted.len())
        .map(|i| {
            let mut coeffs = vec![Fr::from(0u64); n];
            for &(start, size) in &blocks {
                for c in coeffs[start..(start + size).min(n)].iter_mut() {
                    *c = Fr::from(i as u64 + 3);
                }
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
    let betas: Vec<Fr> = (0..virtual_log_n as u64).map(|i| Fr::from(i + 7)).collect();
    let alphas = alpha_powers(&Fr::rand(&mut rng), RelationSet::<Fr>::total_subrelations(&rels) - 1);
    let d = layout.batched_len;
    let u = Fr::from(11u64);
    println!(
        "MegaZK loop 2^{log_n}: active={active_pct}% frag={frag} virtual_log_n={virtual_log_n} \
         {} relations, {} subrelations, d={d}",
        RelationSet::<Fr>::num_relations(&rels),
        RelationSet::<Fr>::total_subrelations(&rels),
    );
    // One warm-up pass, then timed passes. Each pass is a fresh prover so round 0 reads borrowed
    // columns exactly as the flow does.
    for it in 0..iters + 1 {
        // BBREF_WITNESS_END_ACTIVE: cap the round at the active prefix (only meaningful without
        // BBREF_FRAG), so gap rows are never visited — what bb's active-range iteration does.
        let witness_end = if std::env::var_os("BBREF_WITNESS_END_ACTIVE").is_some() && !frag {
            n * active_pct / 100
        } else {
            n
        };
        let mut state = RoundProver::new(n, &polys, &shifted, true, MEGA_ZK.trace_offset, witness_end, None);
        let t = Instant::now();
        let mut round0_ms = 0.0;
        let (mut uni_ms, mut fold_ms) = (0.0f64, 0.0f64);
        for round in 0..virtual_log_n {
            let t_round = Instant::now();
            let t_u = Instant::now();
            let uni = state.univariate(&rels, &params, &betas, &Fr::from(1u64), &alphas, d);
            std::hint::black_box(&uni);
            uni_ms += t_u.elapsed().as_secs_f64() * 1e3;
            let t_f = Instant::now();
            state.partially_evaluate(&u);
            fold_ms += t_f.elapsed().as_secs_f64() * 1e3;
            let rms = t_round.elapsed().as_secs_f64() * 1e3;
            if round == 0 {
                round0_ms = rms;
            }
            if it > 0 && std::env::var_os("BBREF_PER_ROUND").is_some() {
                let f_ms = t_f.elapsed().as_secs_f64() * 1e3;
                println!("    round {round:2}: {rms:7.2} ms   (fold {f_ms:6.2} ms)");
            }
        }
        let ms = t.elapsed().as_secs_f64() * 1e3;
        if it > 0 {
            println!(
                "  loop: {ms:8.1} ms   (round0 {round0_ms:6.1} ms, rest {:6.1} ms)  [univariate {uni_ms:6.1}, fold {fold_ms:6.1}, other {:5.1}]",
                ms - round0_ms,
                ms - uni_ms - fold_ms
            );
        }
    }
}
