//! What one parallel dispatch costs. The sumcheck round loop pays three of these per round and
//! ~20 rounds per instance, and backing the cost out of the round timings suggested ~2.5ms per
//! round against bb's ~0.23ms, which is far more than a dispatch should cost. This measures it
//! directly rather than by subtraction.
//!
//! Usage: dispatchbench [chunks] [reps]

use rayon::prelude::*;
use std::time::Instant;

fn main() {
    let chunks: usize = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(128);
    let reps: usize = std::env::args().nth(2).and_then(|s| s.parse().ok()).unwrap_or(200);
    let threads = rayon::current_num_threads();
    let items: Vec<usize> = (0..chunks).collect();

    // Empty dispatch: everything here is scheduling.
    let t = Instant::now();
    for _ in 0..reps {
        let s: usize = items.par_iter().map(|&i| std::hint::black_box(i)).sum();
        std::hint::black_box(s);
    }
    let empty_us = t.elapsed().as_secs_f64() * 1e6 / reps as f64;

    // Same shape with a little work per chunk, so the pool has a reason to stay awake.
    let t = Instant::now();
    for _ in 0..reps {
        let s: usize = items
            .par_iter()
            .map(|&i| {
                let mut acc = i as u64;
                for k in 0..200u64 {
                    acc = acc.wrapping_mul(6364136223846793005).wrapping_add(k);
                }
                std::hint::black_box(acc) as usize
            })
            .sum();
        std::hint::black_box(s);
    }
    let work_us = t.elapsed().as_secs_f64() * 1e6 / reps as f64;

    // The same work done serially, to separate dispatch cost from the work itself.
    let t = Instant::now();
    for _ in 0..reps {
        let mut s = 0usize;
        for &i in &items {
            let mut acc = i as u64;
            for k in 0..200u64 {
                acc = acc.wrapping_mul(6364136223846793005).wrapping_add(k);
            }
            s = s.wrapping_add(std::hint::black_box(acc) as usize);
        }
        std::hint::black_box(s);
    }
    let serial_us = t.elapsed().as_secs_f64() * 1e6 / reps as f64;

    println!("threads={threads} chunks={chunks} reps={reps}");
    println!("  empty par_iter   : {empty_us:9.1} us/dispatch");
    println!("  with work        : {work_us:9.1} us/dispatch");
    println!("  same work serial : {serial_us:9.1} us");
    println!(
        "  implied overhead : {:9.1} us/dispatch",
        work_us - serial_us / threads as f64
    );
}
