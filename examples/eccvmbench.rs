//! ECCVM sumcheck rung, matched to bb's `sumcheck_iteration_bench`
//! `ECCVMShort/compute_univariate_round0/15` and `ECCVMShort/loop_static_blocks/15`: a dense
//! synthetic 2^15 ECCVM table (every column the nonzero constant `idx + 3`), round 0 and the full
//! round loop. Isolates ECCVM relation-evaluation efficiency from the flow's 13%-active trace.
use ark_ff::UniformRand;
use bb_ref::base::Fq;
use bb_ref::goblin::eccvm::check::eccvm_relation_params;
use bb_ref::goblin::eccvm::prover::sumcheck_spec;
use bb_ref::goblin::eccvm::relations::EccvmRelations;
use bb_ref::goblin::eccvm::trace::EccvmPolys;
use bb_ref::goblin::eccvm::FIXED_SIZE;
use bb_ref::honk::sumcheck::{alpha_powers, RelationSet, RoundProver};
use std::time::Instant;

fn main() {
    let iters: usize = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(3);
    let full_loop = std::env::args().nth(2).map(|s| s == "loop").unwrap_or(false);
    let n = FIXED_SIZE;
    let spec = sumcheck_spec();
    let mut polys = EccvmPolys::zero(n);
    let ncols = polys.cols.len();
    for (i, c) in polys.cols.iter_mut().enumerate() {
        for x in c.coeffs.iter_mut() {
            *x = Fq::from(i as u64 + 3);
        }
    }
    let first_shifted = ncols - spec.shifted_sources.len();
    let mut rng = ark_std::test_rng();
    let params = eccvm_relation_params(Fq::rand(&mut rng), Fq::rand(&mut rng));
    let rels = EccvmRelations;
    let log_n = n.trailing_zeros() as usize;
    let betas: Vec<Fq> = (0..spec.virtual_log_n as u64).map(|i| Fq::from(i + 7)).collect();
    let alphas = alpha_powers(&Fq::rand(&mut rng), RelationSet::<Fq>::total_subrelations(&rels) - 1);
    let d = spec.batched_len;
    let u = Fq::from(11u64);
    println!(
        "ECCVM 2^{log_n} dense: {} relations, {} subrelations, d={d}, cols={first_shifted}(+{} shifts)",
        RelationSet::<Fq>::num_relations(&rels),
        RelationSet::<Fq>::total_subrelations(&rels),
        spec.shifted_sources.len()
    );
    for it in 0..iters + 1 {
        let mut state = RoundProver::new(
            n,
            &polys.cols[..first_shifted],
            &spec.shifted_sources,
            spec.row_disabling,
            spec.trace_offset,
            n,
            None,
        );
        let t = Instant::now();
        let rounds = if full_loop { log_n } else { 1 };
        for _ in 0..rounds {
            let uni = state.univariate(&rels, &params, &betas, &Fq::from(1u64), &alphas, d);
            std::hint::black_box(&uni);
            if full_loop {
                state.partially_evaluate(&u);
            }
        }
        let ms = t.elapsed().as_secs_f64() * 1e3;
        if it > 0 {
            println!("  {}: {ms:8.1} ms", if full_loop { "loop  " } else { "round0" });
        }
    }
}
