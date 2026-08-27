//! Times the relation bodies directly on one row (per point), reported per edge (x partial length).
use ark_ff::UniformRand;
use bb_ref::base::{Fq, Fr};
use bb_ref::goblin::eccvm::relations::{EccvmRelations, ECCVM_RELATIONS};
use bb_ref::honk::flavor::MEGA_KERNEL;
use bb_ref::honk::relations::RelationParams;
use bb_ref::honk::sumcheck::{HonkRelations, RelationSet};
use std::time::Instant;
fn main() {
    if std::env::args().nth(1).as_deref() == Some("translator") {
        return translator();
    }
    let mut rng = ark_std::test_rng();
    let row: Vec<Fq> = (0..119).map(|_| Fq::rand(&mut rng)).collect();
    let mut p = RelationParams::<Fq>::default();
    p.beta = Fq::rand(&mut rng);
    p.gamma = Fq::rand(&mut rng);
    p.beta_sqr = Fq::rand(&mut rng);
    p.beta_cube = Fq::rand(&mut rng);
    p.beta_quartic = Fq::rand(&mut rng);
    p.eccvm_set_permutation_delta = Fq::rand(&mut rng);
    let s = Fq::rand(&mut rng);
    for (r, rel) in ECCVM_RELATIONS.iter().enumerate() {
        let mut acc = vec![Fq::from(0u64); rel.num_subrelations()];
        let len = RelationSet::<Fq>::partial_length(&EccvmRelations, r);
        let n = 20000;
        let t = Instant::now();
        for _ in 0..n {
            RelationSet::<Fq>::accumulate(&EccvmRelations, r, &mut acc, &row, &p, &s);
        }
        let ns = t.elapsed().as_nanos() as f64 / n as f64;
        println!(
            "ours eccvm {rel:?}: {:.1} ns per point x{len} = {:.1} ns per edge",
            ns,
            ns * len as f64
        );
    }
    let layout = MEGA_KERNEL.layout();
    let row: Vec<Fr> = (0..layout.num_all()).map(|_| Fr::rand(&mut rng)).collect();
    let mut p = RelationParams::<Fr>::default();
    p.beta = Fr::rand(&mut rng);
    p.gamma = Fr::rand(&mut rng);
    p.public_input_delta = Fr::rand(&mut rng);
    p.eta = Fr::rand(&mut rng);
    p.eta_two = Fr::rand(&mut rng);
    p.eta_three = Fr::rand(&mut rng);
    let s = Fr::rand(&mut rng);
    let rels = HonkRelations {
        flavor: &MEGA_KERNEL,
        layout: &layout,
    };
    for r in 0..MEGA_KERNEL.relations.len() {
        let mut acc = vec![Fr::from(0u64); RelationSet::<Fr>::num_subrelations(&rels, r)];
        let len = RelationSet::<Fr>::partial_length(&rels, r);
        let n = 200000;
        let t = Instant::now();
        for _ in 0..n {
            RelationSet::<Fr>::accumulate(&rels, r, &mut acc, &row, &p, &s);
        }
        let ns = t.elapsed().as_nanos() as f64 / n as f64;
        println!(
            "ours kernel {:?}: {:.1} ns per point x{len} = {:.1} ns per edge",
            MEGA_KERNEL.relations[r],
            ns,
            ns * len as f64
        );
    }
}
pub fn translator() {
    use bb_ref::goblin::translator::relations::{TranslatorRelations, TRANSLATOR_RELATIONS};
    let mut rng = ark_std::test_rng();
    let row: Vec<Fr> = (0..bb_ref::goblin::translator::NUM_ALL_ENTITIES)
        .map(|_| Fr::rand(&mut rng))
        .collect();
    let mut p = RelationParams::<Fr>::default();
    p.beta = Fr::rand(&mut rng);
    p.gamma = Fr::rand(&mut rng);
    let s = Fr::rand(&mut rng);
    for (r, rel) in TRANSLATOR_RELATIONS.iter().enumerate() {
        let mut acc = vec![Fr::from(0u64); rel.num_subrelations()];
        let len = RelationSet::<Fr>::partial_length(&TranslatorRelations, r);
        let n = 50000;
        let t = Instant::now();
        for _ in 0..n {
            RelationSet::<Fr>::accumulate(&TranslatorRelations, r, &mut acc, &row, &p, &s);
        }
        let ns = t.elapsed().as_nanos() as f64 / n as f64;
        println!(
            "ours translator {rel:?}: {:.1} ns per point x{len} = {:.1} ns per edge",
            ns,
            ns * len as f64
        );
    }
}
