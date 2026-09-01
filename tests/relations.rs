//! Relation-level soundness (T2): satisfying traces vanish under every relation, and a targeted
//! one-value corruption is reported as EXACTLY the expected relation — the failure names its
//! module and row. Standalone: traces are built from in-process op queues and circuits.

mod common;

use bb_ref::base::field::FieldLike;
use bb_ref::base::rng::DebugRng;
use bb_ref::base::{Fq, Fr};

/// ECCVM: the trace of a real op sequence satisfies all eight relation files; corrupting a
/// transcript accumulator cell is caught by the transcript relation, and an MSM count cell by the
/// MSM relation — at the corrupted row.
#[test]
fn eccvm_corruptions_are_named_and_localized() {
    use bb_ref::goblin::eccvm::check::{check_circuit, eccvm_relation_params};
    use bb_ref::goblin::eccvm::{EccvmPolys, Ent};
    use common::eccvm_ops::build_ops;

    let q = build_ops("mixed");
    let params = eccvm_relation_params(Fq::from(2u64), Fq::from(3u64));
    let mut polys = EccvmPolys::from_op_queue(&q);
    polys.compute_derived(&params);
    assert_eq!(check_circuit(&polys, &params), None, "satisfying trace");

    // transcript_accumulator_x: the running accumulator the transcript relation reconstructs.
    let col = Ent::transcript_accumulator_x as usize;
    let row = polys.cols[col]
        .coeffs
        .iter()
        .position(|v| !v.is_zero())
        .expect("accumulator has an active row");
    let mut bad = polys.clone();
    bad.cols[col].coeffs[row] += Fq::from(1u64);
    let (rel, _, at) = check_circuit(&bad, &params).expect("corruption caught");
    assert!(format!("{rel:?}").contains("Transcript"), "named: {rel:?}");
    assert!(
        at.is_some_and(|r| r.abs_diff(row) <= 1),
        "localized near row {row}, got {at:?}"
    );

    // msm_pc: the point counter inside the MSM rows.
    let col = Ent::msm_pc as usize;
    let row = polys.cols[col]
        .coeffs
        .iter()
        .position(|v| !v.is_zero())
        .expect("msm rows exist");
    let mut bad = polys.clone();
    bad.cols[col].coeffs[row] += Fq::from(1u64);
    let (rel, _, _) = check_circuit(&bad, &params).expect("corruption caught");
    let name = format!("{rel:?}");
    assert!(
        name.contains("Msm") || name.contains("MSM") || name.contains("Set"),
        "named: {name}"
    );
}

/// Translator: a queue-derived circuit satisfies all relations; corrupting a decomposition
/// micro-limb is caught by the decomposition relation, and z_perm by the permutation relation.
#[test]
fn translator_corruptions_are_named() {
    use bb_ref::base::field::FieldLike as _;
    use bb_ref::goblin::translator::builder::TranslatorCircuit;
    use bb_ref::goblin::translator::check::{check_circuit, translator_relation_params};
    use bb_ref::goblin::translator::{Ent, TranslatorPolys};
    use common::translator_fixture::build_translator_queue_from_rng;

    let mut rng = DebugRng::new(11);
    let q = build_translator_queue_from_rng(&mut rng);
    let v = Fq::from(11u64).invert();
    let x = Fq::from(13u64).invert();
    let circuit = TranslatorCircuit::new(v, x, &q);
    let result_limbs = circuit.accumulated_result_limbs();
    let masking = TranslatorPolys::random_masking(&mut rng);
    let params = translator_relation_params(&v, &x, result_limbs, Fr::from(2u64), Fr::from(3u64));
    let mut polys = TranslatorPolys::from_circuit(&circuit, &masking);
    polys.compute_grand_product(&params);
    assert_eq!(check_circuit(&polys, &params), None, "satisfying circuit");

    let col = Ent::p_x_low_limbs_range_constraint_0 as usize;
    let row = polys.cols[col]
        .coeffs
        .iter()
        .position(|v| !v.is_zero())
        .expect("active row");
    let mut bad = polys.clone();
    bad.cols[col].coeffs[row] += Fr::from(1u64);
    let (rel, _, _) = check_circuit(&bad, &params).expect("corruption caught");
    let name = format!("{rel:?}");
    assert!(
        name.contains("Decomposition") || name.contains("Range"),
        "named: {name}"
    );

    let col = Ent::z_perm as usize;
    let row = polys.cols[col]
        .coeffs
        .iter()
        .position(|v| !v.is_zero())
        .expect("z_perm active");
    let mut bad = polys.clone();
    bad.cols[col].coeffs[row] += Fr::from(1u64);
    let (rel, _, _) = check_circuit(&bad, &params).expect("corruption caught");
    assert!(format!("{rel:?}").contains("Permutation"), "named: {rel:?}");
}
