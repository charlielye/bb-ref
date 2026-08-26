//! Deterministic ECCVM op queues shared by the M8/M9 tests and mirrored in bb's `BbRefDump.Eccvm`.
#![allow(dead_code)]
use ark_ec::{AffineRepr, CurveGroup};
use bb_ref::base::field::FieldLike;
use bb_ref::base::{Fq, Fr, G1Affine};
use bb_ref::circuit::op_queue::EccOpQueue;

pub fn pt(k: u64) -> G1Affine {
    (G1Affine::generator() * Fr::from(k)).into_affine()
}

pub fn build_ops(kind: &str) -> EccOpQueue {
    let mut q = EccOpQueue::new();
    let inf = G1Affine::identity();
    let x = Fr::from(123456789u64).invert();
    let y = Fr::from(987654321u64).invert();
    let zero = Fr::from(0u64);
    if kind == "base" {
        let (a, b, c) = (pt(3), pt(5), pt(7));
        q.add_accumulate(a);
        q.mul_accumulate(a, x);
        q.mul_accumulate(b, x);
        q.mul_accumulate(b, y);
        q.add_accumulate(a);
        q.mul_accumulate(b, x);
        q.add_accumulate(b);
        q.eq_and_reset();
        q.add_accumulate(c);
        q.mul_accumulate(a, x);
        q.mul_accumulate(inf, x);
        q.mul_accumulate(b, x);
        q.eq_and_reset();
        q.mul_accumulate(a, x);
        q.mul_accumulate(b, x);
        q.mul_accumulate(inf, zero);
        q.mul_accumulate(c, x);
        q.eq_and_reset();
        q.mul_accumulate(inf, zero);
        q.mul_accumulate(inf, x);
        q.mul_accumulate(inf, zero);
        q.add_accumulate(a);
        q.eq_and_reset();
        q.add_accumulate(a);
        q.add_accumulate(inf);
        q.eq_and_reset();
        q.add_accumulate(inf);
        q.eq_and_reset();
        q.mul_accumulate(inf, x);
        q.mul_accumulate(inf, -x);
        q.eq_and_reset();
        q.add_accumulate(a);
        q.mul_accumulate(inf, x);
        q.mul_accumulate(inf, -x);
        q.add_accumulate(a);
        q.add_accumulate(a);
        q.eq_and_reset();
    } else {
        for k in 0..9u64 {
            q.mul_accumulate(pt(k + 11), Fr::from(1000 + k).invert());
        }
        q.eq_and_reset();
    }
    q.merge();
    q.append_hiding_op(Fq::from(11u64), Fq::from(13u64));
    q
}

pub fn g1_times(k: u64) -> G1Affine {
    (G1Affine::generator() * Fr::from(k)).into_affine()
}

/// Subtable `i` of the M6/M10 fixtures: `((1 + i) % 10) + 1` triples of add / mul (with a >128-bit
/// scalar) / eq_and_reset (bb `populate_subtable_deterministic`).
pub fn populate_subtable(q: &mut EccOpQueue, i: usize) {
    for j in 0..((1 + i) % 10) + 1 {
        let k = (1 + 100 * i + j) as u64;
        q.add_accumulate(g1_times(k));
        q.mul_accumulate(g1_times(k + 1), Fr::from(k + 2).invert());
        q.eq_and_reset();
    }
}
