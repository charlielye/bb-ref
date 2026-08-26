//! M8 exit: the ECCVM trace built in Rust matches bb column-for-column on deterministic op queues
//! (`BbRefDump.Eccvm` fixtures, masked rows 1..3 excluded) and every ECCVM relation vanishes on it.
mod common;
use ark_ec::{AffineRepr, CurveGroup};
use bb_ref::base::field::{from_bytes_be, FieldLike};
use bb_ref::base::{Fq, Fr, G1Affine};
use bb_ref::circuit::op_queue::EccOpQueue;
use bb_ref::goblin::eccvm::check::{check_circuit, eccvm_relation_params};
use bb_ref::goblin::eccvm::{Ent, EccvmPolys, FIRST_SHIFTED, NUM_ALL_ENTITIES, TRACE_OFFSET};

fn pt(k: u64) -> G1Affine {
    (G1Affine::generator() * Fr::from(k)).into_affine()
}

fn build_ops(kind: &str) -> EccOpQueue {
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

fn check(kind: &str) {
    let q = build_ops(kind);
    let mut polys = EccvmPolys::from_op_queue(&q);
    let params = eccvm_relation_params(Fq::from(2u64), Fq::from(3u64));
    polys.compute_derived(&params);
    assert_eq!(check_circuit(&polys, &params), None, "{kind}: relations vanish");

    let dump = common::fixture_dir(&format!("instance/eccvm/{kind}"));
    if let Ok(bytes) = std::fs::read(dump.join("eccvm_columns.bin")) {
        let num_rows = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
        let at = |e: usize, r: usize| from_bytes_be::<Fq>(&bytes[4 + 32 * (e * num_rows + r)..4 + 32 * (e * num_rows + r) + 32]);
        for e in 0..NUM_ALL_ENTITIES {
            let first_row = if e >= FIRST_SHIFTED { TRACE_OFFSET - 1 } else { TRACE_OFFSET };
            for r in (0..1).chain(first_row..num_rows) {
                if e < FIRST_SHIFTED && r == 0 || r >= first_row {
                    assert_eq!(polys.cols[e].coeffs[r], at(e, r), "{kind}: entity {e} row {r}");
                }
            }
        }
    } else {
        eprintln!("skipping eccvm/{kind} column comparison: no dump");
    }

    let row = TRACE_OFFSET + 3;
    polys.cols[Ent::msm_accumulator_x as usize].coeffs[row] += Fq::from(1u64);
    polys.set_shifted();
    assert!(check_circuit(&polys, &params).is_some(), "{kind}: corruption detected");
}

#[test]
fn eccvm_base_case() {
    check("base");
}

#[test]
fn eccvm_msm_of_nine() {
    check("msm9");
}
