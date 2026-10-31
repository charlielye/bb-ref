//! The ECCVM trace built in Rust matches bb column-for-column on deterministic op queues
//! (`BbRefDump.Eccvm` fixtures, masked rows 1..3 excluded) and every ECCVM relation vanishes on it.
use crate::common;
use bb_ref::base::field::from_bytes_be;
use bb_ref::base::Fq;
use bb_ref::goblin::eccvm::check::{check_circuit, eccvm_relation_params};
use bb_ref::goblin::eccvm::{EccvmPolys, Ent, FIRST_SHIFTED, NUM_ALL_ENTITIES, TRACE_OFFSET};
use common::eccvm_ops::build_ops;

fn check(kind: &str) {
    let q = build_ops(kind);
    let mut polys = EccvmPolys::from_op_queue(&q);
    let params = eccvm_relation_params(Fq::from(2u64), Fq::from(3u64));
    polys.compute_derived(&params);
    assert_eq!(check_circuit(&polys, &params), None, "{kind}: relations vanish");
    polys.set_shifted();

    let dump = common::fixture_dir(&format!("instance/eccvm/{kind}"));
    if let Ok(bytes) = std::fs::read(dump.join("eccvm_columns.bin")) {
        let num_rows = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
        let at = |e: usize, r: usize| {
            from_bytes_be::<Fq>(&bytes[4 + 32 * (e * num_rows + r)..4 + 32 * (e * num_rows + r) + 32])
        };
        for e in 0..NUM_ALL_ENTITIES {
            let first_row = if e >= FIRST_SHIFTED {
                TRACE_OFFSET - 1
            } else {
                TRACE_OFFSET
            };
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
