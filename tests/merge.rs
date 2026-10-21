//! M6 exit: the Goblin merge and batch merge proofs reproduce bb byte-for-byte on a deterministic op
//! queue (`BbRefDump.Merge` fixtures; the random ZK prefix is injected from the dump), and the Rust
//! verifiers accept them.
mod common;
use bb_ref::base::io::decode_fields;
use bb_ref::base::srs::bn254_g2;
use bb_ref::base::{Bn254, CommitmentKey, FieldLike, Fr, G1Affine, NativeTranscript};
use bb_ref::circuit::op_queue::{
    EccOpCode, EccOpQueue, UltraOp, HIDING_KERNEL_ULTRA_OPS, NUM_ROWS_PER_OP, ZK_ULTRA_OPS,
};
use bb_ref::goblin::batch_merge::{batch_merge_prove, batch_merge_verify, ecc_op_hash_step, CHONK_MAX_NUM_CIRCUITS};
use bb_ref::goblin::merge::{merge_prove, merge_verify, MergeInputs, MERGE_PROOF_SIZE};
use common::eccvm_ops::{g1_times, populate_subtable};
use std::path::Path;

fn op_queue_with(n: usize) -> EccOpQueue {
    let mut q = EccOpQueue::new();
    for i in 0..n {
        if i > 0 {
            q.initialize_new_subtable();
        }
        populate_subtable(&mut q, i);
        q.merge();
    }
    q
}

/// Rebuild the ZK prefix (1 no-op, 3 random ops, 1 hiding op) from bb's dumped columns.
fn inject_zk_ops(q: &mut EccOpQueue, dump: &Path) {
    let frs = decode_fields(&std::fs::read(dump.join("zk_columns.bin")).unwrap());
    assert_eq!(frs.len(), 4 * ZK_ULTRA_OPS);
    let at = |col: usize, row: usize| frs[col * ZK_ULTRA_OPS + row];
    for i in 0..ZK_ULTRA_OPS / NUM_ROWS_PER_OP {
        let (r0, r1) = (i * NUM_ROWS_PER_OP, i * NUM_ROWS_PER_OP + 1);
        let op_code = match i {
            0 => EccOpCode::default(),
            1..=3 => EccOpCode {
                is_random_op: true,
                random_value_1: at(0, r0),
                random_value_2: at(0, r1),
                ..Default::default()
            },
            _ => EccOpCode::eq_reset(),
        };
        q.zk_ops.push(UltraOp {
            op_code,
            x_lo: at(1, r0),
            x_hi: at(2, r0),
            y_lo: at(3, r0),
            y_hi: at(1, r1),
            z_1: at(2, r1),
            z_2: at(3, r1),
            return_is_infinity: false,
        });
    }
    assert_eq!(
        q.zk_columns().iter().flat_map(|p| p.coeffs.clone()).collect::<Vec<_>>(),
        frs,
        "ZK columns rebuilt from the dump"
    );
}

fn read_proof(dump: &Path, name: &str) -> Vec<Fr> {
    decode_fields(&std::fs::read(dump.join(name)).unwrap())
}

#[test]
fn merge_hiding_kernel() {
    let dump = common::fixture_dir("instance/merge/merge_3");
    if !dump.join("merge_proof.bin").exists() {
        eprintln!("skipping merge_3: no dump");
        return;
    }
    let mut q = op_queue_with(3);
    inject_zk_ops(&mut q, &dump);
    q.initialize_new_subtable();
    populate_subtable(&mut q, 3);
    while q.current_subtable_size() < HIDING_KERNEL_ULTRA_OPS {
        q.add_accumulate(g1_times(1000 + q.current_subtable_size() as u64));
    }
    let ck = CommitmentKey::new(1 << 13);
    let mut t = NativeTranscript::new();
    merge_prove(&mut q, &ck, &mut t);
    let proof = t.export_proof();

    let merged = q.construct_ultra_ops_table_columns(true);
    assert_eq!(
        merged.iter().flat_map(|p| p.coeffs.clone()).collect::<Vec<_>>(),
        read_proof(&dump, "merged.bin"),
        "merged table columns"
    );
    assert_eq!(proof.len(), MERGE_PROOF_SIZE);
    assert_eq!(proof, read_proof(&dump, "merge_proof.bin"), "merge proof");

    let commit = |cols: &[bb_ref::base::Poly; 4]| std::array::from_fn(|j| ck.commit(&cols[j]));
    let inputs = MergeInputs::<Bn254> {
        t_commitments: commit(&q.construct_current_subtable_columns()),
        t_prev_commitments: commit(&q.construct_table_columns_up_to_tail()),
    };
    let mut vt = NativeTranscript::from_proof(&proof);
    let out = merge_verify::<Bn254>(&inputs, &mut vt, &());
    assert!(out.ok, "merge identities");
    assert!(out.pairing_points.check(&bn254_g2()), "merge pairing check");
    assert_eq!(out.merged_commitments, commit(&merged));

    let mut tampered = proof.clone();
    tampered[MERGE_PROOF_SIZE - 10] += Fr::one();
    let out = merge_verify::<Bn254>(&inputs, &mut NativeTranscript::from_proof(&tampered), &());
    assert!(!(out.ok && out.pairing_points.check(&bn254_g2())));
}

fn check_batch_merge(name: &str, n: usize, m: usize) {
    let dump = common::fixture_dir(&format!("instance/merge/{name}"));
    if !dump.join("batch_merge_proof.bin").exists() {
        eprintln!("skipping {name}: no dump");
        return;
    }
    let mut q = op_queue_with(n);
    q.add_batch_merge_separators();
    inject_zk_ops(&mut q, &dump);
    let ck = CommitmentKey::new(1 << 12);
    let proof = batch_merge_prove(&q, m, &ck);
    assert_eq!(
        proof.len(),
        1 + m + 4 * (4 * (m + 2) + 1) + (4 * (m + 2) + 1) + 8,
        "BATCH_MERGE_PROOF_SIZE"
    );
    assert_eq!(
        proof,
        read_proof(&dump, "batch_merge_proof.bin"),
        "{name}: batch merge proof"
    );

    // The running hash the kernels chain over the per-circuit subtable commitments.
    let mut hash: Option<Fr> = None;
    for cols in q.construct_subtable_columns() {
        let comms: Vec<G1Affine> = cols.iter().map(|p| ck.commit(p)).collect();
        hash = Some(ecc_op_hash_step::<Bn254>(&comms, hash.as_ref()));
    }
    let hash = hash.unwrap();
    let out = batch_merge_verify::<Bn254>(&proof, &hash, m, &());
    assert!(out.ok, "{name}: batch merge identities");
    assert!(
        out.pairing_points.check(&bn254_g2()),
        "{name}: batch merge pairing check"
    );
    assert_eq!(
        out.merged_commitments,
        std::array::from_fn(|j| ck.commit(&q.construct_ultra_ops_table_columns(true)[j]))
    );
    assert!(
        !batch_merge_verify::<Bn254>(&proof, &(hash + Fr::one()), m, &()).ok,
        "{name}: wrong hash rejected"
    );
}

#[test]
fn batch_merge_padded() {
    check_batch_merge("batch_3_of_9", 3, 9);
}

#[test]
fn batch_merge_max_circuits() {
    check_batch_merge("batch_5_of_max", 5, CHONK_MAX_NUM_CIRCUITS);
}
