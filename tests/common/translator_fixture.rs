//! The deterministic translator op queue shared by the Translator and Batched fixtures: two merged
//! subtables, bb's dumped ZK prefix, a fixed-append subtable ending in bb's dumped random ops.
use super::eccvm_ops::populate_subtable;
use bb_ref::base::io::decode_fields;
use bb_ref::base::rng::Rng;
use bb_ref::base::Fr;
use bb_ref::circuit::op_queue::{EccOpCode, EccOpQueue, UltraOp, NUM_ROWS_PER_OP, ZK_ULTRA_OPS};
use bb_ref::goblin::translator::{NUM_MASKED_ROWS_END, NUM_MINICIRCUIT_WIRES};
use std::path::Path;

fn inject_zk_ops(q: &mut EccOpQueue, dump: &Path) {
    let frs = decode_fields(&std::fs::read(dump.join("zk_columns.bin")).unwrap());
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
}

fn random_ops(dump: &Path) -> Vec<UltraOp> {
    let frs = decode_fields(&std::fs::read(dump.join("random_ops.bin")).unwrap());
    frs.chunks(8)
        .map(|v| UltraOp {
            op_code: EccOpCode {
                is_random_op: true,
                random_value_1: v[0],
                random_value_2: v[1],
                ..Default::default()
            },
            x_lo: v[2],
            x_hi: v[3],
            y_lo: v[4],
            y_hi: v[5],
            z_1: v[6],
            z_2: v[7],
            return_is_infinity: false,
        })
        .collect()
}

pub fn build_translator_queue(dump: &Path) -> EccOpQueue {
    let mut q = EccOpQueue::new();
    for i in 0..2 {
        if i > 0 {
            q.initialize_new_subtable();
        }
        populate_subtable(&mut q, i);
        q.merge();
    }
    inject_zk_ops(&mut q, dump);
    q.initialize_new_subtable();
    populate_subtable(&mut q, 2);
    for op in random_ops(dump) {
        q.ultra_ops.current.push(op);
    }
    q.merge_fixed_append(q.append_offset_for_prover());
    q
}

/// bb's masking values for the key's non-op-queue wires (`masking.bin`).
pub fn read_masking(dump: &Path) -> Vec<[Fr; NUM_MASKED_ROWS_END]> {
    let frs = decode_fields(&std::fs::read(dump.join("masking.bin")).unwrap());
    (0..NUM_MINICIRCUIT_WIRES)
        .map(|w| std::array::from_fn(|k| frs[w * NUM_MASKED_ROWS_END + k]))
        .collect()
}

/// The same recipe with the ZK prefix and random ops drawn from `rng` (bb's draw order).
pub fn build_translator_queue_from_rng(rng: &mut dyn Rng) -> EccOpQueue {
    let mut q = EccOpQueue::new();
    for i in 0..2 {
        if i > 0 {
            q.initialize_new_subtable();
        }
        populate_subtable(&mut q, i);
        q.merge();
    }
    q.construct_zk_columns(rng);
    q.initialize_new_subtable();
    populate_subtable(&mut q, 2);
    for _ in 0..2 {
        let op = UltraOp::random(rng);
        q.ultra_ops.current.push(op);
    }
    q.merge_fixed_append(q.append_offset_for_prover());
    q
}
