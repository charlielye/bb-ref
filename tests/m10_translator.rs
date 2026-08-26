//! M10 exit: the Translator circuit built in Rust matches bb wire-for-wire, its proving key (with
//! bb's masking values injected) matches column-for-column including `z_perm`, and all eight
//! relations vanish on it (`BbRefDump.Translator` fixture).
mod common;
use bb_ref::base::field::{from_bytes_be, u256, FieldLike};
use bb_ref::base::io::decode_fields;
use bb_ref::base::{Fq, Fr};
use bb_ref::circuit::op_queue::{EccOpCode, EccOpQueue, UltraOp, NUM_ROWS_PER_OP, ZK_ULTRA_OPS};
use bb_ref::goblin::translator::builder::{TranslatorCircuit, ACCUMULATORS_BINARY_LIMBS_0};
use bb_ref::goblin::translator::check::{check_circuit, translator_relation_params};
use bb_ref::goblin::translator::{TranslatorPolys, CIRCUIT_SIZE, NUM_MASKED_ROWS_END, NUM_MINICIRCUIT_WIRES, NUM_WIRES, RESULT_ROW};
use common::eccvm_ops::populate_subtable;
use std::path::Path;

fn inject_zk_ops(q: &mut EccOpQueue, dump: &Path) {
    let frs = decode_fields(&std::fs::read(dump.join("zk_columns.bin")).unwrap());
    let at = |col: usize, row: usize| frs[col * ZK_ULTRA_OPS + row];
    for i in 0..ZK_ULTRA_OPS / NUM_ROWS_PER_OP {
        let (r0, r1) = (i * NUM_ROWS_PER_OP, i * NUM_ROWS_PER_OP + 1);
        let op_code = match i {
            0 => EccOpCode::default(),
            1..=3 => EccOpCode { is_random_op: true, random_value_1: at(0, r0), random_value_2: at(0, r1), ..Default::default() },
            _ => EccOpCode::eq_reset(),
        };
        q.zk_ops.push(UltraOp { op_code, x_lo: at(1, r0), x_hi: at(2, r0), y_lo: at(3, r0), y_hi: at(1, r1), z_1: at(2, r1), z_2: at(3, r1), return_is_infinity: false });
    }
}

fn random_ops(dump: &Path) -> Vec<UltraOp> {
    let frs = decode_fields(&std::fs::read(dump.join("random_ops.bin")).unwrap());
    frs.chunks(8)
        .map(|v| UltraOp { op_code: EccOpCode { is_random_op: true, random_value_1: v[0], random_value_2: v[1], ..Default::default() }, x_lo: v[2], x_hi: v[3], y_lo: v[4], y_hi: v[5], z_1: v[6], z_2: v[7], return_is_infinity: false })
        .collect()
}

/// bb's test helper `compute_expected_result`: the batched evaluation the circuit should accumulate.
fn expected_result(q: &EccOpQueue, v: &Fq, x: &Fq) -> Fq {
    let x_inv = x.invert();
    let mut acc = [Fq::from(0u64); 5];
    let mut x_pow = Fq::from(1u64);
    for op in q.get_zk_reconstructed_ultra_ops() {
        if op.op_code.is_random_op || op.op_code.value() == 0 {
            continue;
        }
        let (px, py) = bb_ref::goblin::translator::builder::base_point_standard_form(&op);
        let vals = [Fq::from(op.op_code.value() as u64), px, py, bb_ref::base::field::from_u256(u256(&op.z_1)), bb_ref::base::field::from_u256(u256(&op.z_2))];
        for (a, val) in acc.iter_mut().zip(vals) {
            *a = *a * x_inv + val;
        }
        x_pow *= x;
    }
    x_pow *= x_inv;
    let mut total = acc[4];
    for a in acc[..4].iter().rev() {
        total = total * v + a;
    }
    total * x_pow
}

#[test]
fn translator_matches_bb() {
    let dump = common::fixture_dir("instance/translator");
    if !dump.join("columns.bin").exists() {
        eprintln!("skipping translator: no dump");
        return;
    }
    let mut q = EccOpQueue::new();
    for i in 0..2 {
        if i > 0 {
            q.initialize_new_subtable();
        }
        populate_subtable(&mut q, i);
        q.merge();
    }
    inject_zk_ops(&mut q, &dump);
    q.initialize_new_subtable();
    populate_subtable(&mut q, 2);
    for op in random_ops(&dump) {
        q.ultra_ops.current.push(op);
    }
    q.merge_fixed_append(q.append_offset_for_prover());

    let v = Fq::from(11u64).invert();
    let x = Fq::from(13u64).invert();
    let circuit = TranslatorCircuit::new(v, x, &q);
    let wires = decode_fields(&std::fs::read(dump.join("wires.bin")).unwrap());
    let num_gates = u256(&wires[0]).0[0] as usize;
    assert_eq!(circuit.num_gates, num_gates, "num_gates");
    for w in 0..NUM_WIRES {
        for i in 0..num_gates {
            assert_eq!(circuit.wires[w][i], wires[1 + w * num_gates + i], "wire {w} row {i}");
        }
    }
    let result_limbs = circuit.accumulated_result_limbs();
    let shift = Fr::from(2u64).pow_u64(68);
    let result = result_limbs[0] + result_limbs[1] * shift + result_limbs[2] * shift.sqr() + result_limbs[3] * shift.sqr() * shift;
    assert_eq!(bb_ref::base::field::from_u256::<Fq>(u256(&result)), expected_result(&q, &v, &x), "accumulated result");
    let _ = (ACCUMULATORS_BINARY_LIMBS_0, RESULT_ROW);

    let masking_frs = decode_fields(&std::fs::read(dump.join("masking.bin")).unwrap());
    let masking: Vec<[Fr; NUM_MASKED_ROWS_END]> = (0..NUM_MINICIRCUIT_WIRES).map(|w| std::array::from_fn(|k| masking_frs[w * NUM_MASKED_ROWS_END + k])).collect();
    let mut polys = TranslatorPolys::from_circuit(&circuit, &masking);
    let params = translator_relation_params(&v, &x, result_limbs, Fr::from(2u64), Fr::from(3u64));
    polys.compute_grand_product(&params);

    let columns = std::fs::read(dump.join("columns.bin")).unwrap();
    let entities: Vec<usize> = (1..=11).chain(93..=103).collect();
    for (k, e) in entities.iter().enumerate() {
        for r in 0..CIRCUIT_SIZE {
            let off = 32 * (k * CIRCUIT_SIZE + r);
            let expected = from_bytes_be::<Fr>(&columns[off..off + 32]);
            assert_eq!(polys.cols[*e].coeffs[r], expected, "entity {e} row {r}");
        }
    }
    assert_eq!(check_circuit(&polys, &params), None, "relations vanish");

    let mut bad = circuit;
    bad.wires[ACCUMULATORS_BINARY_LIMBS_0][RESULT_ROW + 2] += Fr::from(1u64);
    let mut bad_polys = TranslatorPolys::from_circuit(&bad, &masking);
    bad_polys.compute_grand_product(&params);
    assert!(check_circuit(&bad_polys, &params).is_some(), "corruption detected");
}
