//! Mega-only builder operations (bb `MegaCircuitBuilder_`): Goblin ECC op "gates", the databus,
//! the bilinear/batched-equality gate and the compressed Poseidon2 gates.

use crate::circuit::op_queue::SharedOpQueue;
use super::builder::Builder;
use super::op_queue::{EccOpCode, UltraOp};
use super::trace::{BlockId, GateRow, Kind};
use crate::base::field::FieldLike;
use crate::base::poseidon2::round_constants;
use crate::base::{Fr, G1Affine, Rng};

pub const NUM_BUS_COLUMNS: usize = 7;
pub const KERNEL_CALLDATA: usize = 0;
pub const APP_CALLDATA: usize = 1;
pub const RETURNDATA: usize = 6;

/// One databus column: witness indices of its entries and how often each was read.
#[derive(Clone, Debug, Default)]
pub struct BusVector {
    pub data: Vec<u32>,
    pub read_counts: Vec<u32>,
}

impl BusVector {
    pub fn len(&self) -> usize {
        self.data.len()
    }
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

/// Witness indices of one ECC op's Ultra-format entries.
#[derive(Clone, Copy, Debug)]
pub struct EccOpTuple {
    pub op: u32,
    pub x_lo: u32,
    pub x_hi: u32,
    pub y_lo: u32,
    pub y_hi: u32,
    pub z_1: u32,
    pub z_2: u32,
    pub return_is_infinity: bool,
}

/// bb `bilinear_batched_eq_gate_`: either `q_m·a·b + q_5·a·c + q_l·a + q_r·b + q_o·c + q_4·d + q_c = 0`
/// or the two equalities `q_l·a + q_r·b + q_c = 0`, `q_o·c + q_4·d + q_m = 0`.
pub struct BilinearBatchedEqGate {
    pub bilinear: bool,
    pub a: u32,
    pub b: u32,
    pub c: u32,
    pub d: u32,
    pub q_l: Fr,
    pub q_r: Fr,
    pub q_o: Fr,
    pub q_4: Fr,
    pub q_c: Fr,
    pub q_m: Fr,
    pub q_5: Fr,
}

pub struct MegaState {
    pub op_queue: SharedOpQueue,
    pub databus: [BusVector; NUM_BUS_COLUMNS],
    add_accum_op_idx: u32,
    mul_accum_op_idx: u32,
    equality_op_idx: u32,
}

impl Builder {
    pub(super) fn init_mega(&mut self, op_queue: SharedOpQueue) {
        op_queue.write().unwrap().initialize_new_subtable();
        let add_accum_op_idx = self.put_constant_variable(Fr::from(EccOpCode::add().value() as u64));
        let mul_accum_op_idx = self.put_constant_variable(Fr::from(EccOpCode::mul().value() as u64));
        let equality_op_idx = self.put_constant_variable(Fr::from(EccOpCode::eq_reset().value() as u64));
        self.mega = Some(MegaState {
            op_queue,
            databus: Default::default(),
            add_accum_op_idx,
            mul_accum_op_idx,
            equality_op_idx,
        });
    }
    fn mega(&mut self) -> &mut MegaState {
        self.mega.as_mut().expect("not a Mega circuit")
    }
    pub fn is_mega(&self) -> bool {
        self.mega.is_some()
    }
    pub fn op_queue(&self) -> SharedOpQueue {
        self.mega.as_ref().expect("not a Mega circuit").op_queue.clone()
    }
    pub fn bus(&self, bus: usize) -> &BusVector {
        &self.mega.as_ref().expect("not a Mega circuit").databus[bus]
    }

    // ---- Goblin ECC ops ----

    pub fn queue_ecc_add_accum(&mut self, point: G1Affine) -> EccOpTuple {
        let op = self.op_queue().write().unwrap().add_accumulate(point);
        self.populate_ecc_op_wires(&op)
    }
    pub fn queue_ecc_mul_accum(&mut self, point: G1Affine, scalar: Fr) -> EccOpTuple {
        let op = self.op_queue().write().unwrap().mul_accumulate(point, scalar);
        self.populate_ecc_op_wires(&op)
    }
    pub fn queue_ecc_eq(&mut self) -> EccOpTuple {
        let op = self.op_queue().write().unwrap().eq_and_reset();
        self.populate_ecc_op_wires(&op)
    }
    pub fn queue_ecc_no_op(&mut self) -> EccOpTuple {
        let op = self.op_queue().write().unwrap().no_op_ultra_only();
        self.populate_ecc_op_wires(&op)
    }
    pub fn queue_ecc_random_op(&mut self, rng: &mut dyn Rng) {
        let op = self.op_queue().write().unwrap().random_op_ultra_only(rng);
        self.populate_ecc_op_wires(&op);
    }

    fn ecc_op_idx(&self, code: &EccOpCode) -> u32 {
        let m = self.mega.as_ref().unwrap();
        if code.add {
            m.add_accum_op_idx
        } else if code.mul {
            m.mul_accum_op_idx
        } else if code.eq && code.reset {
            m.equality_op_idx
        } else if !code.eq && !code.reset {
            self.zero_idx()
        } else {
            panic!("invalid op code")
        }
    }

    /// Two unconstrained rows in the ecc_op block: `op | x_lo | x_hi | y_lo` and `0 | y_hi | z_1 | z_2`.
    fn populate_ecc_op_wires(&mut self, op: &UltraOp) -> EccOpTuple {
        let t = EccOpTuple {
            op: self.ecc_op_idx(&op.op_code),
            x_lo: self.add_variable(op.x_lo),
            x_hi: self.add_variable(op.x_hi),
            y_lo: self.add_variable(op.y_lo),
            y_hi: self.add_variable(op.y_hi),
            z_1: self.add_variable(op.z_1),
            z_2: self.add_variable(op.z_2),
            return_is_infinity: op.return_is_infinity,
        };
        let (mut op_1, mut op_2) = (t.op, self.zero_idx());
        if op.op_code.is_random_op {
            op_1 = self.add_variable(op.op_code.random_value_1);
            op_2 = self.add_variable(op.op_code.random_value_2);
        }
        let block = self.blocks.get_mut(BlockId::EccOp);
        block.rows.push(GateRow::wires([op_1, t.x_lo, t.x_hi, t.y_lo]));
        block.rows.push(GateRow::wires([op_2, t.y_hi, t.z_1, t.z_2]));
        t
    }

    // ---- databus ----

    pub fn add_public_calldata(&mut self, bus: usize, witness_index: u32) {
        self.append_to_bus_vector(bus, witness_index);
    }
    pub fn add_public_return_data(&mut self, witness_index: u32) {
        self.append_to_bus_vector(RETURNDATA, witness_index);
    }
    pub fn read_calldata(&mut self, bus: usize, read_idx_witness: u32) -> u32 {
        self.read_bus_vector(bus, read_idx_witness)
    }
    pub fn read_return_data(&mut self, read_idx_witness: u32) -> u32 {
        self.read_bus_vector(RETURNDATA, read_idx_witness)
    }

    /// Append a witness to a bus column and bind the new slot to it with a read gate.
    fn append_to_bus_vector(&mut self, bus: usize, witness_index: u32) {
        let v = &mut self.mega().databus[bus];
        v.data.push(witness_index);
        v.read_counts.push(0);
        let slot = v.len() - 1;
        let index_witness = self.put_constant_variable(Fr::from(slot as u64));
        self.create_databus_read_gate(witness_index, index_witness, bus);
        self.mega().databus[bus].read_counts[slot] += 1;
    }

    /// A fresh witness holding the bus entry at the (witness) index, plus its read gate.
    fn read_bus_vector(&mut self, bus: usize, read_idx_witness: u32) -> u32 {
        let read_idx = Self::low_u64(&self.get_variable(read_idx_witness)) as usize;
        let entry = self.mega().databus[bus].data[read_idx];
        let value = self.get_variable(entry);
        let value_witness = self.add_variable(value);
        self.create_databus_read_gate(value_witness, read_idx_witness, bus);
        self.mega().databus[bus].read_counts[read_idx] += 1;
        value_witness
    }

    /// Row `value | index | 0 | 0` with the bus's selector (`q_l, q_r, q_o, q_4, q_5, q_c, q_m`) set.
    fn create_databus_read_gate(&mut self, value: u32, index: u32, bus: usize) {
        let mut row = GateRow::wires([value, index, self.zero_idx(), self.zero_idx()]);
        let one = Fr::one();
        match bus {
            0 => row.q_1 = one,
            1 => row.q_2 = one,
            2 => row.q_3 = one,
            3 => row.q_4 = one,
            4 => row.q_5 = one,
            5 => row.q_c = one,
            6 => row.q_m = one,
            _ => panic!("bus index out of range"),
        }
        row.kind = Kind::BusRead;
        row.gate_value = one;
        self.append_row(BlockId::Busread, row);
    }

    // ---- Mega-only gates ----

    pub fn create_bilinear_batched_eq_gate(&mut self, g: &BilinearBatchedEqGate) {
        let row = GateRow {
            wires: [g.a, g.b, g.c, g.d],
            q_m: g.q_m,
            q_c: g.q_c,
            q_1: g.q_l,
            q_2: g.q_r,
            q_3: g.q_o,
            q_4: g.q_4,
            q_5: if g.bilinear { g.q_5 } else { Fr::zero() },
            kind: Kind::BilinearBatchedEq,
            gate_value: Fr::from(if g.bilinear { 1u64 } else { 2 }),
        };
        self.append_row(BlockId::Arithmetic, row);
    }

    /// The initial linear layer: the next row holds `M_E · wires`.
    pub fn create_poseidon2_initial_external_gate(&mut self, wires: [u32; 4]) {
        self.append_row(
            BlockId::Poseidon2,
            GateRow {
                wires,
                kind: Kind::Poseidon2ExtInitial,
                gate_value: Fr::one(),
                ..Default::default()
            },
        );
    }

    /// Four internal rounds per row: wires hold state[0] at rounds `start..start+4`; the selectors
    /// carry this quad's constants and (unless terminal) the next quad's first three.
    pub fn create_poseidon2_quad_internal_gate(
        &mut self,
        wires: [u32; 4],
        start: usize,
        next_start: usize,
        is_terminal: bool,
    ) {
        let rc = round_constants();
        let mut row = GateRow {
            wires,
            q_1: rc[start][0],
            q_2: rc[start + 1][0],
            q_3: rc[start + 2][0],
            q_4: rc[start + 3][0],
            ..Default::default()
        };
        if is_terminal {
            row.kind = Kind::Poseidon2QuadIntTerminal;
        } else {
            row.q_m = rc[next_start][0];
            row.q_c = rc[next_start + 1][0];
            row.q_5 = rc[next_start + 2][0];
            row.kind = Kind::Poseidon2QuadInt;
        }
        row.gate_value = Fr::one();
        self.append_row(BlockId::Poseidon2, row);
    }

    /// The standard-encoded row preceding the first compressed row.
    pub fn create_poseidon2_transition_entry_gate(&mut self, wires: [u32; 4], start: usize) {
        let rc = round_constants();
        self.append_row(
            BlockId::Poseidon2,
            GateRow {
                wires,
                q_1: rc[start][0],
                q_2: rc[start + 1][0],
                q_3: rc[start + 2][0],
                kind: Kind::Poseidon2TransitionEntry,
                gate_value: Fr::one(),
                ..Default::default()
            },
        );
    }
}
