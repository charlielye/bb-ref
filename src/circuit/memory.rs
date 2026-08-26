//! ROM (LogUp scheme) and RAM arrays (bb `rom_ram_logic`). Accesses emit memory gates as they
//! happen; the consistency gates over the sorted records are added at finalization.

use super::builder::{AddQuad, Builder, MemorySelector};
use super::trace::BlockId;
use crate::base::field::FieldLike;
use crate::base::Fr;

const UNINITIALIZED: u32 = u32::MAX;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RomAccess {
    TableEntry,
    Read,
}
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RamAccess {
    Read,
    Write,
}

#[derive(Clone, Debug)]
pub struct RomRecord {
    pub index_witness: u32,
    pub value_witness: u32,
    pub index: u32,
    pub access_type: RomAccess,
    pub gate_index: usize,
}

#[derive(Clone, Debug)]
pub struct RamRecord {
    pub index_witness: u32,
    pub timestamp_witness: u32,
    pub value_witness: u32,
    pub index: u32,
    pub timestamp: u32,
    pub access_type: RamAccess,
    pub record_witness: u32,
    pub gate_index: usize,
}

#[derive(Clone, Debug, Default)]
pub struct RomTranscript {
    /// Value witness per cell (`UNINITIALIZED` until set).
    pub state: Vec<u32>,
    pub records: Vec<RomRecord>,
}

#[derive(Clone, Debug, Default)]
pub struct RamTranscript {
    pub state: Vec<u32>,
    pub records: Vec<RamRecord>,
    pub access_count: u32,
}

#[derive(Clone, Debug, Default)]
pub struct RomRamLogic {
    pub rom_arrays: Vec<RomTranscript>,
    pub ram_arrays: Vec<RamTranscript>,
}

impl Builder {
    // ---- ROM (single-value cells, LogUp) ----

    pub fn create_rom_array(&mut self, size: usize) -> usize {
        self.memory.rom_arrays.push(RomTranscript { state: vec![UNINITIALIZED; size], records: vec![] });
        self.memory.rom_arrays.len() - 1
    }

    /// Initialize cell `index` (a circuit constant) to `value_witness`. Each cell exactly once.
    pub fn set_rom_element(&mut self, rom_id: usize, index: usize, value_witness: u32) {
        let index_witness = if index == 0 { self.zero_idx() } else { self.put_constant_variable(Fr::from(index as u64)) };
        assert_eq!(self.memory.rom_arrays[rom_id].state[index], UNINITIALIZED, "ROM cell initialized twice");
        let record = RomRecord { index_witness, value_witness, index: index as u32, access_type: RomAccess::TableEntry, gate_index: 0 };
        self.memory.rom_arrays[rom_id].state[index] = value_witness;
        let record = self.create_rom_logup_gate(record, rom_id, false);
        self.memory.rom_arrays[rom_id].records.push(record);
    }

    /// Read the cell addressed by `index_witness`; returns a fresh witness holding the value.
    pub fn read_rom_array(&mut self, rom_id: usize, index_witness: u32) -> u32 {
        let index = Self::low_u64(&self.get_variable(index_witness)) as usize;
        let cell = self.memory.rom_arrays[rom_id].state[index];
        assert_ne!(cell, UNINITIALIZED, "ROM read of uninitialized cell");
        let value_witness = self.add_variable(self.get_variable(cell));
        let record = RomRecord { index_witness, value_witness, index: index as u32, access_type: RomAccess::Read, gate_index: 0 };
        let record = self.create_rom_logup_gate(record, rom_id, true);
        self.memory.rom_arrays[rom_id].records.push(record);
        value_witness
    }

    /// Row layout: `w_l = index, w_r = value, w_o = multiplicity (table) or zero (read), w_4 = inverse`
    /// (filled by the prover once `eta`/`rom_logup_gamma` are known); `q_c` carries the array id.
    fn create_rom_logup_gate(&mut self, mut record: RomRecord, rom_id: usize, is_read: bool) -> RomRecord {
        let inverse_witness = self.add_variable(Fr::zero());
        let mut row = self.memory_selectors_row(if is_read { MemorySelector::RomLogupRead } else { MemorySelector::RomLogupTable });
        row.wires = [record.index_witness, record.value_witness, self.zero_idx(), inverse_witness];
        row.q_c = Fr::from(rom_id as u64);
        let block = self.blocks.get_mut(BlockId::Memory);
        block.rows.push(row);
        record.gate_index = block.len() - 1;
        self.rom_logup_records.push(record.gate_index as u32);
        self.num_gates_inc();
        record
    }

    /// Point each table row's `w_o` at a witness holding that cell's read count. Emits no gates.
    fn process_rom_logup_array(&mut self, rom_id: usize) {
        let rom = self.memory.rom_arrays[rom_id].clone();
        assert!(rom.state.iter().all(|c| *c != UNINITIALIZED), "ROM array has uninitialized cells");
        let mut table_row_gate = vec![0usize; rom.state.len()];
        let mut read_counts = vec![0u64; rom.state.len()];
        for r in &rom.records {
            match r.access_type {
                RomAccess::TableEntry => table_row_gate[r.index as usize] = r.gate_index,
                RomAccess::Read => read_counts[r.index as usize] += 1,
            }
        }
        for i in 0..rom.state.len() {
            let count_witness = self.add_variable(Fr::from(read_counts[i]));
            self.blocks.get_mut(BlockId::Memory).rows[table_row_gate[i]].wires[2] = count_witness;
        }
    }

    pub(super) fn process_rom_arrays(&mut self) {
        for i in 0..self.memory.rom_arrays.len() {
            self.process_rom_logup_array(i);
        }
    }

    // ---- RAM ----

    pub fn create_ram_array(&mut self, size: usize) -> usize {
        self.memory.ram_arrays.push(RamTranscript { state: vec![UNINITIALIZED; size], records: vec![], access_count: 0 });
        self.memory.ram_arrays.len() - 1
    }

    pub fn init_ram_element(&mut self, ram_id: usize, index: usize, value_witness: u32) {
        let index_witness = if index == 0 { self.zero_idx() } else { self.put_constant_variable(Fr::from(index as u64)) };
        assert_eq!(self.memory.ram_arrays[ram_id].state[index], UNINITIALIZED, "RAM cell initialized twice");
        let timestamp = self.memory.ram_arrays[ram_id].access_count;
        let timestamp_witness = self.put_constant_variable(Fr::from(timestamp as u64));
        let record = RamRecord {
            index_witness,
            timestamp_witness,
            value_witness,
            index: index as u32,
            timestamp,
            access_type: RamAccess::Write,
            record_witness: 0,
            gate_index: 0,
        };
        let ram = &mut self.memory.ram_arrays[ram_id];
        ram.state[index] = value_witness;
        ram.access_count += 1;
        let record = self.create_ram_gate(record);
        self.memory.ram_arrays[ram_id].records.push(record);
    }

    pub fn read_ram_array(&mut self, ram_id: usize, index_witness: u32) -> u32 {
        let index = Self::low_u64(&self.get_variable(index_witness)) as usize;
        let cell = self.memory.ram_arrays[ram_id].state[index];
        assert_ne!(cell, UNINITIALIZED, "RAM read of uninitialized cell");
        let value_witness = self.add_variable(self.get_variable(cell));
        let timestamp = self.memory.ram_arrays[ram_id].access_count;
        let timestamp_witness = self.put_constant_variable(Fr::from(timestamp as u64));
        let record = RamRecord {
            index_witness,
            timestamp_witness,
            value_witness,
            index: index as u32,
            timestamp,
            access_type: RamAccess::Read,
            record_witness: 0,
            gate_index: 0,
        };
        let record = self.create_ram_gate(record);
        let ram = &mut self.memory.ram_arrays[ram_id];
        ram.records.push(record);
        ram.access_count += 1;
        value_witness
    }

    pub fn write_ram_array(&mut self, ram_id: usize, index_witness: u32, value_witness: u32) {
        let index = Self::low_u64(&self.get_variable(index_witness)) as usize;
        assert_ne!(self.memory.ram_arrays[ram_id].state[index], UNINITIALIZED, "RAM write to uninitialized cell");
        let timestamp = self.memory.ram_arrays[ram_id].access_count;
        let timestamp_witness = self.put_constant_variable(Fr::from(timestamp as u64));
        let record = RamRecord {
            index_witness,
            timestamp_witness,
            value_witness,
            index: index as u32,
            timestamp,
            access_type: RamAccess::Write,
            record_witness: 0,
            gate_index: 0,
        };
        let record = self.create_ram_gate(record);
        let ram = &mut self.memory.ram_arrays[ram_id];
        ram.records.push(record);
        ram.access_count += 1;
        ram.state[index] = value_witness;
    }

    fn push_memory_row(&mut self, mut row: crate::circuit::GateRow, record: &mut RamRecord) {
        record.record_witness = self.add_variable(Fr::zero());
        row.wires = [record.index_witness, record.timestamp_witness, record.value_witness, record.record_witness];
        let block = self.blocks.get_mut(BlockId::Memory);
        block.rows.push(row);
        record.gate_index = block.len() - 1;
        self.num_gates_inc();
    }

    fn create_ram_gate(&mut self, mut record: RamRecord) -> RamRecord {
        let row = self.memory_selectors_row(if record.access_type == RamAccess::Read { MemorySelector::RamRead } else { MemorySelector::RamWrite });
        self.push_memory_row(row, &mut record);
        record
    }

    fn create_sorted_ram_gate(&mut self, record: &mut RamRecord) {
        let row = self.memory_selectors_row(MemorySelector::RamConsistencyCheck);
        self.push_memory_row(row, record);
    }

    /// The last sorted record only needs its index pinned to `size - 1`; its wires are read by the
    /// previous consistency gate through shifts.
    fn create_final_sorted_ram_gate(&mut self, record: &mut RamRecord, ram_size: usize) {
        record.record_witness = self.add_variable(Fr::zero());
        record.gate_index = self.blocks.get(BlockId::Memory).len();
        self.create_unconstrained_gate(BlockId::Memory, [record.index_witness, record.timestamp_witness, record.value_witness, record.record_witness]);
        let z = self.zero_idx();
        self.create_big_add_gate(
            AddQuad {
                a: record.index_witness,
                b: z,
                c: z,
                d: z,
                a_scaling: Fr::one(),
                b_scaling: Fr::zero(),
                c_scaling: Fr::zero(),
                d_scaling: Fr::zero(),
                const_scaling: -Fr::from(ram_size as u64 - 1),
            },
            false,
        );
    }

    fn process_ram_array(&mut self, ram_id: usize) {
        let access_tag = self.get_new_tag();
        let sorted_list_tag = self.get_new_tag();
        self.set_tau_transposition(access_tag, sorted_list_tag);
        let ram = self.memory.ram_arrays[ram_id].clone();
        assert!(ram.state.iter().all(|c| *c != UNINITIALIZED), "RAM array has uninitialized cells");
        let mut records = ram.records.clone();
        records.sort_by_key(|r| (r.index, r.timestamp));

        let mut sorted = vec![];
        for (i, record) in records.iter().enumerate() {
            let index_witness = if i == 0 { self.zero_idx() } else { self.add_variable(Fr::from(record.index as u64)) };
            let timestamp_witness = self.add_variable(Fr::from(record.timestamp as u64));
            let value_witness = self.add_variable(self.get_variable(record.value_witness));
            let mut s = RamRecord { index_witness, timestamp_witness, value_witness, record_witness: 0, gate_index: 0, ..*record };
            if i < records.len() - 1 {
                self.create_sorted_ram_gate(&mut s);
            } else {
                self.create_final_sorted_ram_gate(&mut s, ram.state.len());
            }
            self.assign_tag(record.record_witness, access_tag);
            self.assign_tag(s.record_witness, sorted_list_tag);
            let list = match record.access_type {
                RamAccess::Read => &mut self.memory_read_records,
                RamAccess::Write => &mut self.memory_write_records,
            };
            list.push(s.gate_index as u32);
            list.push(record.gate_index as u32);
            sorted.push(s);
        }
        if sorted.len() <= 1 {
            return;
        }
        // Timestamp checks: for equal adjacent indices the timestamp delta is range-constrained.
        let mut timestamp_deltas = vec![];
        for w in sorted.windows(2) {
            let (cur, next) = (&w[0], &w[1]);
            let delta = if cur.index == next.index { Fr::from((next.timestamp - cur.timestamp) as u64) } else { Fr::zero() };
            let delta_witness = self.add_variable(delta);
            let mut row = self.memory_selectors_row(MemorySelector::RamTimestampCheck);
            row.wires = [cur.index_witness, cur.timestamp_witness, delta_witness, self.zero_idx()];
            self.blocks.get_mut(BlockId::Memory).rows.push(row);
            self.num_gates_inc();
            timestamp_deltas.push(delta_witness);
        }
        let last = sorted.last().unwrap();
        let z = self.zero_idx();
        self.create_unconstrained_gate(BlockId::Memory, [last.index_witness, last.timestamp_witness, z, z]);
        let max_timestamp = (ram.access_count - 1) as u64;
        for w in timestamp_deltas {
            self.create_small_range_constraint(w, max_timestamp);
        }
    }

    pub(super) fn process_ram_arrays(&mut self) {
        for i in 0..self.memory.ram_arrays.len() {
            self.process_ram_array(i);
        }
    }
}
