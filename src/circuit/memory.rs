//! ROM and RAM arrays (bb `rom_ram_logic`). Single-value ROM cells use the LogUp scheme; ROM
//! cells holding a pair of values (Straus point tables) use the sorted-transcript scheme, as does
//! RAM. Accesses emit memory gates as they happen; the consistency gates over the sorted records
//! are added at finalization.

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
    /// The second value column of a pair cell (the zero witness for single-value cells).
    pub value2_witness: u32,
    pub index: u32,
    pub access_type: RomAccess,
    pub record_witness: u32,
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
    /// Value witnesses per cell (`UNINITIALIZED` until set).
    pub state: Vec<[u32; 2]>,
    pub records: Vec<RomRecord>,
    /// Fixed by the first access: single-value cells (LogUp) or pairs (sorted transcript).
    pub use_logup: Option<bool>,
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
        self.memory.rom_arrays.push(RomTranscript {
            state: vec![[UNINITIALIZED; 2]; size],
            records: vec![],
            use_logup: None,
        });
        self.memory.rom_arrays.len() - 1
    }

    fn rom_scheme(&mut self, rom_id: usize, logup: bool) {
        let rom = &mut self.memory.rom_arrays[rom_id];
        assert_ne!(
            rom.use_logup,
            Some(!logup),
            "ROM array mixes single-value and pair accesses"
        );
        rom.use_logup = Some(logup);
    }

    /// Initialize cell `index` (a circuit constant) to `value_witness`. Each cell exactly once.
    pub fn set_rom_element(&mut self, rom_id: usize, index: usize, value_witness: u32) {
        self.rom_scheme(rom_id, true);
        let index_witness = if index == 0 {
            self.zero_idx()
        } else {
            self.put_constant_variable(Fr::from(index as u64))
        };
        assert_eq!(
            self.memory.rom_arrays[rom_id].state[index][0], UNINITIALIZED,
            "ROM cell initialized twice"
        );
        let z = self.zero_idx();
        let record = RomRecord {
            index_witness,
            value_witness,
            value2_witness: z,
            index: index as u32,
            access_type: RomAccess::TableEntry,
            record_witness: 0,
            gate_index: 0,
        };
        self.memory.rom_arrays[rom_id].state[index] = [value_witness, z];
        let record = self.create_rom_logup_gate(record, rom_id, false);
        self.memory.rom_arrays[rom_id].records.push(record);
    }

    /// Read the cell addressed by `index_witness`; returns a fresh witness holding the value.
    pub fn read_rom_array(&mut self, rom_id: usize, index_witness: u32) -> u32 {
        self.rom_scheme(rom_id, true);
        let index = Self::low_u64(&self.get_variable(index_witness)) as usize;
        let cell = self.memory.rom_arrays[rom_id].state[index][0];
        assert_ne!(cell, UNINITIALIZED, "ROM read of uninitialized cell");
        let value_witness = self.add_variable(self.get_variable(cell));
        let z = self.zero_idx();
        let record = RomRecord {
            index_witness,
            value_witness,
            value2_witness: z,
            index: index as u32,
            access_type: RomAccess::Read,
            record_witness: 0,
            gate_index: 0,
        };
        let record = self.create_rom_logup_gate(record, rom_id, true);
        self.memory.rom_arrays[rom_id].records.push(record);
        value_witness
    }

    // ---- ROM (pair cells, sorted transcript) ----

    /// bb `set_ROM_element_pair`: initialize cell `index` to two value witnesses.
    pub fn set_rom_element_pair(&mut self, rom_id: usize, index: usize, values: [u32; 2]) {
        self.rom_scheme(rom_id, false);
        let index_witness = self.put_constant_variable(Fr::from(index as u64));
        assert_eq!(
            self.memory.rom_arrays[rom_id].state[index][0], UNINITIALIZED,
            "ROM cell initialized twice"
        );
        let record = RomRecord {
            index_witness,
            value_witness: values[0],
            value2_witness: values[1],
            index: index as u32,
            access_type: RomAccess::TableEntry,
            record_witness: 0,
            gate_index: 0,
        };
        self.memory.rom_arrays[rom_id].state[index] = values;
        let record = self.create_rom_gate(record, MemorySelector::RomRead);
        self.memory.rom_arrays[rom_id].records.push(record);
    }

    /// bb `read_ROM_array_pair`: fresh witnesses holding the pair at the (witness) index.
    pub fn read_rom_array_pair(&mut self, rom_id: usize, index_witness: u32) -> [u32; 2] {
        self.rom_scheme(rom_id, false);
        let index = Self::low_u64(&self.get_variable(index_witness)) as usize;
        let cell = self.memory.rom_arrays[rom_id].state[index];
        assert!(
            cell[0] != UNINITIALIZED && cell[1] != UNINITIALIZED,
            "ROM read of uninitialized cell"
        );
        let values = [
            self.add_variable(self.get_variable(cell[0])),
            self.add_variable(self.get_variable(cell[1])),
        ];
        let record = RomRecord {
            index_witness,
            value_witness: values[0],
            value2_witness: values[1],
            index: index as u32,
            access_type: RomAccess::Read,
            record_witness: 0,
            gate_index: 0,
        };
        let record = self.create_rom_gate(record, MemorySelector::RomRead);
        self.memory.rom_arrays[rom_id].records.push(record);
        values
    }

    fn create_rom_gate(&mut self, mut record: RomRecord, selector: MemorySelector) -> RomRecord {
        record.record_witness = self.add_variable(Fr::zero());
        let mut row = self.memory_selectors_row(selector);
        row.wires = [
            record.index_witness,
            record.value_witness,
            record.value2_witness,
            record.record_witness,
        ];
        let block = self.blocks.get_mut(BlockId::Memory);
        block.rows.push(row);
        record.gate_index = block.len() - 1;
        self.num_gates_inc();
        record
    }

    /// bb `process_ROM_array`: the records sorted by index, each paired with its access record
    /// through the tag permutation, and the final index pinned to `size - 1`.
    fn process_rom_array(&mut self, rom_id: usize) {
        let read_tag = self.get_new_tag();
        let sorted_list_tag = self.get_new_tag();
        self.set_tau_transposition(read_tag, sorted_list_tag);
        let rom = self.memory.rom_arrays[rom_id].clone();
        assert!(
            rom.state.iter().all(|c| c[0] != UNINITIALIZED && c[1] != UNINITIALIZED),
            "ROM array has uninitialized cells"
        );
        let mut records = rom.records.clone();
        records.sort_by_key(|r| (r.index, r.gate_index));
        let size = rom.state.len();
        for (i, record) in records.iter().enumerate() {
            let index_witness = if i == 0 {
                self.zero_idx()
            } else if i == records.len() - 1 {
                self.put_constant_variable(Fr::from(size as u64 - 1))
            } else {
                self.add_variable(Fr::from(record.index as u64))
            };
            let value_witness = self.add_variable(self.get_variable(record.value_witness));
            let value2_witness = self.add_variable(self.get_variable(record.value2_witness));
            let sorted = RomRecord {
                index_witness,
                value_witness,
                value2_witness,
                record_witness: 0,
                gate_index: 0,
                ..*record
            };
            let sorted = self.create_rom_gate(sorted, MemorySelector::RomConsistencyCheck);
            self.assign_tag(record.record_witness, read_tag);
            self.assign_tag(sorted.record_witness, sorted_list_tag);
            self.memory_read_records.push(sorted.gate_index as u32);
            self.memory_read_records.push(record.gate_index as u32);
        }
        let max_index = self.add_variable(Fr::from(size as u64));
        let z = self.zero_idx();
        self.create_unconstrained_gate(BlockId::Memory, [max_index, z, z, z]);
        self.create_big_add_gate(
            AddQuad {
                a: max_index,
                b: z,
                c: z,
                d: z,
                a_scaling: Fr::one(),
                b_scaling: Fr::zero(),
                c_scaling: Fr::zero(),
                d_scaling: Fr::zero(),
                const_scaling: -Fr::from(size as u64),
            },
            false,
        );
    }

    /// Row layout: `w_l = index, w_r = value, w_o = multiplicity (table) or zero (read), w_4 = inverse`
    /// (filled by the prover once `eta`/`rom_logup_gamma` are known); `q_c` carries the array id.
    fn create_rom_logup_gate(&mut self, mut record: RomRecord, rom_id: usize, is_read: bool) -> RomRecord {
        let inverse_witness = self.add_variable(Fr::zero());
        let mut row = self.memory_selectors_row(if is_read {
            MemorySelector::RomLogupRead
        } else {
            MemorySelector::RomLogupTable
        });
        row.wires = [
            record.index_witness,
            record.value_witness,
            self.zero_idx(),
            inverse_witness,
        ];
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
        assert!(
            rom.state.iter().all(|c| c[0] != UNINITIALIZED),
            "ROM array has uninitialized cells"
        );
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
            match self.memory.rom_arrays[i].use_logup {
                Some(false) => self.process_rom_array(i),
                _ => self.process_rom_logup_array(i),
            }
        }
    }

    // ---- RAM ----

    pub fn create_ram_array(&mut self, size: usize) -> usize {
        self.memory.ram_arrays.push(RamTranscript {
            state: vec![UNINITIALIZED; size],
            records: vec![],
            access_count: 0,
        });
        self.memory.ram_arrays.len() - 1
    }

    pub fn init_ram_element(&mut self, ram_id: usize, index: usize, value_witness: u32) {
        let index_witness = if index == 0 {
            self.zero_idx()
        } else {
            self.put_constant_variable(Fr::from(index as u64))
        };
        assert_eq!(
            self.memory.ram_arrays[ram_id].state[index], UNINITIALIZED,
            "RAM cell initialized twice"
        );
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
        assert_ne!(
            self.memory.ram_arrays[ram_id].state[index], UNINITIALIZED,
            "RAM write to uninitialized cell"
        );
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
        row.wires = [
            record.index_witness,
            record.timestamp_witness,
            record.value_witness,
            record.record_witness,
        ];
        let block = self.blocks.get_mut(BlockId::Memory);
        block.rows.push(row);
        record.gate_index = block.len() - 1;
        self.num_gates_inc();
    }

    fn create_ram_gate(&mut self, mut record: RamRecord) -> RamRecord {
        let row = self.memory_selectors_row(if record.access_type == RamAccess::Read {
            MemorySelector::RamRead
        } else {
            MemorySelector::RamWrite
        });
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
        self.create_unconstrained_gate(
            BlockId::Memory,
            [
                record.index_witness,
                record.timestamp_witness,
                record.value_witness,
                record.record_witness,
            ],
        );
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
        assert!(
            ram.state.iter().all(|c| *c != UNINITIALIZED),
            "RAM array has uninitialized cells"
        );
        let mut records = ram.records.clone();
        records.sort_by_key(|r| (r.index, r.timestamp));

        let mut sorted = vec![];
        for (i, record) in records.iter().enumerate() {
            let index_witness = if i == 0 {
                self.zero_idx()
            } else {
                self.add_variable(Fr::from(record.index as u64))
            };
            let timestamp_witness = self.add_variable(Fr::from(record.timestamp as u64));
            let value_witness = self.add_variable(self.get_variable(record.value_witness));
            let mut s = RamRecord {
                index_witness,
                timestamp_witness,
                value_witness,
                record_witness: 0,
                gate_index: 0,
                ..*record
            };
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
            let delta = if cur.index == next.index {
                Fr::from((next.timestamp - cur.timestamp) as u64)
            } else {
                Fr::zero()
            };
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

#[cfg(test)]
mod tests {
    use crate::base::field::FieldLike;
    use crate::base::srs::CommitmentKey;
    use crate::base::transcript::NativeTranscript;
    use crate::base::Fr;
    use crate::honk::circuit_checker::check_circuit;
    use crate::honk::flavor::{Ent, ULTRA};
    use crate::honk::oink_prover::prove_oink;
    use crate::honk::prover_instance::ProverInstance;

    /// RAM and paired (sorted-transcript) ROM: reads return the stored values, a RAM write is
    /// visible to the next read, the finalized circuit satisfies every relation, and a corrupted
    /// wire on a memory row is caught by the checker. The LogUp ROM scheme is covered by the
    /// gate-family test in `circuit_checker`; these are the other two schemes.
    #[test]
    fn ram_and_paired_rom_read_back_and_localize() {
        if crate::testutil::crs_or_skip().is_none() {
            return;
        }
        let mut rng = crate::testutil::test_rng();
        let mut builder = crate::testutil::tiny_circuit(&mut rng);

        let rom = builder.create_rom_array(2);
        let a = [
            builder.add_variable(Fr::from(7u64)),
            builder.add_variable(Fr::from(8u64)),
        ];
        let b = [
            builder.add_variable(Fr::from(9u64)),
            builder.add_variable(Fr::from(10u64)),
        ];
        builder.set_rom_element_pair(rom, 0, a);
        builder.set_rom_element_pair(rom, 1, b);
        let idx = builder.add_variable(Fr::from(1u64));
        let pair = builder.read_rom_array_pair(rom, idx);
        assert_eq!(builder.get_variable(pair[0]), Fr::from(9u64));
        assert_eq!(builder.get_variable(pair[1]), Fr::from(10u64));

        let ram = builder.create_ram_array(2);
        let v0 = builder.add_variable(Fr::from(21u64));
        let v1 = builder.add_variable(Fr::from(22u64));
        builder.init_ram_element(ram, 0, v0);
        builder.init_ram_element(ram, 1, v1);
        let i0 = builder.add_variable(Fr::from(0u64));
        let r0 = builder.read_ram_array(ram, i0);
        assert_eq!(builder.get_variable(r0), Fr::from(21u64));
        let v2 = builder.add_variable(Fr::from(23u64));
        builder.write_ram_array(ram, i0, v2);
        let i0_again = builder.add_variable(Fr::from(0u64));
        let r1 = builder.read_ram_array(ram, i0_again);
        assert_eq!(builder.get_variable(r1), Fr::from(23u64));

        assert!(builder.failed.is_none(), "memory circuit must be satisfiable");
        let mut inst = ProverInstance::from_builder(&ULTRA, &mut builder, &mut rng);
        let ck = CommitmentKey::new(inst.max_end_index);
        let vk = inst.compute_vk(&ck);
        let mut t = NativeTranscript::new();
        let out = prove_oink(&mut inst, &vk, &ck, &mut t, &mut rng, true);
        assert_eq!(check_circuit(&inst, &out.params), None, "satisfying circuit must pass");

        // The RAM consistency rows are appended at finalization, so the LAST active memory row
        // belongs to the sorted RAM transcript; corrupting a wire there must trip the Memory
        // relation (or Permutation when the wire sits in a copy cycle).
        let row = inst
            .poly(Ent::q_memory)
            .coeffs
            .iter()
            .rposition(|c| !c.is_zero())
            .expect("memory gates exist");
        let w = inst.layout.idx(Ent::w_4);
        inst.polys[w].coeffs[row] += Fr::one();
        let failure = check_circuit(&inst, &out.params).expect("memory corruption must be caught");
        let rel = format!("{:?}", failure.0);
        assert!(
            rel.contains("Memory") || rel.contains("Permutation"),
            "named relation: {failure:?}"
        );
    }
}
