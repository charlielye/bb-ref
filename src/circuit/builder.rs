//! The Ultra circuit builder: witness variables joined by copy constraints (union-find over
//! `real_variable_index`), tags for the multiset checks, and the gate API that appends rows to the
//! trace blocks. A line-by-line port of bb's `CircuitBuilderBase` + `UltraCircuitBuilder_` restricted
//! to what the client-side circuits use (no non-native-field gates).

use crate::circuit::op_queue::SharedOpQueue;
use super::mega::MegaState;
use super::trace::{BlockId, Blocks, GateRow, Kind, MEGA_BLOCKS, ULTRA_BLOCKS};
use crate::base::field::{u256, u256_num_bits, u256_shr, FieldLike, NativeField};
use crate::base::poseidon2::round_constants;
use crate::base::Fr;
use std::collections::{BTreeMap, HashMap};

pub const IS_CONSTANT: u32 = u32::MAX;
const REAL_VARIABLE: u32 = u32::MAX - 1;
const FIRST_VARIABLE_IN_CLASS: u32 = u32::MAX - 2;
pub const DEFAULT_TAG: u32 = 0;

pub const DEFAULT_PLOOKUP_RANGE_BITNUM: u64 = 14;
const DEFAULT_PLOOKUP_RANGE_STEP_SIZE: u64 = 3;
const MAX_SMALL_RANGE_CONSTRAINT_VAL: u64 = (1 << 16) - 1;
const MAX_NUM_BITS_RANGE_CONSTRAINT: u64 = 253;
const NUM_WIRES: usize = 4;

/// `a*a_scaling + b*b_scaling + c*c_scaling + const_scaling = 0`
pub struct AddTriple {
    pub a: u32,
    pub b: u32,
    pub c: u32,
    pub a_scaling: Fr,
    pub b_scaling: Fr,
    pub c_scaling: Fr,
    pub const_scaling: Fr,
}
/// `a*a_scaling + b*b_scaling + c*c_scaling + d*d_scaling + const_scaling = 0`
pub struct AddQuad {
    pub a: u32,
    pub b: u32,
    pub c: u32,
    pub d: u32,
    pub a_scaling: Fr,
    pub b_scaling: Fr,
    pub c_scaling: Fr,
    pub d_scaling: Fr,
    pub const_scaling: Fr,
}
/// `a*b*mul_scaling + a*a_scaling + b*b_scaling + c*c_scaling + d*d_scaling + const_scaling = 0`
#[derive(Clone, Debug)]
pub struct MulQuad {
    pub a: u32,
    pub b: u32,
    pub c: u32,
    pub d: u32,
    pub mul_scaling: Fr,
    pub a_scaling: Fr,
    pub b_scaling: Fr,
    pub c_scaling: Fr,
    pub d_scaling: Fr,
    pub const_scaling: Fr,
}
/// `q_m*a*b + q_l*a + q_r*b + q_o*c + q_c = 0`
pub struct EccAddGate {
    pub x1: u32,
    pub y1: u32,
    pub x2: u32,
    pub y2: u32,
    pub x3: u32,
    pub y3: u32,
    pub is_addition: bool,
}
pub struct EccDblGate {
    pub x1: u32,
    pub y1: u32,
    pub x3: u32,
    pub y3: u32,
}

pub struct ArithmeticTriple {
    pub a: u32,
    pub b: u32,
    pub c: u32,
    pub q_m: Fr,
    pub q_l: Fr,
    pub q_r: Fr,
    pub q_o: Fr,
    pub q_c: Fr,
}

/// Selector pattern of a memory gate (bb `MEMORY_SELECTORS`).
#[derive(Clone, Copy)]
pub enum MemorySelector {
    None,
    RamConsistencyCheck,
    RomConsistencyCheck,
    RamTimestampCheck,
    RomRead,
    RamRead,
    RamWrite,
    RomLogupTable,
    RomLogupRead,
}

/// Variables range-constrained to the same `target_range` share a tag and one sorted "staircase".
#[derive(Clone, Debug)]
pub struct RangeList {
    pub target_range: u64,
    pub range_tag: u32,
    pub tau_tag: u32,
    pub variable_indices: Vec<u32>,
}

thread_local! {
    static GLOBAL_GATE_COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static CURRENT_BLOCK_LENS: std::cell::RefCell<[usize; 12]> = const { std::cell::RefCell::new([0; 12]) };
}

/// Gates created on this thread so far (all builders); with `BBREF_TRACE_GATES` set, `trace_phase`
/// prints it with a label so a trace-dump difference can be mapped to a verifier phase.
pub fn global_gate_count() -> usize {
    GLOBAL_GATE_COUNT.with(|c| c.get())
}
/// Per-op field_t trace (`BBREF_FT_TRACE`), printed only once the arith block has reached
/// `BBREF_FT_FROM` (default 0) so captures in late regions stay manageable.
pub fn trace_phase(label: &str) {
    if std::env::var_os("BBREF_TRACE_GATES").is_some() {
        let lens = CURRENT_BLOCK_LENS.with(|b| *b.borrow());
        eprintln!(
            "[gates {:>7} | ecc_op {:>5} arith {:>6} nnf {:>5} busread {:>4} poseidon2 {:>5}] {label}",
            global_gate_count(),
            lens[BlockId::EccOp as usize],
            lens[BlockId::Arithmetic as usize],
            lens[BlockId::Nnf as usize],
            lens[BlockId::Busread as usize],
            lens[BlockId::Poseidon2 as usize]
        );
    }
}

pub struct Builder {
    pub(crate) variables: Vec<Fr>,
    pub real_variable_index: Vec<u32>,
    next_var_index: Vec<u32>,
    prev_var_index: Vec<u32>,
    pub real_variable_tags: Vec<u32>,
    pub tau: HashMap<u32, u32>,
    current_tag: u32,
    zero_idx: u32,
    /// bb `builder.ipa_proof`: a rollup circuit's appended 64-field IPA proof (RollupIO).
    pub ipa_proof: Vec<Fr>,
    public_inputs: Vec<u32>,
    public_inputs_finalized: bool,
    num_gates: usize,
    pub circuit_finalized: bool,
    constant_variable_indices: HashMap<Fr, u32>,
    pub blocks: Blocks,
    pub memory: super::memory::RomRamLogic,
    /// Memory-block row indices of RAM/ROM reads, RAM writes, and ROM-LogUp rows.
    pub memory_read_records: Vec<u32>,
    pub memory_write_records: Vec<u32>,
    pub rom_logup_records: Vec<u32>,
    /// Keyed by `target_range`; processed in key order at finalization (bb `std::map`).
    pub range_lists: BTreeMap<u64, RangeList>,
    /// Lookup tables in creation order (bb `lookup_tables`); `table_index` is the 1-based position.
    pub lookup_tables: Vec<super::plookup::BasicTable>,
    /// Non-native partial products whose gates are emitted at finalization (bb
    /// `cached_partial_non_native_field_multiplications`).
    pub cached_partial_multiplications: Vec<super::nnf::CachedPartialMultiplication>,
    pub failed: Option<String>,
    pub is_write_vk_mode: bool,
    /// Present for Mega circuits: the op queue, databus and op-code constants.
    pub mega: Option<MegaState>,
}

/// `2^i` for `i` in `0..=256`, built once. The limb decomposition needs six of these per limb
/// triple; exponentiating each time was most of the builder's range-constraint cost.
fn pow2_table() -> &'static [Fr] {
    static T: std::sync::LazyLock<Vec<Fr>> = std::sync::LazyLock::new(|| {
        let mut v = Vec::with_capacity(257);
        let mut x = Fr::one();
        for _ in 0..=256 {
            v.push(x);
            x = x + x;
        }
        v
    });
    &T
}

impl Builder {
    fn empty(is_write_vk_mode: bool, mega: bool) -> Self {
        Self {
            variables: vec![],
            real_variable_index: vec![],
            next_var_index: vec![],
            prev_var_index: vec![],
            real_variable_tags: vec![],
            tau: HashMap::new(),
            current_tag: DEFAULT_TAG,
            zero_idx: 0,
            ipa_proof: vec![],
            public_inputs: vec![],
            public_inputs_finalized: false,
            num_gates: 0,
            circuit_finalized: false,
            constant_variable_indices: HashMap::new(),
            blocks: Blocks::new(if mega { MEGA_BLOCKS } else { ULTRA_BLOCKS }),
            memory: Default::default(),
            lookup_tables: vec![],
            cached_partial_multiplications: vec![],
            memory_read_records: vec![],
            memory_write_records: vec![],
            rom_logup_records: vec![],
            range_lists: BTreeMap::new(),
            failed: None,
            is_write_vk_mode,
            mega: None,
        }
    }

    pub fn new() -> Self {
        let mut b = Self::empty(false, false);
        b.zero_idx = b.put_constant_variable(Fr::zero());
        b.set_tau_at_index(DEFAULT_TAG, DEFAULT_TAG);
        b
    }

    /// A Mega circuit sharing the IVC's op queue (bb `MegaCircuitBuilder_`).
    pub fn new_mega(op_queue: SharedOpQueue) -> Self {
        let mut b = Self::empty(false, true);
        b.zero_idx = b.put_constant_variable(Fr::zero());
        b.set_tau_at_index(DEFAULT_TAG, DEFAULT_TAG);
        b.init_mega(op_queue);
        b
    }

    /// Builder pre-populated with an ACIR witness vector and public-input indices. The constant
    /// zero is added after the witnesses, so its fixing gate references ACIR witness 0 in its
    /// unused wires (bb's `_zero_idx` default), which matters for copy cycles.
    pub fn from_acir(witness: &[Fr], public_inputs: Vec<u32>, is_write_vk_mode: bool) -> Self {
        let mut b = Self::empty(is_write_vk_mode, false);
        for v in witness {
            b.add_variable(*v);
        }
        b.public_inputs = public_inputs;
        b.zero_idx = b.put_constant_variable(Fr::zero());
        b.set_tau_at_index(DEFAULT_TAG, DEFAULT_TAG);
        b
    }

    pub fn from_acir_mega(
        op_queue: SharedOpQueue,
        witness: &[Fr],
        public_inputs: Vec<u32>,
        is_write_vk_mode: bool,
    ) -> Self {
        let mut b = Self::empty(is_write_vk_mode, true);
        // Bulk equivalent of add_variable per witness: a kernel ingests ~10^6 of them.
        b.variables.extend_from_slice(witness);
        let n = b.variables.len() as u32;
        b.real_variable_index = (0..n).collect();
        b.next_var_index = vec![REAL_VARIABLE; n as usize];
        b.prev_var_index = vec![FIRST_VARIABLE_IN_CLASS; n as usize];
        b.real_variable_tags = vec![DEFAULT_TAG; n as usize];
        b.public_inputs = public_inputs;
        b.zero_idx = b.put_constant_variable(Fr::zero());
        b.set_tau_at_index(DEFAULT_TAG, DEFAULT_TAG);
        b.init_mega(op_queue);
        b
    }

    // ---- variables and copy constraints ----

    pub fn add_variable(&mut self, v: Fr) -> u32 {
        self.variables.push(v);
        let index = (self.variables.len() - 1) as u32;
        self.real_variable_index.push(index);
        self.next_var_index.push(REAL_VARIABLE);
        self.prev_var_index.push(FIRST_VARIABLE_IN_CLASS);
        self.real_variable_tags.push(DEFAULT_TAG);
        index
    }
    pub fn add_public_variable(&mut self, v: Fr) -> u32 {
        let index = self.add_variable(v);
        assert!(
            !self.public_inputs_finalized,
            "cannot add public inputs after they were finalized"
        );
        self.public_inputs.push(index);
        index
    }
    pub fn set_public_input(&mut self, witness_index: u32) -> u32 {
        if self.public_inputs.contains(&witness_index) {
            self.failure("attempted to set a public input that is already public");
            return 0;
        }
        assert!(
            !self.public_inputs_finalized,
            "cannot add public inputs after they were finalized"
        );
        self.public_inputs.push(witness_index);
        (self.public_inputs.len() - 1) as u32
    }
    pub fn finalize_public_inputs(&mut self) {
        self.public_inputs_finalized = true;
    }
    pub fn public_inputs(&self) -> &[u32] {
        &self.public_inputs
    }
    pub fn get_variable(&self, index: u32) -> Fr {
        self.variables[self.real_variable_index[index as usize] as usize]
    }
    pub fn set_variable(&mut self, index: u32, v: Fr) {
        let r = self.real_variable_index[index as usize] as usize;
        self.variables[r] = v;
    }
    pub fn num_variables(&self) -> usize {
        self.variables.len()
    }
    pub fn zero_idx(&self) -> u32 {
        self.zero_idx
    }
    pub fn num_gates(&self) -> usize {
        self.num_gates
    }
    pub(super) fn num_gates_inc(&mut self) {
        self.increment_num_gates();
    }
    fn increment_num_gates(&mut self) {
        assert!(
            !self.circuit_finalized,
            "cannot add gates after the circuit is finalized"
        );
        self.num_gates += 1;
        GLOBAL_GATE_COUNT.with(|c| c.set(c.get() + 1));
    }
    pub fn failure(&mut self, msg: &str) {
        if self.failed.is_none() {
            self.failed = Some(msg.to_string());
        }
    }
    fn get_first_variable_in_class(&self, mut index: u32) -> u32 {
        while self.prev_var_index[index as usize] != FIRST_VARIABLE_IN_CLASS {
            index = self.prev_var_index[index as usize];
        }
        index
    }
    /// Join the class of `b` to the class of `a` (the real variable of `a`'s class survives).
    pub fn assert_equal(&mut self, a: u32, b: u32) {
        if self.get_variable(a) != self.get_variable(b) {
            self.failure("assert_equal");
        }
        let a_real = self.real_variable_index[a as usize];
        let b_real = self.real_variable_index[b as usize];
        if a_real == b_real {
            return;
        }
        let mut cur = self.get_first_variable_in_class(b);
        loop {
            self.real_variable_index[cur as usize] = a_real;
            cur = self.next_var_index[cur as usize];
            if cur == REAL_VARIABLE {
                break;
            }
        }
        let a_start = self.get_first_variable_in_class(a);
        self.next_var_index[b_real as usize] = a_start;
        self.prev_var_index[a_start as usize] = b_real;
        let (ta, tb) = (
            self.real_variable_tags[a_real as usize],
            self.real_variable_tags[b_real as usize],
        );
        if !(ta == DEFAULT_TAG || tb == DEFAULT_TAG || ta == tb) {
            self.failure("assert_equal: tag clash");
        }
        if ta == DEFAULT_TAG {
            self.real_variable_tags[a_real as usize] = tb;
        }
    }
    pub fn assert_equal_constant(&mut self, a: u32, b: Fr) {
        if self.get_variable(a) != b {
            self.failure("assert equal constant");
        }
        let b_idx = self.put_constant_variable(b);
        self.assert_equal(a, b_idx);
    }
    /// The variable fixed to `v` by an arithmetic gate, created on first use.
    pub fn put_constant_variable(&mut self, v: Fr) -> u32 {
        if let Some(i) = self.constant_variable_indices.get(&v) {
            return *i;
        }
        let index = self.add_variable(v);
        self.fix_witness(index, v);
        self.constant_variable_indices.insert(v, index);
        index
    }

    // ---- tags (generalized permutation) ----

    pub fn assign_tag(&mut self, variable_index: u32, tag: u32) {
        assert!(tag <= self.current_tag);
        let real = self.real_variable_index[variable_index as usize] as usize;
        if self.real_variable_tags[real] == tag {
            return;
        }
        assert_eq!(self.real_variable_tags[real], DEFAULT_TAG, "variable already tagged");
        self.real_variable_tags[real] = tag;
    }
    pub fn set_tau_at_index(&mut self, tag: u32, tau: u32) {
        assert!(self.tau.insert(tag, tau).is_none(), "tag reuse detected");
    }
    pub fn set_tau_transposition(&mut self, t1: u32, t2: u32) {
        self.set_tau_at_index(t1, t2);
        self.set_tau_at_index(t2, t1);
    }
    pub fn get_new_tag(&mut self) -> u32 {
        self.current_tag += 1;
        self.current_tag
    }

    // ---- gates ----

    pub(super) fn append_row(&mut self, block: BlockId, row: GateRow) {
        self.blocks.get_mut(block).rows.push(row);
        self.increment_num_gates();
        let len = self.blocks.get(block).rows.len();
        CURRENT_BLOCK_LENS.with(|b| b.borrow_mut()[block as usize] = len);
    }
    fn append(&mut self, block: BlockId, row: GateRow) {
        self.append_row(block, row);
    }
    /// Ultra keeps external rounds in their own block; Mega puts every Poseidon2 gate in one block.
    fn poseidon2_external_block(&self) -> BlockId {
        if self.is_mega() {
            BlockId::Poseidon2
        } else {
            BlockId::Poseidon2External
        }
    }
    /// The rows every lookup table occupies in the trace (bb `get_tables_size`).
    pub fn tables_size(&self) -> usize {
        self.lookup_tables.iter().map(|t| t.size()).sum()
    }

    /// The position of the basic table `id`, created on first use (bb `get_table`).
    fn get_table(&mut self, id: super::plookup::BasicTableId) -> usize {
        if let Some(i) = self.lookup_tables.iter().position(|t| t.id == id) {
            return i;
        }
        let index = self.lookup_tables.len() + 1;
        self.lookup_tables.push(super::plookup::create_basic_table(id, index));
        self.lookup_tables.len() - 1
    }

    /// bb `register_basic_lookup_table`: append a dynamically-built table (indices are 1-based).
    pub fn register_basic_lookup_table(&mut self, mut table: super::plookup::BasicTable) -> usize {
        table.table_index = self.lookup_tables.len() + 1;
        self.lookup_tables.push(table);
        self.lookup_tables.len() - 1
    }

    /// bb `create_lookup_gate` with zero step sizes (standalone read, e.g. a Straus plookup table).
    pub fn create_standalone_lookup_gate(&mut self, wires: [u32; 3], table: usize, entry: super::plookup::LookupEntry) {
        self.create_lookup_gate(wires, table, entry, [Fr::zero(), Fr::zero(), Fr::zero()]);
    }

    /// bb `create_gates_from_plookup_accumulators`: one lookup gate per slice of a multi-table read,
    /// the first row holding the key witnesses; returns the accumulator witnesses.
    pub fn create_gates_from_plookup_accumulators(
        &mut self,
        id: super::plookup::MultiTableId,
        read_values: &super::plookup::ReadData<Fr>,
        key_a_index: u32,
        key_b_index: Option<u32>,
    ) -> super::plookup::ReadData<u32> {
        let multi_table = super::plookup::get_multitable(id);
        let num_lookups = read_values.columns[0].len();
        let mut read_data = super::plookup::ReadData {
            columns: [vec![], vec![], vec![]],
            lookup_entries: vec![],
        };
        for i in 0..num_lookups {
            let is_first = i == 0;
            let is_last = i == num_lookups - 1;
            let table = self.get_table(multi_table.basic_table_ids[i]);
            let first_idx = if is_first {
                key_a_index
            } else {
                self.add_variable(read_values.columns[0][i])
            };
            let second_idx = match key_b_index {
                Some(b) if is_first => b,
                _ => self.add_variable(read_values.columns[1][i]),
            };
            let third_idx = self.add_variable(read_values.columns[2][i]);
            read_data.columns[0].push(first_idx);
            read_data.columns[1].push(second_idx);
            read_data.columns[2].push(third_idx);
            let step = |c: usize| {
                if is_last {
                    Fr::zero()
                } else {
                    -multi_table.column_step_sizes[c][i + 1]
                }
            };
            self.create_lookup_gate(
                [first_idx, second_idx, third_idx],
                table,
                read_values.lookup_entries[i],
                [step(0), step(1), step(2)],
            );
        }
        read_data
    }

    /// bb `create_lookup_gate`: wires `(key, value1, value2, 0)`, `q_2/q_m/q_c` the negated step
    /// sizes into the next row's accumulators, `q_3` the table index.
    fn create_lookup_gate(
        &mut self,
        wires: [u32; 3],
        table: usize,
        entry: super::plookup::LookupEntry,
        column_step_sizes: [Fr; 3],
    ) {
        self.lookup_tables[table].lookup_gates.push(entry);
        let mut row = GateRow::wires([wires[0], wires[1], wires[2], self.zero_idx]);
        row.kind = Kind::Lookup;
        row.gate_value = Fr::one();
        row.q_m = column_step_sizes[1];
        row.q_c = column_step_sizes[2];
        row.q_2 = column_step_sizes[0];
        row.q_3 = Fr::from(self.lookup_tables[table].table_index as u64);
        self.append(BlockId::Lookup, row);
    }

    pub fn create_add_gate(&mut self, g: AddTriple) {
        self.create_big_add_gate(
            AddQuad {
                a: g.a,
                b: g.b,
                c: g.c,
                d: self.zero_idx,
                a_scaling: g.a_scaling,
                b_scaling: g.b_scaling,
                c_scaling: g.c_scaling,
                d_scaling: Fr::zero(),
                const_scaling: g.const_scaling,
            },
            false,
        );
    }
    pub fn create_big_add_gate(&mut self, g: AddQuad, include_next_gate_w_4: bool) {
        self.append(
            BlockId::Arithmetic,
            GateRow {
                wires: [g.a, g.b, g.c, g.d],
                q_c: g.const_scaling,
                q_1: g.a_scaling,
                q_2: g.b_scaling,
                q_3: g.c_scaling,
                q_4: g.d_scaling,
                kind: Kind::Arith,
                gate_value: Fr::small(1 + include_next_gate_w_4 as u64),
                ..Default::default()
            },
        );
    }
    /// With `include_next_gate_w_4`, `q_arith = 2` scales the linear terms by 2, so the quadratic
    /// term is scaled here to compensate.
    pub fn create_big_mul_add_gate(&mut self, g: &MulQuad, include_next_gate_w_4: bool) {
        let mul_scaling = if include_next_gate_w_4 {
            g.mul_scaling + g.mul_scaling
        } else {
            g.mul_scaling
        };
        self.append(
            BlockId::Arithmetic,
            GateRow {
                wires: [g.a, g.b, g.c, g.d],
                q_m: mul_scaling,
                q_c: g.const_scaling,
                q_1: g.a_scaling,
                q_2: g.b_scaling,
                q_3: g.c_scaling,
                q_4: g.d_scaling,
                kind: Kind::Arith,
                gate_value: Fr::small(1 + include_next_gate_w_4 as u64),
                ..Default::default()
            },
        );
    }
    /// `x^2 - x = 0`
    /// bb `create_ecc_add_gate`: `(x1, y1) ± (x2, y2) = (x3, y3)` on Grumpkin; the second row is an
    /// unconstrained carrier read by the first through shifts, and a gate whose input is the previous
    /// gate's output fuses into that carrier row.
    pub fn create_ecc_add_gate(&mut self, g: EccAddGate) {
        let q_sign = if g.is_addition { Fr::one() } else { -Fr::one() };
        let z = self.zero_idx();
        let block = self.blocks.get_mut(BlockId::Elliptic);
        match block.rows.last_mut() {
            Some(last) if last.wires[1] == g.x1 && last.wires[2] == g.y1 => {
                last.q_1 = q_sign;
                last.kind = Kind::Elliptic;
                last.gate_value = Fr::one();
            }
            _ => {
                block.rows.push(GateRow {
                    wires: [z, g.x1, g.y1, z],
                    q_1: q_sign,
                    kind: Kind::Elliptic,
                    gate_value: Fr::one(),
                    ..Default::default()
                });
                self.increment_num_gates();
            }
        }
        self.create_unconstrained_gate(BlockId::Elliptic, [g.x2, g.x3, g.y3, g.y2]);
    }
    /// bb `create_ecc_dbl_gate`: `2 * (x1, y1) = (x3, y3)` (`q_m` marks a doubling).
    pub fn create_ecc_dbl_gate(&mut self, g: EccDblGate) {
        let z = self.zero_idx();
        let block = self.blocks.get_mut(BlockId::Elliptic);
        match block.rows.last_mut() {
            Some(last) if last.wires[1] == g.x1 && last.wires[2] == g.y1 => {
                last.q_m = Fr::one();
                last.kind = Kind::Elliptic;
                last.gate_value = Fr::one();
            }
            _ => {
                block.rows.push(GateRow {
                    wires: [z, g.x1, g.y1, z],
                    q_m: Fr::one(),
                    kind: Kind::Elliptic,
                    gate_value: Fr::one(),
                    ..Default::default()
                });
                self.increment_num_gates();
            }
        }
        self.create_unconstrained_gate(BlockId::Elliptic, [z, g.x3, g.y3, z]);
    }
    pub fn create_bool_gate(&mut self, x: u32) {
        self.append(
            BlockId::Arithmetic,
            GateRow {
                wires: [x, x, self.zero_idx, self.zero_idx],
                q_m: Fr::one(),
                q_1: -Fr::one(),
                kind: Kind::Arith,
                gate_value: Fr::one(),
                ..Default::default()
            },
        );
    }
    pub fn create_arithmetic_gate(&mut self, g: ArithmeticTriple) {
        self.append(
            BlockId::Arithmetic,
            GateRow {
                wires: [g.a, g.b, g.c, self.zero_idx],
                q_m: g.q_m,
                q_c: g.q_c,
                q_1: g.q_l,
                q_2: g.q_r,
                q_3: g.q_o,
                kind: Kind::Arith,
                gate_value: Fr::one(),
                ..Default::default()
            },
        );
    }
    pub fn fix_witness(&mut self, witness_index: u32, value: Fr) {
        self.append(
            BlockId::Arithmetic,
            GateRow {
                wires: [witness_index, self.zero_idx, self.zero_idx, self.zero_idx],
                q_c: -value,
                q_1: Fr::one(),
                kind: Kind::Arith,
                gate_value: Fr::one(),
                ..Default::default()
            },
        );
    }
    /// A row with all selectors zero; its wires are read by the previous gate through shifts.
    pub fn create_unconstrained_gate(&mut self, block: BlockId, wires: [u32; 4]) {
        self.append(block, GateRow::wires(wires));
    }
    /// Put variables into the trace (padded with zeros to a multiple of four) so that their tags
    /// take part in the permutation argument.
    pub fn create_unconstrained_gates(&mut self, indices: &[u32]) {
        let mut padded = indices.to_vec();
        while padded.len() % NUM_WIRES != 0 {
            padded.push(self.zero_idx);
        }
        for c in padded.chunks(NUM_WIRES) {
            self.create_unconstrained_gate(BlockId::Arithmetic, [c[0], c[1], c[2], c[3]]);
        }
    }
    pub fn memory_selectors_row(&self, t: MemorySelector) -> GateRow {
        let one = Fr::one();
        let mut row = GateRow {
            kind: Kind::Memory,
            ..Default::default()
        };
        row.gate_value = if matches!(t, MemorySelector::None) {
            Fr::zero()
        } else {
            one
        };
        match t {
            MemorySelector::None => {}
            MemorySelector::RomConsistencyCheck => {
                row.q_1 = one;
                row.q_2 = one;
            }
            MemorySelector::RamConsistencyCheck => row.q_3 = one,
            MemorySelector::RamTimestampCheck => {
                row.q_1 = one;
                row.q_4 = one;
            }
            MemorySelector::RomRead | MemorySelector::RamRead => {
                row.q_1 = one;
                row.q_m = one;
            }
            MemorySelector::RamWrite => {
                row.q_1 = one;
                row.q_m = one;
                row.q_c = one;
            }
            MemorySelector::RomLogupTable => row.q_2 = one,
            MemorySelector::RomLogupRead => row.q_4 = one,
        }
        row
    }
    pub fn create_poseidon2_external_gate(&mut self, wires: [u32; 4], round_idx: usize) {
        let rc = &round_constants()[round_idx];
        let block = self.poseidon2_external_block();
        self.append(
            block,
            GateRow {
                wires,
                q_1: rc[0],
                q_2: rc[1],
                q_3: rc[2],
                q_4: rc[3],
                kind: Kind::Poseidon2Ext,
                gate_value: Fr::one(),
                ..Default::default()
            },
        );
    }
    pub fn create_poseidon2_internal_gate(&mut self, wires: [u32; 4], round_idx: usize) {
        let rc = &round_constants()[round_idx];
        self.append(
            BlockId::Poseidon2Internal,
            GateRow {
                wires,
                q_1: rc[0],
                kind: Kind::Poseidon2Int,
                gate_value: Fr::one(),
                ..Default::default()
            },
        );
    }

    // ---- range constraints ----

    /// `x < 2^num_bits`: a bool gate, a small (delta-range) constraint, or a limb decomposition.
    pub fn create_dyadic_range_constraint(&mut self, variable_index: u32, num_bits: u64) {
        if num_bits == 1 {
            self.create_bool_gate(variable_index);
        } else if num_bits <= DEFAULT_PLOOKUP_RANGE_BITNUM {
            // Ensure the variable appears in a wire (see `create_small_range_constraint`).
            self.create_unconstrained_gate(
                BlockId::Arithmetic,
                [variable_index, self.zero_idx, self.zero_idx, self.zero_idx],
            );
            self.create_small_range_constraint(variable_index, (1u64 << num_bits) - 1);
        } else {
            self.create_limbed_range_constraint(variable_index, num_bits, DEFAULT_PLOOKUP_RANGE_BITNUM);
        }
    }

    /// Constrain `x ∈ [0, target_range]` (`target_range < 2^16`) by tagging it into the range list
    /// for `target_range`; the sorted-list gates are created at finalization. The variable must
    /// appear in some wire or the circuit becomes unsatisfiable.
    pub fn create_small_range_constraint(&mut self, variable_index: u32, target_range: u64) {
        assert!(target_range <= MAX_SMALL_RANGE_CONSTRAINT_VAL);
        if Self::low_u64(&self.get_variable(variable_index)) > target_range {
            self.failure("create_small_range_constraint");
        }
        if !self.range_lists.contains_key(&target_range) {
            let list = self.create_range_list(target_range);
            self.range_lists.insert(target_range, list);
        }
        let existing_tag = self.real_variable_tags[self.real_variable_index[variable_index as usize] as usize];
        let range_tag = self.range_lists[&target_range].range_tag;
        if existing_tag == range_tag {
            return;
        }
        if existing_tag == DEFAULT_TAG {
            self.assign_tag(variable_index, range_tag);
            self.range_lists
                .get_mut(&target_range)
                .unwrap()
                .variable_indices
                .push(variable_index);
            return;
        }
        // Already constrained to another range: keep it if tighter, else constrain an arithmetic copy.
        let existing_range = self
            .range_lists
            .iter()
            .find(|(_, l)| l.range_tag == existing_tag)
            .map(|(r, _)| *r)
            .expect("tag without range list");
        if existing_range < target_range {
            return;
        }
        let copied = self.add_variable(self.get_variable(variable_index));
        self.create_add_gate(AddTriple {
            a: variable_index,
            b: copied,
            c: self.zero_idx,
            a_scaling: Fr::one(),
            b_scaling: -Fr::one(),
            c_scaling: Fr::zero(),
            const_scaling: Fr::zero(),
        });
        self.create_small_range_constraint(copied, target_range);
    }

    fn create_range_list(&mut self, target_range: u64) -> RangeList {
        let range_tag = self.get_new_tag();
        let tau_tag = self.get_new_tag();
        self.set_tau_transposition(range_tag, tau_tag);
        let mut variable_indices = vec![];
        for i in 0..=target_range / DEFAULT_PLOOKUP_RANGE_STEP_SIZE {
            let index = self.add_variable(Fr::from(i * DEFAULT_PLOOKUP_RANGE_STEP_SIZE));
            variable_indices.push(index);
            self.assign_tag(index, range_tag);
        }
        let index = self.add_variable(Fr::from(target_range));
        variable_indices.push(index);
        self.assign_tag(index, range_tag);
        self.create_unconstrained_gates(&variable_indices);
        RangeList {
            target_range,
            range_tag,
            tau_tag,
            variable_indices,
        }
    }

    /// Decompose into `target_range_bitnum`-bit limbs, range-constrain each, and prove the
    /// reconstruction three limbs per gate. Returns the limb witnesses.
    pub fn create_limbed_range_constraint(
        &mut self,
        variable_index: u32,
        num_bits: u64,
        target_range_bitnum: u64,
    ) -> Vec<u32> {
        assert!(num_bits > 0 && num_bits <= MAX_NUM_BITS_RANGE_CONSTRAINT);
        let val = u256(&self.get_variable(variable_index));
        if u256_num_bits(&val) as u64 > num_bits {
            self.failure("create_limbed_range_constraint");
        }
        let sublimb_mask = (1u64 << target_range_bitnum) - 1;
        let has_remainder_bits = num_bits % target_range_bitnum != 0;
        let num_limbs = num_bits / target_range_bitnum + has_remainder_bits as u64;
        let last_limb_size = num_bits - (num_bits / target_range_bitnum) * target_range_bitnum;
        let last_limb_range = (1u64 << last_limb_size) - 1;

        // Each sublimb converted to a field element once, for its witness and the accumulator.
        let mut sublimbs = Vec::with_capacity(num_limbs as usize);
        let mut acc = val;
        for _ in 0..num_limbs {
            sublimbs.push(Fr::from(acc.0[0] & sublimb_mask));
            acc = u256_shr(acc, target_range_bitnum as u32);
        }
        let mut sublimb_indices = Vec::with_capacity(num_limbs as usize);
        let num_full_limbs = if has_remainder_bits {
            sublimbs.len() - 1
        } else {
            sublimbs.len()
        };
        for &limb in &sublimbs[..num_full_limbs] {
            let idx = self.add_variable(limb);
            sublimb_indices.push(idx);
            self.create_small_range_constraint(idx, sublimb_mask);
        }
        if has_remainder_bits {
            let idx = self.add_variable(*sublimbs.last().unwrap());
            sublimb_indices.push(idx);
            self.create_small_range_constraint(idx, last_limb_range);
        }

        let num_limb_triples = num_limbs / 3 + (num_limbs % 3 != 0) as u64;
        let leftovers = if num_limbs % 3 == 0 { 3 } else { num_limbs % 3 };
        let mut accumulator = self.get_variable(variable_index);
        let mut accumulator_idx = variable_index;
        for i in 0..num_limb_triples as usize {
            let last = i as u64 == num_limb_triples - 1;
            let real = |k: u64| !(last && leftovers < k + 1);
            let limb_val = |k: usize| if real(k as u64) { sublimbs[3 * i + k] } else { Fr::zero() };
            let limb_idx = |k: usize| {
                if real(k as u64) {
                    sublimb_indices[3 * i + k]
                } else {
                    self.zero_idx
                }
            };
            let shift = |k: u64| target_range_bitnum * (3 * i as u64 + k);
            let pow2 = |k: u64| pow2_table()[shift(k) as usize];
            let mut new_accumulator = accumulator;
            for k in 0..3 {
                new_accumulator -= limb_val(k) * pow2(k as u64);
            }
            self.create_big_add_gate(
                AddQuad {
                    a: limb_idx(0),
                    b: limb_idx(1),
                    c: limb_idx(2),
                    d: accumulator_idx,
                    a_scaling: pow2(0),
                    b_scaling: pow2(1),
                    c_scaling: pow2(2),
                    d_scaling: -Fr::one(),
                    const_scaling: Fr::zero(),
                },
                !last,
            );
            if !last {
                accumulator_idx = self.add_variable(new_accumulator);
                accumulator = new_accumulator;
            }
        }
        sublimb_indices
    }

    fn process_range_list(&mut self, list: &mut RangeList) {
        assert!(!list.variable_indices.is_empty());
        for x in &mut list.variable_indices {
            *x = self.real_variable_index[*x as usize];
        }
        list.variable_indices.sort_unstable();
        list.variable_indices.dedup();
        let mut sorted_list: Vec<u32> = list
            .variable_indices
            .iter()
            .map(|i| Self::low_u64(&self.get_variable(*i)) as u32)
            .collect();
        sorted_list.sort_unstable();

        let mut padding = (NUM_WIRES - list.variable_indices.len() % NUM_WIRES) % NUM_WIRES;
        if list.variable_indices.len() <= NUM_WIRES {
            padding += NUM_WIRES;
        }
        let mut indices = vec![self.zero_idx; padding];
        indices.reserve(sorted_list.len());
        self.blocks
            .get_mut(BlockId::DeltaRange)
            .rows
            .reserve((padding + sorted_list.len()) / NUM_WIRES + 1);
        for value in crate::base::field::ascending_to_fr(sorted_list.into_iter().map(u64::from)) {
            let index = self.add_variable(value);
            self.assign_tag(index, list.tau_tag);
            indices.push(index);
        }
        self.create_sort_constraint_with_edges(&indices, Fr::zero(), Fr::from(list.target_range));
    }

    fn process_range_lists(&mut self) {
        let mut lists = std::mem::take(&mut self.range_lists);
        for list in lists.values_mut() {
            self.process_range_list(list);
        }
        self.range_lists = lists;
    }

    /// Sorted list with first element `start`, last element `end`, consecutive deltas in {0,1,2,3}.
    fn create_sort_constraint_with_edges(&mut self, indices: &[u32], start: Fr, end: Fr) {
        assert!(indices.len() % NUM_WIRES == 0 && indices.len() > NUM_WIRES);
        let z = self.zero_idx;
        let edge = |x: u32, v: Fr| AddTriple {
            a: x,
            b: z,
            c: z,
            a_scaling: Fr::one(),
            b_scaling: Fr::zero(),
            c_scaling: Fr::zero(),
            const_scaling: -v,
        };
        self.create_add_gate(edge(indices[0], start));
        for c in indices.chunks(NUM_WIRES) {
            self.append(
                BlockId::DeltaRange,
                GateRow {
                    wires: [c[0], c[1], c[2], c[3]],
                    kind: Kind::DeltaRange,
                    gate_value: Fr::one(),
                    ..Default::default()
                },
            );
        }
        let last = *indices.last().unwrap();
        self.create_unconstrained_gate(BlockId::DeltaRange, [last, z, z, z]);
        self.create_add_gate(edge(last, end));
    }

    // ---- finalization ----

    /// Adds the deferred gates in bb's fixed order: ROM arrays, RAM arrays, range lists, then the
    /// public-input rows. Called once; the order is part of the verification key.
    pub fn finalize_circuit(&mut self) {
        if self.circuit_finalized {
            return;
        }
        self.process_non_native_field_multiplications();
        self.process_rom_arrays();
        self.process_ram_arrays();
        self.process_range_lists();
        for idx in self.public_inputs.clone() {
            self.blocks
                .get_mut(BlockId::PubInputs)
                .rows
                .push(GateRow::wires([idx, idx, self.zero_idx, self.zero_idx]));
        }
        self.circuit_finalized = true;
    }

    /// For a finalized builder about to be laid out and dropped: trim the growable vectors to
    /// their length (an in-place shrink) and free the equivalence links only `assert_equal` reads.
    pub fn release_slack(&mut self) {
        for b in &mut self.blocks.blocks {
            b.rows.shrink_to_fit();
        }
        for t in &mut self.lookup_tables {
            t.lookup_gates.shrink_to_fit();
        }
        self.variables.shrink_to_fit();
        self.real_variable_index.shrink_to_fit();
        self.real_variable_tags.shrink_to_fit();
        (self.next_var_index, self.prev_var_index) = (Vec::new(), Vec::new());
    }

    /// The low 64 bits of a field element's integer representation (bb `uint256_t(fr).data[0]`).
    pub(crate) fn low_u64(v: &Fr) -> u64 {
        u256(v).0[0]
    }
}

impl Default for Builder {
    fn default() -> Self {
        Self::new()
    }
}
