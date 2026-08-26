//! Execution trace blocks (bb `ExecutionTraceBlock` / `UltraTraceBlockData`): gates are rows of
//! wire indices plus selector values, grouped by gate type; blocks are laid out sequentially in
//! the trace after the disabled rows.

use crate::base::field::FieldLike;
use crate::base::Fr;

/// The gate selector a row activates (bb `GateKind`). At most one per row.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    None,
    Lookup,
    Arith,
    DeltaRange,
    Elliptic,
    Memory,
    Nnf,
    Poseidon2Ext,
    Poseidon2Int,
}

#[derive(Clone, Debug, PartialEq)]
pub struct GateRow {
    pub wires: [u32; 4],
    pub q_m: Fr,
    pub q_c: Fr,
    pub q_1: Fr,
    pub q_2: Fr,
    pub q_3: Fr,
    pub q_4: Fr,
    pub q_5: Fr,
    pub kind: Kind,
    pub gate_value: Fr,
}

impl GateRow {
    /// An unconstrained row (all selectors zero) holding the given wires.
    pub fn wires(wires: [u32; 4]) -> Self {
        Self { wires, ..Default::default() }
    }
    pub fn gate_selector(&self, kind: Kind) -> Fr {
        if self.kind == kind {
            self.gate_value
        } else {
            Fr::zero()
        }
    }
}

impl Default for GateRow {
    fn default() -> Self {
        let z = Fr::zero();
        Self { wires: [0; 4], q_m: z, q_c: z, q_1: z, q_2: z, q_3: z, q_4: z, q_5: z, kind: Kind::None, gate_value: z }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BlockId {
    PubInputs,
    Lookup,
    Arithmetic,
    DeltaRange,
    Elliptic,
    Memory,
    Nnf,
    Poseidon2External,
    Poseidon2Internal,
}

/// Ultra block order and the gate kind each block owns (bb `ultra_execution_trace_generated.hpp`).
pub const ULTRA_BLOCKS: [(BlockId, Kind); 9] = [
    (BlockId::PubInputs, Kind::None),
    (BlockId::Lookup, Kind::Lookup),
    (BlockId::Arithmetic, Kind::Arith),
    (BlockId::DeltaRange, Kind::DeltaRange),
    (BlockId::Elliptic, Kind::Elliptic),
    (BlockId::Memory, Kind::Memory),
    (BlockId::Nnf, Kind::Nnf),
    (BlockId::Poseidon2External, Kind::Poseidon2Ext),
    (BlockId::Poseidon2Internal, Kind::Poseidon2Int),
];

#[derive(Clone, Debug, Default)]
pub struct Block {
    pub rows: Vec<GateRow>,
    /// Row of the full trace at which this block starts (set by `Blocks::compute_offsets`).
    pub trace_offset: usize,
}

impl Block {
    pub fn len(&self) -> usize {
        self.rows.len()
    }
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }
    pub fn trace_end(&self) -> usize {
        self.trace_offset + self.rows.len()
    }
}

#[derive(Clone, Debug)]
pub struct Blocks {
    pub blocks: Vec<Block>,
}

impl Blocks {
    pub fn ultra() -> Self {
        Self { blocks: (0..ULTRA_BLOCKS.len()).map(|_| Block::default()).collect() }
    }
    pub fn get(&self, id: BlockId) -> &Block {
        &self.blocks[Self::position(id)]
    }
    pub fn get_mut(&mut self, id: BlockId) -> &mut Block {
        &mut self.blocks[Self::position(id)]
    }
    fn position(id: BlockId) -> usize {
        ULTRA_BLOCKS.iter().position(|(b, _)| *b == id).expect("block not in trace")
    }
    /// The block owning a gate kind, if any.
    pub fn owner(&self, kind: Kind) -> Option<&Block> {
        ULTRA_BLOCKS.iter().position(|(_, k)| *k == kind).map(|i| &self.blocks[i])
    }
    /// Blocks are placed one after another starting right after the zero row that follows the
    /// disabled rows.
    pub fn compute_offsets(&mut self, trace_offset: usize) {
        let mut offset = trace_offset + super::NUM_ZERO_ROWS;
        for b in &mut self.blocks {
            b.trace_offset = offset;
            offset += b.len();
        }
    }
    pub fn total_content_size(&self) -> usize {
        self.blocks.iter().map(Block::len).sum()
    }
}
