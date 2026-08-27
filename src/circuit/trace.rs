//! Execution trace blocks (bb `ExecutionTraceBlock` / `{Ultra,Mega}TraceBlockData`): gates are rows
//! of wire indices plus selector values, grouped by gate type; blocks are laid out sequentially in
//! the trace after the disabled rows.

use crate::base::field::FieldLike;
use crate::base::Fr;

/// The gate selector a row activates (bb `GateKind`). At most one per row.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    None,
    BusRead,
    Lookup,
    Arith,
    BilinearBatchedEq,
    DeltaRange,
    Elliptic,
    Memory,
    Nnf,
    Poseidon2Ext,
    Poseidon2Int,
    Poseidon2ExtInitial,
    Poseidon2QuadInt,
    Poseidon2QuadIntTerminal,
    Poseidon2TransitionEntry,
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
        Self {
            wires,
            ..Default::default()
        }
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
        Self {
            wires: [0; 4],
            q_m: z,
            q_c: z,
            q_1: z,
            q_2: z,
            q_3: z,
            q_4: z,
            q_5: z,
            kind: Kind::None,
            gate_value: z,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BlockId {
    EccOp,
    PubInputs,
    Lookup,
    Arithmetic,
    DeltaRange,
    Elliptic,
    Memory,
    Nnf,
    Busread,
    Poseidon2External,
    Poseidon2Internal,
    Poseidon2,
}

/// A trace block and the gate kinds whose selector it owns.
#[derive(Debug)]
pub struct BlockDesc {
    pub id: BlockId,
    pub kinds: &'static [Kind],
}

const fn b(id: BlockId, kinds: &'static [Kind]) -> BlockDesc {
    BlockDesc { id, kinds }
}

/// Ultra block order (bb `ultra_execution_trace_generated.hpp`).
pub const ULTRA_BLOCKS: &[BlockDesc] = &[
    b(BlockId::PubInputs, &[]),
    b(BlockId::Lookup, &[Kind::Lookup]),
    b(BlockId::Arithmetic, &[Kind::Arith]),
    b(BlockId::DeltaRange, &[Kind::DeltaRange]),
    b(BlockId::Elliptic, &[Kind::Elliptic]),
    b(BlockId::Memory, &[Kind::Memory]),
    b(BlockId::Nnf, &[Kind::Nnf]),
    b(BlockId::Poseidon2External, &[Kind::Poseidon2Ext]),
    b(BlockId::Poseidon2Internal, &[Kind::Poseidon2Int]),
];

/// Mega block order (bb `mega_execution_trace_generated.hpp`); `ecc_op` must come first so that
/// `ecc_op_wire[r] == w_shift[r]`.
pub const MEGA_BLOCKS: &[BlockDesc] = &[
    b(BlockId::EccOp, &[]),
    b(BlockId::PubInputs, &[]),
    b(BlockId::Lookup, &[Kind::Lookup]),
    b(BlockId::Arithmetic, &[Kind::Arith, Kind::BilinearBatchedEq]),
    b(BlockId::DeltaRange, &[Kind::DeltaRange]),
    b(BlockId::Elliptic, &[Kind::Elliptic]),
    b(BlockId::Memory, &[Kind::Memory]),
    b(BlockId::Nnf, &[Kind::Nnf]),
    b(BlockId::Busread, &[Kind::BusRead]),
    b(
        BlockId::Poseidon2,
        &[
            Kind::Poseidon2Ext,
            Kind::Poseidon2ExtInitial,
            Kind::Poseidon2QuadInt,
            Kind::Poseidon2QuadIntTerminal,
            Kind::Poseidon2TransitionEntry,
        ],
    ),
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
    pub descs: &'static [BlockDesc],
    pub blocks: Vec<Block>,
}

impl Blocks {
    pub fn new(descs: &'static [BlockDesc]) -> Self {
        Self {
            descs,
            blocks: descs.iter().map(|_| Block::default()).collect(),
        }
    }
    fn position(&self, id: BlockId) -> usize {
        self.descs
            .iter()
            .position(|d| d.id == id)
            .unwrap_or_else(|| panic!("block {id:?} not in this trace"))
    }
    pub fn has(&self, id: BlockId) -> bool {
        self.descs.iter().any(|d| d.id == id)
    }
    pub fn get(&self, id: BlockId) -> &Block {
        &self.blocks[self.position(id)]
    }
    pub fn get_mut(&mut self, id: BlockId) -> &mut Block {
        let i = self.position(id);
        &mut self.blocks[i]
    }
    /// Blocks and their descriptors, in trace order.
    pub fn iter(&self) -> impl Iterator<Item = (&BlockDesc, &Block)> {
        self.descs.iter().zip(&self.blocks)
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
