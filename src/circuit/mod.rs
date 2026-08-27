//! Circuit construction: variables, copy constraints, gates and the execution trace
//! (bb `stdlib_circuit_builders/{circuit_builder_base,ultra_circuit_builder,rom_ram_logic}`).
pub mod builder;
pub mod mega;
pub mod memory;
pub mod op_queue;
pub mod plookup;
pub mod trace;

pub use builder::{Builder, IS_CONSTANT};
pub use op_queue::EccOpQueue;
pub use trace::{Block, BlockDesc, BlockId, Blocks, GateRow, Kind};

/// Rows at the top of the trace reserved for row disabling / ZK masking (bb `NUM_DISABLED_ROWS_IN_SUMCHECK`).
pub const TRACE_OFFSET: usize = 4;
/// A single all-zero row precedes the blocks so that shifted polynomials are well defined.
pub const NUM_ZERO_ROWS: usize = 1;
