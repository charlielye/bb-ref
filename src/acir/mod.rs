//! ACIR ingestion: msgpack decoding of Noir artifacts and lowering of the protocol-relevant opcode
//! subset (arithmetic, range, Poseidon2, memory blocks) to the circuit builder.
pub mod format;
pub mod lower;

pub use format::{decode_program, decode_witness, Circuit};
pub use lower::build_circuit;
