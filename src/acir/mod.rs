//! ACIR ingestion: msgpack decoding of Noir artifacts and lowering of the protocol-relevant opcode
//! subset (arithmetic, range, Poseidon2, Grumpkin MSM/addition, memory and databus blocks,
//! HyperNova recursion) to the circuit builder, plus the `ivc-inputs.msgpack` private execution
//! steps a Chonk proof is made of.
pub mod format;
pub mod lower;
pub mod mock;
pub mod steps;

pub use format::{decode_program, decode_program_gz, decode_witness, Circuit};
pub use lower::{build_circuit, build_circuit_mega};
pub use steps::{decode_steps, prove_steps, PrivateExecutionStep};
