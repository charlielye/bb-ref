//! In-circuit types over the builder (bb `stdlib/primitives`, `stdlib/hash`). Values carry a
//! handle to the builder so that arithmetic on them emits gates in evaluation order.
pub mod curve;
pub mod field;
pub mod goblin;
pub mod hash;
pub mod io;
pub mod memory;
pub mod poseidon2;

pub use curve::StdBn254;
pub use field::{Ctx, FieldT};
pub use goblin::{GoblinElement, GoblinField};
