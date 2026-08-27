//! In-circuit types over the builder (bb `stdlib/primitives`, `stdlib/hash`). Values carry a
//! handle to the builder so that arithmetic on them emits gates in evaluation order.
pub mod bigfield;
pub mod biggroup;
pub mod biggroup_secp256r1;
pub mod byte_array;
pub mod bool;
pub mod curve;
pub mod cycle_group;
pub mod ecdsa;
pub mod field;
pub mod goblin;
pub mod hash;
pub mod io;
pub mod memory;
pub mod plookup;
pub mod poseidon2;
pub mod sha256;

pub use bool::BoolT;
pub use curve::StdBn254;
pub use field::{Ctx, FieldT};
pub use goblin::{GoblinElement, GoblinField};
