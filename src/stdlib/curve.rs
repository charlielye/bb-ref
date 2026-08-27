//! bn254 as seen from inside a goblin circuit (bb `stdlib::bn254<MegaCircuitBuilder>`): scalars
//! are `FieldT`, commitments are `GoblinElement`, the transcript hashes with the Poseidon2 gadget.

use super::field::FieldT;
use super::goblin::GoblinElement;
use super::hash::StdPoseidon2;
use crate::base::group::{Bn254, Curve};
use crate::base::Fr;

#[derive(Clone, Copy, Debug)]
pub struct StdBn254;

impl Curve for StdBn254 {
    type TF = FieldT;
    type Fr = FieldT;
    type G = GoblinElement;
    type Hash = StdPoseidon2;
    const SUBGROUP_SIZE: usize = Bn254::SUBGROUP_SIZE;
    fn subgroup_generator() -> Fr {
        Bn254::subgroup_generator()
    }
    fn subgroup_generator_inverse() -> Fr {
        Bn254::subgroup_generator_inverse()
    }
    const LIBRA_UNIVARIATES_LENGTH: usize = Bn254::LIBRA_UNIVARIATES_LENGTH;
}
