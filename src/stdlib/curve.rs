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

/// bn254 as seen from inside an ULTRA circuit (bb `stdlib::bn254<UltraCircuitBuilder>`, the rollup
/// side): scalars are native `FieldT`, commitments are the non-goblin bigfield `Element`.
#[derive(Clone, Copy, Debug)]
pub struct StdUltraBn254;

impl Curve for StdUltraBn254 {
    type TF = FieldT;
    type Fr = FieldT;
    type G = super::biggroup::Element<ark_bn254::g1::Config>;
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

/// bb `stdlib::grumpkin<UltraCircuitBuilder>`: Grumpkin in-circuit on an Ultra builder — bigfield
/// scalars, `cycle_group` commitments (the rollup-side recursive ECCVM/IPA instantiation).
pub struct StdUltraGrumpkin;

impl Curve for StdUltraGrumpkin {
    type TF = FieldT;
    type Fr = crate::stdlib::bigfield::BigField<crate::base::Fq>;
    type G = crate::stdlib::cycle_group::CycleGroup;
    type Hash = StdPoseidon2;
    const SUBGROUP_SIZE: usize = crate::base::Grumpkin::SUBGROUP_SIZE;
    fn subgroup_generator() -> crate::base::Fq {
        crate::base::Grumpkin::subgroup_generator()
    }
    fn subgroup_generator_inverse() -> crate::base::Fq {
        crate::base::Grumpkin::subgroup_generator_inverse()
    }
    const LIBRA_UNIVARIATES_LENGTH: usize = crate::base::Grumpkin::LIBRA_UNIVARIATES_LENGTH;
}
