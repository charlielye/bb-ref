//! In-circuit Poseidon2 sponge hash (bb `stdlib::FieldSponge::hash_internal`).

use super::field::{Ctx, FieldT};
use super::poseidon2::permutation;
use crate::base::field::FieldLike;
use crate::base::poseidon2::Hasher;
use crate::base::Fr;

const RATE: usize = 3;

pub fn hash(input: &[FieldT]) -> FieldT {
    let ctx: Ctx = input.iter().find_map(|f| f.ctx.clone()).expect("sponge inputs must include a witness");
    assert!(input.iter().all(|f| !f.is_constant()), "sponge inputs should not be stdlib constants");
    let mut iv = FieldT::constant(Fr::from((input.len() as u128) << 64));
    iv.convert_constant_to_fixed_witness(&ctx);
    let zero = || FieldT::constant(Fr::zero());
    let mut state = [zero(), zero(), zero(), iv];
    let mut cache = [zero(), zero(), zero()];
    let mut cache_size = 0;
    let duplex = |state: &mut [FieldT; 4], cache: &mut [FieldT; RATE]| {
        for i in 0..RATE {
            state[i] += &cache[i];
        }
        *state = permutation(&ctx, state);
        *cache = [zero(), zero(), zero()];
    };
    for x in input {
        if cache_size == RATE {
            duplex(&mut state, &mut cache);
            cache[0] = x.clone();
            cache_size = 1;
        } else {
            cache[cache_size] = x.clone();
            cache_size += 1;
        }
    }
    duplex(&mut state, &mut cache);
    state[0].clone()
}

pub struct StdPoseidon2;

impl Hasher<FieldT> for StdPoseidon2 {
    fn hash(input: &[FieldT]) -> FieldT {
        hash(input)
    }
}
