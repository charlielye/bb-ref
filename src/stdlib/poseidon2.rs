//! Poseidon2 permutation in circuit (bb `stdlib::Poseidon2Permutation`, Ultra layout): rounds are
//! computed natively and recorded in the poseidon2 custom gates; the next row holds each round's
//! output, read by the relation through shifts.

use super::field::{Ctx, FieldT};
use crate::base::poseidon2::{matrix_multiplication_external, matrix_multiplication_internal, round_constants, sbox};
use crate::base::poseidon2_params::{ROUNDS_F, ROUNDS_P};
use crate::base::Fr;
use crate::circuit::BlockId;

pub type State = [FieldT; 4];

fn witness_indices(s: &State) -> [u32; 4] {
    [s[0].get_witness_index(), s[1].get_witness_index(), s[2].get_witness_index(), s[3].get_witness_index()]
}

fn native(s: &State) -> [Fr; 4] {
    [s[0].get_value(), s[1].get_value(), s[2].get_value(), s[3].get_value()]
}

fn to_witnesses(ctx: &Ctx, n: &[Fr; 4]) -> State {
    [FieldT::from_witness(ctx, n[0]), FieldT::from_witness(ctx, n[1]), FieldT::from_witness(ctx, n[2]), FieldT::from_witness(ctx, n[3])]
}

/// The initial external linear layer `M_E * state` in six arithmetic gates.
fn matrix_multiplication_external_circuit(state: &mut State) {
    let two = FieldT::constant(Fr::from(2u64));
    let four = FieldT::constant(Fr::from(4u64));
    let tmp1 = state[0].add_two(&state[1], &(&state[3] * &two));
    let tmp2 = state[2].add_two(&(&state[1] * &two), &state[3]);
    state[1] = tmp2.add_two(&(&state[0] * &four), &(&state[1] * &four));
    state[0] = &state[1] + &tmp1;
    state[3] = tmp1.add_two(&(&state[2] * &four), &(&state[3] * &four));
    state[2] = &state[3] + &tmp2;
}

fn propagate_to_next_row(ctx: &Ctx, state: &State, block: BlockId) {
    let w = witness_indices(state);
    ctx.borrow_mut().create_unconstrained_gate(block, w);
}

fn external_rounds(ctx: &Ctx, state: &mut State, n: &mut [Fr; 4], rounds: std::ops::Range<usize>) {
    for i in rounds {
        let w = witness_indices(state);
        ctx.borrow_mut().create_poseidon2_external_gate(w, i);
        for j in 0..4 {
            n[j] += round_constants()[i][j];
        }
        n.iter_mut().for_each(sbox);
        matrix_multiplication_external(n);
        *state = to_witnesses(ctx, n);
    }
}

pub fn permutation(ctx: &Ctx, input: &State) -> State {
    let mut state = input.clone();
    matrix_multiplication_external_circuit(&mut state);
    let mut n = native(&state);

    let rounds_f_beginning = ROUNDS_F / 2;
    external_rounds(ctx, &mut state, &mut n, 0..rounds_f_beginning);
    propagate_to_next_row(ctx, &state, BlockId::Poseidon2External);

    let p_end = rounds_f_beginning + ROUNDS_P;
    for i in rounds_f_beginning..p_end {
        let w = witness_indices(&state);
        ctx.borrow_mut().create_poseidon2_internal_gate(w, i);
        n[0] += round_constants()[i][0];
        sbox(&mut n[0]);
        matrix_multiplication_internal(&mut n);
        state = to_witnesses(ctx, &n);
    }
    propagate_to_next_row(ctx, &state, BlockId::Poseidon2Internal);

    external_rounds(ctx, &mut state, &mut n, p_end..ROUNDS_F + ROUNDS_P);
    propagate_to_next_row(ctx, &state, BlockId::Poseidon2External);
    state
}
