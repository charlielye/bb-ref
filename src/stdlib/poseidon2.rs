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

/// Mega's initial linear layer: one custom gate whose successor row holds `M_E · state`.
fn initial_layer_mega(ctx: &Ctx, state: &mut State) {
    let mut n = native(state);
    matrix_multiplication_external(&mut n);
    for s in state.iter_mut() {
        if s.is_constant() {
            let idx = ctx.borrow_mut().put_constant_variable(s.get_value());
            *s = FieldT::from_witness_index(ctx, idx);
        }
    }
    let w = witness_indices(state);
    ctx.borrow_mut().create_poseidon2_initial_external_gate(w);
    *state = to_witnesses(ctx, &n);
}

fn advance_internal_round(n: &mut [Fr; 4], rc: Fr) {
    n[0] += rc;
    sbox(&mut n[0]);
    matrix_multiplication_internal(n);
}

/// Mega's K=4 compressed internal rounds: an entry row in standard encoding, then one row per
/// four rounds holding state[0] at each round (bb `apply_mega_internal_rounds`).
fn internal_rounds_mega(ctx: &Ctx, state: &mut State, n: &mut [Fr; 4], rounds_f_beginning: usize) {
    let num_quad_rows = ROUNDS_P / 4;
    let w = witness_indices(state);
    ctx.borrow_mut().create_poseidon2_transition_entry_gate(w, rounds_f_beginning);
    let rc = round_constants();
    for q in 0..num_quad_rows {
        let is_terminal = q == num_quad_rows - 1;
        let start = rounds_f_beginning + 4 * q;
        let mut after = *n;
        advance_internal_round(&mut after, rc[start][0]);
        let s0_at_1 = FieldT::from_witness(ctx, after[0]);
        advance_internal_round(&mut after, rc[start + 1][0]);
        let s0_at_2 = FieldT::from_witness(ctx, after[0]);
        advance_internal_round(&mut after, rc[start + 2][0]);
        let s0_at_3 = FieldT::from_witness(ctx, after[0]);
        let wires = [state[0].get_witness_index(), s0_at_1.witness_index, s0_at_2.witness_index, s0_at_3.witness_index];
        ctx.borrow_mut().create_poseidon2_quad_internal_gate(wires, start, start + 4, is_terminal);
        advance_internal_round(&mut after, rc[start + 3][0]);
        *n = after;
        state[0] = FieldT::from_witness(ctx, n[0]);
        if is_terminal {
            for j in 1..4 {
                state[j] = FieldT::from_witness(ctx, n[j]);
            }
        }
    }
}

pub fn permutation(ctx: &Ctx, input: &State) -> State {
    let is_mega = ctx.borrow().is_mega();
    let mut state = input.clone();
    if is_mega {
        initial_layer_mega(ctx, &mut state);
    } else {
        matrix_multiplication_external_circuit(&mut state);
    }
    let mut n = native(&state);

    let rounds_f_beginning = ROUNDS_F / 2;
    external_rounds(ctx, &mut state, &mut n, 0..rounds_f_beginning);
    let p_end = rounds_f_beginning + ROUNDS_P;
    if is_mega {
        internal_rounds_mega(ctx, &mut state, &mut n, rounds_f_beginning);
    } else {
        propagate_to_next_row(ctx, &state, BlockId::Poseidon2External);
        for i in rounds_f_beginning..p_end {
            let w = witness_indices(&state);
            ctx.borrow_mut().create_poseidon2_internal_gate(w, i);
            advance_internal_round(&mut n, round_constants()[i][0]);
            state = to_witnesses(ctx, &n);
        }
        propagate_to_next_row(ctx, &state, BlockId::Poseidon2Internal);
    }

    external_rounds(ctx, &mut state, &mut n, p_end..ROUNDS_F + ROUNDS_P);
    propagate_to_next_row(ctx, &state, if is_mega { BlockId::Poseidon2 } else { BlockId::Poseidon2External });
    state
}
