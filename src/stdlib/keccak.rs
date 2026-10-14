//! Keccak-f[1600] over lanes in base-11 sparse form (bb `stdlib/hash/keccak/keccak.cpp`): XOR is
//! addition of sparse lanes, the plookup tables in `circuit::keccak_tables` renormalize digits back
//! to bits and rotate, and each lane carries its top bit separately for θ's rotation by one.

use super::field::{Ctx, FieldT};
use super::plookup::{get_lookup_accumulators, read_from_1_to_2_table};
use crate::base::field::NativeField;
use crate::base::Fr;
use crate::circuit::keccak_tables::{pow11, rho_slices, BASE, LANE_BITS, ROTATIONS};
use crate::circuit::plookup::{LookupEntry, MultiTableId, ReadData};
use ark_ff::PrimeField;
use num_bigint::BigUint;
use std::sync::LazyLock;

pub const NUM_ROUNDS: usize = 24;
pub const NUM_LANES: usize = 25;
const RC: [u64; NUM_ROUNDS] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

fn big(f: &Fr) -> BigUint {
    f.into_bigint().into()
}
fn pow11_big(e: usize) -> BigUint {
    BigUint::from(BASE).pow(e as u32)
}
/// A 64-bit value as base-11 digits.
fn convert_to_sparse(input: u64) -> BigUint {
    let mut out = BigUint::from(0u64);
    for i in (0..64).rev() {
        out = out * BASE + ((input >> i) & 1);
    }
    out
}
static SPARSE_RC: LazyLock<[Fr; NUM_ROUNDS]> =
    LazyLock::new(|| std::array::from_fn(|i| Fr::from(convert_to_sparse(RC[i]))));
/// `Σ 11^i` for `i < 64`: one added to every digit before χ's `2a − b + c`.
static CHI_OFFSET: LazyLock<Fr> = LazyLock::new(|| {
    let mut result = BigUint::from(0u64);
    for _ in 0..LANE_BITS {
        result = result * BASE + 1u64;
    }
    Fr::from(result)
});

struct KeccakState {
    ctx: Ctx,
    state: [FieldT; NUM_LANES],
    state_msb: [FieldT; NUM_LANES],
    twisted_state: [FieldT; NUM_LANES],
}

/// Little-endian base-11 digits of `v` (at least `LANE_BITS` of them): division by 11^9 on 32-bit
/// pieces, so every step is a native 64-bit division.
fn base11_digits(v: &Fr) -> Vec<u8> {
    const D: u64 = 2_357_947_691; // 11^9
    let l = v.into_bigint().0;
    let mut w: [u32; 8] = std::array::from_fn(|i| (l[i / 2] >> (32 * (i % 2))) as u32);
    let mut out = Vec::with_capacity(72);
    while w.iter().any(|&x| x != 0) {
        let mut rem = 0u64;
        for x in w.iter_mut().rev() {
            let cur = (rem << 32) | u64::from(*x);
            *x = (cur / D) as u32;
            rem = cur % D;
        }
        for _ in 0..9 {
            out.push((rem % BASE) as u8);
            rem /= BASE;
        }
    }
    if out.len() < LANE_BITS {
        out.resize(LANE_BITS, 0);
    }
    out
}

/// `Σ d[i]·11^i` over a digit run, optionally keeping only each digit's parity.
fn pack11(d: &[u8], parity: bool) -> u64 {
    d.iter().rev().fold(0u64, |acc, &x| acc * BASE + u64::from(if parity { x & 1 } else { x }))
}

/// `Fr` image of `Σ d[i]·11^i` (any length).
fn fr11(d: &[u8], parity: bool) -> Fr {
    let pow8 = Fr::from(pow11(8));
    d.chunks(8).rev().fold(Fr::from(0u64), |acc, c| acc * pow8 + Fr::from(pack11(c, parity)))
}

/// bb `normalize_and_rotate<lane>`: renormalizes the lane's digits to bits and rotates left by
/// `ROTATIONS[lane]` through the per-lane ρ multi-table; returns the lane and its new top bit.
/// Works on the lane's base-11 digits: slice values are short digit runs and the accumulator
/// columns are Horner sums from the top slice down.
fn normalize_and_rotate(ctx: &Ctx, lane: usize, limb: &FieldT) -> (FieldT, FieldT) {
    let (right, left) = rho_slices(ROTATIONS[lane]);
    let digits = base11_digits(&limb.get_value());
    let n = right.len() + left.len();
    // Slice digit ranges in order (right part, then left part).
    let mut ranges = Vec::with_capacity(n);
    let mut pos = 0;
    for &bits in right.iter().chain(&left) {
        ranges.push((pos, bits));
        pos += bits;
    }
    let mut col0 = vec![Fr::from(0u64); n];
    let mut col1 = vec![Fr::from(0u64); n];
    let mut col2 = vec![Fr::from(0u64); n];
    let mut entries = Vec::with_capacity(n);
    // Column 0 runs over every digit above the slice; column 1 over the parities of its own part
    // (the right part ends at its last slice, the left part runs to the top digit).
    let mut acc0 = fr11(&digits[pos.min(digits.len())..], false);
    let mut acc1 = fr11(&digits[pos.min(digits.len())..], true);
    for k in (0..n).rev() {
        let (start, bits) = ranges[k];
        if k + 1 == right.len() {
            acc1 = Fr::from(0u64);
        }
        let shift = Fr::from(pow11(bits));
        let slice = &digits[start..start + bits];
        let input_slice = pack11(slice, false);
        let normalized_slice = pack11(slice, true);
        let normalized_msb = u64::from(slice[bits - 1] & 1);
        let normalized_slice_fr = Fr::from(normalized_slice);
        acc0 = Fr::from(input_slice) + shift * acc0;
        acc1 = normalized_slice_fr + shift * acc1;
        col0[k] = acc0;
        col1[k] = acc1;
        col2[k] = Fr::small(normalized_msb);
        entries.push(LookupEntry {
            key: [input_slice, 0],
            value: [normalized_slice_fr, Fr::small(normalized_msb)],
        });
    }
    entries.reverse();
    let lookup = ReadData::<Fr> {
        columns: [col0, col1, col2],
        lookup_entries: entries,
    };
    let limb_index = limb.get_witness_index();
    let witnesses = ctx.borrow_mut().create_gates_from_plookup_accumulators(
        MultiTableId::KeccakNormalizeAndRotate(lane as u8),
        &lookup,
        limb_index,
        None,
    );
    let msb = FieldT::from_witness_index(ctx, witnesses.columns[2][left.len() + right.len() - 1]);
    let right_output = FieldT::from_witness_index(ctx, witnesses.columns[1][0]);
    if left.is_empty() {
        return (right_output, msb);
    }
    let left_output = FieldT::from_witness_index(ctx, witnesses.columns[1][right.len()]);
    let shift = FieldT::constant(Fr::from(pow11_big(ROTATIONS[lane])));
    (left_output.add(&right_output.mul(&shift)), msb)
}

fn compute_twisted_state(internal: &mut KeccakState) {
    for i in 0..NUM_LANES {
        internal.twisted_state[i] = internal.state[i]
            .mul(&FieldT::constant(Fr::from(BASE)))
            .add(&internal.state_msb[i])
            .normalize();
    }
}

fn theta(internal: &mut KeccakState) {
    let twisted = &internal.twisted_state;
    let c: [FieldT; 5] = std::array::from_fn(|i| {
        FieldT::accumulate(&[
            twisted[i].clone(),
            twisted[5 + i].clone(),
            twisted[10 + i].clone(),
            twisted[15 + i].clone(),
            twisted[20 + i].clone(),
        ])
    });
    let mut d: [FieldT; 5] = std::array::from_fn(|i| {
        let shifted_equivalent = c[(i + 1) % 5].mul(&FieldT::constant(Fr::from(BASE)));
        c[(i + 4) % 5].add(&shifted_equivalent)
    });
    let divisor = pow11_big(LANE_BITS);
    let multiplicand = FieldT::constant(Fr::from(pow11_big(LANE_BITS + 1)));
    for d_i in d.iter_mut() {
        let d_native = big(&d_i.get_value());
        let (d_quotient, lo_native) = (&d_native / BASE, &d_native % BASE);
        let hi_native = &d_quotient / &divisor;
        let mid_native = &d_quotient - &hi_native * &divisor;
        let hi = FieldT::from_witness(&internal.ctx, Fr::from(hi_native));
        let mid = FieldT::from_witness(&internal.ctx, Fr::from(mid_native));
        let lo = FieldT::from_witness(&internal.ctx, Fr::from(lo_native));
        d_i.assert_equal(
            &hi.mul(&multiplicand)
                .add_two(&mid.mul(&FieldT::constant(Fr::from(BASE))), &lo),
        );
        let (hi_index, lo_index) = (hi.get_witness_index(), lo.get_witness_index());
        internal
            .ctx
            .borrow_mut()
            .create_small_range_constraint(hi_index, BASE - 1);
        internal
            .ctx
            .borrow_mut()
            .create_small_range_constraint(lo_index, BASE - 1);
        *d_i = read_from_1_to_2_table(MultiTableId::KeccakThetaOutput, &mid);
    }
    for i in 0..5 {
        for j in 0..5 {
            internal.state[j * 5 + i] = internal.state[j * 5 + i].add(&d[i]);
        }
    }
}

fn rho(internal: &mut KeccakState) {
    for i in 0..NUM_LANES {
        let (lane, msb) = normalize_and_rotate(&internal.ctx, i, &internal.state[i]);
        internal.state[i] = lane;
        internal.state_msb[i] = msb;
    }
}

fn pi(internal: &mut KeccakState) {
    let b = internal.state.clone();
    for y in 0..5 {
        for x in 0..5 {
            let u = y % 5;
            let v = (2 * x + 3 * y) % 5;
            internal.state[v * 5 + u] = b[5 * y + x].clone();
        }
    }
}

fn chi(internal: &mut KeccakState) {
    for y in 0..5 {
        let lane_outputs: [FieldT; 5] = std::array::from_fn(|x| {
            let a = &internal.state[y * 5 + x];
            let b = &internal.state[y * 5 + (x + 1) % 5];
            let c = &internal.state[y * 5 + (x + 2) % 5];
            a.add(a).add(&FieldT::constant(*CHI_OFFSET)).add_two(&b.neg(), c)
        });
        for (x, lane) in lane_outputs.iter().enumerate() {
            let accumulators = get_lookup_accumulators(
                MultiTableId::KeccakChiOutput,
                lane,
                &FieldT::constant(Fr::from(0u64)),
                false,
            );
            internal.state[y * 5 + x] = accumulators.columns[1][0].clone();
            internal.state_msb[y * 5 + x] = accumulators.columns[2].last().unwrap().clone();
        }
    }
}

fn iota(internal: &mut KeccakState, round: usize) {
    let xor_result = internal.state[0].add(&FieldT::constant(SPARSE_RC[round]));
    let (lane, msb) = normalize_and_rotate(&internal.ctx, 0, &xor_result);
    internal.state[0] = lane;
    internal.state_msb[0] = msb;
    if round != NUM_ROUNDS - 1 {
        compute_twisted_state(internal);
    }
}

/// bb `keccak::permutation_opcode`: the 25 lanes (64-bit values) through Keccak-f[1600].
pub fn permutation_opcode(ctx: &Ctx, state: &[FieldT; NUM_LANES]) -> [FieldT; NUM_LANES] {
    let zero = || FieldT::constant(Fr::from(0u64));
    let mut internal = KeccakState {
        ctx: ctx.clone(),
        state: std::array::from_fn(|_| zero()),
        state_msb: std::array::from_fn(|_| zero()),
        twisted_state: std::array::from_fn(|_| zero()),
    };
    for i in 0..NUM_LANES {
        let accumulators = get_lookup_accumulators(MultiTableId::KeccakFormatInput, &state[i], &zero(), false);
        internal.state[i] = accumulators.columns[1][0].clone();
        internal.state_msb[i] = accumulators.columns[2].last().unwrap().clone();
    }
    compute_twisted_state(&mut internal);
    for round in 0..NUM_ROUNDS {
        theta(&mut internal);
        rho(&mut internal);
        pi(&mut internal);
        chi(&mut internal);
        iota(&mut internal, round);
    }
    std::array::from_fn(|i| read_from_1_to_2_table(MultiTableId::KeccakFormatOutput, &internal.state[i]))
}
