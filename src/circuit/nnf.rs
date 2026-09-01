//! Non-native-field gates (bb `UltraCircuitBuilder`'s `evaluate_non_native_field_*`,
//! `range_constrain_two_limbs`, `queue_partial_non_native_field_multiplication`): the gate-level
//! support the `bigfield` gadget builds 4×68-bit limb arithmetic on.

use super::builder::{AddQuad, Builder};
use super::trace::{BlockId, GateRow, Kind};
use crate::base::field::{from_u256, u256, u256_low_bits, u256_shr, FieldLike, U256};
use crate::base::Fr;

pub const DEFAULT_NON_NATIVE_FIELD_LIMB_BITS: u64 = 68;

#[derive(Clone, Copy, PartialEq, Eq)]
enum NnfSelector {
    None,
    LimbAccumulate1,
    LimbAccumulate2,
    NonNativeField1,
    NonNativeField2,
    NonNativeField3,
}

/// Witness indices of `a * b = q * p + r` over the binary-basis limbs.
pub struct NonNativeMultiplicationWitnesses {
    pub a: [u32; 4],
    pub b: [u32; 4],
    pub q: [u32; 4],
    pub r: [u32; 4],
    pub neg_modulus: [Fr; 4],
}

/// A partial product whose gates are emitted at finalization, deduplicated by operands
/// (bb `cached_partial_non_native_field_multiplication`).
#[derive(Clone)]
pub struct CachedPartialMultiplication {
    pub a: [u32; 4],
    pub b: [u32; 4],
    pub lo_0: u32,
    pub hi_0: u32,
    pub hi_1: u32,
}

/// `(witness, multiplicative constant)` of a limb.
pub type ScaledWitness = (u32, Fr);
/// `(x limb, y limb, additive constant)` of one limb of a non-native addition.
pub type AddSimple = (ScaledWitness, ScaledWitness, Fr);

fn limb_shift() -> Fr {
    from_u256(U256::from(1u64) << DEFAULT_NON_NATIVE_FIELD_LIMB_BITS as u32)
}

impl Builder {
    fn nnf_selectors_row(&self, t: NnfSelector) -> GateRow {
        let mut row = GateRow::wires([0; 4]);
        row.kind = Kind::Nnf;
        row.gate_value = if t == NnfSelector::None { Fr::zero() } else { Fr::one() };
        let one = Fr::one();
        match t {
            NnfSelector::LimbAccumulate1 => {
                row.q_3 = one;
                row.q_4 = one;
            }
            NnfSelector::LimbAccumulate2 => {
                row.q_3 = one;
                row.q_m = one;
            }
            NnfSelector::NonNativeField1 => {
                row.q_2 = one;
                row.q_3 = one;
            }
            NnfSelector::NonNativeField2 => {
                row.q_2 = one;
                row.q_4 = one;
            }
            NnfSelector::NonNativeField3 => {
                row.q_2 = one;
                row.q_m = one;
            }
            NnfSelector::None => {}
        }
        row
    }

    fn nnf_row(&mut self, t: NnfSelector, wires: [u32; 4]) {
        let mut row = self.nnf_selectors_row(t);
        row.wires = wires;
        self.append_row(BlockId::Nnf, row);
    }

    /// bb `range_constrain_two_limbs`: both limbs split into 14-bit sublimbs (three NNF rows
    /// accumulate them) and each sublimb range-constrained.
    pub fn range_constrain_two_limbs(&mut self, lo_idx: u32, hi_idx: u32, lo_limb_bits: usize, hi_limb_bits: usize) {
        assert!(lo_limb_bits <= 70 && hi_limb_bits <= 70);
        for (idx, bits) in [(lo_idx, lo_limb_bits), (hi_idx, hi_limb_bits)] {
            if u256(&self.get_variable(idx)) >= (U256::from(1u64) << bits as u32) {
                self.failure("range_constrain_two_limbs");
            }
        }
        let masks = |limb_bits: usize| -> [u64; 5] {
            let bits = [
                if limb_bits >= 14 { 14 } else { limb_bits },
                if limb_bits >= 28 {
                    14
                } else if limb_bits > 14 {
                    limb_bits - 14
                } else {
                    0
                },
                if limb_bits >= 42 {
                    14
                } else if limb_bits > 28 {
                    limb_bits - 28
                } else {
                    0
                },
                if limb_bits >= 56 {
                    14
                } else if limb_bits > 42 {
                    limb_bits - 42
                } else {
                    0
                },
                if limb_bits > 56 { limb_bits - 56 } else { 0 },
            ];
            bits.map(|b| (1u64 << b) - 1)
        };
        let (lo_masks, hi_masks) = (masks(lo_limb_bits), masks(hi_limb_bits));
        let zero = self.zero_idx();
        let sublimbs = |b: &mut Builder, idx: u32, m: &[u64; 5]| -> [u32; 5] {
            let limb = u256(&b.get_variable(idx));
            std::array::from_fn(|i| {
                if m[i] != 0 {
                    let v = u256_low_bits(u256_shr(limb, 14 * i as u32), 14);
                    b.add_variable(from_u256(v))
                } else {
                    zero
                }
            })
        };
        let lo = sublimbs(self, lo_idx, &lo_masks);
        let hi = sublimbs(self, hi_idx, &hi_masks);
        self.nnf_row(NnfSelector::LimbAccumulate1, [lo[0], lo[1], lo[2], lo_idx]);
        self.nnf_row(NnfSelector::LimbAccumulate2, [lo[3], lo[4], hi[0], hi[1]]);
        self.nnf_row(NnfSelector::None, [hi[2], hi[3], hi[4], hi_idx]);
        for i in 0..5 {
            if lo_masks[i] != 0 {
                self.create_small_range_constraint(lo[i], lo_masks[i]);
            }
            if hi_masks[i] != 0 {
                self.create_small_range_constraint(hi[i], hi_masks[i]);
            }
        }
    }

    /// bb `evaluate_non_native_field_multiplication`: the limb identity `a·b − q·p − r = 0` over
    /// the low and high halves, returning the two carry witnesses.
    pub fn evaluate_non_native_field_multiplication(&mut self, w: &NonNativeMultiplicationWitnesses) -> [u32; 2] {
        let v = |b: &Builder, i: &[u32; 4]| -> [Fr; 4] { std::array::from_fn(|k| b.get_variable(i[k])) };
        let (a, b, q, r) = (v(self, &w.a), v(self, &w.b), v(self, &w.q), v(self, &w.r));
        let p_neg = &w.neg_modulus;
        let shift = limb_shift();
        let rshift = shift.invert();
        let rshift_2 = rshift * rshift;
        let lo_0 = (a[0] * b[0] - r[0]) + (a[1] * b[0] + a[0] * b[1]) * shift;
        let lo_1 = (lo_0 + q[0] * p_neg[0] + (q[1] * p_neg[0] + q[0] * p_neg[1] - r[1]) * shift) * rshift_2;
        let hi_0 = (a[2] * b[0] + a[0] * b[2]) + (a[0] * b[3] + a[3] * b[0] - r[3]) * shift;
        let hi_1 = hi_0 + (a[1] * b[1] - r[2]) + (a[1] * b[2] + a[2] * b[1]) * shift;
        let hi_2 = hi_1 + lo_1 + q[2] * p_neg[0] + (q[3] * p_neg[0] + q[2] * p_neg[1]) * shift;
        let hi_3 = (hi_2 + q[0] * p_neg[2] + q[1] * p_neg[1] + (q[0] * p_neg[3] + q[1] * p_neg[2]) * shift) * rshift_2;
        let lo_0_idx = self.add_variable(lo_0);
        let lo_1_idx = self.add_variable(lo_1);
        let hi_0_idx = self.add_variable(hi_0);
        let hi_1_idx = self.add_variable(hi_1);
        let hi_2_idx = self.add_variable(hi_2);
        let hi_3_idx = self.add_variable(hi_3);
        let zero = self.zero_idx();
        self.create_big_add_gate(
            AddQuad {
                a: w.q[0],
                b: w.q[1],
                c: w.r[1],
                d: lo_1_idx,
                a_scaling: p_neg[0] + p_neg[1] * shift,
                b_scaling: p_neg[0] * shift,
                c_scaling: -shift,
                d_scaling: -(shift * shift),
                const_scaling: Fr::zero(),
            },
            true,
        );
        self.create_unconstrained_gate(BlockId::Arithmetic, [zero, zero, zero, lo_0_idx]);
        self.nnf_row(NnfSelector::NonNativeField1, [w.a[1], w.b[1], w.r[0], lo_0_idx]);
        self.nnf_row(NnfSelector::NonNativeField2, [w.a[0], w.b[0], w.a[3], w.b[3]]);
        self.nnf_row(NnfSelector::NonNativeField3, [w.a[2], w.b[2], w.r[3], hi_0_idx]);
        self.nnf_row(NnfSelector::None, [w.a[1], w.b[1], w.r[2], hi_1_idx]);
        self.create_big_add_gate(
            AddQuad {
                a: w.q[2],
                b: w.q[3],
                c: lo_1_idx,
                d: hi_1_idx,
                a_scaling: -p_neg[1] * shift - p_neg[0],
                b_scaling: -p_neg[0] * shift,
                c_scaling: -Fr::one(),
                d_scaling: -Fr::one(),
                const_scaling: Fr::zero(),
            },
            true,
        );
        self.create_big_add_gate(
            AddQuad {
                a: hi_3_idx,
                b: w.q[0],
                c: w.q[1],
                d: hi_2_idx,
                a_scaling: -Fr::one(),
                b_scaling: p_neg[3] * rshift + p_neg[2] * rshift_2,
                c_scaling: p_neg[2] * rshift + p_neg[1] * rshift_2,
                d_scaling: rshift_2,
                const_scaling: Fr::zero(),
            },
            false,
        );
        [lo_1_idx, hi_3_idx]
    }

    /// bb `queue_partial_non_native_field_multiplication`: the low/high partial products of `a·b`
    /// as witnesses, their gates deferred to `finalize_circuit`.
    pub fn queue_partial_non_native_field_multiplication(&mut self, a_idx: [u32; 4], b_idx: [u32; 4]) -> [u32; 2] {
        let a: [Fr; 4] = std::array::from_fn(|k| self.get_variable(a_idx[k]));
        let b: [Fr; 4] = std::array::from_fn(|k| self.get_variable(b_idx[k]));
        let shift = limb_shift();
        let lo_0 = a[0] * b[0] + (a[1] * b[0] + a[0] * b[1]) * shift;
        let hi_0 = a[2] * b[0] + a[0] * b[2] + (a[0] * b[3] + a[3] * b[0]) * shift;
        let hi_1 = hi_0 + a[1] * b[1] + (a[1] * b[2] + a[2] * b[1]) * shift;
        let lo_0_idx = self.add_variable(lo_0);
        let hi_0_idx = self.add_variable(hi_0);
        let hi_1_idx = self.add_variable(hi_1);
        self.cached_partial_multiplications.push(CachedPartialMultiplication {
            a: a_idx,
            b: b_idx,
            lo_0: lo_0_idx,
            hi_0: hi_0_idx,
            hi_1: hi_1_idx,
        });
        [lo_0_idx, hi_1_idx]
    }

    /// bb `process_non_native_field_multiplications`: deduplicate the queued partial products by
    /// their (real) operand indices, equating the outputs of duplicates, then emit their gates.
    pub(super) fn process_non_native_field_multiplications(&mut self) {
        let mut cached = std::mem::take(&mut self.cached_partial_multiplications);
        for c in cached.iter_mut() {
            for j in 0..4 {
                c.a[j] = self.real_variable_index[c.a[j] as usize];
                c.b[j] = self.real_variable_index[c.b[j] as usize];
            }
        }
        let mut unique: Vec<CachedPartialMultiplication> = vec![];
        for item in cached {
            match unique.iter().find(|u| u.a == item.a && u.b == item.b) {
                Some(existing) => {
                    let (lo_0, hi_0, hi_1) = (existing.lo_0, existing.hi_0, existing.hi_1);
                    self.assert_equal(item.lo_0, lo_0);
                    self.assert_equal(item.hi_0, hi_0);
                    self.assert_equal(item.hi_1, hi_1);
                }
                None => unique.push(item),
            }
        }
        let zero = self.zero_idx();
        for input in unique {
            self.nnf_row(NnfSelector::NonNativeField1, [input.a[1], input.b[1], zero, input.lo_0]);
            self.nnf_row(
                NnfSelector::NonNativeField2,
                [input.a[0], input.b[0], input.a[3], input.b[3]],
            );
            self.nnf_row(NnfSelector::NonNativeField3, [input.a[2], input.b[2], zero, input.hi_0]);
            self.nnf_row(NnfSelector::None, [input.a[1], input.b[1], zero, input.hi_1]);
        }
    }

    /// bb `evaluate_non_native_field_addition` / `_subtraction`: `z = x ± y` limb-wise over four
    /// arithmetic rows (gate values 3, 2, 1, 1), returning the five result witnesses.
    fn evaluate_non_native_field_add_sub(
        &mut self,
        limbs: [AddSimple; 4],
        limbp: (u32, u32, Fr),
        subtract: bool,
    ) -> [u32; 5] {
        let sign = if subtract { -Fr::one() } else { Fr::one() };
        let z: [u32; 4] = std::array::from_fn(|i| {
            let ((x, xm), (y, ym), c) = limbs[i];
            let v = self.get_variable(x) * xm + sign * (self.get_variable(y) * ym) + c;
            self.add_variable(v)
        });
        let (x_p, y_p, addconstp) = limbp;
        let z_p = {
            let v = self.get_variable(x_p) + sign * self.get_variable(y_p) + addconstp;
            self.add_variable(v)
        };
        let two = Fr::from(2u64);
        let ((x_0, xm0), (y_0, ym0), c0) = limbs[0];
        let ((x_1, xm1), (y_1, ym1), c1) = limbs[1];
        let ((x_2, xm2), (y_2, ym2), c2) = limbs[2];
        let ((x_3, xm3), (y_3, ym3), c3) = limbs[3];
        let zero = self.zero_idx();
        let mut row = GateRow::wires(if subtract {
            [y_p, x_0, y_0, z_p]
        } else {
            [y_p, x_0, y_0, x_p]
        });
        row.q_m = sign * addconstp;
        row.q_c = -c0 * two;
        row.q_2 = -xm0 * two;
        row.q_3 = -sign * ym0 * two;
        row.kind = Kind::Arith;
        row.gate_value = Fr::from(3u64);
        self.append_row(BlockId::Arithmetic, row);
        let mut row = GateRow::wires(if subtract {
            [x_p, x_1, y_1, z[0]]
        } else {
            [z_p, x_1, y_1, z[0]]
        });
        row.q_c = -c1;
        row.q_2 = -xm1;
        row.q_3 = -sign * ym1;
        row.kind = Kind::Arith;
        row.gate_value = Fr::from(2u64);
        self.append_row(BlockId::Arithmetic, row);
        let mut row = GateRow::wires([x_2, y_2, z[2], z[1]]);
        row.q_c = -c2;
        row.q_1 = -xm2;
        row.q_2 = -sign * ym2;
        row.q_3 = Fr::one();
        row.kind = Kind::Arith;
        row.gate_value = Fr::one();
        self.append_row(BlockId::Arithmetic, row);
        let mut row = GateRow::wires([x_3, y_3, z[3], zero]);
        row.q_c = -c3;
        row.q_1 = -xm3;
        row.q_2 = -sign * ym3;
        row.q_3 = Fr::one();
        row.kind = Kind::Arith;
        row.gate_value = Fr::one();
        self.append_row(BlockId::Arithmetic, row);
        [z[0], z[1], z[2], z[3], z_p]
    }

    pub fn evaluate_non_native_field_addition(&mut self, limbs: [AddSimple; 4], limbp: (u32, u32, Fr)) -> [u32; 5] {
        self.evaluate_non_native_field_add_sub(limbs, limbp, false)
    }

    pub fn evaluate_non_native_field_subtraction(&mut self, limbs: [AddSimple; 4], limbp: (u32, u32, Fr)) -> [u32; 5] {
        self.evaluate_non_native_field_add_sub(limbs, limbp, true)
    }
}
