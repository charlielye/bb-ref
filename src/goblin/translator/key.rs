//! The Translator proving key (bb `translator_proving_key.cpp`): the mini-circuit wires laid into
//! the 2^17-row polynomials, the Lagrange selectors, the 16-fold concatenations of the range-constraint
//! wires, and their sorted ("ordered") counterparts for the permutation-based range check.

use super::builder::TranslatorCircuit;
use super::*;
use crate::base::field::{ascending_to_fr, u256, FieldLike};
use crate::base::rng::{random_field, Rng};

/// `2^14 - 1, 2^14 - 4, ..., 1` — the step values the range check permutes into every ordered column.
pub fn sorted_steps() -> Vec<u64> {
    let max = (1u64 << MICRO_LIMB_BITS) - 1;
    (0..SORTED_STEPS_COUNT as u64).map(|i| max - SORT_STEP * i).collect()
}

impl TranslatorPolys {
    /// Random masking for the last `NUM_MASKED_ROWS_END` rows of the mini-circuit wires.
    pub fn random_masking(rng: &mut dyn Rng) -> Vec<[Fr; NUM_MASKED_ROWS_END]> {
        (0..NUM_MINICIRCUIT_WIRES)
            .map(|_| std::array::from_fn(|_| random_field(rng)))
            .collect()
    }

    /// bb `TranslatorProvingKey(circuit)` with the given masking values for wires `4..81`.
    pub fn from_circuit(circuit: &TranslatorCircuit, masking: &[[Fr; NUM_MASKED_ROWS_END]]) -> Self {
        assert!(circuit.num_gates <= MINI_CIRCUIT_SIZE);
        let mut p = TranslatorPolys::zero();
        for (w, wire) in circuit.wires.iter().enumerate() {
            let start = if w == 0 { 0 } else { 1 };
            for i in start..circuit.num_gates {
                p.cols[FIRST_WIRE + w].coeffs[i] = wire[i];
            }
            if w >= NUM_OP_QUEUE_WIRES {
                for k in 0..NUM_MASKED_ROWS_END {
                    p.cols[FIRST_WIRE + w].coeffs[MINI_CIRCUIT_SIZE - NUM_MASKED_ROWS_END + k] =
                        masking[w - NUM_OP_QUEUE_WIRES][k];
                }
            }
        }
        crate::base::timing::phase("    translator: wires");
        p.compute_lagrange_polynomials();
        p.compute_extra_range_constraint_numerator();
        p.compute_concatenated_polynomials();
        crate::base::timing::phase("    translator: lagrange + concatenated");
        p.compute_ordered_range_constraint_polynomials();
        crate::base::timing::phase("    translator: ordered");
        p
    }

    fn set(&mut self, e: Ent, i: usize, v: Fr) {
        self.cols[e as usize].coeffs[i] = v;
    }

    fn compute_lagrange_polynomials(&mut self) {
        let one = Fr::one();
        let n = CIRCUIT_SIZE;
        let mini = MINI_CIRCUIT_SIZE;
        let mini_without_masking = mini - NUM_MASKED_ROWS_END;
        self.set(Ent::lagrange_first, 0, one);
        self.set(Ent::lagrange_real_last, n - MAX_RANDOM_VALUES_PER_ORDERED - 1, one);
        self.set(Ent::lagrange_last, n - 1, one);
        for j in 0..CONCATENATION_GROUP_SIZE {
            for k in mini_without_masking..mini {
                self.set(Ent::lagrange_masking, j * mini + k, one);
            }
        }
        for i in n - MAX_RANDOM_VALUES_PER_ORDERED..n {
            self.set(Ent::lagrange_ordered_masking, i, one);
        }
        for i in RANDOMNESS_START..RESULT_ROW {
            self.set(Ent::lagrange_mini_masking, i, one);
        }
        for i in mini_without_masking..mini {
            self.set(Ent::lagrange_mini_masking, i, one);
        }
        for i in (RESULT_ROW..mini_without_masking).step_by(2) {
            self.set(Ent::lagrange_even_in_minicircuit, i, one);
            self.set(Ent::lagrange_odd_in_minicircuit, i + 1, one);
        }
        self.set(Ent::lagrange_result_row, RESULT_ROW, one);
        self.set(Ent::lagrange_last_in_minicircuit, mini_without_masking - 1, one);
    }

    fn compute_extra_range_constraint_numerator(&mut self) {
        let steps = sorted_steps();
        for shift in 0..NUM_CONCATENATED_POLYS {
            for (i, s) in steps.iter().enumerate() {
                self.set(
                    Ent::ordered_extra_range_constraints_numerator,
                    shift + i * NUM_CONCATENATED_POLYS,
                    Fr::from(*s),
                );
            }
        }
    }

    fn compute_concatenated_polynomials(&mut self) {
        for g in 0..NUM_CONCATENATED_POLYS {
            for (j, wire) in concatenation_group_wires(g).into_iter().enumerate() {
                let Some(w) = wire else { continue };
                for k in 1..MINI_CIRCUIT_SIZE {
                    let v = self.cols[FIRST_WIRE + w].coeffs[k];
                    self.cols[FIRST_CONCATENATED + g].coeffs[j * MINI_CIRCUIT_SIZE + k] = v;
                }
            }
        }
    }

    /// bb `compute_translator_range_constraint_ordered_polynomials` + `split_concatenated_random_coefficients_to_ordered`.
    fn compute_ordered_range_constraint_polynomials(&mut self) {
        let n = CIRCUIT_SIZE;
        let steps = sorted_steps();
        let size_without_masking = n - NUM_MASKED_ROWS_END * CONCATENATION_GROUP_SIZE;
        let free_space_before_runway = size_without_masking - steps.len();
        let values_per_lane = MINI_CIRCUIT_SIZE - 1 - NUM_MASKED_ROWS_END;
        let low = |v: &Fr| u256(v).0[0] as u32;
        let mut extra_denominator = vec![0u32; size_without_masking];
        for g in 0..NUM_CONCATENATED_POLYS - 1 {
            let mut ordered = vec![0u32; size_without_masking];
            let mut extra_offset = g * steps.len();
            for (j, wire) in concatenation_group_wires(g).into_iter().enumerate() {
                let w = wire.unwrap();
                for k in 1..MINI_CIRCUIT_SIZE - NUM_MASKED_ROWS_END {
                    let idx = j * values_per_lane + (k - 1);
                    let v = low(&self.cols[FIRST_WIRE + w].coeffs[k]);
                    if idx < free_space_before_runway {
                        ordered[idx] = v;
                    } else {
                        extra_denominator[extra_offset] = v;
                        extra_offset += 1;
                    }
                }
            }
            assert!(extra_offset <= (g + 1) * steps.len());
            for (i, s) in steps.iter().enumerate() {
                ordered[free_space_before_runway + i] = *s as u32;
            }
            ordered.sort_unstable();
            let col = &mut self.cols[FIRST_ORDERED + g].coeffs[1..n - MAX_RANDOM_VALUES_PER_ORDERED];
            for (c, v) in col.iter_mut().zip(ascending_to_fr(ordered[1..].iter().map(|v| *v as u64))) {
                *c = v;
            }
        }
        for (i, s) in steps.iter().enumerate() {
            extra_denominator[(NUM_CONCATENATED_POLYS - 1) * steps.len() + i] = *s as u32;
        }
        extra_denominator.sort_unstable();
        let col = &mut self.cols[FIRST_ORDERED + 4].coeffs[1..n - MAX_RANDOM_VALUES_PER_ORDERED];
        for (c, v) in col.iter_mut().zip(ascending_to_fr(extra_denominator[1..].iter().map(|v| *v as u64))) {
            *c = v;
        }
        // The masking values of the four range-constraint concatenations move to the tails of the
        // ordered columns so that the permutation still holds.
        let per_concat = NUM_MASKED_ROWS_END * CONCATENATION_GROUP_SIZE;
        let total = per_concat * (NUM_CONCATENATED_POLYS - 1);
        let per_ordered = total / NUM_ORDERED;
        let remaining = total % NUM_ORDERED;
        let mut random_values = Vec::with_capacity(total);
        for g in 0..NUM_CONCATENATED_POLYS - 1 {
            for j in 0..CONCATENATION_GROUP_SIZE {
                let start = j * MINI_CIRCUIT_SIZE + (MINI_CIRCUIT_SIZE - NUM_MASKED_ROWS_END);
                for k in 0..NUM_MASKED_ROWS_END {
                    random_values.push(self.cols[FIRST_CONCATENATED + g].coeffs[start + k]);
                }
            }
        }
        for i in 0..NUM_ORDERED {
            let count = per_ordered + usize::from(i < remaining);
            let mut idx = i * per_ordered + i.min(remaining);
            for k in 0..count {
                self.cols[FIRST_ORDERED + i].coeffs[n - count + k] = random_values[idx];
                idx += 1;
            }
        }
    }
}
