//! Byte strings as one range-constrained field element per byte, big-endian (bb
//! `stdlib/primitives/byte_array`, the subset the ECDSA path uses).

use super::field::{Ctx, FieldT};
use crate::base::field::{from_u256, u256, U256};
use crate::base::Fr;

#[derive(Clone)]
pub struct ByteArray {
    ctx: Option<Ctx>,
    values: Vec<FieldT>,
}

impl ByteArray {
    /// Witness bytes, each range-constrained to 8 bits.
    pub fn from_bytes(ctx: &Ctx, bytes: &[u8]) -> Self {
        let values = bytes
            .iter()
            .map(|b| {
                let value = FieldT::from_witness(ctx, Fr::from(*b as u64));
                value.create_range_constraint(8);
                value
            })
            .collect();
        Self {
            ctx: Some(ctx.clone()),
            values,
        }
    }
    pub fn empty(ctx: &Ctx) -> Self {
        Self {
            ctx: Some(ctx.clone()),
            values: vec![],
        }
    }
    /// bb `byte_array(field_t, num_bytes)`: the big-endian byte decomposition of `input`, each byte
    /// range-constrained and the reconstruction asserted equal to the input. bb's extra uniqueness
    /// constraints for 32-byte decompositions are not ported (nothing on the pinned flows needs them).
    pub fn from_field(input: &FieldT, num_bytes: usize) -> Self {
        assert!(
            num_bytes < 32,
            "32-byte decompositions need bb's uniqueness constraints"
        );
        const MIDPOINT: usize = 16;
        let value = u256(&input.get_value());
        let mut values = Vec::with_capacity(num_bytes);
        let mut accumulator_lo = vec![];
        let mut accumulator_hi = vec![];
        for i in 0..num_bytes {
            let bit_start = ((num_bytes - i - 1) * 8) as u32;
            let scaling_factor = FieldT::constant(from_u256(U256::from(1u64) << bit_start));
            let byte_val = Fr::from(((value >> bit_start) & U256::from(0xffu64)).0[0]);
            let byte = if input.is_constant() {
                FieldT::constant(byte_val)
            } else {
                FieldT::from_witness(input.ctx.as_ref().unwrap(), byte_val)
            };
            byte.create_range_constraint(8);
            values.push(byte.clone());
            if i < MIDPOINT {
                accumulator_hi.push(scaling_factor.mul(&byte));
            } else {
                accumulator_lo.push(scaling_factor.mul(&byte));
            }
        }
        let reconstructed_lo = FieldT::accumulate(&accumulator_lo);
        let reconstructed_hi = FieldT::accumulate(&accumulator_hi);
        let reconstructed = reconstructed_hi.add(&reconstructed_lo);
        input.assert_equal(&reconstructed);
        Self {
            ctx: input.ctx.clone(),
            values,
        }
    }
    /// bb `byte_array::constant_padding`: constant bytes, no witnesses or constraints.
    pub fn constant_padding(num_bytes: usize, value: u8) -> Self {
        Self {
            ctx: None,
            values: vec![FieldT::constant(Fr::from(value as u64)); num_bytes],
        }
    }
    pub fn reverse(&self) -> Self {
        Self {
            ctx: self.ctx.clone(),
            values: self.values.iter().rev().cloned().collect(),
        }
    }
    /// bb `byte_array::write_at`: overwrite bytes starting at `offset` (growing if needed).
    pub fn write_at(&mut self, other: &ByteArray, offset: usize) {
        if self.ctx.is_none() {
            self.ctx = other.ctx.clone();
        }
        for (i, v) in other.values.iter().enumerate() {
            if offset + i < self.values.len() {
                self.values[offset + i] = v.clone();
            } else {
                self.values.push(v.clone());
            }
        }
    }
    pub fn slice_from(&self, offset: usize) -> Self {
        self.slice(offset, self.values.len() - offset)
    }
    pub fn write(&mut self, other: &ByteArray) {
        if self.ctx.is_none() {
            self.ctx = other.ctx.clone();
        }
        self.values.extend(other.values.iter().cloned());
    }
    pub fn slice(&self, offset: usize, length: usize) -> Self {
        Self {
            ctx: self.ctx.clone(),
            values: self.values[offset..offset + length].to_vec(),
        }
    }
    /// bb `operator field_t`: the bytes as one big-endian integer.
    pub fn to_field(&self) -> FieldT {
        let n = self.values.len();
        let scaled: Vec<FieldT> = self
            .values
            .iter()
            .enumerate()
            .map(|(i, v)| {
                v.mul(&FieldT::constant(from_u256(
                    U256::from(1u64) << (8 * (n - i - 1)) as u32,
                )))
            })
            .collect();
        FieldT::accumulate(&scaled)
    }
    pub fn bytes(&self) -> &[FieldT] {
        &self.values
    }
    pub fn len(&self) -> usize {
        self.values.len()
    }
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
    pub fn ctx(&self) -> Option<Ctx> {
        self.ctx.clone()
    }
    pub fn get_value(&self) -> Vec<u8> {
        self.values.iter().map(|v| u256(&v.get_value()).0[0] as u8).collect()
    }
}
