//! The Goblin ECC op queue (bb `op_queue/ecc_op_queue.hpp`, `ecc_ops_table.hpp`): every EC
//! operation a Mega circuit defers is recorded twice, natively for the ECCVM and as two width-4
//! rows (`op | x_lo | x_hi | y_lo` / `0 | y_hi | z1 | z2`) for the Mega circuit and Translator.
//! The native accumulator shadows the operations so that `eq_and_reset` knows the expected result.

use crate::base::field::{from_u256, u256, u256_low_bits, u256_num_bits, u256_shr, FieldLike, U256};
use crate::base::{Fq, Fr, G1Affine, Rng};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use std::sync::OnceLock;

/// Bits per coordinate limb pair (`2 * NUM_LIMB_BITS_IN_FIELD_SIMULATION`).
const CHUNK_BITS: u32 = 136;

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct EccOpCode {
    pub add: bool,
    pub mul: bool,
    pub eq: bool,
    pub reset: bool,
    pub is_random_op: bool,
    pub random_value_1: Fr,
    pub random_value_2: Fr,
}

impl EccOpCode {
    pub fn add() -> Self {
        Self { add: true, ..Default::default() }
    }
    pub fn mul() -> Self {
        Self { mul: true, ..Default::default() }
    }
    pub fn eq_reset() -> Self {
        Self { eq: true, reset: true, ..Default::default() }
    }
    /// `add*8 + mul*4 + eq*2 + reset`
    pub fn value(&self) -> u32 {
        assert!(!self.is_random_op, "random ops have no op code value");
        (self.add as u32) << 3 | (self.mul as u32) << 2 | (self.eq as u32) << 1 | self.reset as u32
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct UltraOp {
    pub op_code: EccOpCode,
    pub x_lo: Fr,
    pub x_hi: Fr,
    pub y_lo: Fr,
    pub y_hi: Fr,
    pub z_1: Fr,
    pub z_2: Fr,
    pub return_is_infinity: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct EccvmOp {
    pub op_code: EccOpCode,
    pub base_point: G1Affine,
    pub z1: U256,
    pub z2: U256,
    pub mul_scalar_full: Fr,
}

/// A table that grows by whole subtables, one per circuit (bb `EccOpsTable`).
#[derive(Clone, Debug)]
pub struct SubTables<T> {
    pub tables: Vec<Vec<T>>,
    pub current: Vec<T>,
}

impl<T> Default for SubTables<T> {
    fn default() -> Self {
        Self { tables: vec![], current: vec![] }
    }
}

impl<T> SubTables<T> {
    pub fn merge(&mut self) {
        self.tables.push(std::mem::take(&mut self.current));
    }
    pub fn num_ops(&self) -> usize {
        self.tables.iter().map(Vec::len).sum()
    }
}

pub struct EccOpQueue {
    accumulator: ark_bn254::G1Projective,
    pub eccvm_ops: SubTables<EccvmOp>,
    pub ultra_ops: SubTables<UltraOp>,
    /// The ZK prefix of the merged Ultra table (built once, at the end of an IVC).
    pub zk_ops: Vec<UltraOp>,
    pub fixed_append_offset: Option<usize>,
    pub hiding_op: Option<EccvmOp>,
}

impl Default for EccOpQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl EccOpQueue {
    pub fn new() -> Self {
        Self {
            accumulator: ark_bn254::G1Projective::default(),
            eccvm_ops: Default::default(),
            ultra_ops: Default::default(),
            zk_ops: vec![],
            fixed_append_offset: None,
            hiding_op: None,
        }
    }
    /// Called by every new circuit; the previous circuit's subtable must have been merged.
    pub fn initialize_new_subtable(&mut self) {
        assert!(self.ultra_ops.current.is_empty() && self.eccvm_ops.current.is_empty(), "previous subtable not merged");
    }
    pub fn num_subtables(&self) -> usize {
        self.ultra_ops.tables.len()
    }
    pub fn current_subtable_size(&self) -> usize {
        self.ultra_ops.current.len()
    }
    pub fn merge(&mut self) {
        assert!(self.fixed_append_offset.is_none(), "cannot merge after the fixed-location append");
        self.eccvm_ops.merge();
        self.ultra_ops.merge();
    }
    pub fn get_accumulator(&self) -> G1Affine {
        self.accumulator.into_affine()
    }

    pub fn add_accumulate(&mut self, point: G1Affine) -> UltraOp {
        self.accumulator += point;
        self.eccvm_ops.current.push(EccvmOp { op_code: EccOpCode::add(), base_point: point, z1: U256::zero(), z2: U256::zero(), mul_scalar_full: Fr::zero() });
        self.construct_and_populate_ultra_op(EccOpCode::add(), point, Fr::zero())
    }
    pub fn mul_accumulate(&mut self, point: G1Affine, scalar: Fr) -> UltraOp {
        self.accumulator += point * scalar;
        let op = self.construct_and_populate_ultra_op(EccOpCode::mul(), point, scalar);
        self.eccvm_ops.current.push(EccvmOp { op_code: EccOpCode::mul(), base_point: point, z1: u256(&op.z_1), z2: u256(&op.z_2), mul_scalar_full: scalar });
        op
    }
    pub fn eq_and_reset(&mut self) -> UltraOp {
        let expected = self.get_accumulator();
        self.accumulator = ark_bn254::G1Projective::default();
        self.eccvm_ops.current.push(EccvmOp { op_code: EccOpCode::eq_reset(), base_point: expected, z1: U256::zero(), z2: U256::zero(), mul_scalar_full: Fr::zero() });
        self.construct_and_populate_ultra_op(EccOpCode::eq_reset(), expected, Fr::zero())
    }
    /// Two zero rows in the Ultra table only (the Translator needs shiftable columns).
    pub fn no_op_ultra_only(&mut self) -> UltraOp {
        let op = UltraOp::default();
        self.ultra_ops.current.push(op.clone());
        op
    }
    /// Eight random values in the Ultra table only; masks the merged columns.
    pub fn random_op_ultra_only(&mut self, rng: &mut dyn Rng) -> UltraOp {
        let op = UltraOp {
            op_code: EccOpCode { is_random_op: true, random_value_1: rng.fr(), random_value_2: rng.fr(), ..Default::default() },
            x_lo: rng.fr(),
            x_hi: rng.fr(),
            y_lo: rng.fr(),
            y_hi: rng.fr(),
            z_1: rng.fr(),
            z_2: rng.fr(),
            return_is_infinity: false,
        };
        self.ultra_ops.current.push(op.clone());
        op
    }
    /// A hiding op with (possibly off-curve) coordinates; opcode eq+reset, no accumulator change.
    pub fn append_hiding_op(&mut self, px: Fq, py: Fq) -> UltraOp {
        let (ultra_op, eccvm_op) = Self::make_hiding_op_pair(px, py);
        self.hiding_op = Some(eccvm_op);
        self.ultra_ops.current.push(ultra_op.clone());
        ultra_op
    }
    pub fn make_hiding_op_pair(px: Fq, py: Fq) -> (UltraOp, EccvmOp) {
        let (x_lo, x_hi) = split_coordinate(&px);
        let (y_lo, y_hi) = split_coordinate(&py);
        let ultra = UltraOp { op_code: EccOpCode::eq_reset(), x_lo, x_hi, y_lo, y_hi, z_1: Fr::zero(), z_2: Fr::zero(), return_is_infinity: false };
        let eccvm = EccvmOp { op_code: EccOpCode::eq_reset(), base_point: G1Affine::new_unchecked(px, py), z1: U256::zero(), z2: U256::zero(), mul_scalar_full: Fr::zero() };
        (ultra, eccvm)
    }

    fn construct_and_populate_ultra_op(&mut self, op_code: EccOpCode, point: G1Affine, scalar: Fr) -> UltraOp {
        let return_is_infinity = point.is_zero();
        let (x, y) = if return_is_infinity { (Fq::zero(), Fq::zero()) } else { (point.x, point.y) };
        let (x_lo, x_hi) = split_coordinate(&x);
        let (y_lo, y_hi) = split_coordinate(&y);
        let k = u256(&scalar);
        let (z_1, z_2) = if u256_num_bits(&k) <= 128 {
            (scalar, Fr::zero())
        } else {
            let (k1, k2) = split_into_endomorphism_scalars(k);
            (from_u256(k1), from_u256(k2))
        };
        let op = UltraOp { op_code, x_lo, x_hi, y_lo, y_hi, z_1, z_2, return_is_infinity };
        self.ultra_ops.current.push(op.clone());
        op
    }
}

/// A base-field coordinate as two scalar-field limbs split at bit 136.
fn split_coordinate(c: &Fq) -> (Fr, Fr) {
    let v = u256(c);
    (from_u256(u256_low_bits(v, CHUNK_BITS)), from_u256(u256_shr(v, CHUNK_BITS)))
}

fn mul_wide(a: &[u64; 4], b: &[u64; 4]) -> [u64; 8] {
    let mut r = [0u64; 8];
    for i in 0..4 {
        let mut carry = 0u128;
        for j in 0..4 {
            let t = a[i] as u128 * b[j] as u128 + r[i + j] as u128 + carry;
            r[i + j] = t as u64;
            carry = t >> 64;
        }
        r[i + 4] = carry as u64;
    }
    r
}

fn fr_from_limbs(l: [u64; 4]) -> Fr {
    let mut bytes = [0u8; 32];
    for (i, limb) in l.iter().enumerate() {
        bytes[i * 8..i * 8 + 8].copy_from_slice(&limb.to_le_bytes());
    }
    Fr::from_le_bytes_mod_order(&bytes)
}

/// The cube root of unity `β` used by bb's GLV decomposition (bb stores it in Montgomery form).
fn cube_root_of_unity() -> Fr {
    static B: OnceLock<Fr> = OnceLock::new();
    *B.get_or_init(|| {
        let mont = fr_from_limbs([0x93e7cede4a0329b3, 0x7d4fdca77a96c167, 0x8be4ba08b19a750a, 0x1cbd5653a5661c25]);
        let r = Fr::from(2u64).pow_u64(256);
        mont * r.invert()
    })
}

/// bb `field::split_into_endomorphism_scalars`: `k = k1 - k2·λ` with both parts below 2^128.
fn split_into_endomorphism_scalars(k: U256) -> (U256, U256) {
    const G1: [u64; 4] = [0x7a7bd9d4391eb18d, 0x4ccef014a773d2cf, 2, 0];
    const G2: [u64; 4] = [0xd91d232ec7e0b3d7, 2, 0, 0];
    const MINUS_B1: [u64; 4] = [0x8211bbeb7d4f1128, 0x6f4d8248eeb859fc, 0, 0];
    const B2: [u64; 4] = [0x89d3256894d213e3, 0, 0, 0];
    let kl = k.0;
    if kl[2] == 0 && kl[3] == 0 && kl[1] >> 63 == 0 {
        return (k, U256::zero());
    }
    let hi = |p: [u64; 8]| [p[4], p[5], p[6], p[7]];
    let lo = |p: [u64; 8]| [p[0], p[1], p[2], p[3]];
    let c1_hi = hi(mul_wide(&G2, &kl));
    let c2_hi = hi(mul_wide(&G1, &kl));
    let q1 = lo(mul_wide(&c1_hi, &MINUS_B1));
    let q2 = lo(mul_wide(&c2_hi, &B2));
    let mut t1 = fr_from_limbs(q2) - fr_from_limbs(q1);
    if u256(&t1).0[2] != 0 || u256(&t1).0[3] != 0 {
        t1 += fr_from_limbs(MINUS_B1);
    }
    let t2 = t1 * cube_root_of_unity() + fr_from_limbs(kl);
    (u256_low_bits(u256(&t2), 128), u256_low_bits(u256(&t1), 128))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::Field;

    #[test]
    fn cube_root_is_a_primitive_cube_root() {
        let b = cube_root_of_unity();
        assert_ne!(b, Fr::one());
        assert_eq!(b * b * b, Fr::one());
    }

    /// `k == k1 - k2·λ` where `λ` is the scalar acting as `x ↦ βx` on the curve.
    #[test]
    fn endomorphism_split_reconstructs_scalar() {
        let beta = cube_root_of_unity();
        let k = Fr::from(7u64).pow_u64(1000);
        let (k1, k2) = split_into_endomorphism_scalars(u256(&k));
        let (k1, k2): (Fr, Fr) = (from_u256(k1), from_u256(k2));
        // k1 - k2·λ = k for λ = -β (bb's convention: k2 is negated); check both candidates.
        assert!(k1 - k2 * beta == k || k1 + k2 * beta == k || k1 - k2 * beta * beta == k || k1 + k2 * beta * beta == k);
        assert!(u256_num_bits(&u256(&k1)) <= 128 && u256_num_bits(&u256(&k2)) <= 128);
    }
}
