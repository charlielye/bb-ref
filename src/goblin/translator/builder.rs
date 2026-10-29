//! The Translator circuit builder (bb `translator_circuit_builder.cpp`): two rows per op holding the
//! op, its coordinates and scalars, their 68-bit limbs, the accumulator before and after the step,
//! the quotient of the non-native reduction, and 14-bit micro-limbs of everything range-constrained.

use super::*;
use crate::base::field::{from_u256, u256, u256_low_bits, u256_shr, FieldLike, U256};
use crate::base::Fq;
use crate::circuit::op_queue::{EccOpQueue, UltraOp};
use ark_ff::{BigInteger, PrimeField};

/// Wire indices (bb `WireIds`).
pub const OP: usize = 0;
pub const X_LOW_Y_HI: usize = 1;
pub const X_HIGH_Z_1: usize = 2;
pub const Y_LOW_Z_2: usize = 3;
pub const P_X_LOW_LIMBS: usize = 4;
pub const P_X_HIGH_LIMBS: usize = 5;
pub const P_Y_LOW_LIMBS: usize = 6;
pub const P_Y_HIGH_LIMBS: usize = 7;
pub const Z_LOW_LIMBS: usize = 8;
pub const Z_HIGH_LIMBS: usize = 9;
pub const ACCUMULATORS_BINARY_LIMBS_0: usize = 10;
pub const QUOTIENT_LOW_BINARY_LIMBS: usize = 14;
pub const QUOTIENT_HIGH_BINARY_LIMBS: usize = 15;
pub const RELATION_WIDE_LIMBS: usize = 16;
pub const P_X_LOW_LIMBS_RANGE_CONSTRAINT_0: usize = 17;
pub const P_X_HIGH_LIMBS_RANGE_CONSTRAINT_0: usize = 23;
pub const P_Y_LOW_LIMBS_RANGE_CONSTRAINT_0: usize = 29;
pub const P_Y_HIGH_LIMBS_RANGE_CONSTRAINT_0: usize = 35;
pub const Z_LOW_LIMBS_RANGE_CONSTRAINT_0: usize = 41;
pub const Z_HIGH_LIMBS_RANGE_CONSTRAINT_0: usize = 47;
pub const ACCUMULATOR_LOW_LIMBS_RANGE_CONSTRAINT_0: usize = 53;
pub const ACCUMULATOR_HIGH_LIMBS_RANGE_CONSTRAINT_0: usize = 59;
pub const QUOTIENT_LOW_LIMBS_RANGE_CONSTRAINT_0: usize = 65;
pub const QUOTIENT_HIGH_LIMBS_RANGE_CONSTRAINT_0: usize = 71;
pub const RELATION_WIDE_LIMBS_RANGE_CONSTRAINT_0: usize = 77;

pub struct TranslatorCircuit {
    /// `wires[w][row]`, values rather than variable indices (the Translator has no copy constraints).
    pub wires: Vec<Vec<Fr>>,
    pub num_gates: usize,
    pub batching_challenge_v: Fq,
    pub evaluation_input_x: Fq,
}

fn slice(v: &U256, lo: u32, hi: u32) -> Fr {
    from_u256(u256_low_bits(u256_shr(*v, lo), hi - lo))
}

/// Four 68-bit limbs of a bn254 base field element, as scalar field elements.
pub fn split_fq_into_limbs(base: &Fq) -> [Fr; NUM_BINARY_LIMBS] {
    let u = u256(base);
    std::array::from_fn(|i| slice(&u, NUM_LIMB_BITS * i as u32, NUM_LIMB_BITS * (i as u32 + 1)))
}

fn split_wide_limb_into_2_limbs(wide: &Fr) -> [Fr; NUM_Z_LIMBS] {
    let u = u256(wide);
    [slice(&u, 0, NUM_LIMB_BITS), slice(&u, NUM_LIMB_BITS, 2 * NUM_LIMB_BITS)]
}

/// bb `split_limb_into_microlimbs`: 14-bit chunks; a partial last chunk is repeated shifted up so
/// that its range check is strict.
fn split_limb_into_microlimbs(limb: &Fr, num_bits: u32) -> [Fr; NUM_MICRO_LIMBS] {
    let u = u256(limb);
    let full = (num_bits / MICRO_LIMB_BITS) as usize;
    let last_bits = num_bits % MICRO_LIMB_BITS;
    let mut micro = [Fr::from(0u64); NUM_MICRO_LIMBS];
    for (i, m) in micro.iter_mut().enumerate().take(full) {
        *m = slice(&u, MICRO_LIMB_BITS * i as u32, MICRO_LIMB_BITS * (i as u32 + 1));
    }
    if last_bits > 0 {
        micro[full] = slice(&u, MICRO_LIMB_BITS * full as u32, MICRO_LIMB_BITS * (full as u32 + 1));
        micro[full + 1] = from_u256(u256(&micro[full]) << (MICRO_LIMB_BITS - last_bits));
    }
    micro
}

/// The bn254 base field modulus as an integer.
fn fq_modulus() -> U256 {
    Fq::MODULUS
}

/// `2^272 - q` in 68-bit limbs, and `-q` in the scalar field (bb `NEGATIVE_MODULUS_LIMBS`).
pub fn negative_modulus_limbs() -> [Fr; 5] {
    static L: std::sync::LazyLock<[Fr; 5]> = std::sync::LazyLock::new(|| {
        let h = |s: &str| crate::base::field::from_hex::<Fr>(s);
        [
            h("0x2c3df73e9278302b9"),
            h("0xa2687e956e978e357"),
            h("0xfd647afba497e7ea7"),
            h("0xffffcf9bb18d1ece5"),
            -Fr::from_le_bytes_mod_order(&fq_modulus().to_bytes_le()),
        ]
    });
    *L
}

fn mul_wrapping(a: &U256, b: &U256) -> U256 {
    let mut out = [0u64; 4];
    for i in 0..4 {
        let mut carry = 0u128;
        for j in 0..4 - i {
            let t = out[i + j] as u128 + (a.0[i] as u128) * (b.0[j] as u128) + carry;
            out[i + j] = t as u64;
            carry = t >> 64;
        }
    }
    U256::new(out)
}

fn add_wrapping(a: &U256, b: &U256) -> U256 {
    let mut r = *a;
    r.add_with_carry(b);
    r
}

fn sub_wrapping(a: &U256, b: &U256) -> U256 {
    let mut r = *a;
    r.sub_with_borrow(b);
    r
}

/// `q^{-1} mod 2^256` by Newton iteration.
fn modulus_inverse_2_256() -> U256 {
    let q = fq_modulus();
    let two = U256::from(2u64);
    let mut x = U256::from(1u64);
    for _ in 0..8 {
        let qx = mul_wrapping(&q, &x);
        x = mul_wrapping(&x, &sub_wrapping(&two, &qx));
    }
    x
}

/// The base point of an op as coordinates (infinity as `(0, 0)`).
pub fn base_point_standard_form(op: &UltraOp) -> (Fq, Fq) {
    if op.return_is_infinity {
        return (Fq::from(0u64), Fq::from(0u64));
    }
    let join = |lo: &Fr, hi: &Fr| from_u256::<Fq>(add_wrapping(&(u256(hi) << (2 * NUM_LIMB_BITS)), &u256(lo)));
    (join(&op.x_lo, &op.x_hi), join(&op.y_lo, &op.y_hi))
}

/// One accumulation step's witness (bb `AccumulationInput`).
pub struct AccumulationInput {
    pub p_x_limbs: [Fr; 4],
    pub p_x_microlimbs: [[Fr; 6]; 4],
    pub p_y_limbs: [Fr; 4],
    pub p_y_microlimbs: [[Fr; 6]; 4],
    pub z_1_limbs: [Fr; 2],
    pub z_1_microlimbs: [[Fr; 6]; 2],
    pub z_2_limbs: [Fr; 2],
    pub z_2_microlimbs: [[Fr; 6]; 2],
    pub previous_accumulator: [Fr; 4],
    pub current_accumulator: [Fr; 4],
    pub current_accumulator_microlimbs: [[Fr; 6]; 4],
    pub quotient_binary_limbs: [Fr; 4],
    pub quotient_microlimbs: [[Fr; 6]; 4],
    pub relation_wide_limbs: [Fr; 2],
    pub relation_wide_microlimbs: [[Fr; 6]; 2],
}

/// bb `generate_witness_values`.
pub fn generate_witness_values(op: &UltraOp, previous_accumulator: &Fq, v: &Fq, x: &Fq) -> AccumulationInput {
    let v_squared = *v * v;
    let v_cubed = v_squared * v;
    let v_quarted = v_cubed * v;
    let previous_accumulator_limbs = split_fq_into_limbs(previous_accumulator);
    let v_witnesses = split_fq_into_limbs(v);
    let v_squared_witnesses = split_fq_into_limbs(&v_squared);
    let v_cubed_witnesses = split_fq_into_limbs(&v_cubed);
    let v_quarted_witnesses = split_fq_into_limbs(&v_quarted);
    let x_witnesses = split_fq_into_limbs(x);
    let op_code = op.op_code.value() as u64;
    let (base_p_x, base_p_y) = base_point_standard_form(op);
    let base_z_1: Fq = from_u256(u256(&op.z_1));
    let base_z_2: Fq = from_u256(u256(&op.z_2));
    let p_x_limbs = split_fq_into_limbs(&base_p_x);
    let p_y_limbs = split_fq_into_limbs(&base_p_y);
    let z_1_limbs = split_wide_limb_into_2_limbs(&op.z_1);
    let z_2_limbs = split_wide_limb_into_2_limbs(&op.z_2);

    let remainder = *previous_accumulator * x
        + Fq::from(op_code)
        + base_p_x * v
        + base_p_y * v_squared
        + base_z_1 * v_cubed
        + base_z_2 * v_quarted;
    // The integer relation X - r = quotient · q with quotient < 2^256, solved modulo 2^256.
    let mut integer = mul_wrapping(&u256(previous_accumulator), &u256(x));
    integer = add_wrapping(&integer, &U256::from(op_code));
    for (a, b) in [
        (&base_p_x, v),
        (&base_p_y, &v_squared),
        (&base_z_1, &v_cubed),
        (&base_z_2, &v_quarted),
    ] {
        integer = add_wrapping(&integer, &mul_wrapping(&u256(a), &u256(b)));
    }
    integer = sub_wrapping(&integer, &u256(&remainder));
    let quotient = mul_wrapping(&integer, &modulus_inverse_2_256());
    let remainder_limbs = split_fq_into_limbs(&remainder);
    let quotient_limbs: [Fr; 4] =
        std::array::from_fn(|i| slice(&quotient, NUM_LIMB_BITS * i as u32, NUM_LIMB_BITS * (i as u32 + 1)));
    let neg_mod = negative_modulus_limbs();
    static SHIFTS: std::sync::LazyLock<(Fr, Fr)> = std::sync::LazyLock::new(|| {
        let shift_1 = Fr::from(2u64).pow_u64(NUM_LIMB_BITS as u64);
        (shift_1, (shift_1 * shift_1).invert())
    });
    let (shift_1, shift_2_inverse) = *SHIFTS;
    let pa = &previous_accumulator_limbs;
    let (xw, vw, v2, v3, v4) = (
        &x_witnesses,
        &v_witnesses,
        &v_squared_witnesses,
        &v_cubed_witnesses,
        &v_quarted_witnesses,
    );
    let (px, py, z1, z2, qt, rm) = (
        &p_x_limbs,
        &p_y_limbs,
        &z_1_limbs,
        &z_2_limbs,
        &quotient_limbs,
        &remainder_limbs,
    );

    let low_part_1 = pa[0] * xw[0]
        + Fr::from(op_code)
        + px[0] * vw[0]
        + py[0] * v2[0]
        + z1[0] * v3[0]
        + z2[0] * v4[0]
        + qt[0] * neg_mod[0]
        - rm[0];
    let low_wide = low_part_1
        + (pa[1] * xw[0]
            + pa[0] * xw[1]
            + px[0] * vw[1]
            + px[1] * vw[0]
            + py[0] * v2[1]
            + py[1] * v2[0]
            + z1[0] * v3[1]
            + z1[1] * v3[0]
            + z2[0] * v4[1]
            + z2[1] * v4[0]
            + qt[0] * neg_mod[1]
            + qt[1] * neg_mod[0]
            - rm[1])
            * shift_1;
    let low_wide_divided = low_wide * shift_2_inverse;
    let high_part_1 = low_wide_divided
        + pa[2] * xw[0]
        + pa[1] * xw[1]
        + pa[0] * xw[2]
        + px[0] * vw[2]
        + px[1] * vw[1]
        + px[2] * vw[0]
        + py[0] * v2[2]
        + py[1] * v2[1]
        + py[2] * v2[0]
        + z1[0] * v3[2]
        + z1[1] * v3[1]
        + z2[0] * v4[2]
        + z2[1] * v4[1]
        + qt[2] * neg_mod[0]
        + qt[1] * neg_mod[1]
        + qt[0] * neg_mod[2]
        - rm[2];
    let high_wide = high_part_1
        + (pa[3] * xw[0]
            + pa[2] * xw[1]
            + pa[1] * xw[2]
            + pa[0] * xw[3]
            + px[0] * vw[3]
            + px[1] * vw[2]
            + px[2] * vw[1]
            + px[3] * vw[0]
            + py[0] * v2[3]
            + py[1] * v2[2]
            + py[2] * v2[1]
            + py[3] * v2[0]
            + z1[0] * v3[3]
            + z1[1] * v3[2]
            + z2[0] * v4[3]
            + z2[1] * v4[2]
            + qt[3] * neg_mod[0]
            + qt[2] * neg_mod[1]
            + qt[1] * neg_mod[2]
            + qt[0] * neg_mod[3]
            - rm[3])
            * shift_1;
    let high_wide_divided = high_wide * shift_2_inverse;

    let micro4 = |limbs: &[Fr; 4], last_bits: u32| -> [[Fr; 6]; 4] {
        std::array::from_fn(|i| split_limb_into_microlimbs(&limbs[i], if i == 3 { last_bits } else { NUM_LIMB_BITS }))
    };
    let micro2 = |limbs: &[Fr; 2]| -> [[Fr; 6]; 2] {
        [
            split_limb_into_microlimbs(&limbs[0], NUM_LIMB_BITS),
            split_limb_into_microlimbs(&limbs[1], NUM_Z_BITS - NUM_LIMB_BITS),
        ]
    };
    AccumulationInput {
        p_x_limbs,
        p_x_microlimbs: micro4(&p_x_limbs, NUM_LAST_LIMB_BITS),
        p_y_limbs,
        p_y_microlimbs: micro4(&p_y_limbs, NUM_LAST_LIMB_BITS),
        z_1_limbs,
        z_1_microlimbs: micro2(&z_1_limbs),
        z_2_limbs,
        z_2_microlimbs: micro2(&z_2_limbs),
        previous_accumulator: previous_accumulator_limbs,
        current_accumulator: remainder_limbs,
        current_accumulator_microlimbs: micro4(&remainder_limbs, NUM_LAST_LIMB_BITS),
        quotient_binary_limbs: quotient_limbs,
        quotient_microlimbs: micro4(&quotient_limbs, NUM_LAST_QUOTIENT_LIMB_BITS),
        relation_wide_limbs: [low_wide_divided, high_wide_divided],
        relation_wide_microlimbs: [
            split_limb_into_microlimbs(&low_wide_divided, RELATION_WIDE_LIMB_BITS),
            split_limb_into_microlimbs(&high_wide_divided, RELATION_WIDE_LIMB_BITS),
        ],
    }
}

impl TranslatorCircuit {
    /// bb `TranslatorCircuitBuilder(v, x, op_queue)`: feeds the ZK-reconstructed ultra ops.
    pub fn new(batching_challenge_v: Fq, evaluation_input_x: Fq, q: &EccOpQueue) -> Self {
        Self::with_mode(batching_challenge_v, evaluation_input_x, q, false)
    }

    /// bb `TranslatorCircuitBuilder(v, x, op_queue, avm_mode)`: in AVM mode the queue carries its own
    /// leading no-op and random ops (queued by `GoblinAvm`), there is no ZK prefix and no trailing
    /// random ops.
    pub fn with_mode(batching_challenge_v: Fq, evaluation_input_x: Fq, q: &EccOpQueue, avm_mode: bool) -> Self {
        let mut c = Self {
            wires: vec![Vec::new(); NUM_WIRES],
            num_gates: 0,
            batching_challenge_v,
            evaluation_input_x,
        };
        if avm_mode {
            c.feed(&q.get_no_zk_reconstructed_ultra_ops(), 0);
        } else {
            c.feed(&q.get_zk_reconstructed_ultra_ops(), NUM_RANDOM_OPS_END);
        }
        c
    }

    fn push_pair(&mut self, wire: usize, first: Fr, second: Fr) {
        self.wires[wire].push(first);
        self.wires[wire].push(second);
    }

    fn populate_wires_from_ultra_op(&mut self, op: &UltraOp) {
        if op.op_code.is_random_op {
            self.push_pair(OP, op.op_code.random_value_1, op.op_code.random_value_2);
        } else {
            self.push_pair(OP, Fr::from(op.op_code.value() as u64), Fr::from(0u64));
        }
        self.push_pair(X_LOW_Y_HI, op.x_lo, op.y_hi);
        self.push_pair(X_HIGH_Z_1, op.x_hi, op.z_1);
        self.push_pair(Y_LOW_Z_2, op.y_lo, op.z_2);
    }

    fn lay_limbs_in_row(&mut self, values: &[Fr], starting_wire: usize) {
        for (i, v) in values.iter().enumerate() {
            self.wires[starting_wire + i].push(*v);
        }
    }

    fn process_random_op(&mut self, op: &UltraOp) {
        assert!(op.op_code.is_random_op);
        self.populate_wires_from_ultra_op(op);
        for w in P_X_LOW_LIMBS..NUM_WIRES {
            self.push_pair(w, Fr::from(0u64), Fr::from(0u64));
        }
        self.num_gates += 2;
    }

    /// bb `create_accumulation_gate`.
    fn create_accumulation_gate(&mut self, op: &UltraOp, a: &AccumulationInput) {
        self.populate_wires_from_ultra_op(op);
        self.push_pair(P_X_LOW_LIMBS, a.p_x_limbs[0], a.p_x_limbs[1]);
        self.push_pair(P_X_HIGH_LIMBS, a.p_x_limbs[2], a.p_x_limbs[3]);
        self.push_pair(P_Y_LOW_LIMBS, a.p_y_limbs[0], a.p_y_limbs[1]);
        self.push_pair(P_Y_HIGH_LIMBS, a.p_y_limbs[2], a.p_y_limbs[3]);
        self.push_pair(Z_LOW_LIMBS, a.z_1_limbs[0], a.z_2_limbs[0]);
        self.push_pair(Z_HIGH_LIMBS, a.z_1_limbs[1], a.z_2_limbs[1]);
        self.push_pair(
            QUOTIENT_LOW_BINARY_LIMBS,
            a.quotient_binary_limbs[0],
            a.quotient_binary_limbs[1],
        );
        self.push_pair(
            QUOTIENT_HIGH_BINARY_LIMBS,
            a.quotient_binary_limbs[2],
            a.quotient_binary_limbs[3],
        );
        self.push_pair(RELATION_WIDE_LIMBS, a.relation_wide_limbs[0], a.relation_wide_limbs[1]);
        let low = a.relation_wide_microlimbs[0];
        let high = a.relation_wide_microlimbs[1];
        for k in 0..4 {
            self.push_pair(RELATION_WIDE_LIMBS_RANGE_CONSTRAINT_0 + k, low[k], high[k]);
        }
        // The top limbs' spare micro-limb slots carry the relation-wide micro-limbs 4 and 5.
        let mut top_p_x = a.p_x_microlimbs[3];
        top_p_x[5] = low[4];
        let mut top_p_y = a.p_y_microlimbs[3];
        top_p_y[5] = high[4];
        let mut top_acc = a.current_accumulator_microlimbs[3];
        top_acc[5] = low[5];
        let mut top_quotient = a.quotient_microlimbs[3];
        top_quotient[5] = high[5];
        self.lay_limbs_in_row(&a.p_x_microlimbs[0], P_X_LOW_LIMBS_RANGE_CONSTRAINT_0);
        self.lay_limbs_in_row(&a.p_x_microlimbs[1], P_X_LOW_LIMBS_RANGE_CONSTRAINT_0);
        self.lay_limbs_in_row(&a.p_x_microlimbs[2], P_X_HIGH_LIMBS_RANGE_CONSTRAINT_0);
        self.lay_limbs_in_row(&top_p_x, P_X_HIGH_LIMBS_RANGE_CONSTRAINT_0);
        self.lay_limbs_in_row(&a.p_y_microlimbs[0], P_Y_LOW_LIMBS_RANGE_CONSTRAINT_0);
        self.lay_limbs_in_row(&a.p_y_microlimbs[1], P_Y_LOW_LIMBS_RANGE_CONSTRAINT_0);
        self.lay_limbs_in_row(&a.p_y_microlimbs[2], P_Y_HIGH_LIMBS_RANGE_CONSTRAINT_0);
        self.lay_limbs_in_row(&top_p_y, P_Y_HIGH_LIMBS_RANGE_CONSTRAINT_0);
        self.lay_limbs_in_row(&a.z_1_microlimbs[0], Z_LOW_LIMBS_RANGE_CONSTRAINT_0);
        self.lay_limbs_in_row(&a.z_2_microlimbs[0], Z_LOW_LIMBS_RANGE_CONSTRAINT_0);
        self.lay_limbs_in_row(&a.z_1_microlimbs[1], Z_HIGH_LIMBS_RANGE_CONSTRAINT_0);
        self.lay_limbs_in_row(&a.z_2_microlimbs[1], Z_HIGH_LIMBS_RANGE_CONSTRAINT_0);
        self.lay_limbs_in_row(&a.current_accumulator, ACCUMULATORS_BINARY_LIMBS_0);
        self.lay_limbs_in_row(&a.previous_accumulator, ACCUMULATORS_BINARY_LIMBS_0);
        self.lay_limbs_in_row(
            &a.current_accumulator_microlimbs[0],
            ACCUMULATOR_LOW_LIMBS_RANGE_CONSTRAINT_0,
        );
        self.lay_limbs_in_row(
            &a.current_accumulator_microlimbs[1],
            ACCUMULATOR_LOW_LIMBS_RANGE_CONSTRAINT_0,
        );
        self.lay_limbs_in_row(
            &a.current_accumulator_microlimbs[2],
            ACCUMULATOR_HIGH_LIMBS_RANGE_CONSTRAINT_0,
        );
        self.lay_limbs_in_row(&top_acc, ACCUMULATOR_HIGH_LIMBS_RANGE_CONSTRAINT_0);
        self.lay_limbs_in_row(&a.quotient_microlimbs[0], QUOTIENT_LOW_LIMBS_RANGE_CONSTRAINT_0);
        self.lay_limbs_in_row(&a.quotient_microlimbs[1], QUOTIENT_LOW_LIMBS_RANGE_CONSTRAINT_0);
        self.lay_limbs_in_row(&a.quotient_microlimbs[2], QUOTIENT_HIGH_LIMBS_RANGE_CONSTRAINT_0);
        self.lay_limbs_in_row(&top_quotient, QUOTIENT_HIGH_LIMBS_RANGE_CONSTRAINT_0);
        self.num_gates += 2;
        for w in &self.wires {
            assert_eq!(w.len(), self.num_gates);
        }
    }

    /// bb `feed_ecc_op_queue_into_circuit`: two zero rows, the leading random ops, then every real op
    /// as an accumulation gate (no-ops carry the accumulator through), then the trailing random ops.
    fn feed(&mut self, ops: &[UltraOp], random_ops_end: usize) {
        if ops.is_empty() {
            return;
        }
        let v = self.batching_challenge_v;
        let x = self.evaluation_input_x;
        for w in 0..NUM_WIRES {
            self.push_pair(w, Fr::from(0u64), Fr::from(0u64));
        }
        self.num_gates += 2;
        for op in &ops[..NUM_NO_OPS_START] {
            assert_eq!(op.op_code.value(), 0, "expected a no-op at the start of the op queue");
        }
        for op in &ops[NUM_NO_OPS_START..NUM_NO_OPS_START + NUM_RANDOM_OPS_START] {
            self.process_random_op(op);
        }
        assert!(ops.len() >= NUM_NO_OPS_START + NUM_RANDOM_OPS_START + random_ops_end, "op queue too small for the Translator");
        let ops_end = ops.len() - random_ops_end;
        let span = &ops[NUM_NO_OPS_START + NUM_RANDOM_OPS_START..ops_end];
        // Horner from the last op gives the accumulator *before* each op.
        let mut accumulator_trace = Vec::new();
        let mut current = Fq::from(0u64);
        for op in span.iter().rev() {
            if op.op_code.value() == 0 {
                continue;
            }
            current *= x;
            let (x_fq, y_fq) = base_point_standard_form(op);
            let z1: Fq = from_u256(u256(&op.z_1));
            let z2: Fq = from_u256(u256(&op.z_2));
            current += Fq::from(op.op_code.value() as u64) + v * (x_fq + v * (y_fq + v * (z1 + v * z2)));
            accumulator_trace.push(current);
        }
        let final_state = accumulator_trace.pop().unwrap();
        let mut previous_accumulator_limbs = split_fq_into_limbs(&final_state);
        for op in span {
            if op.op_code.value() == 0 {
                for w in 0..ACCUMULATORS_BINARY_LIMBS_0 {
                    self.push_pair(w, Fr::from(0u64), Fr::from(0u64));
                }
                for (i, limb) in previous_accumulator_limbs.iter().enumerate() {
                    self.push_pair(ACCUMULATORS_BINARY_LIMBS_0 + i, *limb, *limb);
                }
                for w in ACCUMULATORS_BINARY_LIMBS_0 + 4..NUM_WIRES {
                    self.push_pair(w, Fr::from(0u64), Fr::from(0u64));
                }
                self.num_gates += 2;
                continue;
            }
            let previous_accumulator = accumulator_trace.pop().unwrap_or(Fq::from(0u64));
            let step = generate_witness_values(op, &previous_accumulator, &v, &x);
            previous_accumulator_limbs = step.previous_accumulator;
            self.create_accumulation_gate(op, &step);
        }
        for op in &ops[ops_end..] {
            self.process_random_op(op);
        }
        assert!(self.num_gates % 2 == 0);
    }

    /// The accumulation result read from the result row (bb `get_computation_result`).
    pub fn accumulated_result_limbs(&self) -> [Fr; 4] {
        std::array::from_fn(|i| self.wires[ACCUMULATORS_BINARY_LIMBS_0 + i][RESULT_ROW])
    }
    /// The accumulated result as a base field element (bb test helper `get_accumulated_result`).
    pub fn accumulated_result(&self) -> Fq {
        let limbs = self.accumulated_result_limbs();
        let shift = Fr::from(2u64).pow_u64(NUM_LIMB_BITS as u64);
        let v = limbs[0] + limbs[1] * shift + limbs[2] * shift.sqr() + limbs[3] * shift.sqr() * shift;
        from_u256(u256(&v))
    }
}
