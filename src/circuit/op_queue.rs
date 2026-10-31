//! The Goblin ECC op queue (bb `op_queue/ecc_op_queue.hpp`, `ecc_ops_table.hpp`): every EC
//! operation a Mega circuit defers is recorded twice, natively for the ECCVM and as two width-4
//! rows (`op | x_lo | x_hi | y_lo` / `0 | y_hi | z1 | z2`) for the Mega circuit and Translator.
//! The native accumulator shadows the operations so that `eq_and_reset` knows the expected result.

use crate::base::field::{from_u256, u256, u256_low_bits, u256_num_bits, u256_shr, FieldLike, U256};
use crate::base::{Fq, Fr, G1Affine, Poly, Rng};
use ark_ec::{AffineRepr, CurveGroup};

/// Bits per coordinate limb pair (`2 * NUM_LIMB_BITS_IN_FIELD_SIMULATION`).
const CHUNK_BITS: u32 = 136;

/// Each op occupies two width-4 rows of the Ultra table.
pub const NUM_ROWS_PER_OP: usize = 2;
const ECC_NUM_RANDOM_OPS_START: usize = 3;
const ECC_NUM_NO_OPS_START: usize = 1;
const ECC_NUM_HIDING_OPS_START: usize = 1;
/// Rows of the ZK prefix (1 no-op, 3 random ops, 1 hiding op) that masks the merged Chonk table.
pub const ZK_ULTRA_OPS: usize =
    (ECC_NUM_RANDOM_OPS_START + ECC_NUM_NO_OPS_START + ECC_NUM_HIDING_OPS_START) * NUM_ROWS_PER_OP;
/// Leading zero rows of a fixed-location appended subtable (matches the sumcheck-disabled rows of the appender).
pub const APPEND_TRACE_OFFSET: usize = super::TRACE_OFFSET;
pub const CONST_OP_QUEUE_LOG_SIZE: usize = 12;
/// Fixed number of ops in the merged Chonk table (`1 << CONST_OP_QUEUE_LOG_SIZE`).
pub const OP_QUEUE_SIZE: usize = 1 << CONST_OP_QUEUE_LOG_SIZE;
/// Ultra ops appended by the hiding kernel; the merge verifier hard-codes its shift size from this.
pub const HIDING_KERNEL_ULTRA_OPS: usize = 363;
/// The four column polynomials of an Ultra ops table.
pub type Columns = [Poly; 4];

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
        Self {
            add: true,
            ..Default::default()
        }
    }
    pub fn mul() -> Self {
        Self {
            mul: true,
            ..Default::default()
        }
    }
    pub fn eq_reset() -> Self {
        Self {
            eq: true,
            reset: true,
            ..Default::default()
        }
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

impl UltraOp {
    pub fn random(rng: &mut dyn Rng) -> Self {
        UltraOp {
            op_code: EccOpCode {
                is_random_op: true,
                random_value_1: rng.fr(),
                random_value_2: rng.fr(),
                ..Default::default()
            },
            x_lo: rng.fr(),
            x_hi: rng.fr(),
            y_lo: rng.fr(),
            y_hi: rng.fr(),
            z_1: rng.fr(),
            z_2: rng.fr(),
            return_is_infinity: false,
        }
    }
    /// The op's two table rows `op | x_lo | x_hi | y_lo` and `0 | y_hi | z_1 | z_2` (random ops carry their
    /// two random values in the op column).
    pub fn rows(&self) -> [[Fr; 4]; NUM_ROWS_PER_OP] {
        let (op_0, op_1) = if self.op_code.is_random_op {
            (self.op_code.random_value_1, self.op_code.random_value_2)
        } else {
            (Fr::from(self.op_code.value() as u64), Fr::zero())
        };
        [
            [op_0, self.x_lo, self.x_hi, self.y_lo],
            [op_1, self.y_hi, self.z_1, self.z_2],
        ]
    }
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
        Self {
            tables: vec![],
            current: vec![],
        }
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

/// The op queue shared by `Chonk` and each circuit it builds. An `RwLock` keeps `RefCell`'s rules
/// (many readers or one writer) while letting the prover state cross threads, so the msgpack
/// handler that owns it is `Send`.
pub type SharedOpQueue = std::sync::Arc<std::sync::RwLock<EccOpQueue>>;

pub struct EccOpQueue {
    accumulator: crate::base::G1Projective,
    /// The `mul_accumulate` terms not yet in `accumulator`: summed as one MSM at `eq_and_reset`.
    pending: (Vec<G1Affine>, Vec<Fr>),
    pub eccvm_ops: SubTables<EccvmOp>,
    pub ultra_ops: SubTables<UltraOp>,
    /// The ZK prefix of the merged Ultra table (built once, at the end of an IVC).
    pub zk_ops: Vec<UltraOp>,
    pub fixed_append_offset: Option<usize>,
    pub hiding_op: Option<EccvmOp>,
    /// Subtables followed by a batch-merge separator op in the aggregate views (bb
    /// `num_separator_subtables`): every subtable merged before the hiding kernel's.
    pub num_separators: usize,
}

impl Default for EccOpQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl EccOpQueue {
    /// A fresh queue to share.
    pub fn shared() -> SharedOpQueue {
        std::sync::Arc::new(std::sync::RwLock::new(Self::new()))
    }

    pub fn new() -> Self {
        Self {
            accumulator: crate::base::G1Projective::default(),
            pending: Default::default(),
            eccvm_ops: Default::default(),
            ultra_ops: Default::default(),
            zk_ops: vec![],
            fixed_append_offset: None,
            hiding_op: None,
            num_separators: 0,
        }
    }
    /// Called by every new circuit; the previous circuit's subtable must have been merged.
    pub fn initialize_new_subtable(&mut self) {
        assert!(
            self.ultra_ops.current.is_empty() && self.eccvm_ops.current.is_empty(),
            "previous subtable not merged"
        );
    }
    /// Take over the subtable of a circuit built against a private queue (`prebuild_circuit_mega`):
    /// its `eq_and_reset`s saw a zero accumulator, as they would have here.
    pub fn absorb_current(&mut self, other: EccOpQueue) {
        self.initialize_new_subtable();
        assert!(
            self.accumulator == crate::base::G1Projective::default() && self.pending.0.is_empty(),
            "accumulator not reset before a new circuit"
        );
        assert!(other.ultra_ops.tables.is_empty() && other.zk_ops.is_empty());
        assert!(other.hiding_op.is_none() && other.fixed_append_offset.is_none());
        self.accumulator = other.accumulator;
        self.pending = other.pending;
        self.ultra_ops.current = other.ultra_ops.current;
        self.eccvm_ops.current = other.eccvm_ops.current;
    }
    pub fn num_subtables(&self) -> usize {
        self.ultra_ops.tables.len()
    }
    pub fn current_subtable_size(&self) -> usize {
        self.ultra_ops.current.len()
    }
    pub fn merge(&mut self) {
        assert!(
            self.fixed_append_offset.is_none(),
            "cannot merge after the fixed-location append"
        );
        self.eccvm_ops.merge();
        self.ultra_ops.merge();
    }
    pub fn add_accumulate(&mut self, point: G1Affine) -> UltraOp {
        self.accumulator += point;
        self.eccvm_ops.current.push(EccvmOp {
            op_code: EccOpCode::add(),
            base_point: point,
            z1: U256::zero(),
            z2: U256::zero(),
            mul_scalar_full: Fr::zero(),
        });
        self.construct_and_populate_ultra_op(EccOpCode::add(), point, Fr::zero())
    }
    pub fn mul_accumulate(&mut self, point: G1Affine, scalar: Fr) -> UltraOp {
        self.pending.0.push(point);
        self.pending.1.push(scalar);
        let op = self.construct_and_populate_ultra_op(EccOpCode::mul(), point, scalar);
        self.eccvm_ops.current.push(EccvmOp {
            op_code: EccOpCode::mul(),
            base_point: point,
            z1: u256(&op.z_1),
            z2: u256(&op.z_2),
            mul_scalar_full: scalar,
        });
        op
    }
    pub fn eq_and_reset(&mut self) -> UltraOp {
        let (points, scalars) = std::mem::take(&mut self.pending);
        let expected = (std::mem::take(&mut self.accumulator) + crate::base::msm::msm(&points, &scalars)).into_affine();
        self.eccvm_ops.current.push(EccvmOp {
            op_code: EccOpCode::eq_reset(),
            base_point: expected,
            z1: U256::zero(),
            z2: U256::zero(),
            mul_scalar_full: Fr::zero(),
        });
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
        let op = UltraOp::random(rng);
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
        let ultra = UltraOp {
            op_code: EccOpCode::eq_reset(),
            x_lo,
            x_hi,
            y_lo,
            y_hi,
            z_1: Fr::zero(),
            z_2: Fr::zero(),
            return_is_infinity: false,
        };
        let eccvm = EccvmOp {
            op_code: EccOpCode::eq_reset(),
            base_point: G1Affine::new_unchecked(px, py),
            z1: U256::zero(),
            z2: U256::zero(),
            mul_scalar_full: Fr::zero(),
        };
        (ultra, eccvm)
    }

    /// The fixed op that delimits batch-merged subtables: eq and reset against infinity, which leaves
    /// the accumulator alone and ends any pending MSM.
    pub fn make_separator_op_pair() -> (UltraOp, EccvmOp) {
        let ultra = UltraOp {
            op_code: EccOpCode::eq_reset(),
            return_is_infinity: true,
            ..Default::default()
        };
        let eccvm = EccvmOp {
            op_code: EccOpCode::eq_reset(),
            base_point: G1Affine::identity(),
            z1: U256::zero(),
            z2: U256::zero(),
            mul_scalar_full: Fr::zero(),
        };
        (ultra, eccvm)
    }
    /// bb `add_batch_merge_separators`: every subtable merged so far gets a separator in the
    /// aggregate views; the subtable commitments themselves are unchanged.
    pub fn add_batch_merge_separators(&mut self) {
        assert!(self.fixed_append_offset.is_none() && self.num_separators == 0);
        assert!(self.ultra_ops.current.is_empty(), "current subtable must be merged");
        self.num_separators = self.num_subtables();
    }
    /// Separators among the first `n` subtables.
    fn separators_in(&self, n: usize) -> usize {
        self.num_separators.min(n)
    }

    /// Shift `k` of the final merge `M = L + X^k R`: the ZK prefix (if any) plus `append_offset` op slots.
    pub fn compute_fixed_append_offset(append_offset: usize, include_zk_prefix: bool) -> usize {
        (if include_zk_prefix { ZK_ULTRA_OPS } else { 0 }) + append_offset * NUM_ROWS_PER_OP
    }
    /// Op slot at which a subtable of `current_subtable_size` ops must be appended so that the merged table
    /// always ends at `OP_QUEUE_SIZE` ops.
    pub fn get_append_offset(current_subtable_size: usize) -> usize {
        OP_QUEUE_SIZE - current_subtable_size - APPEND_TRACE_OFFSET / NUM_ROWS_PER_OP - ZK_ULTRA_OPS / NUM_ROWS_PER_OP
    }
    pub fn append_offset_for_prover(&self) -> usize {
        Self::get_append_offset(self.current_subtable_size())
    }
    pub fn append_offset_for_verifier() -> usize {
        Self::get_append_offset(HIDING_KERNEL_ULTRA_OPS)
    }
    /// Merge the current subtable at a fixed op slot (the hiding kernel's final merge).
    pub fn merge_fixed_append(&mut self, offset: usize) {
        assert!(
            self.fixed_append_offset.is_none(),
            "the fixed-location append happens once"
        );
        assert!(
            self.ultra_ops.num_ops() + self.num_separators <= offset,
            "the tables before the fixed append do not fit"
        );
        self.fixed_append_offset = Some(offset);
        self.eccvm_ops.merge();
        self.ultra_ops.merge();
    }
    /// Rows of the merged Ultra table, excluding the ZK prefix.
    pub fn num_ultra_rows(&self) -> usize {
        match self.fixed_append_offset {
            None => (self.ultra_ops.num_ops() + self.num_separators) * NUM_ROWS_PER_OP,
            Some(off) => {
                Self::compute_fixed_append_offset(off, false)
                    + APPEND_TRACE_OFFSET
                    + self.ultra_ops.tables.last().unwrap().len() * NUM_ROWS_PER_OP
            }
        }
    }
    /// Rows of the table up to and including the tail subtable (all but the last), excluding the ZK prefix.
    pub fn ultra_table_size_up_to_tail(&self) -> usize {
        assert!(self.ultra_ops.current.is_empty() && self.num_subtables() > 1);
        let n = self.num_subtables() - 1;
        (self.ultra_ops.tables[..n].iter().map(Vec::len).sum::<usize>() + self.separators_in(n)) * NUM_ROWS_PER_OP
    }

    /// bb `get_zk_reconstructed_ultra_ops`: the ZK prefix, every merged subtable, and — under a
    /// fixed-location append — no-op padding up to the fixed slot (plus the preamble) before the
    /// last subtable.
    pub fn get_zk_reconstructed_ultra_ops(&self) -> Vec<UltraOp> {
        assert!(
            !self.zk_ops.is_empty(),
            "ZK ops must be constructed before reconstructing the Ultra table"
        );
        self.reconstructed(true)
    }

    /// bb `get_no_zk_reconstructed_ultra_ops` (Goblin for the AVM, which queues its own prefix).
    pub fn get_no_zk_reconstructed_ultra_ops(&self) -> Vec<UltraOp> {
        self.reconstructed(false)
    }

    fn reconstructed(&self, include_zk_ops: bool) -> Vec<UltraOp> {
        assert!(
            self.ultra_ops.current.is_empty(),
            "current subtable should be merged first"
        );
        let mut ops = if include_zk_ops {
            self.zk_ops.clone()
        } else {
            Vec::new()
        };
        let n = self.num_subtables();
        let sequential = n - self.fixed_append_offset.is_some() as usize;
        for (i, t) in self.ultra_ops.tables[..sequential].iter().enumerate() {
            ops.extend(t.iter().cloned());
            if i < self.num_separators {
                ops.push(Self::make_separator_op_pair().0);
            }
        }
        match self.fixed_append_offset {
            None => {}
            Some(offset) => {
                let zk = if include_zk_ops { self.zk_ops.len() } else { 0 };
                let target = offset + zk + APPEND_TRACE_OFFSET / NUM_ROWS_PER_OP;
                assert!(ops.len() <= target);
                ops.resize(target, UltraOp::default());
                ops.extend(self.ultra_ops.tables[n - 1].iter().cloned());
            }
        }
        ops
    }

    /// Build the ZK prefix (1 no-op, 3 random ops, 1 hiding op) and return its columns.
    pub fn construct_zk_columns(&mut self, rng: &mut dyn Rng) -> Columns {
        assert!(self.zk_ops.is_empty(), "ZK ops are constructed once");
        self.zk_ops
            .extend((0..ECC_NUM_NO_OPS_START).map(|_| UltraOp::default()));
        self.zk_ops
            .extend((0..ECC_NUM_RANDOM_OPS_START).map(|_| UltraOp::random(rng)));
        let (px, py) = (rng.fq(), rng.fq());
        let (ultra, eccvm) = Self::make_hiding_op_pair(px, py);
        self.hiding_op = Some(eccvm);
        self.zk_ops.push(ultra);
        self.zk_columns()
    }
    pub fn zk_columns(&self) -> Columns {
        assert_eq!(self.zk_ops.len() * NUM_ROWS_PER_OP, ZK_ULTRA_OPS);
        let mut cols = std::array::from_fn(|_| Poly::zero(ZK_ULTRA_OPS));
        for (i, op) in self.zk_ops.iter().enumerate() {
            Self::write_op(&mut cols, op, i * NUM_ROWS_PER_OP);
        }
        cols
    }
    /// Columns of every merged subtable, in append order.
    pub fn construct_subtable_columns(&self) -> Vec<Columns> {
        (0..self.num_subtables())
            .map(|i| {
                self.columns_in_range(
                    self.ultra_ops.tables[i].len() * NUM_ROWS_PER_OP,
                    i,
                    i + 1,
                    false,
                    None,
                    false,
                )
            })
            .collect()
    }
    /// Columns of the full merged table (ZK prefix, subtables, and the fixed-location final subtable if set).
    pub fn construct_ultra_ops_table_columns(&self, include_zk_ops: bool) -> Columns {
        self.columns_in_range(
            self.num_ultra_rows(),
            0,
            self.num_subtables(),
            include_zk_ops,
            self.fixed_append_offset,
            true,
        )
    }
    /// Columns of the aggregate table up to and including the tail subtable (with the ZK prefix).
    pub fn construct_table_columns_up_to_tail(&self) -> Columns {
        assert!(!self.zk_ops.is_empty());
        self.columns_in_range(
            self.ultra_table_size_up_to_tail(),
            0,
            self.num_subtables() - 1,
            true,
            None,
            true,
        )
    }
    /// Columns of the most recently merged subtable; under a fixed-location append they carry the
    /// `APPEND_TRACE_OFFSET` leading zero rows so that they match the appender's ecc op wires.
    pub fn construct_current_subtable_columns(&self) -> Columns {
        let subtable = self.ultra_ops.tables.last().expect("no merged subtable");
        let leading_zeros = if self.fixed_append_offset.is_some() {
            APPEND_TRACE_OFFSET
        } else {
            0
        };
        let mut cols = std::array::from_fn(|_| Poly::zero(leading_zeros + subtable.len() * NUM_ROWS_PER_OP));
        for (i, op) in subtable.iter().enumerate() {
            Self::write_op(&mut cols, op, leading_zeros + i * NUM_ROWS_PER_OP);
        }
        cols
    }

    /// Columns of subtables `[start, end)` laid out sequentially after the optional ZK prefix; with
    /// `fixed_last`, the last subtable in range is instead placed at that op slot (plus the preamble).
    /// With `separators`, each covered sequential subtable is followed by the batch-merge separator.
    fn columns_in_range(
        &self,
        poly_size: usize,
        start: usize,
        end: usize,
        include_zk_ops: bool,
        fixed_last: Option<usize>,
        separators: bool,
    ) -> Columns {
        let size = poly_size + if include_zk_ops { ZK_ULTRA_OPS } else { 0 };
        let mut cols = std::array::from_fn(|_| Poly::zero(size));
        let mut row = 0;
        if include_zk_ops {
            assert!(!self.zk_ops.is_empty(), "ZK ops must be constructed first");
            for op in &self.zk_ops {
                Self::write_op(&mut cols, op, row);
                row += NUM_ROWS_PER_OP;
            }
        }
        let sequential_end = if fixed_last.is_some() { end - 1 } else { end };
        let separator = Self::make_separator_op_pair().0;
        for i in start..sequential_end {
            let sep = (separators && i < self.num_separators).then_some(&separator);
            for op in self.ultra_ops.tables[i].iter().chain(sep) {
                Self::write_op(&mut cols, op, row);
                row += NUM_ROWS_PER_OP;
            }
        }
        if let Some(offset) = fixed_last {
            let mut row = Self::compute_fixed_append_offset(offset, include_zk_ops) + APPEND_TRACE_OFFSET;
            for op in &self.ultra_ops.tables[end - 1] {
                Self::write_op(&mut cols, op, row);
                row += NUM_ROWS_PER_OP;
            }
        }
        cols
    }
    fn write_op(cols: &mut Columns, op: &UltraOp, row: usize) {
        for (r, values) in op.rows().iter().enumerate() {
            for (c, v) in values.iter().enumerate() {
                cols[c].coeffs[row + r] = *v;
            }
        }
    }

    fn construct_and_populate_ultra_op(&mut self, op_code: EccOpCode, point: G1Affine, scalar: Fr) -> UltraOp {
        let return_is_infinity = point.is_zero();
        let (x, y) = if return_is_infinity {
            (Fq::zero(), Fq::zero())
        } else {
            (point.x, point.y)
        };
        let (x_lo, x_hi) = split_coordinate(&x);
        let (y_lo, y_hi) = split_coordinate(&y);
        let k = u256(&scalar);
        let (z_1, z_2) = if u256_num_bits(&k) <= 128 {
            (scalar, Fr::zero())
        } else {
            let (k1, k2) = crate::base::endo::glv_split(&scalar);
            let half = |h: [u64; 2]| from_u256(U256::new([h[0], h[1], 0, 0]));
            (half(k1), half(k2))
        };
        let op = UltraOp {
            op_code,
            x_lo,
            x_hi,
            y_lo,
            y_hi,
            z_1,
            z_2,
            return_is_infinity,
        };
        self.ultra_ops.current.push(op.clone());
        op
    }
}

/// A base-field coordinate as two scalar-field limbs split at bit 136.
fn split_coordinate(c: &Fq) -> (Fr, Fr) {
    let v = u256(c);
    (
        from_u256(u256_low_bits(v, CHUNK_BITS)),
        from_u256(u256_shr(v, CHUNK_BITS)),
    )
}
