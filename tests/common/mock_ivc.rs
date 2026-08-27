//! bb's mock IVC circuits (`PrivateFunctionExecutionMockCircuitProducer` with `log2_num_gates = 5`):
//! arithmetic filler gates with witnesses from bb's debug RNG, the mock databus (`MockDatabusProducer`),
//! and the real kernel logic (`complete_kernel_circuit_logic`).
use bb_ref::base::field::FieldLike;
use bb_ref::base::field::U256;
use bb_ref::base::poly::Poly;
use bb_ref::base::rng::Rng;
use bb_ref::base::Fr;
use bb_ref::base::{CommitmentKey, G1Affine};
use bb_ref::honk::prover_instance::DATABUS_OFFSET;
use bb_ref::stdlib::io::MAX_APPS_PER_KERNEL;

const BUS_ARRAY_SIZE: usize = 3;
/// bb `BusId`: kernel calldata 0, app calldata 1..=5, return data 6.
const RETURN_DATA_BUS_ID: usize = 6;
use bb_ref::chonk::ivc::{Chonk, CircuitKind};
use bb_ref::chonk::kernel::complete_kernel_circuit_logic;
use bb_ref::circuit::builder::AddQuad;
use bb_ref::circuit::Builder;
use bb_ref::stdlib::io::AppIo;
use std::cell::RefCell;
use std::rc::Rc;

/// `std::mt19937_64`.
pub struct Mt19937_64 {
    mt: [u64; 312],
    index: usize,
}

impl Mt19937_64 {
    pub fn new(seed: u64) -> Self {
        let mut mt = [0u64; 312];
        mt[0] = seed;
        for i in 1..312 {
            mt[i] = 6364136223846793005u64.wrapping_mul(mt[i - 1] ^ (mt[i - 1] >> 62)).wrapping_add(i as u64);
        }
        Self { mt, index: 312 }
    }
    fn twist(&mut self) {
        for i in 0..312 {
            let x = (self.mt[i] & 0xFFFF_FFFF_8000_0000) | (self.mt[(i + 1) % 312] & 0x7FFF_FFFF);
            let mut xa = x >> 1;
            if x & 1 == 1 {
                xa ^= 0xB502_6F5A_A966_19E9;
            }
            self.mt[i] = self.mt[(i + 156) % 312] ^ xa;
        }
        self.index = 0;
    }
    pub fn next_u64(&mut self) -> u64 {
        if self.index >= 312 {
            self.twist();
        }
        let mut y = self.mt[self.index];
        self.index += 1;
        y ^= (y >> 29) & 0x5555_5555_5555_5555;
        y ^= (y << 17) & 0x71D6_7FFF_EDA6_0000;
        y ^= (y << 37) & 0xFFF7_EEE0_0000_0000;
        y ^= y >> 43;
        y
    }
}

/// bb `numeric::get_debug_randomness()`: `mt19937_64(12345)`, a u256 being four draws (low limb first).
pub struct DebugRng(pub Mt19937_64);

impl DebugRng {
    pub fn new() -> Self {
        Self(Mt19937_64::new(12345))
    }
}

impl Rng for DebugRng {
    fn next_u256(&mut self) -> U256 {
        let a = self.0.next_u64();
        let b = self.0.next_u64();
        let c = self.0.next_u64();
        let d = self.0.next_u64();
        U256::new([a, b, c, d])
    }
}

/// bb `MockCircuits::add_arithmetic_gates`.
pub fn add_arithmetic_gates(b: &mut Builder, num_gates: usize, rng: &mut dyn Rng) {
    for _ in 0..num_gates {
        let (a, bb_, c) = (rng.fr(), rng.fr(), rng.fr());
        let d = a + bb_ + c;
        let a_idx = b.add_variable(a);
        let b_idx = b.add_variable(bb_);
        let c_idx = b.add_variable(c);
        let d_idx = b.add_variable(d);
        b.create_big_add_gate(
            AddQuad {
                a: a_idx,
                b: b_idx,
                c: c_idx,
                d: d_idx,
                a_scaling: Fr::from(1u64),
                b_scaling: Fr::from(1u64),
                c_scaling: Fr::from(1u64),
                d_scaling: -Fr::from(1u64),
                const_scaling: Fr::from(0u64),
            },
            false,
        );
    }
}

/// bb `MockCircuits::construct_arithmetic_circuit(builder, log2, include_public_inputs = false)`.
pub fn construct_arithmetic_circuit(b: &mut Builder, target_log2_dyadic_size: usize, rng: &mut dyn Rng) {
    const OFFSET_HACK: usize = 10;
    let target = 1usize << target_log2_dyadic_size;
    let preamble = b.num_gates();
    assert!(target > OFFSET_HACK + preamble);
    add_arithmetic_gates(b, target - OFFSET_HACK - 1 - preamble, rng);
}

/// bb `MockDatabusProducer`: deterministic bus contents threaded from apps into kernels.
#[derive(Default)]
pub struct MockDatabus {
    app_return_data: [Vec<Fr>; MAX_APPS_PER_KERNEL],
    pub kernel_return_data: Vec<Fr>,
    next: u64,
}

impl MockDatabus {
    fn mock_array(&mut self) -> Vec<Fr> {
        (0..BUS_ARRAY_SIZE)
            .map(|_| {
                self.next += 1;
                Fr::from(self.next)
            })
            .collect()
    }
    fn append_calldata(b: &mut Builder, bus: usize, data: &[Fr]) {
        for v in data {
            let w = b.add_variable(*v);
            b.add_public_calldata(bus, w);
        }
        let idx = b.add_variable(Fr::from((bus % data.len()) as u64));
        b.read_calldata(bus, idx);
    }
    fn append_return_data(b: &mut Builder, data: &[Fr]) {
        for v in data {
            let w = b.add_variable(*v);
            b.add_public_return_data(w);
        }
        let idx = b.add_variable(Fr::from((RETURN_DATA_BUS_ID % data.len()) as u64));
        b.read_return_data(idx);
    }
    pub fn populate_app(&mut self, b: &mut Builder) {
        let data = self.mock_array();
        Self::append_return_data(b, &data);
        let slot = self.app_return_data.iter_mut().find(|d| d.is_empty()).expect("more than MAX_APPS_PER_KERNEL apps in a group");
        *slot = data;
    }
    /// Returns the app calldata contents (for the kernel's `app_return_data` public inputs).
    pub fn populate_kernel(&mut self, b: &mut Builder) -> [Vec<Fr>; MAX_APPS_PER_KERNEL] {
        let kernel_calldata = if self.kernel_return_data.is_empty() {
            vec![Fr::zero(); 1]
        } else {
            self.kernel_return_data.clone()
        };
        Self::append_calldata(b, 0, &kernel_calldata);
        let app_calldata: [Vec<Fr>; MAX_APPS_PER_KERNEL] = std::array::from_fn(|idx| {
            let bus = 1 + idx;
            let data = if self.app_return_data[idx].is_empty() {
                vec![Fr::zero(); bus + 1]
            } else {
                std::mem::take(&mut self.app_return_data[idx])
            };
            Self::append_calldata(b, bus, &data);
            data
        });
        self.kernel_return_data = self.mock_array();
        Self::append_return_data(b, &self.kernel_return_data);
        app_calldata
    }
    pub fn populate_hiding(&mut self, b: &mut Builder) -> Vec<Fr> {
        let kernel_calldata = if self.kernel_return_data.is_empty() {
            vec![Fr::zero(); 1]
        } else {
            self.kernel_return_data.clone()
        };
        Self::append_calldata(b, 0, &kernel_calldata);
        kernel_calldata
    }
}

/// Commitment to a databus column as laid out in the proving key.
pub fn bus_commitment(values: &[Fr], ck: &CommitmentKey) -> G1Affine {
    let mut coeffs = vec![Fr::zero(); DATABUS_OFFSET];
    coeffs.extend_from_slice(values);
    ck.commit(&Poly::from_coeffs(coeffs))
}

pub struct MockIvcCircuits {
    pub bus: MockDatabus,
    pub rng: DebugRng,
}

impl MockIvcCircuits {
    pub fn new() -> Self {
        Self {
            bus: MockDatabus::default(),
            rng: DebugRng::new(),
        }
    }

    /// bb `create_next_circuit(ivc, log2_num_gates = 5 (0 for the hiding kernel), 0, false)`.
    pub fn next_circuit(&mut self, ivc: &mut Chonk, zk_rng: &mut dyn Rng) -> Builder {
        let kind = ivc.current_kind();
        let ctx = Rc::new(RefCell::new(Builder::new_mega(ivc.op_queue.clone())));
        if kind != CircuitKind::HidingKernel {
            construct_arithmetic_circuit(&mut ctx.borrow_mut(), 5, &mut self.rng);
        }
        match kind {
            CircuitKind::App => {
                self.bus.populate_app(&mut ctx.borrow_mut());
                AppIo::add_default(&ctx);
            }
            CircuitKind::Kernel | CircuitKind::HidingKernel => {
                self.bus.populate_kernel(&mut ctx.borrow_mut());
                complete_kernel_circuit_logic(ivc, &ctx, zk_rng, None);
            }
        }
        Rc::try_unwrap(ctx).ok().expect("builder still referenced").into_inner()
    }
}
