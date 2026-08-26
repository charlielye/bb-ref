//! Kernel-shaped circuits without recursive verifiers, for driving the native Chonk pipeline
//! (bb's mock circuit producer with its kernel logic replaced by the bare IO layout). The native
//! Chonk verifier only inspects the hiding kernel's IO, so those are computed exactly; the other
//! kernels carry the right shape with placeholder hashes.
use bb_ref::acir::lower::add_default_pairing_points;
use bb_ref::base::codec::Transcriptable;
use bb_ref::base::field::FieldLike;
use bb_ref::base::group::PairingPoints;
use bb_ref::base::poly::Poly;
use bb_ref::base::rng::Rng;
use bb_ref::base::{CommitmentKey, Fr, G1Affine};
use bb_ref::chonk::ivc::Chonk;
use bb_ref::chonk::verifier::HidingKernelIo;
use bb_ref::circuit::builder::AddTriple;
use bb_ref::circuit::op_queue::HIDING_KERNEL_ULTRA_OPS;
use bb_ref::circuit::Builder;
use bb_ref::honk::prover_instance::DATABUS_OFFSET;

pub const MAX_APPS_PER_KERNEL: usize = 5;
const BUS_ARRAY_SIZE: usize = 3;
/// bb `BusId`: kernel calldata 0, app calldata 1..=5, return data 6.
const RETURN_DATA_BUS_ID: usize = 6;

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

fn arithmetic_gates(b: &mut Builder, n: u64) {
    for i in 0..n {
        let a = b.add_variable(Fr::from(i + 1));
        let c = b.add_variable(Fr::from(2 * (i + 1)));
        b.create_add_gate(AddTriple {
            a,
            b: a,
            c,
            a_scaling: Fr::one(),
            b_scaling: Fr::one(),
            c_scaling: -Fr::one(),
            const_scaling: Fr::zero(),
        });
    }
}

fn ecc_ops(b: &mut Builder, pairs: u64) {
    for i in 0..pairs {
        b.queue_ecc_add_accum(super::eccvm_ops::g1_times(i + 1));
        b.queue_ecc_mul_accum(super::eccvm_ops::g1_times(i + 2), Fr::from(i + 3));
    }
}

fn add_public_fields(b: &mut Builder, fields: &[Fr]) {
    for f in fields {
        b.add_public_variable(*f);
    }
}

pub fn app_circuit(ivc: &Chonk, bus: &mut MockDatabus) -> Builder {
    let mut b = Builder::new_mega(ivc.op_queue.clone());
    arithmetic_gates(&mut b, 8);
    ecc_ops(&mut b, 2);
    b.queue_ecc_eq();
    bus.populate_app(&mut b);
    add_default_pairing_points(&mut b);
    b
}

/// bb `KernelIO`: pairing points, kernel return data, five app return data commitments, the ECC op
/// hash and the accumulator hash (the hashes are placeholders: nothing verifies them natively).
pub fn kernel_circuit(ivc: &mut Chonk, bus: &mut MockDatabus) -> Builder {
    let _verified_recursively = ivc.take_verification_queue();
    let mut b = Builder::new_mega(ivc.op_queue.clone());
    b.queue_ecc_eq();
    arithmetic_gates(&mut b, 8);
    ecc_ops(&mut b, 1);
    b.queue_ecc_eq();
    let app_calldata = bus.populate_kernel(&mut b);
    for _ in 0..8 {
        let idx = b.add_public_variable(Fr::zero());
        b.fix_witness(idx, Fr::zero());
    }
    add_public_fields(&mut b, &bus_commitment(&bus.kernel_return_data, &ivc.ck).to_fields());
    for data in &app_calldata {
        add_public_fields(&mut b, &bus_commitment(data, &ivc.ck).to_fields());
    }
    add_public_fields(&mut b, &[Fr::zero(), Fr::zero()]);
    b.finalize_public_inputs();
    b
}

/// bb hiding kernel shape: `queue_ecc_eq` first, exactly `HIDING_KERNEL_ULTRA_OPS` ultra ops ending
/// in two random ops, and `HidingKernelIO` public inputs that the native verifier checks: a valid
/// pairing pair `(-[τ]₁, [1]₁)`, the commitment to its own kernel calldata, and the commitments to
/// the op-queue table before its own subtable.
pub fn hiding_circuit(ivc: &mut Chonk, bus: &mut MockDatabus, rng: &mut dyn Rng) -> Builder {
    let _verified_recursively = ivc.take_verification_queue();
    let mut b = Builder::new_mega(ivc.op_queue.clone());
    b.queue_ecc_eq();
    arithmetic_gates(&mut b, 8);
    let kernel_calldata = bus.populate_hiding(&mut b);
    let pairs = (HIDING_KERNEL_ULTRA_OPS - 1 - 2 - 2) / 2;
    ecc_ops(&mut b, pairs as u64);
    b.queue_ecc_add_accum(super::eccvm_ops::g1_times(7));
    b.queue_ecc_eq();
    b.queue_ecc_random_op(rng);
    b.queue_ecc_random_op(rng);
    let tables = ivc.op_queue.borrow().construct_ultra_ops_table_columns(true);
    let io = HidingKernelIo {
        pairing_points: PairingPoints {
            p0: -ivc.ck.points[1],
            p1: ivc.ck.points[0],
        },
        kernel_return_data: bus_commitment(&kernel_calldata, &ivc.ck),
        ecc_op_tables: std::array::from_fn(|k| ivc.ck.commit(&tables[k])),
    };
    add_public_fields(&mut b, &io.to_public_inputs());
    b.finalize_public_inputs();
    b
}
