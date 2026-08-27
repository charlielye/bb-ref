//! The public-input tails of client circuits (bb `stdlib/special_public_inputs`), the databus
//! commitment depot, and witness views of native proofs and verification keys.

use super::curve::StdBn254;
use super::field::{Ctx, FieldT};
use super::goblin::GoblinElement;
use crate::base::codec::Transcriptable;
use crate::base::field::{from_hex, FieldLike};
use crate::base::group::{Bn254, GroupLike, PairingPoints};
use crate::base::vk::Vk;
use crate::base::{Fq, Fr, G1Affine};

pub const MAX_APPS_PER_KERNEL: usize = 5;
pub const NUM_ECC_OP_TABLES: usize = 4;

/// bb `DEFAULT_ECC_COMMITMENT`: the placeholder commitment in default hiding-kernel IO.
pub fn default_ecc_commitment() -> G1Affine {
    G1Affine::new_unchecked(
        from_hex::<Fq>("0x08434fa4480433735e7aeaccecb911eb7a06165ad70e5ced6ac6848296e59279"),
        from_hex::<Fq>("0x0a13a1839ab95ef15be8d0710b2c8aa47cea0b0e62a8596e68cc0fd54a6ae73d"),
    )
}

pub type StdPairingPoints = PairingPoints<StdBn254>;

/// bb `PairingPoints::set_default_to_public`: eight zero public inputs, each fixed by a gate.
pub fn set_default_pairing_points_public(ctx: &Ctx) -> u32 {
    let mut b = ctx.borrow_mut();
    let start = b.public_inputs().len() as u32;
    for _ in 0..8 {
        let idx = b.add_public_variable(Fr::zero());
        b.fix_witness(idx, Fr::zero());
    }
    start
}

pub fn set_pairing_points_public(pp: &StdPairingPoints) -> u32 {
    let start = pp.p0.set_public();
    pp.p1.set_public();
    start
}

/// A constant point turned into fixed witnesses (bb `convert_constant_to_fixed_witness`).
pub fn fixed_witness_point(ctx: &Ctx, p: G1Affine) -> GoblinElement {
    let mut c = GoblinElement::constant(ctx, p);
    c.convert_constant_to_fixed_witness(ctx);
    c
}

/// bb `DataBusDepot`: return-data commitments handed from one circuit's verifier to the kernel IO.
#[derive(Default)]
pub struct DataBusDepot {
    app_return_data: [Option<GoblinElement>; MAX_APPS_PER_KERNEL],
    kernel_return_data: Option<GoblinElement>,
}

impl DataBusDepot {
    pub fn set_kernel_return_data_commitment(&mut self, c: GoblinElement) {
        self.kernel_return_data = Some(c);
    }
    pub fn set_app_return_data_commitment(&mut self, c: GoblinElement) {
        let slot = self
            .app_return_data
            .iter_mut()
            .find(|s| s.is_none())
            .expect("DataBusDepot has no free app return-data slot");
        *slot = Some(c);
    }
    pub fn app_return_data_slots_are_empty(&self) -> bool {
        self.app_return_data.iter().all(Option::is_none)
    }
    pub fn construct_default_commitment(ctx: &Ctx) -> GoblinElement {
        fixed_witness_point(ctx, G1Affine::identity())
    }
    pub fn get_kernel_return_data_commitment(&mut self, ctx: &Ctx) -> GoblinElement {
        self.kernel_return_data
            .take()
            .unwrap_or_else(|| Self::construct_default_commitment(ctx))
    }
    pub fn get_app_return_data_commitment(&mut self, ctx: &Ctx, idx: usize) -> GoblinElement {
        self.app_return_data[idx]
            .take()
            .unwrap_or_else(|| Self::construct_default_commitment(ctx))
    }
}

fn read<T: Transcriptable<FieldT>>(fields: &[FieldT], index: &mut usize) -> T {
    let n = T::num_fields();
    let v = T::from_fields(&fields[*index..*index + n]);
    *index += n;
    v
}

fn read_pairing_points(fields: &[FieldT], index: &mut usize) -> StdPairingPoints {
    let n = StdPairingPoints::num_fields();
    let v = StdPairingPoints::from_fields(&fields[*index..*index + n]);
    *index += n;
    v
}

/// bb `KernelIO`: pairing points, the kernel's return-data commitment, the verified apps' return
/// data commitments, the running ECC op hash and the output accumulator hash.
pub struct KernelIo {
    pub pairing_inputs: StdPairingPoints,
    pub kernel_return_data: GoblinElement,
    pub app_return_data: [GoblinElement; MAX_APPS_PER_KERNEL],
    pub ecc_op_hash: FieldT,
    pub output_hn_accum_hash: FieldT,
}

impl KernelIo {
    pub const PUBLIC_INPUTS_SIZE: usize = 8 + 4 + 4 * MAX_APPS_PER_KERNEL + 2;

    pub fn reconstruct_from_public(public_inputs: &[FieldT]) -> Self {
        assert!(
            public_inputs.len() >= Self::PUBLIC_INPUTS_SIZE,
            "public inputs too small for KernelIO"
        );
        let mut i = public_inputs.len() - Self::PUBLIC_INPUTS_SIZE;
        let pairing_inputs = read_pairing_points(public_inputs, &mut i);
        let kernel_return_data = read(public_inputs, &mut i);
        let app_return_data = std::array::from_fn(|_| read(public_inputs, &mut i));
        let ecc_op_hash = read(public_inputs, &mut i);
        let output_hn_accum_hash = read(public_inputs, &mut i);
        Self {
            pairing_inputs,
            kernel_return_data,
            app_return_data,
            ecc_op_hash,
            output_hn_accum_hash,
        }
    }
    pub fn set_public(&self) {
        let ctx = self
            .output_hn_accum_hash
            .ctx
            .clone()
            .expect("KernelIO without a builder");
        set_pairing_points_public(&self.pairing_inputs);
        self.kernel_return_data.set_public();
        for c in &self.app_return_data {
            c.set_public();
        }
        self.ecc_op_hash.set_public();
        self.output_hn_accum_hash.set_public();
        ctx.borrow_mut().finalize_public_inputs();
    }
    /// bb `KernelIO::add_default`: default pairing points, infinity commitments, zero hashes
    /// (all members are constructed before any is made public).
    pub fn add_default(ctx: &Ctx) {
        let kernel_return_data = DataBusDepot::construct_default_commitment(ctx);
        let app_return_data: [GoblinElement; MAX_APPS_PER_KERNEL] =
            std::array::from_fn(|_| DataBusDepot::construct_default_commitment(ctx));
        let ecc_op_hash = FieldT::from_witness(ctx, Fr::zero());
        let output_hn_accum_hash = FieldT::from_witness(ctx, Fr::zero());
        set_default_pairing_points_public(ctx);
        kernel_return_data.set_public();
        for c in &app_return_data {
            c.set_public();
        }
        ecc_op_hash.set_public();
        output_hn_accum_hash.set_public();
        ctx.borrow_mut().finalize_public_inputs();
    }
}

/// bb `HidingKernelIO`: pairing points, the tail kernel's return-data commitment and the four
/// merged op-queue table commitments.
pub struct HidingKernelIo {
    pub pairing_inputs: StdPairingPoints,
    pub kernel_return_data: GoblinElement,
    pub ecc_op_tables: [GoblinElement; NUM_ECC_OP_TABLES],
}

impl HidingKernelIo {
    pub const PUBLIC_INPUTS_SIZE: usize = 8 + 4 + 4 * NUM_ECC_OP_TABLES;

    pub fn reconstruct_from_public(public_inputs: &[FieldT]) -> Self {
        assert!(
            public_inputs.len() >= Self::PUBLIC_INPUTS_SIZE,
            "public inputs too small for HidingKernelIO"
        );
        let mut i = public_inputs.len() - Self::PUBLIC_INPUTS_SIZE;
        let pairing_inputs = read_pairing_points(public_inputs, &mut i);
        let kernel_return_data = read(public_inputs, &mut i);
        let ecc_op_tables = std::array::from_fn(|_| read(public_inputs, &mut i));
        Self {
            pairing_inputs,
            kernel_return_data,
            ecc_op_tables,
        }
    }
    pub fn set_public(&self) {
        let ctx = self.ecc_op_tables[0].ctx();
        set_pairing_points_public(&self.pairing_inputs);
        self.kernel_return_data.set_public();
        for c in &self.ecc_op_tables {
            c.set_public();
        }
        ctx.borrow_mut().finalize_public_inputs();
    }
    /// bb `HidingKernelIO::add_default`: default pairing points and the placeholder commitment
    /// (all members are constructed before any is made public).
    pub fn add_default(ctx: &Ctx) {
        let kernel_return_data = fixed_witness_point(ctx, default_ecc_commitment());
        let ecc_op_tables: [GoblinElement; NUM_ECC_OP_TABLES] =
            std::array::from_fn(|_| fixed_witness_point(ctx, default_ecc_commitment()));
        set_default_pairing_points_public(ctx);
        kernel_return_data.set_public();
        for c in &ecc_op_tables {
            c.set_public();
        }
        ctx.borrow_mut().finalize_public_inputs();
    }
}

/// bb `AppIO` / `DefaultIO`: pairing points only.
pub struct AppIo;

impl AppIo {
    pub const PUBLIC_INPUTS_SIZE: usize = 8;
    pub fn add_default(ctx: &Ctx) {
        set_default_pairing_points_public(ctx);
        ctx.borrow_mut().finalize_public_inputs();
    }
    pub fn set_public(pp: &StdPairingPoints) {
        let ctx = pp.p0.ctx();
        set_pairing_points_public(pp);
        ctx.borrow_mut().finalize_public_inputs();
    }
}

/// bb `stdlib::Proof`: every proof field as a witness.
pub fn proof_to_witnesses(ctx: &Ctx, proof: &[Fr]) -> Vec<FieldT> {
    proof.iter().map(|f| FieldT::from_witness(ctx, *f)).collect()
}

/// bb `StdlibVerificationKey_(builder, native_vk)`: the VK fields as witnesses.
pub fn vk_to_witnesses(ctx: &Ctx, vk: &Vk<Bn254>) -> Vk<StdBn254> {
    let fields = proof_to_witnesses(ctx, &vk.to_fields());
    Vk::from_fields(&fields, vk.comms.len())
}
