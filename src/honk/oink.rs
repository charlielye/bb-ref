//! Oink verifier (bb `ultra_honk/oink_verifier.cpp`): binds the VK, reads public inputs and witness
//! commitments, samples the relation-parameter challenges.

use super::flavor::{Ent, FlavorDesc, Layout, Rel, BUS_SPECS};
use super::relations::RelationParams;
use crate::base::field::FieldLike;
use crate::base::group::Curve;
use crate::base::transcript::Transcript;
use crate::base::vk::Vk;

/// bb `PERMUTATION_ARGUMENT_VALUE_SEPARATOR`: the column separator in sigma/id polynomials.
pub const PERMUTATION_ARGUMENT_VALUE_SEPARATOR: u64 = 1 << 28;

pub struct OinkOutput<C: Curve> {
    pub public_inputs: Vec<C::Fr>,
    /// Commitments to all unshifted entities in layout order (precomputed from the VK, witness from the proof).
    pub commitments: Vec<C::G>,
    pub params: RelationParams<C::Fr>,
    pub alpha: C::Fr,
}

/// bb `honk/library/grand_product_delta.hpp`.
pub fn compute_public_input_delta<F: FieldLike>(public_inputs: &[F], beta: &F, gamma: &F, offset: &F) -> F {
    let separator = F::from_u64(PERMUTATION_ARGUMENT_VALUE_SEPARATOR);
    let mut numerator = F::one();
    let mut denominator = F::one();
    let mut numerator_acc = gamma.clone() + &(beta.clone() * &(separator + offset));
    let mut denominator_acc = gamma.clone() - &(beta.clone() * &(offset.clone() + &F::one()));
    for (i, x) in public_inputs.iter().enumerate() {
        numerator *= &(numerator_acc.clone() + x);
        denominator *= &(denominator_acc.clone() + x);
        if i + 1 < public_inputs.len() {
            numerator_acc += beta;
            denominator_acc -= beta;
        }
    }
    numerator.div(&denominator)
}

/// `vk_hash` is the hash the verifier was handed (bb `VKAndHash`); it is checked against the hash
/// recomputed from `vk` (natively an assertion, in-circuit a copy constraint).
pub fn verify_oink<C: Curve>(
    flavor: &FlavorDesc,
    layout: &Layout,
    vk: &Vk<C>,
    vk_hash: &C::TF,
    t: &mut Transcript<C::TF, C::Hash>,
    num_public_inputs: usize,
    emit_alpha: bool,
) -> OinkOutput<C> {
    crate::circuit::builder::trace_phase("oink: start");
    let computed_vk_hash = vk.hash();
    crate::circuit::builder::trace_phase("oink: vk hashed");
    t.add_to_hash_buffer("vk_hash", &computed_vk_hash);
    assert_eq!(vk_hash.value(), computed_vk_hash.value(), "VK hash mismatch");
    vk_hash.assert_equal(&computed_vk_hash);
    let num_public_inputs_field = C::Fr::from_u64(num_public_inputs as u64);
    assert_eq!(
        vk.num_public_inputs.value(),
        num_public_inputs_field.value(),
        "num_public_inputs mismatch with VK"
    );
    vk.num_public_inputs.assert_equal(&num_public_inputs_field);
    assert_eq!(
        vk.comms.len(),
        layout.num_precomputed,
        "VK commitment count does not match flavor"
    );

    let public_inputs: Vec<C::Fr> = (0..num_public_inputs)
        .map(|i| t.receive(&format!("public_input_{i}")))
        .collect();

    let mut comms: Vec<Option<C::G>> = vec![None; layout.num_unshifted()];
    for (i, e) in layout.unshifted.iter().enumerate() {
        // precomputed entities are laid out after the masking columns, in VK order
        if i >= layout.num_masking && i < layout.num_masking + layout.num_precomputed {
            comms[i] = Some(vk.comms[i - layout.num_masking].clone());
        }
        let _ = e;
    }
    let recv = |t: &mut Transcript<C::TF, C::Hash>, comms: &mut Vec<Option<C::G>>, e: Ent| {
        comms[layout.idx(e)] = Some(t.receive::<C::G>(e.name()));
    };

    if flavor.has_gemini_masking {
        recv(t, &mut comms, Ent::gemini_masking_poly);
    }
    recv(t, &mut comms, Ent::w_l);
    recv(t, &mut comms, Ent::w_r);
    recv(t, &mut comms, Ent::w_o);
    if layout.has(Ent::ecc_op_wire_1) {
        for e in [
            Ent::ecc_op_wire_1,
            Ent::ecc_op_wire_2,
            Ent::ecc_op_wire_3,
            Ent::ecc_op_wire_4,
        ] {
            recv(t, &mut comms, e);
        }
    }
    for b in layout.buses() {
        recv(t, &mut comms, BUS_SPECS[b].value);
        recv(t, &mut comms, BUS_SPECS[b].read_counts);
    }

    let mut params = RelationParams::<C::Fr>::default();
    if flavor.has(Rel::Memory) {
        let c: Vec<C::Fr> = t.challenges(&["eta", "rom_logup_gamma"]);
        params.eta = c[0].clone();
        params.eta_two = params.eta.clone() * &params.eta;
        params.eta_three = params.eta_two.clone() * &params.eta;
        params.rom_logup_gamma = c[1].clone();
    }
    if flavor.has(Rel::LogDerivLookup) {
        recv(t, &mut comms, Ent::lookup_read_counts);
        recv(t, &mut comms, Ent::lookup_read_tags);
    }
    recv(t, &mut comms, Ent::w_4);

    let c: Vec<C::Fr> = t.challenges(&["beta", "gamma"]);
    params.beta = c[0].clone();
    params.gamma = c[1].clone();
    if flavor.has(Rel::LogDerivLookup) {
        params.beta_sqr = params.beta.clone() * &params.beta;
        params.beta_cube = params.beta_sqr.clone() * &params.beta;
        recv(t, &mut comms, Ent::lookup_inverses);
    }
    for b in layout.buses() {
        recv(t, &mut comms, BUS_SPECS[b].inverses);
    }

    params.public_input_delta =
        compute_public_input_delta(&public_inputs, &params.beta, &params.gamma, &vk.pub_inputs_offset);
    recv(t, &mut comms, Ent::z_perm);

    let alpha: C::Fr = if emit_alpha {
        t.challenge("alpha")
    } else {
        C::Fr::zero()
    };
    crate::circuit::builder::trace_phase("oink: done");

    let commitments = comms
        .into_iter()
        .zip(&layout.unshifted)
        .map(|(c, e)| c.unwrap_or_else(|| panic!("no commitment received for {}", e.name())))
        .collect();
    OinkOutput {
        public_inputs,
        commitments,
        params,
        alpha,
    }
}
