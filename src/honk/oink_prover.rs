//! Oink prover (bb `ultra_honk/oink_prover.cpp`): commits to the witness, samples the
//! relation-parameter challenges, and derives the witness polynomials that depend on them.

use super::flavor::{Ent, Rel};
use super::oink::compute_public_input_delta;
use super::prover_instance::ProverInstance;
use super::relations::{lookup_term, table_term, RelationParams, Row};
use crate::base::field::{FieldLike, Fr};
use crate::base::poly::Poly;
use crate::base::rng::Rng;
use crate::base::transcript::NativeTranscript;
use crate::base::vk::Vk;
use crate::base::{Bn254, CommitmentKey};

/// bb `NUM_DISABLED_ROWS_IN_SUMCHECK`: the head rows excluded from the relation checks.
pub const TRACE_OFFSET: usize = 4;

pub struct OinkProverOutput {
    pub params: RelationParams<Fr>,
    pub alpha: Fr,
}

fn commit_and_send(inst: &ProverInstance, ck: &CommitmentKey, t: &mut NativeTranscript, e: Ent) {
    let c = ck.commit(inst.poly(e));
    t.send(e.name(), &c);
}

pub fn prove_oink(inst: &mut ProverInstance, vk: &Vk<Bn254>, ck: &CommitmentKey, t: &mut NativeTranscript, rng: &mut dyn Rng) -> OinkProverOutput {
    let flavor = inst.flavor;
    t.add_to_hash_buffer("vk_hash", &vk.hash());
    for (i, pi) in inst.public_inputs.iter().enumerate() {
        t.send(&format!("public_input_{i}"), pi);
    }

    if flavor.has_gemini_masking {
        let mask = build_gemini_masking_poly(inst.log_n(), inst.max_end_index, inst.dyadic_size, rng);
        *inst.poly_mut(Ent::gemini_masking_poly) = mask;
        commit_and_send(inst, ck, t, Ent::gemini_masking_poly);
    }
    commit_and_send(inst, ck, t, Ent::w_l);
    commit_and_send(inst, ck, t, Ent::w_r);
    commit_and_send(inst, ck, t, Ent::w_o);

    let mut params = RelationParams::<Fr>::default();
    if flavor.has(Rel::Memory) {
        let c: Vec<Fr> = t.challenges(&["eta", "rom_logup_gamma"]);
        params.eta = c[0];
        params.eta_two = c[0] * c[0];
        params.eta_three = params.eta_two * c[0];
        params.rom_logup_gamma = c[1];
    }
    add_ram_rom_memory_records_to_wire_4(inst, &params);
    add_rom_logup_inverses_to_wire_4(inst, &params);
    if flavor.has(Rel::LogDerivLookup) {
        commit_and_send(inst, ck, t, Ent::lookup_read_counts);
        commit_and_send(inst, ck, t, Ent::lookup_read_tags);
    }
    commit_and_send(inst, ck, t, Ent::w_4);

    let c: Vec<Fr> = t.challenges(&["beta", "gamma"]);
    params.beta = c[0];
    params.gamma = c[1];
    if flavor.has(Rel::LogDerivLookup) {
        params.beta_sqr = c[0] * c[0];
        params.beta_cube = params.beta_sqr * c[0];
        compute_logderivative_inverses(inst, &params);
        commit_and_send(inst, ck, t, Ent::lookup_inverses);
    }

    params.public_input_delta = compute_public_input_delta(&inst.public_inputs, &params.beta, &params.gamma, &Fr::from(inst.pub_inputs_offset as u64));
    compute_grand_product(inst, &params);
    commit_and_send(inst, ck, t, Ent::z_perm);

    let alpha: Fr = t.challenge("alpha");
    OinkProverOutput { params, alpha }
}

/// `w_4 = w_3 η³ + w_2 η² + w_1 η (+ 1 for writes)` at every memory access row.
fn add_ram_rom_memory_records_to_wire_4(inst: &mut ProverInstance, p: &RelationParams<Fr>) {
    let (reads, writes) = (inst.memory_read_records.clone(), inst.memory_write_records.clone());
    for (rows, is_write) in [(reads, false), (writes, true)] {
        for i in rows {
            let v = inst.poly(Ent::w_o).coeffs[i] * p.eta_three + inst.poly(Ent::w_r).coeffs[i] * p.eta_two + inst.poly(Ent::w_l).coeffs[i] * p.eta;
            inst.poly_mut(Ent::w_4).coeffs[i] = if is_write { v + Fr::from(1u64) } else { v };
        }
    }
}

/// `w_4 = 1 / (rom_logup_gamma + w_1 + η w_2 + η² q_c)` at every ROM-LogUp row.
fn add_rom_logup_inverses_to_wire_4(inst: &mut ProverInstance, p: &RelationParams<Fr>) {
    for i in inst.rom_logup_records.clone() {
        let d = p.rom_logup_gamma + inst.poly(Ent::w_l).coeffs[i] + p.eta * inst.poly(Ent::w_r).coeffs[i] + p.eta_two * inst.poly(Ent::q_c).coeffs[i];
        inst.poly_mut(Ent::w_4).coeffs[i] = d.invert();
    }
}

/// `lookup_inverses[i] = 1 / (lookup_term_i * table_term_i)` on rows with a lookup gate or a read table entry.
fn compute_logderivative_inverses(inst: &mut ProverInstance, p: &RelationParams<Fr>) {
    let mut inv = vec![Fr::from(0u64); inst.dyadic_size];
    for i in TRACE_OFFSET..inst.dyadic_size {
        let active = inst.poly(Ent::q_lookup).coeffs[i] == Fr::from(1u64) || inst.poly(Ent::lookup_read_tags).coeffs[i] == Fr::from(1u64);
        if active {
            let vals = inst.row(i);
            let row = Row { vals: &vals, layout: &inst.layout };
            inv[i] = (lookup_term(&row, p) * table_term(&row, p)).invert();
        }
    }
    *inst.poly_mut(Ent::lookup_inverses) = Poly::from_coeffs(inv);
}

/// The permutation grand product `z_perm` (bb `compute_grand_product` for `UltraPermutationRelation`).
fn compute_grand_product(inst: &mut ProverInstance, p: &RelationParams<Fr>) {
    let gp_start = TRACE_OFFSET;
    let domain_size = inst.final_active_wire_idx + 1;
    let active_size = domain_size - gp_start;
    let wires = [Ent::w_l, Ent::w_r, Ent::w_o, Ent::w_4];
    let ids = [Ent::id_1, Ent::id_2, Ent::id_3, Ent::id_4];
    let sigmas = [Ent::sigma_1, Ent::sigma_2, Ent::sigma_3, Ent::sigma_4];
    let mut num = Fr::from(1u64);
    let mut den = Fr::from(1u64);
    let mut z = inst.poly(Ent::z_perm).clone();
    for i in 0..active_size - 1 {
        let row = i + gp_start;
        for k in 0..4 {
            let w = inst.poly(wires[k]).coeffs[row];
            num *= w + inst.poly(ids[k]).coeffs[row] * p.beta + p.gamma;
            den *= w + inst.poly(sigmas[k]).coeffs[row] * p.beta + p.gamma;
        }
        z.coeffs[gp_start + i + 1] = num * den.invert();
    }
    *inst.poly_mut(Ent::z_perm) = z;
}

/// bb `build_gemini_masking_poly`: a random polynomial on the tail-halving support (dense for tiny circuits).
pub fn build_gemini_masking_poly(d: usize, extent: usize, dyadic_size: usize, rng: &mut dyn Rng) -> Poly {
    let mut poly = Poly::zero(dyadic_size);
    if d < 4 {
        for c in poly.coeffs.iter_mut().take(extent) {
            *c = rng.fr();
        }
        return poly;
    }
    for s in tail_halving_support(d, extent) {
        poly.coeffs[s] = rng.fr();
    }
    poly
}

/// bb `tail_halving_support`: `{E-1, E-2, N/2, N/2-1, N/4, N/4-1, ..., 2, 1}` de-duplicated and
/// tail-filled to `min(2d, N)` distinct indices.
pub fn tail_halving_support(d: usize, extent: usize) -> Vec<usize> {
    let n = 1usize << d;
    assert!(extent > 0 && extent <= n);
    let e = n.min(if extent % 2 == 0 { extent } else { extent + 1 });
    let target = (2 * d).min(n);
    let mut support = Vec::new();
    let add = |i: usize, support: &mut Vec<usize>| {
        if i < n && !support.contains(&i) {
            support.push(i);
        }
    };
    if e >= 2 {
        add(e - 1, &mut support);
        add(e - 2, &mut support);
    }
    for level in 1..d {
        let base = n >> level;
        add(base, &mut support);
        add(base - 1, &mut support);
    }
    let mut i = e - 1;
    while support.len() < target {
        add(i, &mut support);
        if i == 0 {
            break;
        }
        i -= 1;
    }
    support
}
