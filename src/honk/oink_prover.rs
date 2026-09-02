//! Oink prover (bb `ultra_honk/oink_prover.cpp`): commits to the witness, samples the
//! relation-parameter challenges, and derives the witness polynomials that depend on them.

use super::flavor::{Ent, Rel, BUS_SPECS};
use super::oink::compute_public_input_delta;
use super::prover_instance::ProverInstance;
use super::relations::{lookup_term, table_term, RelationParams, Row};
use crate::base::field::{batch_invert, grand_product, FieldLike, Fr};
use crate::base::group::Curve;
use crate::base::poly::Poly;
use crate::base::rng::Rng;
use crate::base::transcript::Transcript;
use crate::base::vk::Vk;
use crate::base::G1Affine;
use crate::base::{Bn254, CommitmentKey};
use rayon::prelude::*;

pub struct OinkProverOutput {
    pub params: RelationParams<Fr>,
    pub alpha: Fr,
    /// Commitments to every unshifted entity in layout order (the VK's, then the witness ones).
    pub commitments: Vec<G1Affine>,
}

/// Commit to the polynomials in parallel, then send them in transcript order.
fn commit_and_send<C: Curve<Fr = Fr, G = G1Affine>>(
    inst: &ProverInstance,
    ck: &CommitmentKey,
    t: &mut Transcript<C::TF, C::Hash>,
    ents: &[Ent],
    out: &mut [Option<G1Affine>],
) where
    Fr: crate::base::codec::Transcriptable<C::TF> + crate::base::codec::FromChallenge<C::TF>,
    G1Affine: crate::base::codec::Transcriptable<C::TF>,
{
    let polys: Vec<_> = ents.iter().map(|e| inst.poly(*e)).collect();
    let comms: Vec<_> = ck.batch_commit(&polys);
    for (e, c) in ents.iter().zip(&comms) {
        t.send(e.name(), c);
        out[inst.layout.idx(*e)] = Some(*c);
    }
}

pub fn prove_oink(
    inst: &mut ProverInstance,
    vk: &Vk<Bn254>,
    ck: &CommitmentKey,
    t: &mut crate::base::transcript::NativeTranscript,
    rng: &mut dyn Rng,
    emit_alpha: bool,
) -> OinkProverOutput {
    prove_oink_as::<Bn254>(inst, vk, ck, t, rng, emit_alpha)
}

/// Generic over the transcript codec/hash (bb instantiates `OinkProver<Flavor>` per flavor).
pub fn prove_oink_as<C: Curve<Fr = Fr, G = G1Affine>>(
    inst: &mut ProverInstance,
    vk: &Vk<C>,
    ck: &CommitmentKey,
    t: &mut Transcript<C::TF, C::Hash>,
    rng: &mut dyn Rng,
    emit_alpha: bool,
) -> OinkProverOutput
where
    Fr: crate::base::codec::Transcriptable<C::TF> + crate::base::codec::FromChallenge<C::TF>,
    G1Affine: crate::base::codec::Transcriptable<C::TF>,
{
    let flavor = inst.flavor;
    let mut comms: Vec<Option<G1Affine>> = vec![None; inst.layout.unshifted.len()];
    for (i, c) in vk.comms.iter().enumerate() {
        comms[inst.layout.num_masking + i] = Some(*c);
    }
    t.add_to_hash_buffer("vk_hash", &vk.hash());
    for (i, pi) in inst.public_inputs.iter().enumerate() {
        t.send(&format!("public_input_{i}"), pi);
    }

    let mut first: Vec<Ent> = vec![];
    if flavor.has_gemini_masking {
        let mask = build_gemini_masking_poly(inst.log_n(), inst.max_end_index, inst.dyadic_size, rng);
        *inst.poly_mut(Ent::gemini_masking_poly) = mask;
        first.push(Ent::gemini_masking_poly);
    }
    first.extend([Ent::w_l, Ent::w_r, Ent::w_o]);
    if inst.layout.has(Ent::ecc_op_wire_1) {
        first.extend([
            Ent::ecc_op_wire_1,
            Ent::ecc_op_wire_2,
            Ent::ecc_op_wire_3,
            Ent::ecc_op_wire_4,
        ]);
    }
    for b in inst.layout.buses() {
        first.extend([BUS_SPECS[b].value, BUS_SPECS[b].read_counts]);
    }
    commit_and_send::<C>(inst, ck, t, &first, &mut comms);
    crate::base::timing::phase("    oink: wire commits");

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
    crate::base::timing::phase("    oink: memory records");
    let mut second: Vec<Ent> = vec![];
    if flavor.has(Rel::LogDerivLookup) {
        second.extend([Ent::lookup_read_counts, Ent::lookup_read_tags]);
    }
    second.push(Ent::w_4);
    commit_and_send::<C>(inst, ck, t, &second, &mut comms);
    crate::base::timing::phase("    oink: w_4/lookup commits");

    let c: Vec<Fr> = t.challenges(&["beta", "gamma"]);
    params.beta = c[0];
    params.gamma = c[1];
    let mut third: Vec<Ent> = vec![];
    if flavor.has(Rel::LogDerivLookup) {
        params.beta_sqr = c[0] * c[0];
        params.beta_cube = params.beta_sqr * c[0];
        compute_logderivative_inverses(inst, &params);
        third.push(Ent::lookup_inverses);
    }
    for b in inst.layout.buses() {
        compute_databus_inverses(inst, b, &params);
        third.push(BUS_SPECS[b].inverses);
    }
    crate::base::timing::phase("    oink: inverses");
    commit_and_send::<C>(inst, ck, t, &third, &mut comms);
    crate::base::timing::phase("    oink: inverse commits");

    params.public_input_delta = compute_public_input_delta(
        &inst.public_inputs,
        &params.beta,
        &params.gamma,
        &Fr::from(inst.pub_inputs_offset as u64),
    );
    compute_grand_product(inst, &params);
    crate::base::timing::phase("    oink: grand product");
    commit_and_send::<C>(inst, ck, t, &[Ent::z_perm], &mut comms);

    let alpha: Fr = if emit_alpha {
        t.challenge("alpha")
    } else {
        Fr::from(0u64)
    };
    let commitments = comms
        .into_iter()
        .zip(&inst.layout.unshifted)
        .map(|(c, e)| c.unwrap_or_else(|| panic!("no commitment for {}", e.name())))
        .collect();
    OinkProverOutput {
        params,
        alpha,
        commitments,
    }
}

/// `w_4 = w_3 η³ + w_2 η² + w_1 η (+ 1 for writes)` at every memory access row.
fn add_ram_rom_memory_records_to_wire_4(inst: &mut ProverInstance, p: &RelationParams<Fr>) {
    let (reads, writes) = (inst.memory_read_records.clone(), inst.memory_write_records.clone());
    for (rows, is_write) in [(reads, false), (writes, true)] {
        for i in rows {
            let v = inst.poly(Ent::w_o).coeffs[i] * p.eta_three
                + inst.poly(Ent::w_r).coeffs[i] * p.eta_two
                + inst.poly(Ent::w_l).coeffs[i] * p.eta;
            inst.poly_mut(Ent::w_4).coeffs[i] = if is_write { v + Fr::from(1u64) } else { v };
        }
    }
}

/// `w_4 = 1 / (rom_logup_gamma + w_1 + η w_2 + η² q_c)` at every ROM-LogUp row.
fn add_rom_logup_inverses_to_wire_4(inst: &mut ProverInstance, p: &RelationParams<Fr>) {
    let rows = inst.rom_logup_records.clone();
    let mut d: Vec<Fr> = rows
        .iter()
        .map(|&i| {
            p.rom_logup_gamma
                + inst.poly(Ent::w_l).coeffs[i]
                + p.eta * inst.poly(Ent::w_r).coeffs[i]
                + p.eta_two * inst.poly(Ent::q_c).coeffs[i]
        })
        .collect();
    batch_invert(&mut d);
    for (i, d) in rows.into_iter().zip(d) {
        inst.poly_mut(Ent::w_4).coeffs[i] = d;
    }
}

/// `lookup_inverses[i] = 1 / (lookup_term_i * table_term_i)` on rows with a lookup gate or a read table entry.
fn compute_logderivative_inverses(inst: &mut ProverInstance, p: &RelationParams<Fr>) {
    let denominators: Vec<Fr> = (inst.flavor.trace_offset..inst.max_end_index)
        .into_par_iter()
        .map_init(Vec::new, |vals, i| {
            let active = inst.poly(Ent::q_lookup).at(i) == Fr::from(1u64)
                || inst.poly(Ent::lookup_read_tags).at(i) == Fr::from(1u64);
            if !active {
                return Fr::zero();
            }
            inst.row_into(i, vals);
            let row = Row {
                vals,
                layout: &inst.layout,
            };
            lookup_term(&row, p) * table_term(&row, p)
        })
        .collect();
    let inv = write_inverses(inst.poly(Ent::lookup_inverses), inst.flavor.trace_offset, denominators);
    *inst.poly_mut(Ent::lookup_inverses) = inv;
}

/// Write `1 / denominators[i]` at row `trace_offset + i` where the denominator is non-zero, into a
/// fresh column sized to the last inverse; `masked` supplies the ZK masking head, which bb
/// batch-inverts along with the whole inverse polynomial.
fn write_inverses(masked: &Poly, trace_offset: usize, mut denominators: Vec<Fr>) -> Poly {
    batch_invert(&mut denominators);
    let extent = denominators.iter().rposition(|d| !d.is_zero()).map_or(0, |i| i + 1);
    let mut inv = Poly::zero(trace_offset + extent);
    for (i, c) in masked.coeffs.iter().take(trace_offset).enumerate() {
        inv.coeffs[i] = *c;
    }
    for (c, d) in inv.coeffs[trace_offset..].iter_mut().zip(denominators) {
        if !d.is_zero() {
            *c = d;
        }
    }
    batch_invert(&mut inv.coeffs[..trace_offset]);
    inv
}

/// bb `SingleBusLookupRelation::compute_logderivative_inverse`: `1 / (L · T)` on read rows and
/// rows with a non-zero read count.
fn compute_databus_inverses(inst: &mut ProverInstance, bus: usize, p: &RelationParams<Fr>) {
    let spec = &BUS_SPECS[bus];
    let one = Fr::from(1u64);
    let denominators: Vec<Fr> = (inst.flavor.trace_offset..inst.max_end_index)
        .into_par_iter()
        .map(|i| {
            let is_read = inst.poly(Ent::q_busread).at(i) == one && inst.poly(spec.selector).at(i) == one;
            let nonzero_count = !inst.poly(spec.read_counts).at(i).is_zero();
            if !(is_read || nonzero_count) {
                return Fr::zero();
            }
            let lookup = inst.poly(Ent::w_r).at(i) * p.beta + inst.poly(Ent::w_l).at(i) + p.gamma;
            let table = inst.poly(Ent::databus_id).at(i) * p.beta + inst.poly(spec.value).at(i) + p.gamma;
            lookup * table
        })
        .collect();
    let inv = write_inverses(inst.poly(spec.inverses), inst.flavor.trace_offset, denominators);
    *inst.poly_mut(spec.inverses) = inv;
}

/// The permutation grand product `z_perm` (bb `compute_grand_product` for `UltraPermutationRelation`).
fn compute_grand_product(inst: &mut ProverInstance, p: &RelationParams<Fr>) {
    let gp_start = inst.flavor.trace_offset;
    let domain_size = inst.final_active_wire_idx + 1;
    let active_size = domain_size - gp_start;
    let wires = [Ent::w_l, Ent::w_r, Ent::w_o, Ent::w_4];
    let ids = [Ent::id_1, Ent::id_2, Ent::id_3, Ent::id_4];
    let sigmas = [Ent::sigma_1, Ent::sigma_2, Ent::sigma_3, Ent::sigma_4];
    let masked = inst.poly(Ent::z_perm);
    let mut z = Poly::zero(gp_start + active_size);
    for (i, c) in masked.coeffs.iter().take(gp_start).enumerate() {
        z.coeffs[i] = *c;
    }
    let terms: Vec<(Fr, Fr)> = (0..active_size - 1)
        .into_par_iter()
        .map(|i| {
            let row = i + gp_start;
            let (mut num, mut den) = (Fr::from(1u64), Fr::from(1u64));
            for k in 0..4 {
                let w = inst.poly(wires[k]).coeffs[row];
                num *= w + inst.poly(ids[k]).coeffs[row] * p.beta + p.gamma;
                den *= w + inst.poly(sigmas[k]).coeffs[row] * p.beta + p.gamma;
            }
            (num, den)
        })
        .collect();
    let (num, den): (Vec<Fr>, Vec<Fr>) = terms.into_iter().unzip();
    let prefix = grand_product(&num, &den);
    z.coeffs[gp_start + 1..gp_start + active_size].copy_from_slice(&prefix[1..]);
    *inst.poly_mut(Ent::z_perm) = z;
}

/// bb `build_gemini_masking_poly`: a random polynomial on the tail-halving support (dense for tiny circuits).
pub fn build_gemini_masking_poly(d: usize, extent: usize, dyadic_size: usize, rng: &mut dyn Rng) -> Poly {
    let _ = dyadic_size;
    if d < 4 {
        let mut poly = Poly::zero(extent);
        for c in poly.coeffs.iter_mut() {
            *c = rng.fr();
        }
        return poly;
    }
    let support = tail_halving_support(d, extent);
    let mut poly = Poly::zero(support.iter().max().map_or(0, |m| m + 1));
    for s in support {
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
