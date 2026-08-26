//! The prover's view of a circuit: all unshifted polynomials at the dyadic size plus the metadata
//! Oink needs (bb `ProverInstance_`). Built from the circuit builder (M3) or loaded from a bb dump.

use super::flavor::{Ent, FlavorDesc, Layout};
use super::oink::PERMUTATION_ARGUMENT_VALUE_SEPARATOR;
use crate::base::field::{from_bytes_be, FieldLike, Fr};
use crate::base::poly::Poly;
use crate::base::vk::Vk;
use crate::base::{Bn254, CommitmentKey, Rng};
use crate::circuit::trace::ULTRA_BLOCKS;
use crate::circuit::{Builder, Kind, NUM_ZERO_ROWS, TRACE_OFFSET};
use std::path::Path;

const NUM_WIRES: usize = 4;
const NUM_MASKED_ROWS: usize = 3;

pub struct ProverInstance {
    pub flavor: &'static FlavorDesc,
    pub layout: Layout,
    /// Unshifted polynomials in layout order.
    pub polys: Vec<Poly>,
    pub dyadic_size: usize,
    pub public_inputs: Vec<Fr>,
    pub pub_inputs_offset: usize,
    pub final_active_wire_idx: usize,
    /// bb `polynomials.max_end_index()`: the allocated extent of the largest polynomial.
    pub max_end_index: usize,
    /// Trace row indices of memory accesses (already offset into the full trace).
    pub memory_read_records: Vec<usize>,
    pub memory_write_records: Vec<usize>,
    pub rom_logup_records: Vec<usize>,
}

impl ProverInstance {
    pub fn log_n(&self) -> usize {
        self.dyadic_size.trailing_zeros() as usize
    }
    pub fn poly(&self, e: Ent) -> &Poly {
        &self.polys[self.layout.idx(e)]
    }
    pub fn poly_mut(&mut self, e: Ent) -> &mut Poly {
        let i = self.layout.idx(e);
        &mut self.polys[i]
    }
    /// All entity polynomials (unshifted then shifted) as the sumcheck sees them.
    pub fn all_polys(&self) -> Vec<Poly> {
        let mut all = self.polys.clone();
        for e in &self.layout.shifted {
            all.push(self.poly(*e).shifted());
        }
        all
    }
    /// One row of all entity values (unshifted at `i`, shifted at `i + 1`).
    pub fn row(&self, i: usize) -> Vec<Fr> {
        let mut r: Vec<Fr> = self.polys.iter().map(|p| p.coeffs[i]).collect();
        for e in &self.layout.shifted {
            let p = self.poly(*e);
            r.push(if i + 1 < p.len() { p.coeffs[i + 1] } else { Fr::from(0u64) });
        }
        r
    }
    /// The verification key: commitments to the precomputed polynomials.
    pub fn compute_vk(&self, ck: &CommitmentKey) -> Vk<Bn254> {
        let m = self.layout.num_masking;
        let comms = (m..m + self.layout.num_precomputed).map(|i| ck.commit(&self.polys[i])).collect();
        Vk {
            log_circuit_size: Fr::from(self.log_n() as u64),
            num_public_inputs: Fr::from(self.public_inputs.len() as u64),
            pub_inputs_offset: Fr::from(self.pub_inputs_offset as u64),
            comms,
        }
    }

    /// Finalize a circuit and lay its trace out as polynomials (bb `ProverInstance_(Circuit&)` +
    /// `TraceToPolynomials::populate` + `compute_permutation_argument_polynomials`). `rng` supplies
    /// the ZK masking values written to rows 1..=3 of the witness polynomials.
    pub fn from_builder(flavor: &'static FlavorDesc, builder: &mut Builder, rng: &mut dyn Rng) -> Self {
        let layout = flavor.layout();
        builder.finalize_circuit();
        builder.blocks.compute_offsets(TRACE_OFFSET);
        let blocks = &builder.blocks;
        // Lookup tables (none yet) sit at the lookup block's offset; the trace must hold both.
        let tables_size = 0;
        let tables_end = blocks.get(crate::circuit::BlockId::Lookup).trace_offset + tables_size;
        let trace_end = TRACE_OFFSET + NUM_ZERO_ROWS + blocks.total_content_size();
        let dyadic_size = tables_end.max(trace_end).next_power_of_two();
        let final_active_wire_idx = blocks.blocks.iter().filter(|b| !b.is_empty()).last().map(|b| b.trace_end() - 1).expect("empty circuit");
        let active_size = final_active_wire_idx + 1;

        let mut polys: Vec<Poly> = layout.unshifted.iter().map(|_| Poly::zero(dyadic_size)).collect();
        let idx = |e: Ent| layout.idx(e);
        let wires = [Ent::w_l, Ent::w_r, Ent::w_o, Ent::w_4];

        // Wires, non-gate selectors, gate selectors, and copy cycles in (block, row, wire) order.
        let mut cycles: Vec<Vec<(usize, usize)>> = vec![vec![]; builder.num_variables()];
        for (block, (_, kind)) in blocks.blocks.iter().zip(ULTRA_BLOCKS.iter()) {
            for (r, row) in block.rows.iter().enumerate() {
                let i = block.trace_offset + r;
                for (w, ent) in wires.iter().enumerate() {
                    let var = row.wires[w];
                    let real = builder.real_variable_index[var as usize];
                    polys[idx(*ent)].coeffs[i] = builder.get_variable(var);
                    cycles[real as usize].push((w, i));
                }
                for (ent, v) in [(Ent::q_m, row.q_m), (Ent::q_c, row.q_c), (Ent::q_l, row.q_1), (Ent::q_r, row.q_2), (Ent::q_o, row.q_3), (Ent::q_4, row.q_4)] {
                    polys[idx(ent)].coeffs[i] = v;
                }
                if let Some(ent) = gate_selector_entity(*kind) {
                    polys[idx(ent)].coeffs[i] = row.gate_selector(*kind);
                }
            }
        }

        // Permutation polynomials: identity, then cycle links with tags, then the public-input override.
        let sep = Fr::from(PERMUTATION_ARGUMENT_VALUE_SEPARATOR);
        let sigmas = [Ent::sigma_1, Ent::sigma_2, Ent::sigma_3, Ent::sigma_4];
        let ids = [Ent::id_1, Ent::id_2, Ent::id_3, Ent::id_4];
        for w in 0..NUM_WIRES {
            for i in NUM_ZERO_ROWS..active_size {
                let v = Fr::from(i as u64) + sep * Fr::from(w as u64);
                polys[idx(sigmas[w])].coeffs[i] = v;
                polys[idx(ids[w])].coeffs[i] = v;
            }
        }
        let tag_base = sep * Fr::from(NUM_WIRES as u64);
        for (var, cycle) in cycles.iter().enumerate() {
            if cycle.is_empty() {
                continue;
            }
            for k in 0..cycle.len() - 1 {
                let (w, i) = cycle[k];
                let (nw, ni) = cycle[k + 1];
                polys[idx(sigmas[w])].coeffs[i] = Fr::from(ni as u64) + sep * Fr::from(nw as u64);
            }
            let tag = builder.real_variable_tags[var];
            let (lw, li) = *cycle.last().unwrap();
            polys[idx(sigmas[lw])].coeffs[li] = tag_base + Fr::from(builder.tau[&tag] as u64);
            let (fw, fi) = cycle[0];
            polys[idx(ids[fw])].coeffs[fi] = tag_base + Fr::from(tag as u64);
        }
        let pub_inputs_offset = blocks.get(crate::circuit::BlockId::PubInputs).trace_offset;
        let num_public_inputs = builder.public_inputs().len();
        for i in 0..num_public_inputs {
            let r = pub_inputs_offset + i;
            polys[idx(Ent::sigma_1)].coeffs[r] = -Fr::from(r as u64 + 1);
        }

        polys[idx(Ent::lagrange_first)].coeffs[TRACE_OFFSET] = Fr::one();
        polys[idx(Ent::lagrange_last)].coeffs[final_active_wire_idx] = Fr::one();

        if flavor.has_zk {
            for e in [Ent::w_l, Ent::w_r, Ent::w_o, Ent::w_4, Ent::z_perm, Ent::lookup_read_counts, Ent::lookup_read_tags, Ent::lookup_inverses] {
                for j in 0..NUM_MASKED_ROWS {
                    polys[idx(e)].coeffs[NUM_ZERO_ROWS + j] = rng.fr();
                }
            }
        }

        let public_inputs = (0..num_public_inputs).map(|i| polys[idx(Ent::w_r)].coeffs[pub_inputs_offset + i]).collect();
        let memory_offset = blocks.get(crate::circuit::BlockId::Memory).trace_offset;
        let rebase = |v: &[u32]| v.iter().map(|i| *i as usize + memory_offset).collect();
        Self {
            flavor,
            layout,
            polys,
            dyadic_size,
            public_inputs,
            pub_inputs_offset,
            final_active_wire_idx,
            max_end_index: active_size.max(tables_end),
            memory_read_records: rebase(&builder.memory_read_records),
            memory_write_records: rebase(&builder.memory_write_records),
            rom_logup_records: rebase(&builder.rom_logup_records),
        }
    }

    /// Load a bb-dumped instance (see `bbref_dump.test.cpp`).
    pub fn load_dump(flavor: &'static FlavorDesc, dir: impl AsRef<Path>) -> Self {
        let dir = dir.as_ref();
        let layout = flavor.layout();
        let meta = std::fs::read_to_string(dir.join("meta.txt")).expect("meta.txt");
        let get = |k: &str| -> usize {
            meta.lines()
                .find_map(|l| l.strip_prefix(&format!("{k}=")))
                .unwrap_or_else(|| panic!("meta.txt missing {k}"))
                .trim()
                .parse()
                .unwrap()
        };
        let dyadic_size = get("dyadic_size");
        let read_frs = |name: &str| -> Vec<Fr> {
            std::fs::read(dir.join(name)).unwrap_or_else(|e| panic!("missing {name}: {e}")).chunks(32).map(from_bytes_be::<Fr>).collect()
        };
        let read_idx = |name: &str| -> Vec<usize> {
            std::fs::read_to_string(dir.join(name)).unwrap_or_default().lines().filter(|l| !l.is_empty()).map(|l| l.trim().parse().unwrap()).collect()
        };
        let polys = layout
            .unshifted
            .iter()
            .map(|e| {
                let c = read_frs(&format!("{}.bin", e.name().to_uppercase()));
                assert_eq!(c.len(), dyadic_size, "{}: unexpected length", e.name());
                Poly::from_coeffs(c)
            })
            .collect();
        Self {
            flavor,
            layout,
            polys,
            dyadic_size,
            public_inputs: read_frs("public_inputs.bin"),
            pub_inputs_offset: get("pub_inputs_offset"),
            final_active_wire_idx: get("final_active_wire_idx"),
            max_end_index: get("max_end_index"),
            memory_read_records: read_idx("memory_read_records.txt"),
            memory_write_records: read_idx("memory_write_records.txt"),
            rom_logup_records: read_idx("rom_logup_records.txt"),
        }
    }
}

/// The selector polynomial a block's gate kind populates.
fn gate_selector_entity(kind: Kind) -> Option<Ent> {
    Some(match kind {
        Kind::None => return None,
        Kind::Lookup => Ent::q_lookup,
        Kind::Arith => Ent::q_arith,
        Kind::DeltaRange => Ent::q_delta_range,
        Kind::Elliptic => Ent::q_elliptic,
        Kind::Memory => Ent::q_memory,
        Kind::Nnf => Ent::q_nnf,
        Kind::Poseidon2Ext => Ent::q_poseidon2_external,
        Kind::Poseidon2Int => Ent::q_poseidon2_internal,
    })
}
