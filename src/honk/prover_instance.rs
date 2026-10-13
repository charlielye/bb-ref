//! The prover's view of a circuit: all unshifted polynomials at the dyadic size plus the metadata
//! Oink needs (bb `ProverInstance_`). Built from the circuit builder (M3) or loaded from a bb dump.

use super::flavor::{Ent, FlavorDesc, Layout, BUS_SPECS};
use super::oink::PERMUTATION_ARGUMENT_VALUE_SEPARATOR;
use crate::base::field::{from_bytes_be, FieldLike, Fr};
use crate::base::poly::Poly;
use crate::base::vk::Vk;
use crate::base::{Bn254, CommitmentKey, Rng};
use crate::circuit::{BlockId, Builder, Kind, NUM_ZERO_ROWS};
use rayon::prelude::*;
use std::path::Path;

const NUM_WIRES: usize = 4;
const NUM_MASKED_ROWS: usize = 3;
/// bb `NUM_DISABLED_ROWS_IN_SUMCHECK`: databus data starts here regardless of the flavor's trace offset.
pub const DATABUS_OFFSET: usize = 4;

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
    /// bb `builder.ipa_proof` (RollupIO circuits): appended verbatim after the Honk proof.
    pub ipa_proof: Vec<Fr>,
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
    /// One row of all entity values (unshifted at `i`, shifted at `i + 1`).
    pub fn row(&self, i: usize) -> Vec<Fr> {
        let mut out = Vec::new();
        self.row_into(i, &mut out);
        out
    }
    /// `row` into a reused buffer (the logup-inverse loop visits every row).
    pub fn row_into(&self, i: usize, out: &mut Vec<Fr>) {
        out.clear();
        out.extend(self.polys.iter().map(|p| p.at(i)));
        out.extend(self.layout.shifted.iter().map(|e| self.poly(*e).at(i + 1)));
    }
    /// The verification key: commitments to the precomputed polynomials.
    pub fn compute_vk(&self, ck: &CommitmentKey) -> Vk<Bn254> {
        let m = self.layout.num_masking;
        let polys: Vec<_> = self.polys[m..m + self.layout.num_precomputed].iter().collect();
        let comms = ck.batch_commit(&polys);
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
        Self::build(flavor, builder, rng, false)
    }

    /// `from_builder` for a builder that is dropped afterwards: its slack and gate rows are freed
    /// as soon as they are consumed, so they never coexist with the whole instance.
    pub fn from_circuit(flavor: &'static FlavorDesc, mut builder: Builder, rng: &mut dyn Rng) -> Self {
        Self::build(flavor, &mut builder, rng, true)
    }

    fn build(flavor: &'static FlavorDesc, builder: &mut Builder, rng: &mut dyn Rng, release: bool) -> Self {
        let mut _g_inst = crate::base::bench::Scope::new("inst/wires_selectors_cycles");
        let layout = flavor.layout();
        let trace_offset = flavor.trace_offset;
        builder.finalize_circuit();
        if release {
            builder.release_slack();
        }
        builder.blocks.compute_offsets(trace_offset);
        let blocks = &builder.blocks;
        // Lookup tables sit at the lookup block's offset; the trace must hold both.
        let tables_size = builder.tables_size();
        let tables_end = blocks.get(BlockId::Lookup).trace_offset + tables_size;
        let trace_end = trace_offset + NUM_ZERO_ROWS + blocks.total_content_size();
        let dyadic_size = tables_end.max(trace_end).next_power_of_two();
        let final_active_wire_idx = blocks
            .blocks
            .iter()
            .filter(|b| !b.is_empty())
            .last()
            .map(|b| b.trace_end() - 1)
            .expect("empty circuit");
        let active_size = final_active_wire_idx + 1;

        // Each column is allocated to its content: consumers zero-default past a column's end
        // (`Polynomial::at`, the sumcheck's trailing-zero trim, `add_scaled_batch` zero-extension),
        // and the oink prover sizes the columns it derives (z_perm, the inverses, the Gemini mask)
        // itself. Only entities a later phase writes past their builder content keep `dyadic_size`.
        let masked_end = if flavor.has_zk {
            NUM_ZERO_ROWS + NUM_MASKED_ROWS
        } else {
            0
        };
        let mut derived_end: std::collections::HashMap<Ent, usize> = std::collections::HashMap::new();
        for (desc, block) in blocks.iter() {
            for kind in desc.kinds {
                let e = gate_selector_entity(*kind);
                let end = derived_end.entry(e).or_insert(0);
                *end = (*end).max(block.trace_offset + block.rows.len());
            }
        }
        let mut max_bus_len = 0;
        for b in (0..BUS_SPECS.len()).filter(|b| layout.has(BUS_SPECS[*b].value)) {
            let spec = &BUS_SPECS[b];
            let end = DATABUS_OFFSET + builder.bus(b).len();
            max_bus_len = max_bus_len.max(end);
            derived_end.insert(spec.value, end.max(masked_end));
            derived_end.insert(spec.read_counts, end.max(masked_end));
            derived_end.insert(spec.indicator, end);
            derived_end.insert(spec.inverses, masked_end);
        }
        let ecc_op_end = if layout.has(Ent::ecc_op_wire_1) {
            let b = blocks.get(BlockId::EccOp);
            b.trace_offset - NUM_ZERO_ROWS + b.len()
        } else {
            0
        };
        let table_alloc = if tables_size == 0 { 0 } else { tables_end };
        let len_of = |e: Ent| -> usize {
            use Ent::*;
            if let Some(end) = derived_end.get(&e) {
                return *end;
            }
            match e {
                w_l | w_r | w_o | w_4 => active_size,
                q_m | q_c | q_l | q_r | q_o | q_4 | q_5 => active_size,
                sigma_1 | sigma_2 | sigma_3 | sigma_4 | id_1 | id_2 | id_3 | id_4 => active_size,
                table_1 | table_2 | table_3 | table_4 => table_alloc,
                lookup_read_counts | lookup_read_tags => table_alloc.max(masked_end),
                lookup_inverses | z_perm => masked_end,
                gemini_masking_poly => 0,
                lagrange_first => trace_offset + 1,
                lagrange_last => final_active_wire_idx + 1,
                lagrange_ecc_op | ecc_op_wire_1 | ecc_op_wire_2 | ecc_op_wire_3 | ecc_op_wire_4 => ecc_op_end,
                databus_id => max_bus_len,
                _ => dyadic_size,
            }
        };
        // Only the selectors are read from the gate rows; the other columns are written once the
        // rows are consumed (and, when `release`, freed). On wasm, allocating commits memory, so
        // they are also allocated only then; natively pages are committed when written, and an
        // allocation after the free would have calloc zero the reused heap memory serially.
        let selectors = [Ent::q_m, Ent::q_c, Ent::q_l, Ent::q_r, Ent::q_o, Ent::q_4, Ent::q_5];
        let from_rows: Vec<bool> = layout
            .unshifted
            .iter()
            .map(|e| !cfg!(target_family = "wasm") || selectors.contains(e) || blocks.iter().any(|(d, _)| d.kinds.iter().any(|k| gate_selector_entity(*k) == *e)))
            .collect();
        let mut polys: Vec<Poly> = (layout.unshifted.iter().zip(&from_rows))
            .map(|(e, early)| Poly::zero(if *early { len_of(*e) } else { 0 }))
            .collect();
        let idx = |e: Ent| layout.idx(e);
        let has = |e: Ent| layout.has(e);
        let wires = [Ent::w_l, Ent::w_r, Ent::w_o, Ent::w_4];

        // Non-gate selectors, gate selectors, and each wire cell's real variable, over row chunks
        // of all blocks in parallel (the arithmetic block dominates). Rows are disjoint, so the
        // columns are written through raw pointers. Blocks are contiguous from `base`, so the
        // cells are in (block, row, wire) order.
        let base = trace_offset + NUM_ZERO_ROWS;
        let mut cell_real: Vec<u32> = vec![0; NUM_WIRES * blocks.total_content_size()];
        {
            use crate::base::msm::SendPtr;
            let cols: Vec<SendPtr<Fr>> = polys.iter_mut().map(|p| SendPtr(p.coeffs.as_mut_ptr())).collect();
            let col = |e: Ent| cols[idx(e)].0;
            let cells = SendPtr(cell_real.as_mut_ptr());
            let cells = &cells;
            let real_index = &builder.real_variable_index;
            let tasks: Vec<_> = blocks
                .iter()
                .flat_map(|(d, b)| {
                    b.rows
                        .chunks(1 << 12)
                        .enumerate()
                        .map(move |(k, rows)| (d, b.trace_offset + (k << 12), rows))
                })
                .collect();
            tasks.par_iter().for_each(|&(desc, start, rows)| {
                for (r, row) in rows.iter().enumerate() {
                    let i = start + r;
                    unsafe {
                        for w in 0..NUM_WIRES {
                            *cells.0.add(NUM_WIRES * (i - base) + w) = real_index[row.wires[w] as usize];
                        }
                        for (ent, v) in [
                            (Ent::q_m, row.q_m),
                            (Ent::q_c, row.q_c),
                            (Ent::q_l, row.q_1),
                            (Ent::q_r, row.q_2),
                            (Ent::q_o, row.q_3),
                            (Ent::q_4, row.q_4),
                            (Ent::q_5, row.q_5),
                        ] {
                            if has(ent) {
                                *col(ent).add(i) = v;
                            }
                        }
                        for kind in desc.kinds {
                            let ent = gate_selector_entity(*kind);
                            if has(ent) {
                                *col(ent).add(i) = row.gate_selector(*kind);
                            }
                        }
                    }
                }
            });
        }
        if release {
            for b in &mut builder.blocks.blocks {
                b.rows = Vec::new();
            }
        }
        for (k, e) in layout.unshifted.iter().enumerate() {
            if !from_rows[k] {
                polys[k] = Poly::zero(len_of(*e));
            }
        }
        // Wires from the cells' real variables.
        {
            use crate::base::msm::SendPtr;
            let cols: [SendPtr<Fr>; NUM_WIRES] = std::array::from_fn(|w| SendPtr(polys[idx(wires[w])].coeffs.as_mut_ptr()));
            let (cols, vars) = (&cols, &builder.variables);
            cell_real.par_chunks(NUM_WIRES << 12).enumerate().for_each(|(k, chunk)| {
                for (c, real) in chunk.iter().enumerate() {
                    let cell = k * (NUM_WIRES << 12) + c;
                    unsafe { *cols[cell % NUM_WIRES].0.add(base + cell / NUM_WIRES) = vars[*real as usize] };
                }
            });
        }
        let blocks = &builder.blocks;
        // Copy cycles in CSR layout (counts, prefix sum, scatter) rather than one Vec per variable:
        // a vector per variable is millions of small allocations on a rollup circuit. Count and
        // scatter split the variables into one range per thread; each scans every cell in order,
        // so each cycle's nodes keep the serial (block, row, wire) order the sigmas depend on.
        let num_vars = builder.num_variables();
        let per = num_vars.div_ceil(rayon::current_num_threads()).max(1);
        let mut cycle_start: Vec<u32> = vec![0; num_vars + 1];
        cycle_start[1..]
            .par_chunks_mut(per)
            .enumerate()
            .for_each(|(t, counts)| {
                let lo = (t * per) as u32;
                for v in &cell_real {
                    if let Some(c) = counts.get_mut(v.wrapping_sub(lo) as usize) {
                        *c += 1;
                    }
                }
            });
        for v in 1..cycle_start.len() {
            cycle_start[v] += cycle_start[v - 1];
        }
        let mut cycle_flat: Vec<u32> = vec![0; *cycle_start.last().unwrap() as usize];
        let mut parts = Vec::new();
        let mut rest = cycle_flat.as_mut_slice();
        for lo in (0..num_vars).step_by(per) {
            let hi = (lo + per).min(num_vars);
            let (part, tail) = std::mem::take(&mut rest).split_at_mut((cycle_start[hi] - cycle_start[lo]) as usize);
            parts.push((lo, hi, part));
            rest = tail;
        }
        parts.into_par_iter().for_each(|(lo, hi, part)| {
            let mut cursor: Vec<u32> = cycle_start[lo..hi].iter().map(|s| s - cycle_start[lo]).collect();
            for (c, v) in cell_real.iter().enumerate() {
                if let Some(k) = cursor.get_mut(v.wrapping_sub(lo as u32) as usize) {
                    part[*k as usize] = (NUM_WIRES * base + c) as u32;
                    *k += 1;
                }
            }
        });

        crate::base::timing::phase("      inst: wires+selectors+cycles");
        drop(_g_inst);
        _g_inst = crate::base::bench::Scope::new("inst/sigma_id");
        // Permutation polynomials: identity, then cycle links with tags, then the public-input override.
        let sep = Fr::from(PERMUTATION_ARGUMENT_VALUE_SEPARATOR);
        let sigmas = [Ent::sigma_1, Ent::sigma_2, Ent::sigma_3, Ent::sigma_4];
        let ids = [Ent::id_1, Ent::id_2, Ent::id_3, Ent::id_4];
        // `Fr::from(u64)` is a Montgomery multiplication; the identity values are consecutive, so
        // one incremental row table serves the fills and the cycle links below with an add each.
        let row_val: Vec<Fr> = {
            let mut v = Vec::with_capacity(active_size);
            let mut cur = Fr::from(0u64);
            for _ in 0..active_size {
                v.push(cur);
                cur += Fr::one();
            }
            v
        };
        let sep_w: [Fr; NUM_WIRES] = std::array::from_fn(|w| sep * Fr::from(w as u64));
        // Identity fill, rows in parallel per wire (bb `compute_permutation_argument_polynomials`
        // runs this on the pool too; serial it was ~0.1s per flow).
        for w in 0..NUM_WIRES {
            for e in [sigmas[w], ids[w]] {
                let rv = &row_val;
                polys[idx(e)].coeffs[NUM_ZERO_ROWS..active_size]
                    .par_iter_mut()
                    .enumerate()
                    .for_each(|(j, x)| *x = rv[NUM_ZERO_ROWS + j] + sep_w[w]);
            }
        }
        let tag_base = sep * Fr::from(NUM_WIRES as u64);
        let ent_of = |e: u32| ((e >> 2) as usize, (e & 3) as usize);
        // Cycle links: every (wire, row) belongs to exactly one variable's cycle, so the writes of
        // different variables never alias and the loop runs over variables in parallel.
        {
            let sig_ptrs: [crate::base::msm::SendPtr<Fr>; NUM_WIRES] =
                std::array::from_fn(|w| crate::base::msm::SendPtr(polys[idx(sigmas[w])].coeffs.as_mut_ptr()));
            let id_ptrs: [crate::base::msm::SendPtr<Fr>; NUM_WIRES] =
                std::array::from_fn(|w| crate::base::msm::SendPtr(polys[idx(ids[w])].coeffs.as_mut_ptr()));
            let (sig_ptrs, id_ptrs) = (&sig_ptrs, &id_ptrs);
            let (cycle_flat, cycle_start, row_val) = (&cycle_flat, &cycle_start, &row_val);
            let tags = &builder.real_variable_tags;
            // Per-tag link values, so the loop does no Montgomery conversions or hash lookups.
            let num_tags = builder.tau.iter().map(|(k, v)| *k.max(v) as usize + 1).max().unwrap_or(0);
            let tag_val = |t: u32| tag_base + Fr::from(t as u64);
            let mut tau_val = vec![Fr::zero(); num_tags];
            for (k, v) in &builder.tau {
                tau_val[*k as usize] = tag_val(*v);
            }
            let id_val: Vec<Fr> = (0..num_tags as u32).map(tag_val).collect();
            let (tau_val, id_val) = (&tau_val, &id_val);
            (0..builder.num_variables()).into_par_iter().with_min_len(256).for_each(|var| {
                let cycle = &cycle_flat[cycle_start[var] as usize..cycle_start[var + 1] as usize];
                if cycle.is_empty() {
                    return;
                }
                for k in 0..cycle.len() - 1 {
                    let (i, w) = ent_of(cycle[k]);
                    let (ni, nw) = ent_of(cycle[k + 1]);
                    unsafe { *sig_ptrs[w].0.add(i) = row_val[ni] + sep_w[nw] };
                }
                let tag = tags[var];
                let (li, lw) = ent_of(*cycle.last().unwrap());
                unsafe { *sig_ptrs[lw].0.add(li) = tau_val[tag as usize] };
                let (fi, fw) = ent_of(cycle[0]);
                unsafe { *id_ptrs[fw].0.add(fi) = id_val[tag as usize] };
            });
        }
        let pub_inputs_offset = blocks.get(BlockId::PubInputs).trace_offset;
        let num_public_inputs = builder.public_inputs().len();
        for i in 0..num_public_inputs {
            let r = pub_inputs_offset + i;
            polys[idx(Ent::sigma_1)].coeffs[r] = -Fr::from(r as u64 + 1);
        }

        crate::base::timing::phase("      inst: sigma/id");
        drop(_g_inst);
        _g_inst = crate::base::bench::Scope::new("inst/tables_bus_masking");
        // bb `construct_lookup_table_polynomials` + `construct_lookup_read_counts`.
        if has(Ent::table_1) {
            let mut offset = blocks.get(BlockId::Lookup).trace_offset;
            for table in &builder.lookup_tables {
                let index: std::collections::HashMap<[Fr; 3], u32, crate::base::srs::LimbHashBuilder> = (0..table
                    .size())
                    .map(|i| {
                        (
                            [table.columns[0][i], table.columns[1][i], table.columns[2][i]],
                            i as u32,
                        )
                    })
                    .collect();
                // Resolve the gates' table rows in parallel, then count them as integers.
                let rows: Vec<u32> = table
                    .lookup_gates
                    .par_iter()
                    .map(|gate| index[&gate.to_table_components(table.use_twin_keys)])
                    .collect();
                let mut counts = vec![0u32; table.size()];
                for r in rows {
                    counts[r as usize] += 1;
                }
                for (i, c) in counts.into_iter().enumerate().filter(|(_, c)| *c != 0) {
                    polys[idx(Ent::lookup_read_counts)].coeffs[offset + i] = Fr::from(c as u64);
                    polys[idx(Ent::lookup_read_tags)].coeffs[offset + i] = Fr::one();
                }
                let rows = offset..offset + table.size();
                for (c, e) in [Ent::table_1, Ent::table_2, Ent::table_3].into_iter().enumerate() {
                    polys[idx(e)].coeffs[rows.clone()].copy_from_slice(&table.columns[c]);
                }
                polys[idx(Ent::table_4)].coeffs[rows].fill(Fr::from(table.table_index as u64));
                offset += table.size();
            }
        } else {
            assert!(
                builder.lookup_tables.is_empty(),
                "lookup gates in a flavor without lookups"
            );
        }
        polys[idx(Ent::lagrange_first)].coeffs[trace_offset] = Fr::one();
        polys[idx(Ent::lagrange_last)].coeffs[final_active_wire_idx] = Fr::one();

        // ECC op wires copy the wires of the ecc_op block one row earlier (`ecc_op_wire[r] == w_shift[r]`).
        if has(Ent::ecc_op_wire_1) {
            let b = blocks.get(BlockId::EccOp);
            let start = b.trace_offset - NUM_ZERO_ROWS;
            let op_wires = [
                Ent::ecc_op_wire_1,
                Ent::ecc_op_wire_2,
                Ent::ecc_op_wire_3,
                Ent::ecc_op_wire_4,
            ];
            for i in 0..ecc_op_end - start {
                for k in 0..NUM_WIRES {
                    polys[idx(op_wires[k])].coeffs[start + i] = polys[idx(wires[k])].coeffs[b.trace_offset + i];
                }
                polys[idx(Ent::lagrange_ecc_op)].coeffs[start + i] = Fr::one();
            }
        }

        // Databus columns start at row NUM_DISABLED_ROWS_IN_SUMCHECK in every flavor so that
        // commitments agree across the IVC boundary.
        let mut max_bus_size = 0;
        for b in layout.buses() {
            let spec = &BUS_SPECS[b];
            let bus = builder.bus(b);
            max_bus_size = max_bus_size.max(bus.len());
            for i in 0..bus.len() {
                polys[idx(spec.value)].coeffs[DATABUS_OFFSET + i] = builder.get_variable(bus.data[i]);
                polys[idx(spec.read_counts)].coeffs[DATABUS_OFFSET + i] = Fr::from(bus.read_counts[i] as u64);
                polys[idx(spec.indicator)].coeffs[DATABUS_OFFSET + i] = Fr::one();
            }
        }
        if has(Ent::databus_id) {
            for i in 0..max_bus_size {
                polys[idx(Ent::databus_id)].coeffs[DATABUS_OFFSET + i] = Fr::from(i as u64);
            }
        }

        // ZK masking values, drawn in bb's allocation order.
        if flavor.has_zk {
            let mut mask = |e: Ent| {
                for j in 0..NUM_MASKED_ROWS {
                    polys[idx(e)].coeffs[NUM_ZERO_ROWS + j] = rng.fr();
                }
            };
            for e in wires {
                mask(e);
            }
            mask(Ent::z_perm);
            if has(Ent::lookup_read_counts) {
                mask(Ent::lookup_read_counts);
                mask(Ent::lookup_read_tags);
                mask(Ent::lookup_inverses);
            }
            for (local, b) in layout.buses().into_iter().enumerate() {
                let spec = &BUS_SPECS[b];
                if local != 0 {
                    mask(spec.value);
                }
                mask(spec.read_counts);
                mask(spec.inverses);
            }
        }

        if std::env::var_os("BBREF_COL_STATS").is_some() {
            let mut used = 0usize;
            let mut alloc = 0usize;
            eprintln!(
                "[col stats] dyadic={dyadic_size} active={active_size} tables_end={tables_end} pubs={num_public_inputs}"
            );
            for (desc, block) in blocks.iter() {
                eprintln!(
                    "[col stats]   block {:?} offset={} rows={}",
                    desc.id,
                    block.trace_offset,
                    block.rows.len()
                );
            }
            for (k, p) in polys.iter().enumerate() {
                let start = p.coeffs.iter().position(|c| !c.is_zero()).unwrap_or(0);
                let end = p.coeffs.iter().rposition(|c| !c.is_zero()).map_or(0, |i| i + 1);
                used += end.saturating_sub(start);
                alloc += p.len();
                eprintln!(
                    "[col stats]   {:>28} start={start} end={end}",
                    format!("{:?}", layout.unshifted[k])
                );
            }
            eprintln!(
                "[col stats] window-used {} MB of {} MB allocated",
                used * 32 / (1 << 20),
                alloc * 32 / (1 << 20)
            );
        }
        crate::base::timing::phase("      inst: tables+bus+masking");
        drop(_g_inst);
        let public_inputs = (0..num_public_inputs)
            .map(|i| polys[idx(Ent::w_r)].coeffs[pub_inputs_offset + i])
            .collect();
        let memory_offset = blocks.get(BlockId::Memory).trace_offset;
        let rebase = |v: &[u32]| v.iter().map(|i| *i as usize + memory_offset).collect();
        let mut max_end_index = active_size.max(tables_end);
        if !layout.buses().is_empty() {
            max_end_index = max_end_index.max(DATABUS_OFFSET + max_bus_size);
        }
        Self {
            flavor,
            layout,
            polys,
            dyadic_size,
            public_inputs,
            pub_inputs_offset,
            final_active_wire_idx,
            max_end_index,
            memory_read_records: rebase(&builder.memory_read_records),
            memory_write_records: rebase(&builder.memory_write_records),
            rom_logup_records: rebase(&builder.rom_logup_records),
            ipa_proof: builder.ipa_proof.clone(),
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
            std::fs::read(dir.join(name))
                .unwrap_or_else(|e| panic!("missing {name}: {e}"))
                .chunks(32)
                .map(from_bytes_be::<Fr>)
                .collect()
        };
        let read_idx = |name: &str| -> Vec<usize> {
            std::fs::read_to_string(dir.join(name))
                .unwrap_or_default()
                .lines()
                .filter(|l| !l.is_empty())
                .map(|l| l.trim().parse().unwrap())
                .collect()
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
            ipa_proof: vec![],
        }
    }
}

/// The selector polynomial a gate kind populates.
fn gate_selector_entity(kind: Kind) -> Ent {
    match kind {
        Kind::None => unreachable!("blocks never own the null gate kind"),
        Kind::BusRead => Ent::q_busread,
        Kind::Lookup => Ent::q_lookup,
        Kind::Arith => Ent::q_arith,
        Kind::BilinearBatchedEq => Ent::q_bilinear_batched_eq,
        Kind::DeltaRange => Ent::q_delta_range,
        Kind::Elliptic => Ent::q_elliptic,
        Kind::Memory => Ent::q_memory,
        Kind::Nnf => Ent::q_nnf,
        Kind::Poseidon2Ext => Ent::q_poseidon2_external,
        Kind::Poseidon2Int => Ent::q_poseidon2_internal,
        Kind::Poseidon2ExtInitial => Ent::q_poseidon2_external_initial,
        Kind::Poseidon2QuadInt => Ent::q_poseidon2_quad_internal,
        Kind::Poseidon2QuadIntTerminal => Ent::q_poseidon2_quad_internal_terminal,
        Kind::Poseidon2TransitionEntry => Ent::q_poseidon2_transition_entry,
    }
}
