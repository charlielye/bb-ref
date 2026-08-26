//! The prover's view of a circuit: all unshifted polynomials at the dyadic size plus the metadata
//! Oink needs (bb `ProverInstance_`). Built from the circuit builder (M3) or loaded from a bb dump.

use super::flavor::{Ent, FlavorDesc, Layout};
use crate::base::field::{from_bytes_be, Fr};
use crate::base::poly::Poly;
use crate::base::vk::Vk;
use crate::base::{Bn254, CommitmentKey};
use std::path::Path;

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
