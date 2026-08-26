//! Flavors as data. A flavor is a list of relations plus a few constants; the entity layout
//! (the order of polynomials/commitments/evaluations) is *derived* from the relation list by the
//! same algorithm as bb's flavor codegen (`scripts/flavor-codegen/src/main.ts::deriveLayout`).

use std::collections::HashSet;

macro_rules! entities {
    ($($e:ident),* $(,)?) => {
        /// Every polynomial that appears in any flavor. Names match bb's `EntityId`.
        #[allow(non_camel_case_types)]
        #[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
        #[repr(u16)]
        pub enum Ent { $($e),* }
        impl Ent {
            pub const ALL: &'static [Ent] = &[$(Ent::$e),*];
            pub const COUNT: usize = Ent::ALL.len();
            pub fn name(self) -> &'static str { match self { $(Ent::$e => stringify!($e)),* } }
        }
    };
}

entities! {
    // precomputed
    sigma_1, sigma_2, sigma_3, sigma_4, id_1, id_2, id_3, id_4, lagrange_first, lagrange_last,
    q_lookup, table_1, table_2, table_3, table_4,
    q_m, q_l, q_r, q_o, q_4, q_c, q_arith, q_delta_range, q_elliptic, q_memory, q_nnf,
    q_poseidon2_external, q_poseidon2_internal,
    // witness
    w_l, w_r, w_o, w_4, z_perm, lookup_inverses, lookup_read_counts, lookup_read_tags,
    // masking (ZK)
    gemini_masking_poly,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Precomputed,
    Witness,
    Masking,
}

/// A relation's static description (bb `scripts/flavor-codegen/src/relations/*.ts` plus the
/// `SUBRELATION_PARTIAL_LENGTHS` / `SUBRELATION_LINEARLY_INDEPENDENT` arrays of the C++ relation).
pub struct RelSpec {
    pub entities: &'static [(Ent, Kind)],
    pub shifted: &'static [Ent],
    /// Named subsets in declaration order (unioned across relations, first mention wins).
    pub subsets: &'static [(&'static str, &'static [Ent])],
    pub partial_lengths: &'static [usize],
    pub lin_indep: &'static [bool],
    pub gate_block: Option<&'static str>,
    /// Contributes entities to the layout but has no algebraic constraint.
    pub structural: bool,
    /// Contribution enters the relation scaled by the offset-row indicator `L` instead of `1 - L`.
    pub offset_only: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Rel {
    Permutation,
    LogDerivLookup,
    Arithmetic,
    DeltaRange,
    Elliptic,
    Memory,
    NonNativeField,
    Poseidon2External,
    Poseidon2Internal,
    Masking,
}

use Ent::*;
use Kind::*;

const WIRES: &[Ent] = &[w_l, w_r, w_o, w_4];
const ALL_SHIFTS: &[Ent] = &[w_l, w_r, w_o, w_4];
const ALL_TRUE: &[bool] = &[true; 8];

impl Rel {
    pub fn spec(self) -> RelSpec {
        const DEFAULT: RelSpec = RelSpec { entities: &[], shifted: &[], subsets: &[], partial_lengths: &[], lin_indep: ALL_TRUE, gate_block: None, structural: false, offset_only: false };
        macro_rules! spec {
            ($($k:ident : $v:expr),* $(,)?) => { RelSpec { $($k: $v,)* ..DEFAULT } };
        }
        match self {
            Rel::Permutation => spec! {
                entities: &[(w_l, Witness), (w_r, Witness), (w_o, Witness), (w_4, Witness), (z_perm, Witness),
                    (sigma_1, Precomputed), (sigma_2, Precomputed), (sigma_3, Precomputed), (sigma_4, Precomputed),
                    (id_1, Precomputed), (id_2, Precomputed), (id_3, Precomputed), (id_4, Precomputed),
                    (lagrange_first, Precomputed), (lagrange_last, Precomputed)],
                shifted: &[z_perm],
                subsets: &[("sigmas", &[sigma_1, sigma_2, sigma_3, sigma_4] as &[Ent]), ("ids", &[id_1, id_2, id_3, id_4] as &[Ent])],
                partial_lengths: &[6, 3, 3],
            },
            Rel::LogDerivLookup => spec! {
                entities: &[(w_l, Witness), (w_r, Witness), (w_o, Witness), (lookup_inverses, Witness),
                    (lookup_read_counts, Witness), (lookup_read_tags, Witness), (q_m, Precomputed), (q_r, Precomputed),
                    (q_o, Precomputed), (q_c, Precomputed), (q_lookup, Precomputed), (table_1, Precomputed),
                    (table_2, Precomputed), (table_3, Precomputed), (table_4, Precomputed)],
                shifted: &[w_l, w_r, w_o],
                subsets: &[("gate_selectors", &[q_lookup] as &[Ent]), ("tables", &[table_1, table_2, table_3, table_4] as &[Ent])],
                partial_lengths: &[5, 5, 3],
                lin_indep: &[true, false, true],
                gate_block: Some("lookup"),
            },
            Rel::Arithmetic => spec! {
                entities: &[(w_l, Witness), (w_r, Witness), (w_o, Witness), (w_4, Witness), (q_m, Precomputed),
                    (q_l, Precomputed), (q_r, Precomputed), (q_o, Precomputed), (q_4, Precomputed), (q_c, Precomputed),
                    (q_arith, Precomputed)],
                shifted: &[w_l, w_4],
                subsets: &[("wires", WIRES), ("non_gate_selectors", &[q_m, q_l, q_r, q_o, q_4, q_c] as &[Ent]), ("gate_selectors", &[q_arith] as &[Ent])],
                partial_lengths: &[6, 5],
                gate_block: Some("arithmetic"),
            },
            Rel::DeltaRange => spec! {
                entities: &[(w_l, Witness), (w_r, Witness), (w_o, Witness), (w_4, Witness), (q_delta_range, Precomputed)],
                shifted: &[w_l],
                subsets: &[("gate_selectors", &[q_delta_range] as &[Ent])],
                partial_lengths: &[6, 6, 6, 6],
                gate_block: Some("delta_range"),
            },
            Rel::Elliptic => spec! {
                entities: &[(w_l, Witness), (w_r, Witness), (w_o, Witness), (w_4, Witness), (q_l, Precomputed),
                    (q_m, Precomputed), (q_elliptic, Precomputed)],
                shifted: ALL_SHIFTS,
                subsets: &[("gate_selectors", &[q_elliptic] as &[Ent])],
                partial_lengths: &[6, 6],
                gate_block: Some("elliptic"),
            },
            Rel::Memory => spec! {
                entities: &[(w_l, Witness), (w_r, Witness), (w_o, Witness), (w_4, Witness), (q_m, Precomputed),
                    (q_l, Precomputed), (q_r, Precomputed), (q_o, Precomputed), (q_4, Precomputed), (q_c, Precomputed),
                    (q_memory, Precomputed)],
                shifted: ALL_SHIFTS,
                subsets: &[("gate_selectors", &[q_memory] as &[Ent])],
                partial_lengths: &[6, 6, 6, 6, 6, 6, 6, 6],
                lin_indep: &[true, true, true, true, true, true, true, false],
                gate_block: Some("memory"),
            },
            Rel::NonNativeField => spec! {
                entities: &[(w_l, Witness), (w_r, Witness), (w_o, Witness), (w_4, Witness), (q_m, Precomputed),
                    (q_r, Precomputed), (q_o, Precomputed), (q_4, Precomputed), (q_nnf, Precomputed)],
                shifted: ALL_SHIFTS,
                subsets: &[("gate_selectors", &[q_nnf] as &[Ent])],
                partial_lengths: &[6],
                gate_block: Some("nnf"),
            },
            Rel::Poseidon2External => spec! {
                entities: &[(w_l, Witness), (w_r, Witness), (w_o, Witness), (w_4, Witness), (q_l, Precomputed),
                    (q_r, Precomputed), (q_o, Precomputed), (q_4, Precomputed), (q_poseidon2_external, Precomputed)],
                shifted: ALL_SHIFTS,
                subsets: &[("gate_selectors", &[q_poseidon2_external] as &[Ent])],
                partial_lengths: &[7, 7, 7, 7],
                gate_block: Some("poseidon2_external"),
            },
            Rel::Poseidon2Internal => spec! {
                entities: &[(w_l, Witness), (w_r, Witness), (w_o, Witness), (w_4, Witness), (q_l, Precomputed),
                    (q_poseidon2_internal, Precomputed)],
                shifted: ALL_SHIFTS,
                subsets: &[("gate_selectors", &[q_poseidon2_internal] as &[Ent])],
                partial_lengths: &[7, 7, 7, 7],
                gate_block: Some("poseidon2_internal"),
            },
            Rel::Masking => spec! {
                entities: &[(gemini_masking_poly, Masking)],
                partial_lengths: &[],
                structural: true,
            },
        }
    }

    pub fn num_subrelations(self) -> usize {
        self.spec().partial_lengths.len()
    }
}

/// Flavor constants. Everything else (entity counts, layout, proof length) is derived.
pub struct FlavorDesc {
    pub name: &'static str,
    /// Order matters: it fixes the entity layout, the subrelation order, and the trace block order.
    pub relations: &'static [Rel],
    pub has_zk: bool,
    /// Whether the flavor commits to its own Gemini masking polynomial (MegaZK does not).
    pub has_gemini_masking: bool,
    /// Number of sumcheck rounds (padded for constant proof size).
    pub virtual_log_n: usize,
    /// Rows reserved at the start of the trace (masking rows + zero row).
    pub trace_offset: usize,
    /// Round-univariate length = max relation partial length + this.
    pub batched_len_extra: usize,
}

pub static ULTRA: FlavorDesc = FlavorDesc {
    name: "UltraFlavor",
    relations: &[Rel::Permutation, Rel::LogDerivLookup, Rel::Arithmetic, Rel::DeltaRange, Rel::Elliptic, Rel::Memory,
        Rel::NonNativeField, Rel::Poseidon2External, Rel::Poseidon2Internal],
    has_zk: false,
    has_gemini_masking: false,
    virtual_log_n: 25,
    trace_offset: 4,
    batched_len_extra: 1,
};

pub static ULTRA_ZK: FlavorDesc = FlavorDesc {
    name: "UltraZKFlavor",
    relations: &[Rel::Permutation, Rel::LogDerivLookup, Rel::Arithmetic, Rel::DeltaRange, Rel::Elliptic, Rel::Memory,
        Rel::NonNativeField, Rel::Poseidon2External, Rel::Poseidon2Internal, Rel::Masking],
    has_zk: true,
    has_gemini_masking: true,
    virtual_log_n: 25,
    trace_offset: 4,
    batched_len_extra: 2,
};

/// The derived entity layout: `[masking | precomputed | witness]` followed by the shifted suffix.
pub struct Layout {
    pub unshifted: Vec<Ent>,
    pub shifted: Vec<Ent>,
    index: Vec<usize>,
    shift_index: Vec<usize>,
    pub num_precomputed: usize,
    pub num_witness: usize,
    pub num_masking: usize,
    pub num_subrelations: usize,
    pub max_partial_len: usize,
    pub batched_len: usize,
    pub subsets: Vec<(&'static str, Vec<Ent>)>,
}

impl Layout {
    pub fn num_unshifted(&self) -> usize {
        self.unshifted.len()
    }
    pub fn num_shifted(&self) -> usize {
        self.shifted.len()
    }
    pub fn num_all(&self) -> usize {
        self.unshifted.len() + self.shifted.len()
    }
    /// Index of an unshifted entity in `AllEntities`.
    pub fn idx(&self, e: Ent) -> usize {
        let i = self.index[e as usize];
        assert!(i != usize::MAX, "entity {} is not in this flavor", e.name());
        i
    }
    /// Index of the shift of a to-be-shifted entity in `AllEntities`.
    pub fn shift_idx(&self, e: Ent) -> usize {
        let i = self.shift_index[e as usize];
        assert!(i != usize::MAX, "entity {} is not shifted in this flavor", e.name());
        i
    }
    pub fn has(&self, e: Ent) -> bool {
        self.index[e as usize] != usize::MAX
    }
    pub fn subset(&self, name: &str) -> &[Ent] {
        self.subsets.iter().find(|(n, _)| *n == name).map(|(_, v)| v.as_slice()).unwrap_or(&[])
    }
}

impl FlavorDesc {
    pub fn has(&self, r: Rel) -> bool {
        self.relations.contains(&r)
    }

    /// bb `deriveLayout`: kind-bucketed (masking → precomputed → witness) walk over the relations;
    /// within each relation, subsets first (declaration order) then leftover entities; first mention wins.
    pub fn layout(&self) -> Layout {
        let mut kind_of = vec![None; Ent::COUNT];
        let mut shifted_set = HashSet::new();
        for r in self.relations {
            let s = r.spec();
            for (e, k) in s.entities {
                let slot = &mut kind_of[*e as usize];
                assert!(slot.is_none() || *slot == Some(*k), "conflicting kinds for {}", e.name());
                *slot = Some(*k);
            }
            shifted_set.extend(s.shifted.iter().copied());
        }
        let mut unshifted = Vec::new();
        let mut emitted = HashSet::new();
        let mut push = |e: Ent, unshifted: &mut Vec<Ent>| {
            if emitted.insert(e) {
                unshifted.push(e);
            }
        };
        for kind in [Masking, Precomputed, Witness] {
            for r in self.relations {
                let s = r.spec();
                for (_, members) in s.subsets {
                    for m in *members {
                        if kind_of[*m as usize] == Some(kind) {
                            push(*m, &mut unshifted);
                        }
                    }
                }
                for (e, k) in s.entities {
                    if *k == kind {
                        push(*e, &mut unshifted);
                    }
                }
            }
        }
        let shifted: Vec<Ent> = unshifted.iter().copied().filter(|e| shifted_set.contains(e)).collect();
        let mut index = vec![usize::MAX; Ent::COUNT];
        for (i, e) in unshifted.iter().enumerate() {
            index[*e as usize] = i;
        }
        let mut shift_index = vec![usize::MAX; Ent::COUNT];
        for (j, e) in shifted.iter().enumerate() {
            shift_index[*e as usize] = unshifted.len() + j;
        }
        let count = |k| unshifted.iter().filter(|e| kind_of[**e as usize] == Some(k)).count();

        let mut subsets: Vec<(&'static str, Vec<Ent>)> = Vec::new();
        for r in self.relations {
            for (name, members) in r.spec().subsets {
                let entry = match subsets.iter_mut().find(|(n, _)| n == name) {
                    Some(e) => e,
                    None => {
                        subsets.push((name, Vec::new()));
                        subsets.last_mut().unwrap()
                    }
                };
                for m in *members {
                    if !entry.1.contains(m) {
                        entry.1.push(*m);
                    }
                }
            }
        }
        let max_partial_len = self.relations.iter().flat_map(|r| r.spec().partial_lengths.iter().copied()).max().unwrap();
        Layout {
            num_precomputed: count(Precomputed),
            num_witness: count(Witness),
            num_masking: count(Masking),
            num_subrelations: self.relations.iter().map(|r| r.num_subrelations()).sum(),
            max_partial_len,
            batched_len: max_partial_len + self.batched_len_extra,
            unshifted,
            shifted,
            index,
            shift_index,
            subsets,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(v: &[Ent]) -> Vec<&'static str> {
        v.iter().map(|e| e.name()).collect()
    }

    /// Pinned against bb's generated `flavor/generated/ultra_flavor_generated.hpp` `EntityId`.
    #[test]
    fn ultra_layout_matches_bb() {
        let l = ULTRA.layout();
        let expected: Vec<&str> = "sigma_1 sigma_2 sigma_3 sigma_4 id_1 id_2 id_3 id_4 lagrange_first lagrange_last q_lookup table_1 table_2 table_3 table_4 q_m q_r q_o q_c q_l q_4 q_arith q_delta_range q_elliptic q_memory q_nnf q_poseidon2_external q_poseidon2_internal w_l w_r w_o w_4 z_perm lookup_inverses lookup_read_counts lookup_read_tags".split(' ').collect();
        assert_eq!(names(&l.unshifted), expected);
        assert_eq!(names(&l.shifted), ["w_l", "w_r", "w_o", "w_4", "z_perm"]);
        assert_eq!((l.num_precomputed, l.num_witness, l.num_masking, l.num_all()), (28, 8, 0, 41));
        assert_eq!((l.num_subrelations, l.max_partial_len, l.batched_len), (31, 7, 8));
        assert_eq!(l.shift_idx(Ent::w_l), 36);
    }

    /// Pinned against `ultra_zk_flavor_generated.hpp`.
    #[test]
    fn ultra_zk_layout_matches_bb() {
        let l = ULTRA_ZK.layout();
        assert_eq!(l.unshifted[0], Ent::gemini_masking_poly);
        assert_eq!(l.idx(Ent::w_l), 29);
        assert_eq!((l.num_precomputed, l.num_witness, l.num_masking, l.num_all()), (28, 8, 1, 42));
        assert_eq!(l.batched_len, 9);
        assert_eq!(l.shift_idx(Ent::z_perm), 41);
    }
}
