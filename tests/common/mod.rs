//! Shared helpers for differential tests against bb fixtures.
#![allow(dead_code)]
use std::path::PathBuf;

pub const PIN: &str = "d43209d";

pub fn fixture_dir(rel: &str) -> PathBuf {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data").join(PIN);
    root.join(rel)
}

pub fn read(rel: &str) -> Vec<u8> {
    let p = fixture_dir(rel);
    std::fs::read(&p).unwrap_or_else(|e| panic!("missing fixture {}: {e}", p.display()))
}

use bb_ref::base::Fr;
use bb_ref::circuit::Builder;
use bb_ref::honk::prover_instance::ProverInstance;

/// Compare the polynomials of a Rust instance with a bb dump and panic with a gate-level report of
/// the earliest differing row: whole-gate selectors first (a gate-sequence difference), then every
/// polynomial (copy cycles, witnesses). `compare` lists the polynomial indices to check.
pub fn assert_polys_equal(
    name: &str,
    inst: &ProverInstance,
    expected: &ProverInstance,
    builder: &Builder,
    compare: &[usize],
) {
    let is_selector = |i: usize| inst.layout.unshifted[i].name().starts_with("q_");
    let mut first: Option<(usize, usize)> = None;
    let scan = |i: usize, first: &mut Option<(usize, usize)>| {
        let (a, b) = (&inst.polys[i], &expected.polys[i]);
        if let Some(r) = (0..a.len().max(b.len())).find(|r| a.at(*r) != b.at(*r)) {
            if first.map_or(true, |(fr, _)| r < fr) {
                *first = Some((r, i));
            }
        }
    };
    for &i in compare.iter().filter(|i| is_selector(**i)) {
        scan(i, &mut first);
    }
    if first.is_none() || std::env::var("BBREF_DIFF_ALL").is_ok() {
        for &i in compare.iter().filter(|i| !is_selector(**i)) {
            scan(i, &mut first);
        }
    }
    if let Ok(range) = std::env::var("BBREF_PRINT_SIGS") {
        let (a, z) = range.split_once(':').unwrap();
        let (a, z): (usize, usize) = (a.parse().unwrap(), z.parse().unwrap());
        let sig = |polys: &[bb_ref::base::Poly], row: usize| -> String {
            ["q_m", "q_l", "q_r", "q_o", "q_4", "q_c", "q_arith"]
                .iter()
                .map(|n| {
                    let i = compare
                        .iter()
                        .copied()
                        .find(|i| inst.layout.unshifted[*i].name() == *n)
                        .unwrap();
                    let v = polys[i].coeffs[row];
                    if v == -Fr::from(1u64) {
                        "-1".to_string()
                    } else {
                        format!("{:?}", v).chars().take(4).collect()
                    }
                })
                .collect::<Vec<_>>()
                .join(" ")
        };
        for row in a..z.min(inst.polys[0].coeffs.len()) {
            eprintln!("SIGROW {row}: [{}]", sig(&inst.polys, row));
        }
    }
    if let Ok(at) = std::env::var("BBREF_DIFF_AT") {
        let at: usize = at.parse().unwrap();
        for row in at.saturating_sub(2)..=at + 2 {
            for &j in compare {
                let (a, b) = (inst.polys[j].coeffs[row], expected.polys[j].coeffs[row]);
                if a != Fr::from(0u64) || b != Fr::from(0u64) {
                    eprintln!(
                        "AT row {row} {:>24}: rust {:?}{}",
                        inst.layout.unshifted[j].name(),
                        a,
                        if a == b { String::new() } else { format!("  bb {b:?}") }
                    );
                }
            }
        }
    }
    let Some((r, i)) = first else { return };
    let mut report = format!(
        "{name}: first difference at row {r} in {}\n",
        inst.layout.unshifted[i].name()
    );
    for (desc, block) in builder.blocks.iter() {
        report += &format!(
            "  block {:?}: offset {} len {}\n",
            desc.id,
            block.trace_offset,
            block.rows.len()
        );
    }
    let after: usize = std::env::var("BBREF_DIFF_ROWS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1);
    if let Ok(before) = std::env::var("BBREF_DIFF_BEFORE") {
        // compact selector signatures: q_m q_l q_r q_o q_4 q_c (small values only)
        let sig = |polys: &[bb_ref::base::Poly], row: usize| -> String {
            ["q_m", "q_l", "q_r", "q_o", "q_4", "q_c"]
                .iter()
                .map(|n| {
                    let i = compare
                        .iter()
                        .copied()
                        .find(|i| inst.layout.unshifted[*i].name() == *n)
                        .unwrap();
                    let v = polys[i].coeffs[row];
                    if v == -Fr::from(1u64) {
                        "-1".to_string()
                    } else {
                        format!("{:?}", v).chars().take(4).collect()
                    }
                })
                .collect::<Vec<_>>()
                .join(" ")
        };
        for row in r.saturating_sub(before.parse().unwrap())..=r + after {
            report += &format!(
                "  sig {row}: rust [{}] bb [{}]\n",
                sig(&inst.polys, row),
                sig(&expected.polys, row)
            );
        }
    }
    for row in r.saturating_sub(2)..=r + after {
        for &j in compare {
            let (a, b) = (inst.polys[j].coeffs[row], expected.polys[j].coeffs[row]);
            if a != Fr::from(0u64) || b != Fr::from(0u64) {
                report += &format!(
                    "  row {row} {:>24}: rust {:?}{}\n",
                    inst.layout.unshifted[j].name(),
                    a,
                    if a == b { String::new() } else { format!("  bb {b:?}") }
                );
            }
        }
    }
    panic!("{report}");
}

pub mod eccvm_ops;
pub mod mock_ivc;
pub mod script;
pub mod translator_fixture;
