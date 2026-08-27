//! Census of the black-box opcodes each step of the pinned flows uses.
use bb_ref::acir::steps::decode_steps;
use bb_ref::acir::format::Opcode;
use bb_ref::base::OsRng;
use std::collections::BTreeMap;
fn main() {
    let root = std::env::args().nth(1).expect("flows dir");
    let mut totals: BTreeMap<String, usize> = BTreeMap::new();
    let mut flows = std::fs::read_dir(&root).unwrap().map(|e| e.unwrap().path()).collect::<Vec<_>>();
    flows.sort();
    for flow in flows {
        let Ok(bytes) = std::fs::read(flow.join("ivc-inputs.msgpack")) else { continue };
        let steps = decode_steps(&bytes, &mut OsRng);
        println!("== {}", flow.file_name().unwrap().to_string_lossy());
        for s in &steps {
            let mut counts: BTreeMap<String, usize> = BTreeMap::new();
            for op in &s.circuit.opcodes {
                if let Opcode::BlackBoxFuncCall(b) = op {
                    let name = format!("{b:?}");
                    let name = name.split(|c: char| !c.is_alphanumeric()).next().unwrap().to_string();
                    if matches!(name.as_str(), "RANGE" | "Poseidon2Permutation" | "RecursiveAggregation" | "MultiScalarMul" | "EmbeddedCurveAdd") { continue; }
                    *counts.entry(name.clone()).or_default() += 1;
                    *totals.entry(name).or_default() += 1;
                }
            }
            if !counts.is_empty() {
                println!("  {:45} {:?}", s.name, counts);
            }
        }
    }
    println!("== totals {totals:?}");
}
