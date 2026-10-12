//! Census of RecursiveAggregation constraints in server (backend) artifacts.
use bb_ref::acir::format::{decode_program, BlackBoxFuncCall, FunctionInput, Opcode};
fn main() {
    let root = std::env::args().nth(1).expect("target dir");
    let mut progs: Vec<_> = std::fs::read_dir(&root).unwrap().map(|e| e.unwrap().path()).collect();
    progs.sort();
    for prog in progs {
        let name = prog.file_name().unwrap().to_string_lossy().to_string();
        if !name.ends_with(".json") || name.contains("simulated") {
            continue;
        }
        let Ok(bytes) = std::fs::read(&prog) else { continue };
        let circuit = decode_program(&bytes);
        let mut lines = vec![];
        for op in &circuit.opcodes {
            if let Opcode::BlackBoxFuncCall(BlackBoxFuncCall::RecursiveAggregation(r)) = op {
                let pred = match &r.predicate {
                    FunctionInput::Constant(c) => format!("const:{}", c.0),
                    FunctionInput::Witness(_) => "witness".to_string(),
                };
                lines.push(format!(
                    "type={} key={} proof={} pis={} pred={pred}",
                    r.proof_type,
                    r.verification_key.len(),
                    r.proof.len(),
                    r.public_inputs.len()
                ));
            }
        }
        if !lines.is_empty() {
            println!("== {name}");
            for l in lines {
                println!("   {l}");
            }
        }
    }
}
