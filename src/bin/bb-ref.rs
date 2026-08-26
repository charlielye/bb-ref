//! `bb-ref`: a minimal CLI mirroring the `bb` subcommands and file formats used by the differential tests.
//!
//!   bb-ref prove    --scheme ultra_honk [--disable_zk] -b <program.json> -w <witness.gz> -o <out_dir> [--write_vk]
//!   bb-ref prove    --scheme ultra_honk [--disable_zk] --instance <bb dump dir> -o <out_dir>
//!   bb-ref write_vk --scheme ultra_honk [--disable_zk] -b <program.json> -o <out_dir>
//!   bb-ref verify   --scheme ultra_honk [--disable_zk] -k <vk> -p <proof> -i <public_inputs>

use bb_ref::acir::{build_circuit, decode_program, decode_witness};
use bb_ref::base::field::{to_bytes_be, Fr};
use bb_ref::base::io::{decode_fields, encode_fields};
use bb_ref::base::srs::bn254_g2;
use bb_ref::base::{Bn254, CommitmentKey, OsRng, Vk};
use bb_ref::honk::prover_instance::ProverInstance;
use bb_ref::honk::ultra_prover::prove_ultra;
use bb_ref::honk::ultra_verifier::verify_ultra;
use bb_ref::honk::{FlavorDesc, ULTRA, ULTRA_ZK};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

fn instance_from_acir(flavor: &'static FlavorDesc, program: &str, witness: Option<&str>) -> ProverInstance {
    let circuit = decode_program(&std::fs::read(program).expect("program.json"));
    let witness: Option<Vec<Fr>> = witness.map(|w| decode_witness(&std::fs::read(w).expect("witness.gz")));
    let mut builder = build_circuit(&circuit, witness.as_deref());
    if let Some(msg) = &builder.failed {
        eprintln!("warning: circuit is not satisfied ({msg})");
    }
    ProverInstance::from_builder(flavor, &mut builder, &mut OsRng)
}

fn write_vk_files(out: &Path, vk: &Vk<Bn254>) {
    std::fs::write(out.join("vk"), vk.to_bytes()).unwrap();
    std::fs::write(out.join("vk_hash"), to_bytes_be(&vk.hash())).unwrap();
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str).unwrap_or("");
    let mut flags: HashMap<String, String> = HashMap::new();
    let mut i = 2;
    while i < args.len() {
        let a = &args[i];
        if a.starts_with('-') {
            if i + 1 < args.len() && !args[i + 1].starts_with('-') {
                flags.insert(a.clone(), args[i + 1].clone());
                i += 2;
            } else {
                flags.insert(a.clone(), String::new());
                i += 1;
            }
        } else {
            i += 1;
        }
    }
    let get = |k: &str| flags.get(k).cloned().unwrap_or_else(|| panic!("missing {k}"));
    let scheme = flags.get("--scheme").cloned().unwrap_or_else(|| "ultra_honk".into());
    assert_eq!(scheme, "ultra_honk", "only ultra_honk is supported");
    let flavor = if flags.contains_key("--disable_zk") { &ULTRA } else { &ULTRA_ZK };

    match cmd {
        "verify" => {
            let vk = Vk::<Bn254>::from_bytes(&std::fs::read(get("-k")).unwrap(), 28);
            let proof = decode_fields(&std::fs::read(get("-p")).unwrap());
            let pis = decode_fields(&std::fs::read(get("-i")).unwrap());
            let ok = verify_ultra(flavor, &vk, &pis, &proof, &bn254_g2());
            println!("{}", if ok { "Proof verified successfully" } else { "Proof verification failed" });
            std::process::exit(if ok { 0 } else { 1 });
        }
        "prove" => {
            let mut inst = match flags.get("--instance") {
                Some(dir) => ProverInstance::load_dump(flavor, dir),
                None => instance_from_acir(flavor, &get("-b"), Some(&get("-w"))),
            };
            let ck = CommitmentKey::new(inst.max_end_index);
            let vk = inst.compute_vk(&ck);
            let num_user_pis = inst.public_inputs.len() - 8;
            let proof = prove_ultra(&mut inst, &vk, &mut OsRng);
            let out = PathBuf::from(get("-o"));
            std::fs::create_dir_all(&out).unwrap();
            std::fs::write(out.join("public_inputs"), encode_fields(&proof[..num_user_pis])).unwrap();
            std::fs::write(out.join("proof"), encode_fields(&proof[num_user_pis..])).unwrap();
            if flags.contains_key("--write_vk") {
                write_vk_files(&out, &vk);
            }
            println!("Proof saved to {}", out.display());
        }
        "write_vk" => {
            let inst = instance_from_acir(flavor, &get("-b"), None);
            let ck = CommitmentKey::new(inst.max_end_index);
            let out = PathBuf::from(get("-o"));
            std::fs::create_dir_all(&out).unwrap();
            write_vk_files(&out, &inst.compute_vk(&ck));
            println!("VK saved to {}", out.display());
        }
        _ => {
            eprintln!("usage: bb-ref prove|write_vk|verify ...");
            std::process::exit(2);
        }
    }
}
