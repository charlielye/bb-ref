//! `bb-ref`: a minimal CLI mirroring the `bb` subcommands and file formats used by the differential tests.
//!
//!   bb-ref verify --scheme ultra_honk [--disable_zk] -k <vk> -p <proof> -i <public_inputs>
//!   bb-ref prove  --scheme ultra_honk [--disable_zk] --instance <dump_dir> -o <out_dir>   (until the builder lands)

use bb_ref::base::io::{decode_fields, encode_fields};
use bb_ref::base::srs::bn254_g2;
use bb_ref::base::{Bn254, CommitmentKey, OsRng, Vk};
use bb_ref::honk::prover_instance::ProverInstance;
use bb_ref::honk::ultra_prover::prove_ultra;
use bb_ref::honk::ultra_verifier::verify_ultra;
use bb_ref::honk::{ULTRA, ULTRA_ZK};
use std::collections::HashMap;

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
            let mut inst = ProverInstance::load_dump(flavor, get("--instance"));
            let ck = CommitmentKey::new(inst.max_end_index);
            let vk = inst.compute_vk(&ck);
            let num_user_pis = inst.public_inputs.len() - 8;
            let proof = prove_ultra(&mut inst, &vk, &mut OsRng);
            let out = std::path::PathBuf::from(get("-o"));
            std::fs::create_dir_all(&out).unwrap();
            std::fs::write(out.join("public_inputs"), encode_fields(&proof[..num_user_pis])).unwrap();
            std::fs::write(out.join("proof"), encode_fields(&proof[num_user_pis..])).unwrap();
            std::fs::write(out.join("vk"), vk.to_bytes()).unwrap();
            println!("Proof saved to {}", out.display());
        }
        _ => {
            eprintln!("usage: bb-ref verify|prove ...");
            std::process::exit(2);
        }
    }
}
