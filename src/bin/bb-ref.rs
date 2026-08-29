//! `bb-ref`: a minimal CLI mirroring the `bb` subcommands and file formats used by the differential tests.
//!
//!   bb-ref prove    --scheme ultra_honk [--disable_zk] -b <program.json> -w <witness.gz> -o <out_dir> [--write_vk]
//!   bb-ref prove    --scheme ultra_honk [--disable_zk] --instance <bb dump dir> -o <out_dir>
//!   bb-ref write_vk --scheme ultra_honk [--disable_zk] -b <program.json> -o <out_dir>
//!   bb-ref verify   --scheme ultra_honk [--disable_zk] -k <vk> -p <proof> -i <public_inputs>
//!   bb-ref write_vk --scheme chonk --circuit_kind app|kernel|hiding -b <program.json> -o <out_dir>
//!   bb-ref prove    --scheme chonk --ivc_inputs_path <ivc-inputs.msgpack> -o <out_dir> [--vk_policy check]
//!   bb-ref verify   --scheme chonk -k <vk> -p <proof>

use bb_ref::acir::{build_circuit, build_circuit_mega, decode_program, decode_steps, decode_witness, prove_steps};
use bb_ref::base::field::{to_bytes_be, Fr};
use bb_ref::base::io::{decode_fields, encode_fields};
use bb_ref::base::srs::bn254_g2;
use bb_ref::base::{Bn254, CommitmentKey, GrumpkinKey, OsRng, Vk};
use bb_ref::chonk::proof::ChonkProof;
use bb_ref::chonk::verifier::chonk_verify;
use bb_ref::goblin::eccvm::FIXED_SIZE as ECCVM_FIXED_SIZE;
use bb_ref::honk::prover_instance::ProverInstance;
use bb_ref::honk::ultra_prover::prove_ultra;
use bb_ref::honk::ultra_verifier::verify_ultra;
use bb_ref::honk::{FlavorDesc, MEGA_APP, MEGA_KERNEL, MEGA_ZK, ULTRA, ULTRA_KECCAK, ULTRA_KECCAK_ZK, ULTRA_ZK};
use bb_ref::base::field::U256;
use bb_ref::base::group::KeccakBn254;
use bb_ref::base::keccak::u256_to_bytes_be;
use bb_ref::honk::ultra_prover::prove_ultra_as;
use bb_ref::rollup::ROLLUP_PUBLIC_INPUTS_SIZE;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

fn instance_from_acir(flavor: &'static FlavorDesc, program: &str, witness: Option<&str>) -> ProverInstance {
    instance_from_acir_opts(flavor, program, witness, false)
}

fn instance_from_acir_opts(
    flavor: &'static FlavorDesc,
    program: &str,
    witness: Option<&str>,
    has_ipa_claim: bool,
) -> ProverInstance {
    let circuit = decode_program(&std::fs::read(program).expect("program.json"));
    let mut rng = bb_ref::base::rng::GlobalProxy;
    let witness: Option<Vec<Fr>> = witness.map(|w| decode_witness(&std::fs::read(w).expect("witness.gz"), &mut rng));
    let mut builder = bb_ref::acir::lower::build_circuit_opts(&circuit, witness.as_deref(), has_ipa_claim);
    if let Some(msg) = &builder.failed {
        eprintln!("warning: circuit is not satisfied ({msg})");
    }
    ProverInstance::from_builder(flavor, &mut builder, &mut rng)
}

/// The Chonk subcommands: per-kind VKs from ACIR (kernels against bb's mocked IVC state), proving
/// an `ivc-inputs.msgpack`, and verifying a Chonk proof against the hiding kernel's VK.
fn chonk(cmd: &str, flags: &HashMap<String, String>) {
    let get = |k: &str| flags.get(k).cloned().unwrap_or_else(|| panic!("missing {k}"));
    let out_dir = |flags: &HashMap<String, String>| {
        let out = PathBuf::from(flags.get("-o").expect("missing -o"));
        std::fs::create_dir_all(&out).unwrap();
        out
    };
    match cmd {
        "write_vk" => {
            let flavor = match get("--circuit_kind").as_str() {
                "app" => &MEGA_APP,
                "kernel" => &MEGA_KERNEL,
                "hiding" => &MEGA_ZK,
                k => panic!("--circuit_kind must be one of app / kernel / hiding (got {k})"),
            };
            let circuit = decode_program(&std::fs::read(get("-b")).expect("program.json"));
            let mut builder = build_circuit_mega(&circuit, None, None, &mut OsRng);
            let inst = ProverInstance::from_builder(flavor, &mut builder, &mut OsRng);
            let ck = CommitmentKey::new(inst.max_end_index);
            let out = out_dir(flags);
            std::fs::write(out.join("vk"), inst.compute_vk(&ck).to_bytes()).unwrap();
            println!("VK saved to {}", out.display());
        }
        "prove" => {
            let mut rng = bb_ref::base::rng::from_env();
            let steps = decode_steps(&std::fs::read(get("--ivc_inputs_path")).expect("ivc inputs"));
            let check_vks = flags.get("--vk_policy").is_some_and(|v| v == "check");
            // The largest circuit of the flow, or the joint proof's 2^17, sizes the commitment key.
            let max_size = steps.iter().map(|s| 1usize << s.vk.log_n()).max().unwrap_or(0).max(1 << 17);
            let (proof, vk) = prove_steps(&steps, CommitmentKey::new(max_size), rng.as_mut(), check_vks);
            let out = out_dir(flags);
            std::fs::write(out.join("proof"), encode_fields(&proof.to_fields())).unwrap();
            std::fs::write(out.join("vk"), vk.to_bytes()).unwrap();
            println!("Proof saved to {}", out.display());
        }
        "verify" => {
            let vk = Vk::<Bn254>::from_bytes(&std::fs::read(get("-k")).unwrap(), MEGA_ZK.layout().num_precomputed);
            let proof = ChonkProof::from_fields(&decode_fields(&std::fs::read(get("-p")).unwrap()));
            let ok = chonk_verify(&vk, &proof, &bn254_g2(), &GrumpkinKey::new(ECCVM_FIXED_SIZE));
            println!(
                "{}",
                if ok {
                    "Proof verified successfully"
                } else {
                    "Proof verification failed"
                }
            );
            std::process::exit(if ok { 0 } else { 1 });
        }
        _ => {
            eprintln!("usage: bb-ref prove|write_vk|verify --scheme chonk ...");
            std::process::exit(2);
        }
    }
}

/// bb's keccak-flavour file format: 32-byte big-endian words, no length prefix.
fn write_words(path: &Path, words: &[U256]) {
    let bytes: Vec<u8> = words.iter().flat_map(|w| u256_to_bytes_be(w)).collect();
    std::fs::write(path, bytes).unwrap();
}

/// The same precomputed commitments under the keccak codec (bb `UltraKeccakFlavor::VerificationKey`).
fn as_keccak_vk(vk: Vk<Bn254>) -> Vk<KeccakBn254> {
    Vk::<KeccakBn254> {
        log_circuit_size: vk.log_circuit_size,
        num_public_inputs: vk.num_public_inputs,
        pub_inputs_offset: vk.pub_inputs_offset,
        comms: vk.comms,
    }
}

fn write_vk_files(out: &Path, vk: &Vk<Bn254>) {
    std::fs::write(out.join("vk"), vk.to_bytes()).unwrap();
    std::fs::write(out.join("vk_hash"), to_bytes_be(&vk.hash())).unwrap();
}

fn main() {
    // Beyond ~48 threads the MSM-heavy phases slow down (arkworks' parallel MSM splits into few
    // windows; oversubscription costs more than it gains); RAYON_NUM_THREADS still overrides.
    if std::env::var_os("RAYON_NUM_THREADS").is_none() {
        let threads = std::thread::available_parallelism().map_or(1, |n| n.get()).min(48);
        rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build_global()
            .expect("rayon pool");
    }
    // bb keeps ONE global engine: witness gap-fills, in-circuit masking and the prover all draw
    // from it, so `BB_RNG_SEED` must seed the global source, not just the explicit prover rng.
    bb_ref::base::rng::set_global_from_env();
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
    let keccak = flags.get("--oracle_hash").is_some_and(|h| h == "keccak");
    let zk = !flags.contains_key("--disable_zk");
    let flavor: &'static FlavorDesc = match (keccak, zk) {
        (true, false) => &ULTRA_KECCAK,
        (true, true) => &ULTRA_KECCAK_ZK,
        (false, false) => &ULTRA,
        (false, true) => &ULTRA_ZK,
    };

    if scheme == "chonk" {
        chonk(cmd, &flags);
        return;
    }
    assert_eq!(scheme, "ultra_honk", "unsupported scheme {scheme}");

    match cmd {
        "verify" => {
            let vk = Vk::<Bn254>::from_bytes(&std::fs::read(get("-k")).unwrap(), 28);
            let proof = decode_fields(&std::fs::read(get("-p")).unwrap());
            let pis = decode_fields(&std::fs::read(get("-i")).unwrap());
            let ok = verify_ultra(flavor, &vk, &pis, &proof, &bn254_g2());
            println!(
                "{}",
                if ok {
                    "Proof verified successfully"
                } else {
                    "Proof verification failed"
                }
            );
            std::process::exit(if ok { 0 } else { 1 });
        }
        "prove" => {
            // `--ipa_accumulation` (the node's rollup-tree flag) selects the RollupIO tail and the
            // combined honk+ipa proof; `--oracle_hash keccak` selects the U256/keccak transcript.
            let ipa = flags.contains_key("--ipa_accumulation");
            let mut rng = bb_ref::base::rng::GlobalProxy;
            let mut inst = match flags.get("--instance") {
                Some(dir) => ProverInstance::load_dump(flavor, dir),
                None => instance_from_acir_opts(flavor, &get("-b"), Some(&get("-w")), ipa),
            };
            let ck = CommitmentKey::new(inst.max_end_index);
            let io_size = if ipa { ROLLUP_PUBLIC_INPUTS_SIZE } else { 8 };
            let num_user_pis = inst.public_inputs.len() - io_size;
            let out = PathBuf::from(get("-o"));
            std::fs::create_dir_all(&out).unwrap();
            let write_vk = flags.contains_key("--write_vk");
            if keccak {
                let vk = as_keccak_vk(inst.compute_vk(&ck));
                let proof = prove_ultra_as::<KeccakBn254>(&mut inst, &vk, &mut rng);
                write_words(&out.join("public_inputs"), &proof[..num_user_pis]);
                write_words(&out.join("proof"), &proof[num_user_pis..]);
                if write_vk {
                    std::fs::write(out.join("vk"), vk.to_bytes()).unwrap();
                    std::fs::write(out.join("vk_hash"), u256_to_bytes_be(&vk.hash())).unwrap();
                }
            } else {
                let vk = inst.compute_vk(&ck);
                let proof = prove_ultra(&mut inst, &vk, &mut rng);
                std::fs::write(out.join("public_inputs"), encode_fields(&proof[..num_user_pis])).unwrap();
                std::fs::write(out.join("proof"), encode_fields(&proof[num_user_pis..])).unwrap();
                if write_vk {
                    write_vk_files(&out, &vk);
                }
            }
            println!("Proof saved to {}", out.display());
        }
        "write_vk" => {
            let ipa = flags.contains_key("--ipa_accumulation");
            let inst = instance_from_acir_opts(flavor, &get("-b"), None, ipa);
            let ck = CommitmentKey::new(inst.max_end_index);
            let out = PathBuf::from(get("-o"));
            std::fs::create_dir_all(&out).unwrap();
            let vk = inst.compute_vk(&ck);
            if keccak {
                let vk = as_keccak_vk(vk);
                std::fs::write(out.join("vk"), vk.to_bytes()).unwrap();
                std::fs::write(out.join("vk_hash"), u256_to_bytes_be(&vk.hash())).unwrap();
            } else {
                write_vk_files(&out, &vk);
            }
            println!("VK saved to {}", out.display());
        }
        _ => {
            eprintln!("usage: bb-ref prove|write_vk|verify ...");
            std::process::exit(2);
        }
    }
}
