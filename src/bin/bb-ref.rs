//! `bb-ref`: a minimal CLI mirroring the `bb` subcommands and file formats used by the differential tests.
//!
//!   bb-ref prove    --scheme ultra_honk [--disable_zk] -b <program.json> -w <witness.gz> -o <out_dir> [--write_vk]
//!   bb-ref prove    --scheme ultra_honk [--disable_zk] --instance <bb dump dir> -o <out_dir>
//!   bb-ref write_vk --scheme ultra_honk [--disable_zk] -b <program.json> -o <out_dir>
//!   bb-ref verify   --scheme ultra_honk [--disable_zk] -k <vk> -p <proof> -i <public_inputs>
//!   bb-ref write_vk --scheme chonk --circuit_kind app|kernel|hiding -b <program.json> -o <out_dir>
//!   bb-ref prove    --scheme chonk --ivc_inputs_path <ivc-inputs.msgpack> -o <out_dir> [--vk_policy check] [--prebuild]
//!   bb-ref verify   --scheme chonk -k <vk> -p <proof>

// mimalloc as an opt-in A/B reference: the default (system) allocator matches it once the
// hugepage tunable below is applied, at roughly half the peak RSS on the client flow.
#[cfg(all(feature = "mimalloc", not(feature = "heap-profile"), not(target_family = "wasm")))]
#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[cfg(feature = "heap-profile")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

use bb_ref::acir::{build_circuit_mega, decode_program, decode_steps, decode_witness, prove_steps};
use bb_ref::base::field::U256;
use bb_ref::base::field::{to_bytes_be, Fr};
use bb_ref::base::group::KeccakBn254;
use bb_ref::base::io::{decode_fields, encode_fields};
use bb_ref::base::keccak::u256_to_bytes_be;
use bb_ref::base::srs::bn254_g2;
use bb_ref::base::{Bn254, CommitmentKey, GrumpkinKey, OsRng, Vk};
use bb_ref::chonk::proof::ChonkProof;
use bb_ref::chonk::verifier::chonk_verify;
use bb_ref::goblin::eccvm::FIXED_SIZE as ECCVM_FIXED_SIZE;
use bb_ref::honk::prover_instance::ProverInstance;
use bb_ref::honk::ultra_prover::prove_ultra;
use bb_ref::honk::ultra_prover::prove_ultra_as;
use bb_ref::honk::ultra_verifier::verify_ultra;
use bb_ref::honk::{FlavorDesc, MEGA_APP, MEGA_KERNEL, MEGA_ZK};
use bb_ref::rollup::ROLLUP_PUBLIC_INPUTS_SIZE;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

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
            let max_size = steps
                .iter()
                .map(|s| 1usize << s.vk.log_n())
                .max()
                .unwrap_or(0)
                .max(1 << 17);
            let prebuild = flags.contains_key("--prebuild");
            let (proof, vk) = prove_steps(steps, CommitmentKey::new(max_size), rng.as_mut(), check_vks, prebuild);
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

/// bb `process_msgpack_commands` (`api/api_msgpack.cpp`): a frame loop over one persistent
/// handler, in bb's single wire framing — `[u32 len][u64 request_id][payload]`, the length
/// covering id and payload, each response echoing its request id. The same stream therefore
/// replays over a file, stdin, a socket or shared memory, against bb or against this.
/// Responses go to stdout; everything else this process prints goes to stderr.
fn msgpack_run(input_path: &str) {
    use bb_ref::msgpack::generated::bb_server::handle_request;
    use bb_ref::msgpack::handler::BbRefHandler;
    use std::io::{Read, Write};

    // Startup, not first-command: the largest served circuit is the 2^23 rollup root, and the
    // ECCVM's Grumpkin IPA runs at 2^16. The handler owns the pool; nothing is global.
    let srs = bb_ref::base::srs::Srs::load((1 << 23) + 2, 1 << 16);
    bb_ref::base::timing::phase("srs preload");

    let mut input: Box<dyn Read> = if input_path == "-" || input_path.is_empty() {
        Box::new(std::io::stdin())
    } else {
        Box::new(std::fs::File::open(input_path).unwrap_or_else(|e| panic!("{input_path}: {e}")))
    };
    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    let mut handler = BbRefHandler::new(srs);
    loop {
        let mut len_buf = [0u8; 4];
        match input.read_exact(&mut len_buf) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => panic!("reading frame length: {e}"),
        }
        let len = u32::from_le_bytes(len_buf) as usize;
        assert!(len >= 8, "frame shorter than its request id");
        let mut frame = vec![0u8; len];
        input.read_exact(&mut frame).expect("incomplete frame");
        let request_id = u64::from_le_bytes(frame[..8].try_into().unwrap());

        let response = handle_request(&mut handler, &frame[8..]);
        out.write_all(&((response.len() + 8) as u32).to_le_bytes()).unwrap();
        out.write_all(&request_id.to_le_bytes()).unwrap();
        out.write_all(&response).unwrap();
        out.flush().unwrap();
    }
}

/// The prover streams gigabytes of short-lived multi-megabyte buffers through malloc; on 4KB
/// pages the page faults and TLB misses of that cycle cost ~40% wall on the rollup base circuit
/// (mimalloc's entire advantage was that it madvises its segments MADV_HUGEPAGE). glibc has the
/// same behavior behind `glibc.malloc.hugetlb=1`, but only reads GLIBC_TUNABLES at process start,
/// so re-exec once to apply it. Setting any `glibc.malloc.hugetlb` value by hand wins.
#[cfg(target_os = "linux")]
fn apply_hugepage_tunable() {
    let cur = std::env::var("GLIBC_TUNABLES").unwrap_or_default();
    if cur.contains("glibc.malloc.hugetlb") {
        return;
    }
    let val = if cur.is_empty() {
        "glibc.malloc.hugetlb=1".to_string()
    } else {
        format!("{cur}:glibc.malloc.hugetlb=1")
    };
    if let Ok(exe) = std::fs::read_link("/proc/self/exe") {
        use std::os::unix::process::CommandExt;
        // exec replaces the process and only returns on failure; then run without the tunable.
        let _ = std::process::Command::new(exe)
            .args(std::env::args_os().skip(1))
            .env("GLIBC_TUNABLES", val)
            .exec();
    }
}

fn main() {
    bb_ref::base::bench::init();
    #[cfg(all(target_os = "linux", not(feature = "heap-profile")))]
    apply_hugepage_tunable();

    #[cfg(feature = "heap-profile")]
    let _profiler = dhat::Profiler::new_heap();

    // Beyond ~48 threads the MSM-heavy phases slow down (arkworks' parallel MSM splits into few
    // windows; oversubscription costs more than it gains); RAYON_NUM_THREADS still overrides
    // (`num_threads(0)` reads it). On wasm the workers' stacks are heap blocks that every
    // linear-memory high-water includes: 1 MiB (as bb) instead of std's 2 MiB saves 8 MiB at 8
    // threads. wasm stacks have no guard page and an overflow silently corrupts the heap below; the
    // deepest worker stack measured is ~158 KB (ECCVM relations, sumcheck round, accumulate_edge).
    let mut pool = rayon::ThreadPoolBuilder::new();
    if std::env::var_os("RAYON_NUM_THREADS").is_none() {
        pool = pool.num_threads(std::thread::available_parallelism().map_or(1, |n| n.get()).min(48));
    }
    if cfg!(target_family = "wasm") {
        pool = pool.stack_size(1 << 20);
    }
    pool.build_global().expect("rayon pool");
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

    if cmd == "msgpack" {
        // `bb-ref msgpack run --input <file|->` — bb's replay mode in bb's wire framing, with one
        // handler surviving across frames so Chonk sequences work.
        msgpack_run(&get("--input"));
        return;
    }

    // bb `dispatch_by_settings`, shared with the msgpack server.
    let settings = bb_ref::msgpack::generated::bb_types::ProofSystemSettings {
        ipa_accumulation: flags.contains_key("--ipa_accumulation"),
        oracle_hash_type: flags
            .get("--oracle_hash")
            .cloned()
            .unwrap_or_else(|| "poseidon2".into()),
        disable_zk: flags.contains_key("--disable_zk"),
        optimized_solidity_verifier: false,
    };
    let keccak = settings.oracle_hash_type == "keccak";

    if scheme == "chonk" {
        chonk(cmd, &flags);
        bb_ref::base::bench::print();
        return;
    }
    let flavor: &'static FlavorDesc = match bb_ref::msgpack::handler::select_flavor(&settings) {
        Ok((f, _)) => f,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
    };
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
                let proof = prove_ultra_as::<KeccakBn254>(&mut inst, &vk, &bb_ref::base::srs::Srs::default(), &mut rng);
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
