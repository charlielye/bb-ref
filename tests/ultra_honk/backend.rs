//! B0 exit: backend (server protocol) circuits, recursion-free warm-up. `inbox_parity_64` — built
//! and executed with the pinned nargo (`tools/regen/regen_backend.sh`) — reproduces bb's proving
//! instance, VK and non-ZK proof byte-for-byte; the ZK proof verifies. The VK-hash sweep compares
//! every artifact under `backend_vk_hash/` that bb-ref can already build (recursion circuits join
//! the supported set as the B-milestones land).

use crate::common;
use bb_ref::acir::format::{decode_program, decode_witness};
use bb_ref::acir::lower::{build_circuit, build_circuit_opts};
use bb_ref::base::field::from_bytes_be;
use bb_ref::base::io::decode_fields;
use bb_ref::base::srs::bn254_g2;
use bb_ref::base::{CommitmentKey, Fr, NativeTranscript, OsRng};
use bb_ref::honk::circuit_checker::check_circuit;
use bb_ref::honk::flavor::FlavorDesc;
use bb_ref::honk::oink_prover::prove_oink;
use bb_ref::honk::prover_instance::ProverInstance;
use bb_ref::honk::ultra_prover::prove_ultra;
use bb_ref::honk::ultra_verifier::verify_ultra;
use bb_ref::honk::{ULTRA, ULTRA_ZK};

fn build(name: &str, flavor: &'static FlavorDesc) -> ProverInstance {
    build_ipa(name, flavor, false)
}

fn build_ipa(name: &str, flavor: &'static FlavorDesc, has_ipa_claim: bool) -> ProverInstance {
    build_ipa_rng(name, flavor, has_ipa_claim, &mut OsRng)
}

fn build_ipa_rng(
    name: &str,
    flavor: &'static FlavorDesc,
    has_ipa_claim: bool,
    rng: &mut impl bb_ref::base::rng::Rng,
) -> ProverInstance {
    let dir = common::fixture_dir(&format!("backend/{name}"));
    let circuit = decode_program(&std::fs::read(dir.join("program.json")).expect("program.json"));
    let witness = decode_witness(&std::fs::read(dir.join("witness.gz")).expect("witness.gz"), rng);
    let mut builder = if has_ipa_claim {
        build_circuit_opts(&circuit, Some(&witness), true)
    } else {
        build_circuit(&circuit, Some(&witness))
    };
    assert!(builder.failed.is_none(), "{name}: builder failure {:?}", builder.failed);
    ProverInstance::from_builder(flavor, &mut builder, rng)
}

fn check_nozk(name: &str) {
    check_nozk_opts(name, false)
}

/// B4 exit: real-witness rollup circuits (RollupIO; the combined honk+ipa proof is compared).
/// Serializes every test that reads or feeds the process-global RNG: the real-witness tests
/// replay bb's tape through it, and any concurrent circuit build would steal draws.
static GLOBAL_RNG_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn check_nozk_opts(name: &str, has_ipa_claim: bool) {
    let _rng_guard = GLOBAL_RNG_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let dump = common::fixture_dir(&format!("instance/backend/{name}/nozk"));
    if !dump.join("proof.bin").exists() {
        eprintln!("skipping {name}: no instance dump");
        return;
    }
    // bb fills ACIR witness-map gaps and in-circuit masks with random field elements;
    // byte-equality of witness columns needs bb's tape replayed through the ONE global source
    // (pre-tape dumps like inbox_parity_64 draw nothing observable, so OsRng suffices there).
    let tape_path = common::fixture_dir(&format!("instance/backend/{name}/rng_tape.bin"));
    let has_tape = tape_path.exists();
    if has_tape {
        let tape = bb_ref::base::rng::TapeRng::from_bytes(std::fs::read(&tape_path).unwrap());
        bb_ref::base::rng::set_global(Box::new(tape));
    } else {
        bb_ref::base::rng::set_global(Box::new(bb_ref::base::rng::OsRng));
    }
    let mut tape = bb_ref::base::rng::GlobalProxy;
    let mut inst = build_ipa_rng(name, &ULTRA, has_ipa_claim, &mut tape);
    let expected = ProverInstance::load_dump(&ULTRA, &dump);
    assert_eq!(inst.dyadic_size, expected.dyadic_size, "{name}: dyadic size");
    assert_eq!(inst.public_inputs, expected.public_inputs, "{name}: public inputs");
    let mut first: Option<usize> = None;
    for (e, (a, b)) in inst.layout.unshifted.iter().zip(inst.polys.iter().zip(&expected.polys)) {
        let diffs: Vec<usize> = a
            .coeffs
            .iter()
            .zip(&b.coeffs)
            .enumerate()
            .filter(|(_, (x, y))| x != y)
            .map(|(i, _)| i)
            .collect();
        if !diffs.is_empty() {
            eprintln!(
                "{name}: {} differs at {} rows; first {:?} last {:?}",
                e.name(),
                diffs.len(),
                &diffs[..diffs.len().min(4)],
                diffs.last()
            );
            for &i in diffs.iter().take(3) {
                eprintln!("  row {i}: mine {:?} bb {:?}", a.coeffs[i], b.coeffs[i]);
            }
            first = first.or(Some(diffs[0]));
        }
    }
    if let Some(i) = first {
        panic!("{name}: witness polynomials differ (first at row {i})");
    }
    let ck = CommitmentKey::new(inst.max_end_index);
    let vk = inst.compute_vk(&ck);
    assert_eq!(vk.to_bytes(), std::fs::read(dump.join("vk")).unwrap(), "{name}: VK");
    let proof = prove_ultra(&mut inst, &vk, &mut tape);
    let expected_proof = decode_fields(&std::fs::read(dump.join("proof.bin")).unwrap());
    assert_eq!(proof, expected_proof, "{name}: proof");
    if has_tape {
        let tape = bb_ref::base::rng::TapeRng::from_bytes(std::fs::read(&tape_path).unwrap());
        bb_ref::base::rng::set_global(Box::new(tape));
    }
    let mut tape = bb_ref::base::rng::GlobalProxy;
    let mut inst = build_ipa_rng(name, &ULTRA, has_ipa_claim, &mut tape);
    let out = prove_oink(&mut inst, &vk, &ck, &mut NativeTranscript::new(), &mut tape, true);
    assert_eq!(check_circuit(&inst, &out.params), None, "{name}: relation failure");
}

fn check_zk(name: &str) {
    let dump = common::fixture_dir(&format!("instance/backend/{name}/zk"));
    if !dump.join("vk").exists() {
        eprintln!("skipping {name}: no instance dump");
        return;
    }
    let mut inst = build(name, &ULTRA_ZK);
    let ck = CommitmentKey::new(inst.max_end_index);
    let vk = inst.compute_vk(&ck);
    assert_eq!(vk.to_bytes(), std::fs::read(dump.join("vk")).unwrap(), "{name}: VK");
    let num_pi = inst.public_inputs.len();
    let proof = prove_ultra(&mut inst, &vk, &mut OsRng);
    let (pis, rest): (&[Fr], &[Fr]) = proof.split_at(num_pi - 8);
    assert!(
        verify_ultra(&ULTRA_ZK, &vk, pis, rest, &bn254_g2()),
        "{name}: ZK proof rejected"
    );
}

macro_rules! backend_tests {
    ($($name:ident),* $(,)?) => { $(
        mod $name {
            #[test] fn nozk() { super::check_nozk(stringify!($name)); }
            #[test] fn zk() { super::check_zk(stringify!($name)); }
        }
    )* };
}
backend_tests! {
    inbox_parity_64,
}

// Real-witness proving through the recursion lowerings (CHONK for tx_base_private, ROLLUP_HONK
// for the tree levels): instance + VK + combined honk+ipa proof byte-equal to bb. The witnesses
// come from the conformance corpus's epochs (tools/regen/backend_from_corpus.py), which reach every
// rollup circuit.
mod rollup_tx_base_private_witness {
    #[test]
    fn nozk() {
        super::check_nozk_opts("rollup_tx_base_private", true);
    }
}
mod rollup_tx_merge_witness {
    #[test]
    fn nozk() {
        super::check_nozk_opts("rollup_tx_merge", true);
    }
}
mod rollup_block_root_witness {
    #[test]
    fn nozk() {
        super::check_nozk_opts("rollup_block_root", true);
    }
}
mod rollup_block_root_single_tx_witness {
    #[test]
    fn nozk() {
        super::check_nozk_opts("rollup_block_root_single_tx", true);
    }
}
mod rollup_block_root_no_txs_witness {
    #[test]
    fn nozk() {
        super::check_nozk_opts("rollup_block_root_no_txs", true);
    }
}
mod rollup_block_merge_witness {
    #[test]
    fn nozk() {
        super::check_nozk_opts("rollup_block_merge", true);
    }
}
mod rollup_checkpoint_root_witness {
    #[test]
    fn nozk() {
        super::check_nozk_opts("rollup_checkpoint_root", true);
    }
}
mod rollup_checkpoint_root_single_block_witness {
    #[test]
    fn nozk() {
        super::check_nozk_opts("rollup_checkpoint_root_single_block", true);
    }
}
mod rollup_checkpoint_merge_witness {
    #[test]
    fn nozk() {
        super::check_nozk_opts("rollup_checkpoint_merge", true);
    }
}
mod rollup_checkpoint_padding_witness {
    #[test]
    fn nozk() {
        super::check_nozk_opts("rollup_checkpoint_padding", true);
    }
}

/// The circuits bb-ref can currently build, with the node's `--ipa_accumulation` flag (grows per
/// B-milestone; the rest of `backend_vk_hash/` is fixture-complete but unsupported until the
/// remaining recursion lowerings land: CHONK for rollup_tx_base_private/chonk_verifier_public,
/// keccak vk_hash for rollup_root, AVM never).
const SUPPORTED: &[(&str, bool)] = &[
    ("rollup_root", false),
    ("inbox_parity_4", false),
    ("inbox_parity_16", false),
    ("inbox_parity_64", false),
    ("inbox_parity_256", false),
    ("inbox_parity_1024", false),
    ("rollup_checkpoint_padding", true),
    ("rollup_tx_merge", true),
    ("rollup_checkpoint_merge", true),
    ("rollup_checkpoint_root", true),
    ("rollup_checkpoint_root_single_block", true),
    ("rollup_block_merge", true),
    ("rollup_block_root", true),
    ("rollup_block_root_no_txs", true),
    ("rollup_block_root_single_tx", true),
    ("rollup_tx_base_private", true),
    ("chonk_verifier_public", true),
];

fn artifact(name: &str) -> std::path::PathBuf {
    let copied = common::fixture_dir(&format!("backend/{name}/program.json"));
    if copied.exists() {
        return copied;
    }
    let root = std::env::var("PROTOCOL_CIRCUITS").unwrap_or_else(|_| {
        format!(
            "{}/pin/aztec-packages/noir-projects/fnd/noir-protocol-circuits/target",
            env!("CARGO_MANIFEST_DIR")
        )
    });
    std::path::PathBuf::from(root).join(format!("{name}.json"))
}

/// The VK hash of one `backend_vk_hash/` artifact against bb's (rollup_root's is the UltraKeccak
/// one: it is proven with `--oracle_hash keccak`, bb-prover honk.ts).
fn vk_hash_case(name: &str, full_only: bool) {
    if !common::in_tier(name, full_only) {
        return;
    }
    let _rng_guard = GLOBAL_RNG_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    bb_ref::base::rng::set_global(Box::new(bb_ref::base::rng::OsRng));
    let (_, ipa) = SUPPORTED.iter().find(|(n, _)| *n == name).expect("supported circuit");
    let expected: Fr = from_bytes_be(&common::read(&format!("backend_vk_hash/{name}")));
    let circuit = decode_program(&std::fs::read(artifact(name)).expect("program.json"));
    let mut builder = bb_ref::acir::lower::build_circuit_opts(&circuit, None, *ipa);
    let inst = ProverInstance::from_builder(&ULTRA, &mut builder, &mut OsRng);
    let ck = CommitmentKey::new(inst.max_end_index);
    let vk = inst.compute_vk(&ck);
    let hash: Fr = if name == "rollup_root" {
        let kvk = bb_ref::base::vk::Vk::<bb_ref::base::KeccakBn254> {
            log_circuit_size: vk.log_circuit_size,
            num_public_inputs: vk.num_public_inputs,
            pub_inputs_offset: vk.pub_inputs_offset,
            comms: vk.comms,
        };
        use bb_ref::base::codec::Transcriptable;
        <Fr as Transcriptable<bb_ref::base::U256>>::from_fields(&[kvk.hash()])
    } else {
        vk.hash()
    };
    assert_eq!(hash, expected, "{name}: VK hash");
}

/// Every `backend_vk_hash/` artifact is a supported circuit with a sweep case below.
#[test]
fn backend_vk_hash_fixtures_are_all_swept() {
    let dir = common::fixture_dir("backend_vk_hash");
    for e in std::fs::read_dir(&dir).expect("backend_vk_hash fixtures") {
        let name = e.unwrap().file_name().into_string().unwrap();
        assert!(SUPPORTED.iter().any(|(n, _)| *n == name), "{name}: no sweep case");
    }
}

macro_rules! vk_hash_sweep {
    ($($name:ident: $full_only:expr),* $(,)?) => {
        mod vk_hash_sweep { $(
            #[test] fn $name() { super::vk_hash_case(stringify!($name), $full_only); }
        )* }
    };
}
// One test per circuit so they run in parallel; the fast tier keeps the six that take a second or
// two (still through ROLLUP_HONK recursion and its IPA claim).
vk_hash_sweep! {
    inbox_parity_4: false,
    inbox_parity_16: false,
    inbox_parity_64: false,
    inbox_parity_256: true,
    inbox_parity_1024: true,
    rollup_checkpoint_padding: false,
    rollup_block_root_no_txs: false,
    rollup_block_root_single_tx: false,
    rollup_tx_merge: true,
    rollup_checkpoint_merge: true,
    rollup_checkpoint_root: true,
    rollup_checkpoint_root_single_block: true,
    rollup_block_merge: true,
    rollup_block_root: true,
    rollup_tx_base_private: true,
    chonk_verifier_public: true,
    rollup_root: true,
}

/// Gate-level diff of a backend write-VK circuit against a bb `BbRefDump.UltraWriteVk` dump
/// (deterministic polynomials only: precomputed and permutation; witness values are mock-random on
/// both sides). Set `BBREF_WVK=<name>`; the dump lives at `instance/backend_wvk/<name>`.
#[test]
fn backend_write_vk_instance_diff() {
    let _rng_guard = GLOBAL_RNG_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    bb_ref::base::rng::set_global(Box::new(bb_ref::base::rng::OsRng));
    let Ok(name) = std::env::var("BBREF_WVK") else {
        eprintln!("skipping: set BBREF_WVK=<circuit name>");
        return;
    };
    let dump = common::fixture_dir(&format!("instance/backend_wvk/{name}"));
    if !dump.join("vk").exists() {
        eprintln!("skipping {name}: no write-vk dump");
        return;
    }
    let ipa = SUPPORTED
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, i)| *i)
        .unwrap_or(true);
    let circuit = decode_program(&std::fs::read(artifact(&name)).expect("program.json"));
    let mut builder = bb_ref::acir::lower::build_circuit_opts(&circuit, None, ipa);
    let inst = ProverInstance::from_builder(&ULTRA, &mut builder, &mut OsRng);
    let expected = ProverInstance::load_dump(&ULTRA, &dump);
    assert_eq!(inst.dyadic_size, expected.dyadic_size, "{name}: dyadic size");
    let compare: Vec<usize> = (0..inst.layout.num_unshifted())
        .filter(|&i| {
            let n = inst.layout.unshifted[i].name();
            n.starts_with("q_")
                || n.starts_with("sigma_")
                || n.starts_with("id_")
                || n.starts_with("table_")
                || n.starts_with("lagrange_")
        })
        .collect();
    common::assert_polys_equal(&name, &inst, &expected, &builder, &compare);
    eprintln!("{name}: deterministic polynomials match");
}
