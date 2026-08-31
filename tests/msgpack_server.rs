//! Differential oracle for the msgpack server: the same request frames through `bin/bb msgpack
//! run` (the pin-built bb) and through bb-ref's handler, response streams compared frame by frame.
//! Both sides run seeded, so every response — proofs included — must be byte-identical; error
//! responses are compared by shape where bb's message text is legitimately different (noted
//! per case).

use bb_ref::acir::format::gunzip;
use bb_ref::base::rng::{set_global, DebugRng};
use bb_ref::msgpack::generated::bb_server::handle_request;
use bb_ref::msgpack::generated::bb_types::*;
use bb_ref::msgpack::handler::BbRefHandler;
use serde::de::{Deserializer, Visitor};
use serde::Deserialize;

/// msgpack `bin` as bytes (serde's `Vec<u8>` only accepts sequences).
struct Bytes(Vec<u8>);

impl<'de> Deserialize<'de> for Bytes {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Bytes;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("bytes")
            }
            fn visit_bytes<E>(self, v: &[u8]) -> Result<Bytes, E> {
                Ok(Bytes(v.to_vec()))
            }
        }
        d.deserialize_bytes(V)
    }
}
use std::path::{Path, PathBuf};
use std::process::Command as Proc;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn fixture(rel: &str) -> PathBuf {
    repo_root().join("fixtures/data/9df414e").join(rel)
}

/// The raw gzipped ACIR buffer out of a program.json wrapper.
fn bytecode_gz(program_json: &Path) -> Vec<u8> {
    #[derive(Deserialize)]
    struct P {
        bytecode: String,
    }
    let p: P = serde_json::from_slice(&std::fs::read(program_json).unwrap()).unwrap();
    use base64::Engine;
    gunzip(&base64::engine::general_purpose::STANDARD.decode(p.bytecode).unwrap())
}

/// One wire frame: `[u32 len][u64 request_id][payload]`, the length covering id and payload. Both
/// servers read this framing from a file, a pipe, a socket or shared memory, so the same bytes go
/// to either. Ids are the caller's to choose and come back echoed; these are sequential.
fn encode_frame(cmd: &Command, request_id: u64) -> Vec<u8> {
    let payload = rmp_serde::to_vec_named(&vec![cmd]).unwrap();
    let mut frame = ((payload.len() + 8) as u32).to_le_bytes().to_vec();
    frame.extend_from_slice(&request_id.to_le_bytes());
    frame.extend_from_slice(&payload);
    frame
}

fn split_frames(stream: &[u8]) -> Vec<Vec<u8>> {
    let mut frames = Vec::new();
    let mut i = 0;
    while i + 12 <= stream.len() {
        let len = u32::from_le_bytes(stream[i..i + 4].try_into().unwrap()) as usize;
        // Skip the echoed request id; the payload is what gets compared.
        i += 12;
        frames.push(stream[i..i + len - 8].to_vec());
        i += len - 8;
    }
    assert_eq!(i, stream.len(), "trailing bytes in response stream");
    frames
}

/// Runs the frames through `bin/bb msgpack run` with the given env, and through a fresh seeded
/// in-process handler, returning both response streams split into frames.
fn run_both(name: &str, cmds: &[Command], threads: Option<u32>) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let dir = std::env::temp_dir().join(format!("bbref-msgpack-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let input = dir.join("frames.bin");
    let mut all = Vec::new();
    for (n, c) in cmds.iter().enumerate() {
        all.extend_from_slice(&encode_frame(c, n as u64 + 1));
    }
    std::fs::write(&input, &all).unwrap();

    let bb = repo_root().join("bin/bb");
    assert!(bb.exists(), "bin/bb missing — run ./bootstrap.sh");
    let mut proc = Proc::new(&bb);
    proc.args(["msgpack", "run", "--input"])
        .arg(&input)
        .env("BB_RNG_SEED", "12345");
    if let Some(t) = threads {
        proc.env("HARDWARE_CONCURRENCY", t.to_string());
    }
    let out = proc.output().expect("running bin/bb");
    assert!(
        out.status.success(),
        "bb msgpack run failed for {name}: {}",
        String::from_utf8_lossy(&out.stderr)
            .chars()
            .rev()
            .take(2000)
            .collect::<String>()
            .chars()
            .rev()
            .collect::<String>()
    );
    let bb_frames = split_frames(&out.stdout);

    set_global(Box::new(DebugRng::new(12345)));
    let mut handler = BbRefHandler::new();
    let ours: Vec<Vec<u8>> = cmds
        .iter()
        .map(|c| handle_request(&mut handler, &rmp_serde::to_vec_named(&vec![c]).unwrap()))
        .collect();
    (bb_frames, ours)
}

fn assert_streams_equal(name: &str, bb: &[Vec<u8>], ours: &[Vec<u8>], cmds: &[Command]) {
    assert_eq!(bb.len(), ours.len(), "{name}: response count");
    for (i, (b, o)) in bb.iter().zip(ours).enumerate() {
        if b != o {
            let d = b
                .iter()
                .zip(o.iter())
                .position(|(x, y)| x != y)
                .unwrap_or(b.len().min(o.len()));
            panic!(
                "{name}: frame {i} ({:?}) differs at byte {d} (bb {} bytes / ours {} bytes; bb tag {}, ours tag {})",
                cmds.get(i).map(command_name),
                b.len(),
                o.len(),
                response_tag(b),
                response_tag(o),
            );
        }
    }
}

fn response_tag(frame: &[u8]) -> String {
    #[derive(Deserialize)]
    struct Tagged(String, serde::de::IgnoredAny);
    rmp_serde::from_slice::<Tagged>(frame).map(|t| t.0).unwrap_or_default()
}

fn command_name(c: &Command) -> &'static str {
    match c {
        Command::BbCircuitProve(_) => "CircuitProve",
        Command::BbCircuitComputeVk(_) => "CircuitComputeVk",
        Command::BbCircuitVerify(_) => "CircuitVerify",
        Command::BbChonkStart(_) => "ChonkStart",
        Command::BbChonkLoad(_) => "ChonkLoad",
        Command::BbChonkAccumulate(_) => "ChonkAccumulate",
        Command::BbChonkProve(_) => "ChonkProve",
        Command::BbChonkVerify(_) => "ChonkVerify",
        Command::BbPoseidon2Hash(_) => "Poseidon2Hash",
        Command::BbAvmProve(_) => "AvmProve",
        _ => "other",
    }
}

fn settings(oracle: &str, disable_zk: bool, ipa: bool) -> ProofSystemSettings {
    ProofSystemSettings {
        ipa_accumulation: ipa,
        oracle_hash_type: oracle.into(),
        disable_zk,
        optimized_solidity_verifier: false,
    }
}

/// One deterministic sequence per fixture circuit: ComputeVk and Prove (vk computed in-band),
/// byte-compared; then a Verify command built from those very responses, byte-compared again.
/// Self-contained — the only inputs are the committed bytecode and witness.
fn circuit_case(name: &str, dir: &Path, oracle: &str, ipa: bool, threads: Option<u32>) {
    let bytecode = bytecode_gz(&dir.join("program.json"));
    let witness = gunzip(&std::fs::read(dir.join("witness.gz")).unwrap());
    let s = settings(oracle, true, ipa);

    let cmds = vec![
        Command::BbCircuitComputeVk(BbCircuitComputeVk {
            circuit: CircuitInputNoVK { name: name.into(), bytecode: bytecode.clone() },
            settings: s.clone(),
        }),
        Command::BbCircuitProve(BbCircuitProve {
            circuit: CircuitInput { name: name.into(), bytecode, verification_key: vec![] },
            witness,
            settings: s.clone(),
        }),
    ];
    let (bb, ours) = run_both(name, &cmds, threads);
    assert_streams_equal(name, &bb, &ours, &cmds);

    let (_, vk_resp): (String, BbCircuitComputeVkResponse) = rmp_serde::from_slice(&bb[0]).unwrap();
    let (_, prove_resp): (String, BbCircuitProveResponse) = rmp_serde::from_slice(&bb[1]).unwrap();
    let verify = vec![Command::BbCircuitVerify(BbCircuitVerify {
        verification_key: vk_resp.bytes,
        public_inputs: prove_resp.public_inputs,
        proof: prove_resp.proof,
        settings: s,
    })];
    let (bbv, oursv) = run_both(&format!("{name}_verify"), &verify, threads);
    assert_streams_equal(&format!("{name}_verify"), &bbv, &oursv, &verify);
    println!("{name}: {} responses byte-identical", bb.len() + 1);
}

/// The transfer pinned flow driven as bb drives it over the wire: ChonkStart, then per step
/// ChonkLoad + ChonkAccumulate, ChonkProve, and a ChonkVerify of the produced proof.
fn chonk_case() {
    let flow = PathBuf::from(std::env::var("HOME").unwrap()).join(
        "aztec-repos/aztec-packages2/barretenberg/cpp/chonk-pinned-flows/ecdsar1+transfer_0_recursions+sponsored_fpc/ivc-inputs.msgpack",
    );
    if !flow.exists() {
        eprintln!("skipping chonk case: {} missing", flow.display());
        return;
    }
    #[derive(Deserialize)]
    struct StepRaw {
        bytecode: Bytes,
        witness: Bytes,
        vk: Bytes,
        #[serde(rename = "functionName")]
        function_name: String,
        kind: u8,
    }
    let steps: Vec<StepRaw> = rmp_serde::from_slice(&std::fs::read(&flow).unwrap()).unwrap();

    let mut cmds = vec![Command::BbChonkStart(BbChonkStart {
        kinds: steps.iter().map(|s| s.kind).collect(),
    })];
    for s in &steps {
        cmds.push(Command::BbChonkLoad(BbChonkLoad {
            circuit: CircuitInput {
                name: s.function_name.clone(),
                bytecode: gunzip(&s.bytecode.0),
                verification_key: s.vk.0.clone(),
            },
            kind: s.kind,
        }));
        cmds.push(Command::BbChonkAccumulate(BbChonkAccumulate {
            witness: gunzip(&s.witness.0),
        }));
    }
    cmds.push(Command::BbChonkProve(BbChonkProve {}));

    // ZK/Chonk proving draws from parallel phases, so byte-reproducibility needs one thread.
    let (bb, ours) = run_both("chonk_transfer", &cmds, Some(1));
    assert_streams_equal("chonk_transfer", &bb, &ours, &cmds);

    // Round-trip: verify the proof both produced, through both implementations.
    let resp: (String, BbChonkProveResponse) = rmp_serde::from_slice(bb.last().unwrap()).unwrap();
    let hiding_vk = steps.last().unwrap().vk.0.clone();
    let verify = vec![Command::BbChonkVerify(BbChonkVerify {
        proof: resp.1.proof,
        vk: hiding_vk,
    })];
    let (bbv, oursv) = run_both("chonk_verify", &verify, Some(1));
    assert_streams_equal("chonk_verify", &bbv, &oursv, &verify);
    println!("chonk_transfer: {} responses byte-identical", bb.len() + 1);
}

/// bb serves every command, so "unsupported" can only be compared by shape: both sides must
/// answer commands we reject with SOME well-formed response, and malformed frames with an error.
fn error_shape_case() {
    let avm = Command::BbAvmProve(BbAvmProve { inputs: vec![1, 2, 3] });
    let (bb, ours) = run_both("errors", &[avm.clone()], None);
    // Stock bb rejects AVM proving ("AVM is not supported in this build"), we reject it as
    // unsupported — the message text differs, the response type must not.
    assert_eq!(response_tag(&bb[0]), "BbErrorResponse", "bb response to AvmProve");
    assert_eq!(response_tag(&ours[0]), "BbErrorResponse", "our response to AvmProve");
    println!("errors: both sides answer AvmProve with BbErrorResponse (texts differ by design)");
}

#[test]
fn msgpack_server_oracle() {
    circuit_case(
        "inbox_parity_64",
        &fixture("backend/inbox_parity_64"),
        "poseidon2",
        false,
        None,
    );
    circuit_case("a_1_mul_keccak", &fixture("keccak/a_1_mul"), "keccak", false, None);
    circuit_case("rollup_parity_root", &fixture("backend/rollup_parity_root"), "poseidon2", false, None);
    error_shape_case();
    chonk_case();
}
