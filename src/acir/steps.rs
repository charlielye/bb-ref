//! bb `PrivateExecutionSteps`: the `ivc-inputs.msgpack` a Chonk proof is made from — one
//! `{bytecode, witness, vk, functionName, kind}` per circuit, bytecode and witness gzipped.

use super::format::{decode_program_gz, decode_witness, decode_witness_gaps, Circuit};
use super::lower::{build_circuit_mega, finish_circuit_mega, prebuild_circuit_mega, Prebuilt};
use crate::base::rng::Rng;
use crate::base::vk::Vk;
use crate::base::{Bn254, CommitmentKey, Fr};
use crate::circuit::Builder;
use crate::chonk::ivc::{Chonk, CircuitKind};
use crate::chonk::proof::ChonkProof;
use serde::de::{Deserializer, SeqAccess, Visitor};
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
            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Bytes, E> {
                Ok(Bytes(v.to_vec()))
            }
            fn visit_byte_buf<E: serde::de::Error>(self, v: Vec<u8>) -> Result<Bytes, E> {
                Ok(Bytes(v))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Bytes, A::Error> {
                let mut v = vec![];
                while let Some(b) = seq.next_element()? {
                    v.push(b);
                }
                Ok(Bytes(v))
            }
        }
        d.deserialize_any(V)
    }
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

pub struct PrivateExecutionStep {
    pub name: String,
    /// The gzipped bytecode, decoded only when the step is accumulated (bb `ChonkLoad` per step),
    /// so at most one decoded program is alive at a time.
    pub bytecode_gz: Vec<u8>,
    /// The gzipped witness, decoded (and its gaps filled with random elements) only when the step is
    /// accumulated: `bb prove` drives the bbapi `ChonkAccumulate` command, which decodes per step,
    /// so the gap-fill draws interleave with the accumulation draws.
    pub witness_gz: Vec<u8>,
    pub kind: CircuitKind,
    /// The VK pinned alongside the circuit; proving checks the circuit still has it.
    pub vk: Vk<Bn254>,
}

impl PrivateExecutionStep {
    pub fn circuit(&self) -> Circuit {
        decode_program_gz(&self.bytecode_gz)
    }
    pub fn decode_witness(&self, rng: &mut dyn Rng) -> Vec<Fr> {
        decode_witness(&self.witness_gz, rng)
    }
}

/// The VK half of bb's step parsing (bytecode and witnesses stay raw; see `PrivateExecutionStep`).
pub fn decode_steps(bytes: &[u8]) -> Vec<PrivateExecutionStep> {
    let raw: Vec<StepRaw> = rmp_serde::from_slice(bytes).expect("ivc-inputs msgpack");
    raw.into_iter()
        .map(|s| {
            let kind = match s.kind {
                0 => CircuitKind::App,
                1 => CircuitKind::Kernel,
                2 => CircuitKind::HidingKernel,
                k => panic!("unknown circuit kind {k}"),
            };
            PrivateExecutionStep {
                name: s.function_name,
                bytecode_gz: s.bytecode.0,
                witness_gz: s.witness.0,
                kind,
                vk: Vk::<crate::base::Bn254>::from_bytes(&s.vk.0, kind.flavor().layout().num_precomputed),
            }
        })
        .collect()
}

/// bb `ChonkAPI::prove`: accumulate every step, then prove. Returns the proof and the hiding
/// kernel's VK. `check_vks` recomputes each circuit's VK and compares it with the pinned one
/// (bb `--vk_policy check`); otherwise the pinned VKs are used as they are (bb's default).
/// `prebuild` builds each next circuit on a helper thread while the current step accumulates: the
/// serial build is mostly hidden, but the finished builder is held through that accumulation's
/// memory peak (opt-in: faster for up to one extra builder of memory).
pub fn prove_steps(
    mut steps: Vec<PrivateExecutionStep>,
    ck: CommitmentKey,
    rng: &mut dyn Rng,
    check_vks: bool,
    prebuild: bool,
) -> (ChonkProof, Vk<Bn254>) {
    let mut ivc = Chonk::new(steps.iter().map(|s| s.kind).collect(), ck);
    // Each step's gzipped bytecode and witness, taken when decoded so they are freed as they go.
    let mut inputs: Vec<_> = (steps.iter_mut())
        .map(|s| Some((std::mem::take(&mut s.bytecode_gz), std::mem::take(&mut s.witness_gz))))
        .collect();
    std::thread::scope(|s| {
        // Step `i + 1`'s circuit, lowered on a helper thread while step `i` accumulates; its inputs
        // come back when it has to be built in turn.
        let mut next: Option<std::thread::ScopedJoinHandle<Result<Prebuilt, Inputs>>> = None;
        for (i, step) in steps.iter().enumerate() {
            crate::base::timing::phase(&format!("== {} ({:?})", step.name, step.kind));
            let _gc = next.is_some().then(|| crate::base::bench::Scope::new("create_circuit"));
            let circuit = match next.take().map(|h| h.join().unwrap_or_else(|e| std::panic::resume_unwind(e))) {
                Some(Ok(prebuilt)) => {
                    crate::base::timing::phase("      build: built ahead");
                    finish_circuit_mega(prebuilt, &mut ivc, rng)
                }
                Some(Err(input)) => build_inline(input, &mut ivc, rng),
                None => build_inline(inputs[i].take().unwrap(), &mut ivc, rng),
            };
            drop(_gc);
            assert!(
                circuit.failed.is_none(),
                "{}: circuit not satisfied: {:?}",
                step.name,
                circuit.failed
            );
            crate::base::timing::phase("circuit built");
            if prebuild && i + 1 < steps.len() {
                let (bytecode, witness) = inputs[i + 1].take().unwrap();
                let helper = std::thread::Builder::new().stack_size(if cfg!(target_family = "wasm") { 1 << 20 } else { 8 << 20 });
                next = Some(helper.spawn_scoped(s, move || {
                    let _gp = crate::base::bench::Scope::new("prebuild");
                    let (w, gaps) = decode_witness_gaps(&witness);
                    prebuild_circuit_mega(&decode_program_gz(&bytecode), &w, gaps).ok_or((bytecode, witness))
                }).unwrap());
            }
            let _ga = crate::base::bench::Scope::new("Chonk::accumulate");
            ivc.accumulate(circuit, (!check_vks).then(|| step.vk.clone()), rng);
            drop(_ga);
            if check_vks {
                let computed = match step.kind {
                    CircuitKind::HidingKernel => ivc.hiding_vk(),
                    _ => &ivc.verification_queue.last().unwrap().vk,
                };
                assert_eq!(
                    computed.to_bytes(),
                    step.vk.to_bytes(),
                    "{}: the pinned VK does not match the circuit",
                    step.name
                );
            }
        }
    });
    let proof = ivc.prove(rng);
    let vk = ivc.hiding_vk().clone();
    (proof, vk)
}

/// A step's gzipped bytecode and witness.
type Inputs = (Vec<u8>, Vec<u8>);

fn build_inline((bytecode, witness): Inputs, ivc: &mut Chonk, rng: &mut dyn Rng) -> Builder {
    let _gp = crate::base::bench::Scope::new("decode_program");
    let program = decode_program_gz(&bytecode);
    drop((_gp, bytecode));
    let _gc = crate::base::bench::Scope::new("create_circuit");
    let _gw = crate::base::bench::Scope::new("create_circuit/decode_witness");
    let witness = decode_witness(&witness, rng);
    drop(_gw);
    let _gb = crate::base::bench::Scope::new("create_circuit/build_circuit");
    build_circuit_mega(&program, Some(&witness), Some(ivc), rng)
}
