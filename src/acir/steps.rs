//! bb `PrivateExecutionSteps`: the `ivc-inputs.msgpack` a Chonk proof is made from — one
//! `{bytecode, witness, vk, functionName, kind}` per circuit, bytecode and witness gzipped.

use super::format::{decode_program_gz, decode_witness, Circuit};
use super::lower::build_circuit_mega;
use crate::base::rng::Rng;
use crate::base::vk::Vk;
use crate::base::{Bn254, CommitmentKey, Fr};
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
    pub circuit: Circuit,
    /// The gzipped witness, decoded (and its gaps filled with random elements) only when the step is
    /// accumulated: `bb prove` drives the bbapi `ChonkAccumulate` command, which decodes per step,
    /// so the gap-fill draws interleave with the accumulation draws.
    pub witness_gz: Vec<u8>,
    pub kind: CircuitKind,
    /// The VK pinned alongside the circuit; proving checks the circuit still has it.
    pub vk: Vk<Bn254>,
}

impl PrivateExecutionStep {
    pub fn decode_witness(&self, rng: &mut dyn Rng) -> Vec<Fr> {
        decode_witness(&self.witness_gz, rng)
    }
}

/// The bytecode/VK halves of bb's step parsing (witnesses stay raw; see `PrivateExecutionStep`).
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
                circuit: decode_program_gz(&s.bytecode.0),
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
pub fn prove_steps(
    steps: &[PrivateExecutionStep],
    ck: CommitmentKey,
    rng: &mut dyn Rng,
    check_vks: bool,
) -> (ChonkProof, Vk<Bn254>) {
    let mut ivc = Chonk::new(steps.iter().map(|s| s.kind).collect(), ck);
    for step in steps {
        crate::base::timing::phase(&format!("== {} ({:?})", step.name, step.kind));
        let witness = step.decode_witness(rng);
        let mut circuit = build_circuit_mega(&step.circuit, Some(&witness), Some(&mut ivc), rng);
        assert!(
            circuit.failed.is_none(),
            "{}: circuit not satisfied: {:?}",
            step.name,
            circuit.failed
        );
        drop(witness);
        crate::base::timing::phase("circuit built");
        ivc.accumulate(circuit, (!check_vks).then(|| step.vk.clone()), rng);
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
    let proof = ivc.prove(rng);
    let vk = ivc.hiding_vk().clone();
    (proof, vk)
}
