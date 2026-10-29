//! bb's bbapi command handlers over bb-ref's proving functions.
//!
//! Each implemented command mirrors the semantics of bb's thin adapters (`bbapi_ultra_honk.cpp`,
//! `bbapi_chonk.cpp`): the same flavor dispatch, the same proof split, the same self-verification,
//! and error responses where bb throws. Commands outside the proving surface answer
//! `unsupported command`. All randomness draws from the process-global source, so `BB_RNG_SEED`
//! governs reproducibility exactly as it does for bb.

use super::generated::bb_server::{Handler, Responder};
use super::generated::bb_types::*;
use crate::acir::build_circuit_mega;
use crate::acir::format::{decode_program_raw, decode_witness_raw};
use crate::acir::lower::build_circuit_srs;
use crate::base::field::{to_bytes_be, Fr as FrField, U256};
use crate::base::keccak::u256_to_bytes_be;
use crate::base::poseidon2::{self, Hasher};
use crate::base::rng::GlobalProxy;
use crate::base::srs::{bn254_g2, Srs};
use crate::base::{Bn254, KeccakBn254, Vk as VkGeneric};
use crate::chonk::ivc::Chonk;
use crate::chonk::ivc::CircuitKind;
use crate::chonk::verifier::chonk_verify;
use crate::goblin::eccvm::FIXED_SIZE as ECCVM_FIXED_SIZE;
use crate::honk::prover_instance::ProverInstance;
use crate::honk::ultra_prover::prove_ultra_as;
use crate::honk::ultra_verifier::{verify_ultra, verify_ultra_keccak};
use crate::honk::{FlavorDesc, MEGA_APP, MEGA_KERNEL, MEGA_ZK, ULTRA, ULTRA_KECCAK, ULTRA_KECCAK_ZK, ULTRA_ZK};
use crate::rollup::{verify_ultra_rollup, ROLLUP_PUBLIC_INPUTS_SIZE};
use std::panic::{catch_unwind, AssertUnwindSafe};

/// bb `dispatch_by_settings` (`bbapi_shared.hpp`): settings -> (flavor, IO), with bb's exact
/// rejection messages. Rollup circuits force UltraFlavor + RollupIO; `disable_zk` is ignored there.
pub fn select_flavor(s: &ProofSystemSettings) -> Result<(&'static FlavorDesc, bool), String> {
    if s.ipa_accumulation {
        if s.oracle_hash_type != "poseidon2" {
            return Err(format!(
                "Rollup circuits (ipa_accumulation=true) must use oracle_hash_type='poseidon2', got '{}'",
                s.oracle_hash_type
            ));
        }
        return Ok((&ULTRA, true));
    }
    match (s.oracle_hash_type.as_str(), s.disable_zk) {
        ("poseidon2", true) => Ok((&ULTRA, false)),
        ("poseidon2", false) => Ok((&ULTRA_ZK, false)),
        ("keccak", true) => Ok((&ULTRA_KECCAK, false)),
        ("keccak", false) => Ok((&ULTRA_KECCAK_ZK, false)),
        _ => Err(format!(
            "Invalid proof system settings: oracle_hash_type='{}', disable_zk={}, ipa_accumulation={}",
            s.oracle_hash_type, s.disable_zk as u8, s.ipa_accumulation as u8
        )),
    }
}

fn io_public_inputs_size(ipa: bool) -> usize {
    if ipa {
        ROLLUP_PUBLIC_INPUTS_SIZE
    } else {
        8
    }
}

fn fr_to_wire(f: &FrField) -> Bin32 {
    Bin32(to_bytes_be(f))
}

fn u256_to_wire(u: &U256) -> Bin32 {
    Bin32(u256_to_bytes_be(u))
}

/// bb's wire decoding of a field element rejects a non-canonical encoding.
fn fr_from_wire(b: &Bin32) -> FrField {
    crate::base::field::from_bytes_be_canonical(&b.0)
}

fn u256_from_wire(b: &Bin32) -> U256 {
    let mut limbs = [0u64; 4];
    for (i, chunk) in b.0.chunks(8).enumerate() {
        limbs[3 - i] = u64::from_be_bytes(chunk.try_into().unwrap());
    }
    U256::new(limbs)
}

fn is_canonical_fr(b: &Bin32) -> bool {
    use ark_ff::PrimeField;
    u256_from_wire(b) < FrField::MODULUS
}

/// The keccak flavors share the poseidon2 VK's commitments under the U256 codec.
/// Reinterpret a native VK under the keccak transcript codec (same data, different wire type).
pub fn as_keccak_vk(vk: VkGeneric<Bn254>) -> VkGeneric<KeccakBn254> {
    VkGeneric::<KeccakBn254> {
        log_circuit_size: vk.log_circuit_size,
        num_public_inputs: vk.num_public_inputs,
        pub_inputs_offset: vk.pub_inputs_offset,
        comms: vk.comms,
    }
}

fn vk_data_poseidon2(vk: &VkGeneric<Bn254>) -> VkData {
    VkData {
        bytes: vk.to_bytes(),
        fields: vk.to_fields().iter().map(fr_to_wire).collect(),
        hash: to_bytes_be(&vk.hash()).to_vec(),
    }
}

fn vk_data_keccak(vk: &VkGeneric<KeccakBn254>) -> VkData {
    VkData {
        bytes: vk.to_bytes(),
        fields: vk.to_fields().iter().map(u256_to_wire).collect(),
        hash: u256_to_bytes_be(&vk.hash()).to_vec(),
    }
}

/// One circuit loaded by `ChonkLoad`, consumed by the next `ChonkAccumulate` (bb keeps the same
/// staging area on `BBApiRequest`).
struct Loaded {
    circuit: crate::acir::format::Circuit,
    vk_bytes: Vec<u8>,
    kind: CircuitKind,
}

/// bb's `BBApiRequest`: the state that persists across commands of one connection/stream.
#[derive(Default)]
pub struct BbRefHandler {
    ivc: Option<Chonk>,
    loaded: Option<Loaded>,
    srs: Srs,
}

impl BbRefHandler {
    /// `srs` is the server's preloaded pool; `Srs::default()` (empty, load-on-demand) suits
    /// one-shot and test use.
    pub fn new(srs: Srs) -> Self {
        Self { srs, ..Self::default() }
    }
}

/// Runs a handler body, converting a panic into bb's catch-all error response (bb wraps every
/// handler in `catch (std::exception& e) { responder.error(e.what()) }`; our proving functions
/// signal malformed input by panicking).
fn run_catching<R>(respond: Responder<R>, body: impl FnOnce() -> Result<R, String>) {
    let result = catch_unwind(AssertUnwindSafe(body));
    match result {
        Ok(Ok(resp)) => respond.ok(resp),
        Ok(Err(msg)) => respond.error(msg),
        Err(panic) => {
            let msg = panic
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| panic.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_else(|| "internal error".to_string());
            respond.error(msg);
        }
    }
}

/// The wire `ChonkProof` carries the same five sub-proofs as the internal one.
fn wire_to_chonk_proof(p: &crate::msgpack::generated::bb_types::ChonkProof) -> crate::chonk::proof::ChonkProof {
    let f = |v: &Vec<Bin32>| v.iter().map(fr_from_wire).collect();
    crate::chonk::proof::ChonkProof {
        hiding_oink_proof: f(&p.hiding_oink_proof),
        merge_proof: f(&p.merge_proof),
        eccvm_proof: f(&p.eccvm_proof),
        ipa_proof: f(&p.ipa_proof),
        joint_proof: f(&p.joint_proof),
    }
}

fn chonk_proof_to_wire(p: &crate::chonk::proof::ChonkProof) -> crate::msgpack::generated::bb_types::ChonkProof {
    let f = |v: &Vec<FrField>| v.iter().map(fr_to_wire).collect();
    crate::msgpack::generated::bb_types::ChonkProof {
        hiding_oink_proof: f(&p.hiding_oink_proof),
        merge_proof: f(&p.merge_proof),
        eccvm_proof: f(&p.eccvm_proof),
        ipa_proof: f(&p.ipa_proof),
        joint_proof: f(&p.joint_proof),
    }
}

/// bb `_verify<Flavor, IO>`: native verification of a split (public_inputs, proof) pair. Malformed
/// inputs (wrong sizes, bad points) make the underlying verifier panic; the caller maps that to
/// `verified: false` like bb's explicit size checks do.
fn native_verify(
    flavor: &'static FlavorDesc,
    ipa: bool,
    srs: &Srs,
    vk_bytes: &[u8],
    public_inputs: &[Bin32],
    proof: &[Bin32],
) -> bool {
    let keccak = flavor.name.contains("Keccak");
    catch_unwind(AssertUnwindSafe(|| {
        if ipa {
            let vk = VkGeneric::<Bn254>::from_bytes(vk_bytes, flavor.layout().num_precomputed);
            let pis: Vec<FrField> = public_inputs.iter().map(fr_from_wire).collect();
            let pf: Vec<FrField> = proof.iter().map(fr_from_wire).collect();
            verify_ultra_rollup(flavor, &vk, &pis, &pf, &bn254_g2(), &srs.grumpkin_key(1 << 16))
        } else if keccak {
            let vk = VkGeneric::<KeccakBn254>::from_bytes(vk_bytes, flavor.layout().num_precomputed);
            let pis: Vec<FrField> = public_inputs.iter().map(fr_from_wire).collect();
            let pf: Vec<U256> = proof.iter().map(u256_from_wire).collect();
            verify_ultra_keccak(flavor, &vk, &pis, &pf, &bn254_g2())
        } else {
            let vk = VkGeneric::<Bn254>::from_bytes(vk_bytes, flavor.layout().num_precomputed);
            let pis: Vec<FrField> = public_inputs.iter().map(fr_from_wire).collect();
            let pf: Vec<FrField> = proof.iter().map(fr_from_wire).collect();
            verify_ultra(flavor, &vk, &pis, &pf, &bn254_g2())
        }
    }))
    .unwrap_or(false)
}

/// bb `_prove<Flavor, IO>` (`bbapi_ultra_honk.cpp`): build, prove, split, self-verify.
/// Reports global RNG draws per command under BBREF_RNG_COUNT.
struct DrawReport(u64, String);
impl Drop for DrawReport {
    fn drop(&mut self) {
        if std::env::var_os("BBREF_RNG_COUNT").is_some() {
            let now = crate::base::rng::GLOBAL_DRAWS.load(std::sync::atomic::Ordering::Relaxed);
            eprintln!("[rng] {} drew {} (total {now})", self.1, now - self.0);
        }
    }
}
fn scopeguard_draws(before: u64, name: String) -> DrawReport {
    DrawReport(before, name)
}

fn circuit_prove_impl(cmd: BbCircuitProve, srs: &Srs) -> Result<BbCircuitProveResponse, String> {
    let draws_before = crate::base::rng::GLOBAL_DRAWS.load(std::sync::atomic::Ordering::Relaxed);
    let _guard = scopeguard_draws(draws_before, cmd.circuit.name.clone());
    let (flavor, ipa) = select_flavor(&cmd.settings)?;
    let keccak = flavor.name.contains("Keccak");

    crate::base::timing::phase("cmd: start");
    let circuit = decode_program_raw(&cmd.circuit.bytecode);
    let mut rng = GlobalProxy;
    let witness = decode_witness_raw(&cmd.witness, &mut rng);
    crate::base::timing::phase("cmd: decode");
    let builder = build_circuit_srs(&circuit, Some(&witness), ipa, srs);
    crate::base::timing::phase("cmd: build");
    if let Some(msg) = &builder.failed {
        return Err(format!("circuit is not satisfied: {msg}"));
    }
    // The builder and decoded witness are dead weight from here; the prover's peak working set
    // (instance + sumcheck tables + shplemini batches) is what remains, as in bb.
    let mut inst = ProverInstance::from_circuit(flavor, builder, &mut rng);
    drop(witness);
    crate::base::timing::phase("cmd: instance");

    // bb validates IO/IPA consistency after instance construction.
    if ipa && inst.ipa_proof.is_empty() {
        return Err("RollupIO circuit expected IPA proof but none was provided. Ensure the circuit includes IPA accumulation data.".into());
    }
    if !ipa && !inst.ipa_proof.is_empty() {
        return Err(
            "Non-rollup circuit should not have IPA proof. Use ipa_accumulation=true in settings for rollup circuits."
                .into(),
        );
    }

    let ck = srs.bn254_key(inst.max_end_index);
    crate::base::timing::phase("cmd: commitment key");
    let num_public_inputs = inst.public_inputs.len();
    let io_size = io_public_inputs_size(ipa);
    if num_public_inputs < io_size {
        return Err("Public inputs should contain the expected IO structure.".into());
    }
    let num_inner = num_public_inputs - io_size;

    let vk_provided = !cmd.circuit.verification_key.is_empty();
    let (public_inputs, proof, vk_bytes, vk_response): (Vec<Bin32>, Vec<Bin32>, Vec<u8>, VkData) = if keccak {
        let vk = if vk_provided {
            VkGeneric::<KeccakBn254>::from_bytes(&cmd.circuit.verification_key, flavor.layout().num_precomputed)
        } else {
            as_keccak_vk(inst.compute_vk(&ck))
        };
        let full = prove_ultra_as::<KeccakBn254>(&mut inst, &vk, srs, &mut rng);
        let (pis, pf) = full.split_at(num_inner);
        let vk_response = if vk_provided {
            VkData::default()
        } else {
            vk_data_keccak(&vk)
        };
        (
            pis.iter().map(u256_to_wire).collect(),
            pf.iter().map(u256_to_wire).collect(),
            vk.to_bytes(),
            vk_response,
        )
    } else {
        let vk = if vk_provided {
            VkGeneric::<Bn254>::from_bytes(&cmd.circuit.verification_key, flavor.layout().num_precomputed)
        } else {
            inst.compute_vk(&ck)
        };
        let full = prove_ultra_as::<Bn254>(&mut inst, &vk, srs, &mut rng);
        let (pis, pf) = full.split_at(num_inner);
        let vk_response = if vk_provided {
            VkData::default()
        } else {
            vk_data_poseidon2(&vk)
        };
        (
            pis.iter().map(fr_to_wire).collect(),
            pf.iter().map(fr_to_wire).collect(),
            vk.to_bytes(),
            vk_response,
        )
    };

    crate::base::timing::phase("cmd: prove+vk");
    if !native_verify(flavor, ipa, srs, &vk_bytes, &public_inputs, &proof) {
        return Err("Failed to verify the generated proof!".into());
    }

    crate::base::timing::phase("cmd: self-verify");
    Ok(BbCircuitProveResponse {
        public_inputs,
        proof,
        vk: vk_response,
    })
}

fn circuit_compute_vk_impl(cmd: BbCircuitComputeVk, srs: &Srs) -> Result<BbCircuitComputeVkResponse, String> {
    let (flavor, ipa) = select_flavor(&cmd.settings)?;
    let keccak = flavor.name.contains("Keccak");
    let circuit = decode_program_raw(&cmd.circuit.bytecode);
    let mut rng = GlobalProxy;
    let mut builder = build_circuit_srs(&circuit, None, ipa, srs);
    let inst = ProverInstance::from_builder(flavor, &mut builder, &mut rng);
    let ck = srs.bn254_key(inst.max_end_index);
    let d = if keccak {
        vk_data_keccak(&as_keccak_vk(inst.compute_vk(&ck)))
    } else {
        vk_data_poseidon2(&inst.compute_vk(&ck))
    };
    Ok(BbCircuitComputeVkResponse {
        bytes: d.bytes,
        fields: d.fields,
        hash: d.hash,
    })
}

impl Default for VkData {
    fn default() -> Self {
        VkData {
            bytes: vec![],
            fields: vec![],
            hash: vec![],
        }
    }
}

fn circuit_kind(kind: u8) -> Result<CircuitKind, String> {
    match kind {
        0 => Ok(CircuitKind::App),
        1 => Ok(CircuitKind::Kernel),
        2 => Ok(CircuitKind::HidingKernel),
        k => Err(format!("unknown circuit kind {k}")),
    }
}

/// Ensure the session's commitment key covers a circuit of the given log size (bb sizes its
/// global CRS on demand; our key is a plain SRS slice, re-loaded when it must grow).
fn ensure_ck(ivc: &mut Chonk, srs: &Srs, log_n: usize) {
    let needed = (1usize << log_n).max(1 << 17);
    if ivc.ck.points.len() < needed {
        ivc.ck = srs.bn254_key(needed);
    }
}

/// Fills the `Handler` methods bb-ref does not serve with an "unsupported command" error response.
macro_rules! unsupported {
    ($($method:ident: $cmd:ty => $resp:ty),* $(,)?) => {
        $(
            fn $method(&mut self, _cmd: $cmd, respond: Responder<$resp>) {
                respond.error(concat!("unsupported command: ", stringify!($cmd)).into());
            }
        )*
    };
}

// `--cfg chonk_only` (bb-ref.js's wasm build, tools/build_bb_ref_js.sh): the browser proves Chonk
// only, so the Ultra commands answer unsupported and the linker drops the Ultra/rollup provers and
// verifiers and the rollup recursion gadgets they alone reach (-14% of the module).
impl Handler for BbRefHandler {
    fn circuit_prove(&mut self, cmd: BbCircuitProve, respond: Responder<BbCircuitProveResponse>) {
        if cfg!(chonk_only) {
            return respond.error("unsupported command: circuit_prove".into());
        }
        run_catching(respond, || circuit_prove_impl(cmd, &self.srs));
    }

    fn circuit_compute_vk(&mut self, cmd: BbCircuitComputeVk, respond: Responder<BbCircuitComputeVkResponse>) {
        if cfg!(chonk_only) {
            return respond.error("unsupported command: circuit_compute_vk".into());
        }
        run_catching(respond, || circuit_compute_vk_impl(cmd, &self.srs));
    }

    fn circuit_verify(&mut self, cmd: BbCircuitVerify, respond: Responder<BbCircuitVerifyResponse>) {
        if cfg!(chonk_only) {
            return respond.error("unsupported command: circuit_verify".into());
        }
        run_catching(respond, || {
            let (flavor, ipa) = select_flavor(&cmd.settings)?;
            // bb's order: a wrong VK size is verified=false; a malformed VK or (unpadded flavors) a
            // log_n below the flavor's minimum is an error response, as is a non-canonical input;
            // anything else that fails is verified=false.
            let num_comms = flavor.layout().num_precomputed;
            let keccak = flavor.name.contains("Keccak");
            let vk_fields = if keccak {
                VkGeneric::<KeccakBn254>::num_fields(num_comms)
            } else {
                VkGeneric::<Bn254>::num_fields(num_comms)
            };
            if cmd.verification_key.len() != vk_fields * 32 {
                return Ok(BbCircuitVerifyResponse { verified: false });
            }
            if keccak {
                let log_n = VkGeneric::<KeccakBn254>::from_bytes(&cmd.verification_key, num_comms).log_n_value();
                let min = if flavor.has_zk { 3 } else { 1 };
                if !flavor.use_padding && log_n < min {
                    return Err(format!(
                        "Assertion failed: (log_circuit_size >= min_log_circuit_size)\n  Left   : {log_n}\n  Right  : {min}\n  Reason : VK log_circuit_size is below the flavor's minimum"
                    ));
                }
            } else {
                VkGeneric::<Bn254>::from_bytes(&cmd.verification_key, num_comms);
            }
            let modulus_check = |vals: &[Bin32], what: &str| -> Result<(), String> {
                for v in vals {
                    if !is_canonical_fr(v) {
                        return Err(format!("Non-canonical {what}: value >= field modulus"));
                    }
                }
                Ok(())
            };
            modulus_check(&cmd.public_inputs, "public input")?;
            modulus_check(&cmd.proof, "proof element")?;
            let verified = native_verify(
                flavor,
                ipa,
                &self.srs,
                &cmd.verification_key,
                &cmd.public_inputs,
                &cmd.proof,
            );
            Ok(BbCircuitVerifyResponse { verified })
        });
    }

    fn chonk_compress_proof(&mut self, cmd: BbChonkCompressProof, respond: Responder<BbChonkCompressProofResponse>) {
        run_catching(respond, || {
            let proof = wire_to_chonk_proof(&cmd.proof);
            Ok(BbChonkCompressProofResponse {
                compressed_proof: crate::chonk::compression::compress_chonk_proof(&proof),
            })
        });
    }

    fn chonk_decompress_proof(
        &mut self,
        cmd: BbChonkDecompressProof,
        respond: Responder<BbChonkDecompressProofResponse>,
    ) {
        let r = crate::chonk::compression::mega_num_public_inputs_from_len(cmd.compressed_proof.len())
            .and_then(|n| crate::chonk::compression::decompress_chonk_proof(&cmd.compressed_proof, n));
        match r {
            Ok(proof) => respond.ok(BbChonkDecompressProofResponse {
                proof: chonk_proof_to_wire(&proof),
            }),
            Err(e) => respond.error(e),
        }
    }

    fn vk_as_fields(&mut self, cmd: BbVkAsFields, respond: Responder<BbVkAsFieldsResponse>) {
        run_catching(respond, || {
            let vk = VkGeneric::<Bn254>::from_bytes(&cmd.verification_key, ULTRA.layout().num_precomputed);
            Ok(BbVkAsFieldsResponse {
                fields: vk.to_fields().iter().map(fr_to_wire).collect(),
            })
        });
    }

    fn mega_app_vk_as_fields(&mut self, cmd: BbMegaAppVkAsFields, respond: Responder<BbMegaAppVkAsFieldsResponse>) {
        run_catching(respond, || {
            let vk = VkGeneric::<Bn254>::from_bytes(&cmd.verification_key, MEGA_APP.layout().num_precomputed);
            Ok(BbMegaAppVkAsFieldsResponse {
                fields: vk.to_fields().iter().map(fr_to_wire).collect(),
            })
        });
    }

    fn mega_kernel_vk_as_fields(
        &mut self,
        cmd: BbMegaKernelVkAsFields,
        respond: Responder<BbMegaKernelVkAsFieldsResponse>,
    ) {
        run_catching(respond, || {
            let vk = VkGeneric::<Bn254>::from_bytes(&cmd.verification_key, MEGA_KERNEL.layout().num_precomputed);
            Ok(BbMegaKernelVkAsFieldsResponse {
                fields: vk.to_fields().iter().map(fr_to_wire).collect(),
            })
        });
    }

    fn mega_z_k_vk_as_fields(&mut self, cmd: BbMegaZKVkAsFields, respond: Responder<BbMegaZKVkAsFieldsResponse>) {
        run_catching(respond, || {
            let vk = VkGeneric::<Bn254>::from_bytes(&cmd.verification_key, MEGA_ZK.layout().num_precomputed);
            Ok(BbMegaZKVkAsFieldsResponse {
                fields: vk.to_fields().iter().map(fr_to_wire).collect(),
            })
        });
    }

    fn chonk_start(&mut self, cmd: BbChonkStart, respond: Responder<BbChonkStartResponse>) {
        run_catching(respond, || {
            let kinds = cmd
                .kinds
                .iter()
                .map(|k| circuit_kind(*k))
                .collect::<Result<Vec<_>, _>>()?;
            // The key grows as circuits load; the translator's 2^17 is the floor.
            let mut ivc = Chonk::new(kinds, self.srs.bn254_key(1 << 17));
            ivc.eccvm_ck = Some(self.srs.grumpkin_key(ECCVM_FIXED_SIZE));
            self.ivc = Some(ivc);
            self.loaded = None;
            Ok(BbChonkStartResponse {})
        });
    }

    fn chonk_load(&mut self, cmd: BbChonkLoad, respond: Responder<BbChonkLoadResponse>) {
        run_catching(respond, || {
            if self.ivc.is_none() {
                return Err("Chonk not started. Call ChonkStart first.".into());
            }
            self.loaded = Some(Loaded {
                circuit: decode_program_raw(&cmd.circuit.bytecode),
                vk_bytes: cmd.circuit.verification_key,
                kind: circuit_kind(cmd.kind)?,
            });
            Ok(BbChonkLoadResponse {})
        });
    }

    fn chonk_accumulate(&mut self, cmd: BbChonkAccumulate, respond: Responder<BbChonkAccumulateResponse>) {
        let ivc = &mut self.ivc;
        let loaded = &mut self.loaded;
        run_catching(respond, || {
            let Some(ivc) = ivc.as_mut() else {
                return Err("Chonk not started. Call ChonkStart first.".into());
            };
            let Some(step) = loaded.take() else {
                return Err("No circuit loaded. Call ChonkLoad first.".into());
            };
            let vk = (!step.vk_bytes.is_empty())
                .then(|| VkGeneric::<Bn254>::from_bytes(&step.vk_bytes, step.kind.flavor().layout().num_precomputed));
            if let Some(vk) = &vk {
                ensure_ck(ivc, &self.srs, vk.log_n());
            }
            let mut rng = GlobalProxy;
            let witness = decode_witness_raw(&cmd.witness, &mut rng);
            crate::acir::lower::check_representable(&step.circuit, step.kind)?;
            let circuit = build_circuit_mega(&step.circuit, Some(&witness), Some(ivc), &mut rng);
            if let Some(msg) = &circuit.failed {
                return Err(format!("circuit is not satisfied: {msg}"));
            }
            ivc.accumulate(circuit, vk, &mut rng);
            Ok(BbChonkAccumulateResponse {})
        });
    }

    fn chonk_prove(&mut self, _cmd: BbChonkProve, respond: Responder<BbChonkProveResponse>) {
        let ivc_slot = &mut self.ivc;
        run_catching(respond, || {
            let Some(ivc) = ivc_slot.as_mut() else {
                return Err("Chonk not started. Call ChonkStart first.".into());
            };
            if ivc.num_accumulated() == 0 {
                return Err("No circuits accumulated. Call ChonkAccumulate first.".into());
            }
            let mut rng = GlobalProxy;
            let proof = ivc.prove(&mut rng);
            let hiding_vk = ivc.hiding_vk().clone();
            // bb sanity-checks the freshly produced proof in-process.
            if !chonk_verify(
                &hiding_vk,
                &proof,
                &bn254_g2(),
                &self.srs.grumpkin_key(ECCVM_FIXED_SIZE),
            ) {
                return Err("Failed to verify the generated proof!".into());
            }
            *ivc_slot = None;
            let wire = |v: &[FrField]| v.iter().map(fr_to_wire).collect::<Vec<_>>();
            Ok(BbChonkProveResponse {
                proof: ChonkProof {
                    hiding_oink_proof: wire(&proof.hiding_oink_proof),
                    merge_proof: wire(&proof.merge_proof),
                    eccvm_proof: wire(&proof.eccvm_proof),
                    ipa_proof: wire(&proof.ipa_proof),
                    joint_proof: wire(&proof.joint_proof),
                },
            })
        });
    }

    fn chonk_verify(&mut self, cmd: BbChonkVerify, respond: Responder<BbChonkVerifyResponse>) {
        // bb decodes the proof before its try block (a non-canonical element is an error response);
        // every other malformed input is valid=false.
        run_catching(respond, || {
            let proof = wire_to_chonk_proof(&cmd.proof);
            let valid = catch_unwind(AssertUnwindSafe(|| {
                let vk = VkGeneric::<Bn254>::from_bytes(&cmd.vk, MEGA_ZK.layout().num_precomputed);
                // bb checks the total size against the VK before verifying.
                proof.to_fields().len()
                    == vk.num_public_inputs_usize() + crate::chonk::proof::proof_length_without_pub_inputs()
                    && chonk_verify(&vk, &proof, &bn254_g2(), &self.srs.grumpkin_key(ECCVM_FIXED_SIZE))
            }))
            .unwrap_or(false);
            Ok(BbChonkVerifyResponse { valid })
        });
    }

    fn chonk_compute_vk(&mut self, cmd: BbChonkComputeVk, respond: Responder<BbChonkComputeVkResponse>) {
        run_catching(respond, || {
            let kind = circuit_kind(cmd.kind)?;
            let circuit = decode_program_raw(&cmd.circuit.bytecode);
            crate::acir::lower::check_representable(&circuit, kind)?;
            let mut rng = GlobalProxy;
            let mut builder = build_circuit_mega(&circuit, None, None, &mut rng);
            let inst = ProverInstance::from_builder(kind.flavor(), &mut builder, &mut rng);
            let ck = self.srs.bn254_key(inst.max_end_index);
            let d = vk_data_poseidon2(&inst.compute_vk(&ck));
            Ok(BbChonkComputeVkResponse {
                bytes: d.bytes,
                fields: d.fields,
            })
        });
    }

    fn poseidon2_hash(&mut self, cmd: BbPoseidon2Hash, respond: Responder<BbPoseidon2HashResponse>) {
        run_catching(respond, || {
            let inputs: Vec<FrField> = cmd.inputs.iter().map(fr_from_wire).collect();
            Ok(BbPoseidon2HashResponse {
                hash: fr_to_wire(&poseidon2::Poseidon2::hash(&inputs)),
            })
        });
    }

    fn poseidon2_absorb_chain(
        &mut self,
        cmd: BbPoseidon2AbsorbChain,
        respond: Responder<BbPoseidon2AbsorbChainResponse>,
    ) {
        // bb `Sponge::absorb_blocks`: each 3-element block is added into the rate part of the state,
        // then permuted; no IV, padding or squeeze.
        run_catching(respond, || {
            const BLOCK_BYTES: usize = 3 * 32;
            if cmd.inputs.len() % BLOCK_BYTES != 0 {
                return Err(format!("Poseidon2AbsorbChain: input size must be a multiple of {BLOCK_BYTES} bytes"));
            }
            let mut state = cmd.state.each_ref().map(fr_from_wire);
            for block in cmd.inputs.chunks(BLOCK_BYTES) {
                for (s, f) in state.iter_mut().zip(block.chunks(32)) {
                    *s += crate::base::field::from_bytes_be_canonical::<FrField>(f);
                }
                poseidon2::permutation(&mut state);
            }
            Ok(BbPoseidon2AbsorbChainResponse { state: state.each_ref().map(fr_to_wire) })
        });
    }

    fn init(&mut self, cmd: BbInit, respond: Responder<BbInitResponse>) {
        // bb `handle_init`, plus the setup bb does lazily and a library user has no main for: the
        // thread pool and the session's seeded randomness (`BB_RNG_SEED`). Sent first; anything
        // before it is undefined. Sent again it restarts the seeded stream, as bb's does.
        run_catching(respond, || {
            start_pool();
            crate::base::rng::set_global_from_env();
            if cmd.warmup.unwrap_or(true) {
                warmup()?;
                // The warmup's random scalars must not count against the session.
                crate::base::rng::set_global_from_env();
            }
            Ok(BbInitResponse {})
        });
    }

    fn poseidon2_permutation(
        &mut self,
        cmd: BbPoseidon2Permutation,
        respond: Responder<BbPoseidon2PermutationResponse>,
    ) {
        run_catching(respond, || {
            let mut state = [FrField::from(0u64); 4];
            for (s, w) in state.iter_mut().zip(&cmd.inputs) {
                *s = fr_from_wire(w);
            }
            poseidon2::permutation(&mut state);
            Ok(BbPoseidon2PermutationResponse {
                outputs: [
                    fr_to_wire(&state[0]),
                    fr_to_wire(&state[1]),
                    fr_to_wire(&state[2]),
                    fr_to_wire(&state[3]),
                ],
            })
        });
    }

    // Pushed points are authenticated as bb does and then serve every key they cover; anything
    // larger still loads from ~/.bb-crs.
    fn srs_init_srs(&mut self, cmd: BbSrsInitSrs, respond: Responder<BbSrsInitSrsResponse>) {
        run_catching(respond, || {
            let (points, points_buf) =
                crate::base::srs::bn254_from_ingress(cmd.num_points, &cmd.points_buf, &cmd.g2_point)?;
            self.srs.set_bn254(points);
            Ok(BbSrsInitSrsResponse { points_buf })
        });
    }

    fn srs_init_grumpkin_srs(&mut self, cmd: BbSrsInitGrumpkinSrs, respond: Responder<BbSrsInitGrumpkinSrsResponse>) {
        run_catching(respond, || {
            self.srs.set_grumpkin(crate::base::srs::grumpkin_from_ingress(cmd.num_points, &cmd.points_buf)?);
            Ok(BbSrsInitGrumpkinSrsResponse { dummy: 0 })
        });
    }

    #[cfg(feature = "bb-avm")]
    fn avm_prove(&mut self, cmd: BbAvmProve, respond: Responder<BbAvmProveResponse>) {
        super::bb_avm::forward(respond, |bb| bb.avm_prove(&cmd.inputs));
    }

    #[cfg(feature = "bb-avm")]
    fn avm_verify(&mut self, cmd: BbAvmVerify, respond: Responder<BbAvmVerifyResponse>) {
        super::bb_avm::forward(respond, |bb| bb.avm_verify(cmd.proof, &cmd.public_inputs));
    }

    #[cfg(feature = "bb-avm")]
    fn avm_check_circuit(&mut self, cmd: BbAvmCheckCircuit, respond: Responder<BbAvmCheckCircuitResponse>) {
        super::bb_avm::forward(respond, |bb| bb.avm_check_circuit(&cmd.inputs));
    }

    // The AVM is bb's own (the `bb-avm` feature) or unsupported.
    #[cfg(not(feature = "bb-avm"))]
    unsupported! {
        avm_prove: BbAvmProve => BbAvmProveResponse,
        avm_verify: BbAvmVerify => BbAvmVerifyResponse,
        avm_check_circuit: BbAvmCheckCircuit => BbAvmCheckCircuitResponse,
    }

    // Everything below is outside bb-ref's scope (crypto helpers, raw curve ops, batch
    // verification, proof compression, Solidity output).
    unsupported! {
        circuit_stats: BbCircuitStats => BbCircuitStatsResponse,
        chonk_verify_from_fields: BbChonkVerifyFromFields => BbChonkVerifyFromFieldsResponse,
        chonk_batch_verify: BbChonkBatchVerify => BbChonkBatchVerifyResponse,
        mega_vk_as_fields: BbMegaVkAsFields => BbMegaVkAsFieldsResponse,
        circuit_write_solidity_verifier: BbCircuitWriteSolidityVerifier => BbCircuitWriteSolidityVerifierResponse,
        chonk_check_precomputed_vk: BbChonkCheckPrecomputedVk => BbChonkCheckPrecomputedVkResponse,
        chonk_stats: BbChonkStats => BbChonkStatsResponse,
        pedersen_commit: BbPedersenCommit => BbPedersenCommitResponse,
        pedersen_hash: BbPedersenHash => BbPedersenHashResponse,
        blake2s: BbBlake2s => BbBlake2sResponse,
        blake2s_to_field: BbBlake2sToField => BbBlake2sToFieldResponse,
        aes_encrypt: BbAesEncrypt => BbAesEncryptResponse,
        aes_decrypt: BbAesDecrypt => BbAesDecryptResponse,
        grumpkin_mul: BbGrumpkinMul => BbGrumpkinMulResponse,
        grumpkin_add: BbGrumpkinAdd => BbGrumpkinAddResponse,
        grumpkin_batch_mul: BbGrumpkinBatchMul => BbGrumpkinBatchMulResponse,
        grumpkin_get_random_fr: BbGrumpkinGetRandomFr => BbGrumpkinGetRandomFrResponse,
        grumpkin_reduce512: BbGrumpkinReduce512 => BbGrumpkinReduce512Response,
        secp256k1_mul: BbSecp256k1Mul => BbSecp256k1MulResponse,
        secp256k1_get_random_fr: BbSecp256k1GetRandomFr => BbSecp256k1GetRandomFrResponse,
        secp256k1_reduce512: BbSecp256k1Reduce512 => BbSecp256k1Reduce512Response,
        bn254_fr_sqrt: BbBn254FrSqrt => BbBn254FrSqrtResponse,
        bn254_fq_sqrt: BbBn254FqSqrt => BbBn254FqSqrtResponse,
        bn254_g1_mul: BbBn254G1Mul => BbBn254G1MulResponse,
        bn254_g2_mul: BbBn254G2Mul => BbBn254G2MulResponse,
        bn254_g1_is_on_curve: BbBn254G1IsOnCurve => BbBn254G1IsOnCurveResponse,
        bn254_g1_from_compressed: BbBn254G1FromCompressed => BbBn254G1FromCompressedResponse,
        schnorr_compute_public_key: BbSchnorrComputePublicKey => BbSchnorrComputePublicKeyResponse,
        schnorr_construct_signature: BbSchnorrConstructSignature => BbSchnorrConstructSignatureResponse,
        schnorr_verify_signature: BbSchnorrVerifySignature => BbSchnorrVerifySignatureResponse,
        ecdsa_secp256k1_compute_public_key: BbEcdsaSecp256k1ComputePublicKey => BbEcdsaSecp256k1ComputePublicKeyResponse,
        ecdsa_secp256r1_compute_public_key: BbEcdsaSecp256r1ComputePublicKey => BbEcdsaSecp256r1ComputePublicKeyResponse,
        ecdsa_secp256k1_construct_signature: BbEcdsaSecp256k1ConstructSignature => BbEcdsaSecp256k1ConstructSignatureResponse,
        ecdsa_secp256r1_construct_signature: BbEcdsaSecp256r1ConstructSignature => BbEcdsaSecp256r1ConstructSignatureResponse,
        ecdsa_secp256k1_recover_public_key: BbEcdsaSecp256k1RecoverPublicKey => BbEcdsaSecp256k1RecoverPublicKeyResponse,
        ecdsa_secp256r1_recover_public_key: BbEcdsaSecp256r1RecoverPublicKey => BbEcdsaSecp256r1RecoverPublicKeyResponse,
        ecdsa_secp256k1_verify_signature: BbEcdsaSecp256k1VerifySignature => BbEcdsaSecp256k1VerifySignatureResponse,
        ecdsa_secp256r1_verify_signature: BbEcdsaSecp256r1VerifySignature => BbEcdsaSecp256r1VerifySignatureResponse,
        chonk_batch_verifier_start: BbChonkBatchVerifierStart => BbChonkBatchVerifierStartResponse,
        chonk_batch_verifier_queue: BbChonkBatchVerifierQueue => BbChonkBatchVerifierQueueResponse,
        chonk_batch_verifier_stop: BbChonkBatchVerifierStop => BbChonkBatchVerifierStopResponse,
    }
}

/// The rayon pool, built once with the calling thread as its first worker, so work issued from the
/// thread that serves commands runs in it and the host's thread count (`RAYON_NUM_THREADS`) includes
/// that thread. Not `build_global`: it waits for every worker to start, and a browser starts a
/// worker spawned from a blocked worker only once that worker returns to its event loop; until the
/// others come up the calling thread runs the work itself. Leaked: it lives for the process.
fn start_pool() {
    static STARTED: std::sync::Once = std::sync::Once::new();
    STARTED.call_once(|| {
        let mut pool = rayon::ThreadPoolBuilder::new().use_current_thread();
        if cfg!(target_family = "wasm") {
            // bb's 1 MiB worker stacks: on wasm they are heap blocks in every linear-memory peak.
            pool = pool.stack_size(1 << 20);
        }
        if let Ok(pool) = pool.build() {
            std::mem::forget(pool);
        }
    });
}

/// bb `run_warmup`: one pass over the hot loops (a 2^14 MSM over 2^i·G, a batch inversion, 2^10
/// Poseidon2 hashes) so a tiering wasm engine has optimized them before real work. Its 2^14 random
/// scalars come from the session source, as bb's do.
fn warmup() -> Result<(), String> {
    use crate::base::{G1Affine, G1Projective};
    use ark_ec::{AdditiveGroup, CurveGroup, PrimeGroup};
    use ark_ff::Field;
    const NUM_POINTS: usize = 1 << 14;
    const NUM_HASHES: usize = 1 << 10;
    let mut acc = G1Projective::generator();
    let mut points = Vec::with_capacity(NUM_POINTS);
    for _ in 0..NUM_POINTS {
        points.push(acc);
        acc.double_in_place();
    }
    let points: Vec<G1Affine> = G1Projective::normalize_batch(&points);
    let scalars: Vec<FrField> = (0..NUM_POINTS).map(|_| crate::base::rng::global_field()).collect();
    let commitment = crate::base::msm::msm(&points, &scalars);
    let mut elements: Vec<FrField> =
        scalars.iter().enumerate().map(|(i, s)| s.square() + FrField::from(i as u64 + 1)).collect();
    crate::base::field::batch_invert(&mut elements);
    let mut h = elements[0];
    for e in &elements[..NUM_HASHES] {
        h = poseidon2::Poseidon2::hash(&[h, *e]);
    }
    if commitment == G1Projective::default() || h == FrField::from(0u64) {
        return Err("Init: warmup produced a degenerate result".into());
    }
    Ok(())
}
