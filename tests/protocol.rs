//! The real protocol kernels. `bb write_vk --scheme chonk` on every private/hiding
//! kernel artifact (tools/regen/regen_protocol.sh) is byte-equal to Rust's VK and to the artifact's.
mod common;
use bb_ref::acir::{build_circuit_mega, decode_program};
use bb_ref::base::{CommitmentKey, OsRng};
use bb_ref::chonk::ivc::CircuitKind;
use bb_ref::honk::prover_instance::ProverInstance;
use std::path::PathBuf;

const KERNELS: [(&str, CircuitKind); 8] = [
    ("private_kernel_init", CircuitKind::Kernel),
    ("private_kernel_inner", CircuitKind::Kernel),
    ("private_kernel_reset", CircuitKind::Kernel),
    ("private_kernel_reset_4_4_4_4_4_4_0_0_0", CircuitKind::Kernel),
    ("private_kernel_reset_tail", CircuitKind::Kernel),
    ("private_kernel_reset_tail_to_public", CircuitKind::Kernel),
    ("hiding_kernel_to_public", CircuitKind::HidingKernel),
    ("hiding_kernel_to_rollup", CircuitKind::HidingKernel),
];

fn protocol_circuits_dir() -> PathBuf {
    std::env::var("PROTOCOL_CIRCUITS")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("pin/aztec-packages/noir-projects/fnd/noir-protocol-circuits/target")
        })
}

fn artifact(name: &str) -> Vec<u8> {
    let path = protocol_circuits_dir().join(format!("{name}.json"));
    std::fs::read(&path)
        .unwrap_or_else(|e| panic!("{}: {e} (the pin's compiled noir-protocol-circuits)", path.display()))
}

/// Filter with `BBREF_KERNEL=<name>` to run one kernel.
fn selected() -> Vec<(&'static str, CircuitKind)> {
    let filter = std::env::var("BBREF_KERNEL").ok();
    KERNELS
        .iter()
        .copied()
        .filter(|(n, _)| filter.as_deref().map_or(true, |f| *n == f))
        .collect()
}

#[test]
fn protocol_kernel_vks_match_bb() {
    for (name, kind) in selected() {
        let artifact = artifact(name);
        let circuit = decode_program(&artifact);
        let mut builder = build_circuit_mega(&circuit, None, None, &mut OsRng);
        let inst = ProverInstance::from_builder(kind.flavor(), &mut builder, &mut OsRng);
        let vk = inst.compute_vk(&CommitmentKey::new(inst.max_end_index)).to_bytes();
        let fixture = common::require(
            common::fixture_dir(&format!("protocol/vks/{name}.vk")),
            "regen_protocol.sh",
        );
        assert_eq!(
            vk,
            std::fs::read(fixture).unwrap(),
            "{name}: VK differs from bb write_vk's"
        );
        let json: serde_json::Value = serde_json::from_slice(&artifact).unwrap();
        let bytes = json["verificationKey"]["bytes"]
            .as_str()
            .expect("artifact verificationKey");
        assert_eq!(
            vk,
            hex::decode(bytes).unwrap(),
            "{name}: VK differs from the artifact's"
        );
        eprintln!("{name}: VK matches");
    }
}
