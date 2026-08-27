//! M16 exit: the real protocol kernels. `bb write_vk --scheme chonk` on every private/hiding
//! kernel artifact is byte-equal to Rust's VK (and to the artifact's), and where a bb instance dump
//! exists the circuits agree polynomial-for-polynomial.
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
                .join("../aztec-packages2/noir-projects/fnd/noir-protocol-circuits/target")
        })
}

fn instance(name: &str, kind: CircuitKind) -> Option<(ProverInstance, bb_ref::circuit::Builder)> {
    let path = protocol_circuits_dir().join(format!("{name}.json"));
    let Ok(artifact) = std::fs::read(&path) else {
        eprintln!("skipping {name}: no artifact at {}", path.display());
        return None;
    };
    let circuit = decode_program(&artifact);
    let mut builder = build_circuit_mega(&circuit, None, None, &mut OsRng);
    let inst = ProverInstance::from_builder(kind.flavor(), &mut builder, &mut OsRng);
    Some((inst, builder))
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
        let Some((inst, _)) = instance(name, kind) else {
            continue;
        };
        let vk = inst.compute_vk(&CommitmentKey::new(inst.max_end_index)).to_bytes();
        let fixture = common::fixture_dir(&format!("protocol/vks/{name}.vk"));
        if fixture.exists() {
            assert_eq!(
                vk,
                std::fs::read(fixture).unwrap(),
                "{name}: VK differs from bb write_vk's"
            );
        }
        let json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(protocol_circuits_dir().join(format!("{name}.json"))).unwrap())
                .unwrap();
        if let Some(bytes) = json["verificationKey"]["bytes"].as_str() {
            assert_eq!(
                vk,
                hex::decode(bytes).unwrap(),
                "{name}: VK differs from the artifact's"
            );
        }
        eprintln!("{name}: VK matches");
    }
}

/// bb `BbRefDump.AcirMega` dumps (`fixtures/regen_protocol.sh`): the gate-level diff.
#[test]
fn protocol_kernel_circuits_match_bb() {
    for (name, kind) in selected() {
        let dump = common::fixture_dir(&format!("instance/protocol/{name}"));
        if !dump.join("vk").exists() {
            eprintln!("skipping {name}: no dump");
            continue;
        }
        let Some((inst, builder)) = instance(name, kind) else {
            continue;
        };
        let expected = ProverInstance::load_dump(kind.flavor(), &dump);
        assert_eq!(inst.dyadic_size, expected.dyadic_size, "{name}: dyadic size");
        assert_eq!(
            inst.public_inputs.len(),
            expected.public_inputs.len(),
            "{name}: public input count"
        );
        // witnesses depend on the mocked IVC's random proof values (and on ZK masking): compare the
        // precomputed polynomials, i.e. what the VK commits to
        let m = inst.layout.num_masking;
        let compare: Vec<usize> = (m..m + inst.layout.num_precomputed).collect();
        common::assert_polys_equal(name, &inst, &expected, &builder, &compare);
        eprintln!("{name}: circuit matches");
    }
}
