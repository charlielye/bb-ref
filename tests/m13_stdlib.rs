//! M13 exit: the in-circuit primitives (field ops, Poseidon2 sponge, transcript, goblin group ops,
//! pairing-point aggregation, kernel IO) emit exactly bb's gates: every polynomial and the VK of
//! each `BbRefDump.Stdlib` program match.
mod common;
use bb_ref::base::field::from_hex;
use bb_ref::base::group::{GroupLike, PairingPoints};
use bb_ref::base::transcript::Transcript;
use bb_ref::base::{CommitmentKey, Fr, OsRng};
use bb_ref::circuit::{Builder, EccOpQueue};
use bb_ref::honk::prover_instance::ProverInstance;
use bb_ref::honk::MEGA_KERNEL;
use bb_ref::stdlib::field::split_unique;
use bb_ref::stdlib::hash::StdPoseidon2;
use bb_ref::stdlib::io::{AppIo, DataBusDepot, HidingKernelIo, KernelIo, MAX_APPS_PER_KERNEL};
use bb_ref::stdlib::{Ctx, FieldT, GoblinElement, StdBn254};
use common::eccvm_ops::g1_times;
use std::cell::RefCell;
use std::rc::Rc;

fn w(ctx: &Ctx, v: u64) -> FieldT {
    FieldT::from_witness(ctx, Fr::from(v))
}
fn point(ctx: &Ctx, k: u64) -> GoblinElement {
    GoblinElement::from_witness(ctx, g1_times(k))
}
fn c(v: u64) -> FieldT {
    FieldT::constant(Fr::from(v))
}

fn field_ops(ctx: &Ctx) {
    let (a, b, cc) = (w(ctx, 3), w(ctx, 5), w(ctx, 7));
    let d = &a + &b;
    let e = &d * &cc;
    let f = &e - &a;
    let g = -&f;
    let h = &(&g + &c(11)) * &c(2);
    let i = a.madd(&b, &cc);
    let j = a.add_two(&b, &cc);
    let k = e.div(&b);
    let l = cc.inverse();
    let m = d.pow_u32(5);
    let n = FieldT::accumulate(&[a.clone(), b.clone(), cc.clone(), d.clone(), e.clone(), c(4), f.clone(), g.clone(), h.clone(), i.clone(), j.clone()]);
    let p = &(&m * &c(3)) + &c(1);
    let r = FieldT::from_witness(ctx, p.get_value());
    p.assert_equal(&r);
    let s = w(ctx, 0);
    s.assert_is_zero();
    a.assert_is_not_zero();
    (&a * &b).assert_equal(&c(15));
    let neg22 = FieldT::from_witness(ctx, -Fr::from(22u64));
    FieldT::evaluate_polynomial_identity(&a, &b, &cc, &neg22);
    let neg15 = FieldT::from_witness(ctx, -Fr::from(15u64));
    FieldT::evaluate_linear_identity(&a, &b, &cc, &neg15);
    a.create_range_constraint(8);
    e.create_range_constraint(20);
    (&d * &c(1000)).create_range_constraint(68);
    let t = FieldT::from_witness(ctx, from_hex("0x00000000000000000123456789abcdef0123456789abcdef0123456789abcdef"));
    let (lo, hi) = split_unique(&t, 127);
    let mut u = c(9);
    u.convert_constant_to_fixed_witness(ctx);
    u.set_public();
    a.set_public();
    (&(&(&(&k + &l) + &n) + &lo) + &hi).set_public();
}

fn poseidon2_hash(ctx: &Ctx, n: u64) {
    let inputs: Vec<FieldT> = (0..n).map(|i| w(ctx, i + 1)).collect();
    bb_ref::stdlib::hash::hash(&inputs).set_public();
}

fn transcript(ctx: &Ctx) {
    let mut t = Transcript::<FieldT, StdPoseidon2>::new();
    t.send("a", &w(ctx, 42));
    t.add_to_hash_buffer("vk", &w(ctx, 43));
    let c1: FieldT = t.challenge("c1");
    let p = point(ctx, 7);
    t.send("P", &p);
    let shorts: Vec<FieldT> = t.short_challenges(&["s1", "s2"]);
    let c2: FieldT = t.challenge("c2");
    let powers: Vec<FieldT> = t.dyadic_powers("gate", 4);
    (&(&(&(&c1 + &shorts[0]) + &shorts[1]) + &c2) + &powers[3]).set_public();
}

fn goblin_batch_mul(ctx: &Ctx, k: u64) {
    let points: Vec<GoblinElement> = (0..k).map(|i| point(ctx, i + 1)).collect();
    let scalars: Vec<FieldT> = (0..k).map(|i| if i == 1 { c(1) } else { w(ctx, i + 3) }).collect();
    let r = GoblinElement::batch_mul(&points, &scalars);
    let expected = GoblinElement::from_witness(ctx, r.value());
    r.incomplete_assert_equal(&expected);
    if k >= 2 {
        let s = points[0].add(&points[1]);
        let d = points[0].sub(&points[1]);
        s.set_public();
        d.set_public();
    }
    points[0].neg().set_public();
    r.scalar_mul(&scalars[0]).set_public();
    GoblinElement::one(ctx).add(&points[0]).set_public();
}

fn aggregate_multiple(ctx: &Ctx, n: u64) {
    let pps: Vec<PairingPoints<StdBn254>> = (0..n)
        .map(|i| PairingPoints {
            p0: point(ctx, 2 * i + 1),
            p1: point(ctx, 2 * i + 2),
        })
        .collect();
    let agg = PairingPoints::aggregate_multiple(&pps);
    AppIo::set_public(&agg);
}

fn kernel_io_set(ctx: &Ctx) {
    let mut depot = DataBusDepot::default();
    depot.set_app_return_data_commitment(point(ctx, 5));
    depot.set_kernel_return_data_commitment(point(ctx, 6));
    let pairing_inputs = PairingPoints { p0: point(ctx, 1), p1: point(ctx, 2) };
    let kernel_return_data = depot.get_kernel_return_data_commitment(ctx);
    let app_return_data = std::array::from_fn(|i| depot.get_app_return_data_commitment(ctx, i));
    let io = KernelIo {
        pairing_inputs,
        kernel_return_data,
        app_return_data,
        ecc_op_hash: w(ctx, 9),
        output_hn_accum_hash: w(ctx, 10),
    };
    io.set_public();
    let _ = MAX_APPS_PER_KERNEL;
}

fn hiding_io_set(ctx: &Ctx) {
    let io = HidingKernelIo {
        pairing_inputs: PairingPoints { p0: point(ctx, 1), p1: point(ctx, 2) },
        kernel_return_data: point(ctx, 3),
        ecc_op_tables: std::array::from_fn(|i| point(ctx, 10 + i as u64)),
    };
    io.set_public();
}

fn run(ctx: &Ctx, name: &str) {
    let suffix = |prefix: &str| name[prefix.len()..].parse::<u64>().unwrap();
    match name {
        "field_ops" => field_ops(ctx),
        "transcript" => transcript(ctx),
        "io_app_default" => AppIo::add_default(ctx),
        "io_kernel_default" => KernelIo::add_default(ctx),
        "io_hiding_default" => HidingKernelIo::add_default(ctx),
        "kernel_io_set" => kernel_io_set(ctx),
        "hiding_io_set" => hiding_io_set(ctx),
        _ if name.starts_with("poseidon2_hash_") => poseidon2_hash(ctx, suffix("poseidon2_hash_")),
        _ if name.starts_with("goblin_batch_mul_") => goblin_batch_mul(ctx, suffix("goblin_batch_mul_")),
        _ if name.starts_with("aggregate_multiple_") => aggregate_multiple(ctx, suffix("aggregate_multiple_")),
        _ => panic!("unknown stdlib program {name}"),
    }
}

pub const PROGRAMS: &[&str] = &[
    "field_ops",
    "poseidon2_hash_1",
    "poseidon2_hash_2",
    "poseidon2_hash_3",
    "poseidon2_hash_4",
    "poseidon2_hash_7",
    "poseidon2_hash_16",
    "poseidon2_hash_20",
    "transcript",
    "goblin_batch_mul_1",
    "goblin_batch_mul_2",
    "goblin_batch_mul_7",
    "aggregate_multiple_2",
    "aggregate_multiple_3",
    "aggregate_multiple_7",
    "io_app_default",
    "io_kernel_default",
    "io_hiding_default",
    "kernel_io_set",
    "hiding_io_set",
];

fn check(name: &str) {
    let dump = common::fixture_dir(&format!("instance/stdlib/{name}"));
    if !dump.join("vk").exists() {
        eprintln!("skipping stdlib/{name}: no dump");
        return;
    }
    let ctx = Rc::new(RefCell::new(Builder::new_mega(Rc::new(RefCell::new(EccOpQueue::new())))));
    run(&ctx, name);
    let mut builder = Rc::try_unwrap(ctx).ok().unwrap().into_inner();
    assert!(builder.failed.is_none(), "{name}: builder failure {:?}", builder.failed);
    let inst = ProverInstance::from_builder(&MEGA_KERNEL, &mut builder, &mut OsRng);
    let expected = ProverInstance::load_dump(&MEGA_KERNEL, &dump);
    assert_eq!(inst.dyadic_size, expected.dyadic_size, "{name}: dyadic size");
    assert_eq!(inst.public_inputs, expected.public_inputs, "{name}: public inputs");
    for i in 0..inst.layout.num_unshifted() {
        let e = inst.layout.unshifted[i];
        if let Some(r) = inst.polys[i].coeffs.iter().zip(&expected.polys[i].coeffs).position(|(x, y)| x != y) {
            panic!(
                "{name}: polynomial {} differs at row {r}: {:?} vs bb {:?}",
                e.name(),
                inst.polys[i].coeffs[r],
                expected.polys[i].coeffs[r]
            );
        }
    }
    let ck = CommitmentKey::new(inst.max_end_index);
    assert_eq!(inst.compute_vk(&ck).to_bytes(), std::fs::read(dump.join("vk")).unwrap(), "{name}: VK");
}

#[test]
fn stdlib_programs_match_bb() {
    for name in PROGRAMS {
        check(name);
    }
}
