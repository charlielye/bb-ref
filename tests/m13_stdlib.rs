//! M13 exit: the in-circuit primitives (field ops, Poseidon2 sponge, transcript, goblin group ops,
//! pairing-point aggregation, kernel IO) emit exactly bb's gates: every polynomial and the VK of
//! each `BbRefDump.Stdlib` program match.
mod common;
use ark_ec::{AffineRepr, CurveGroup};
use bb_ref::base::field::from_hex;
use bb_ref::base::group::{GroupLike, PairingPoints};
use bb_ref::base::transcript::Transcript;
use bb_ref::base::{CommitmentKey, Fq, Fr, GrumpkinAffine, NativeTranscript, OsRng};
use bb_ref::circuit::{Builder, EccOpQueue};
use bb_ref::honk::circuit_checker::check_circuit;
use bb_ref::honk::oink_prover::prove_oink;
use bb_ref::honk::prover_instance::ProverInstance;
use bb_ref::honk::MEGA_KERNEL;
use bb_ref::stdlib::cycle_group::{CycleGroup, CycleScalar};
use bb_ref::stdlib::field::split_unique;
use bb_ref::stdlib::hash::StdPoseidon2;
use bb_ref::stdlib::io::{AppIo, DataBusDepot, HidingKernelIo, KernelIo, MAX_APPS_PER_KERNEL};
use bb_ref::stdlib::{BoolT, Ctx, FieldT, GoblinElement, StdBn254};
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
    let n = FieldT::accumulate(&[
        a.clone(),
        b.clone(),
        cc.clone(),
        d.clone(),
        e.clone(),
        c(4),
        f.clone(),
        g.clone(),
        h.clone(),
        i.clone(),
        j.clone(),
    ]);
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
    let t = FieldT::from_witness(
        ctx,
        from_hex("0x00000000000000000123456789abcdef0123456789abcdef0123456789abcdef"),
    );
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
    let pairing_inputs = PairingPoints {
        p0: point(ctx, 1),
        p1: point(ctx, 2),
    };
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
        pairing_inputs: PairingPoints {
            p0: point(ctx, 1),
            p1: point(ctx, 2),
        },
        kernel_return_data: point(ctx, 3),
        ecc_op_tables: std::array::from_fn(|i| point(ctx, 10 + i as u64)),
    };
    io.set_public();
}

// --- M16: booleans, conditional selection, Grumpkin points ---
fn gp(k: u64) -> GrumpkinAffine {
    (GrumpkinAffine::generator() * Fq::from(k)).into_affine()
}
fn wb(ctx: &Ctx, v: bool) -> BoolT {
    BoolT::from_witness(ctx, v)
}

fn bool_ops(ctx: &Ctx) {
    let (t, f, ct) = (wb(ctx, true), wb(ctx, false), BoolT::constant(true));
    let a1 = t.and(&f);
    let a2 = t.or(&f);
    let a3 = t.xor(&f);
    let a4 = t.not();
    let a5 = a4.and(&f);
    let a6 = t.eq(&f);
    let a7 = t.not().eq(&f.not());
    let a8 = t.or(&f.not());
    let a9 = t.and(&ct);
    let a10 = f.or(&ct);
    let a11 = f.not().and(&a2);
    let a12 = a4.xor(&f.not());
    let n = a4.normalize();
    t.not().assert_equal(&f);
    t.assert_equal(&ct);
    a1.assert_equal(&a5);
    let c1 = BoolT::conditional_assign(&t, &a1, &a2);
    let c2 = BoolT::conditional_assign(&f.not(), &a3, &a6);
    let c3 = BoolT::conditional_assign(&ct, &a1, &a2);
    let c4 = BoolT::conditional_assign(&a1, &a2, &a2);
    let (x, y, z) = (w(ctx, 3), w(ctx, 3), w(ctx, 4));
    let e1 = x.eq(&y);
    let e2 = x.eq(&z);
    let iz = (&x - &y).is_zero();
    let iz2 = (&(&x * &c(2)) - &c(6)).is_zero();
    let s1 = FieldT::conditional_assign(&t, &x, &z);
    let s2 = FieldT::conditional_assign(&t.not(), &x, &z);
    let s3 = FieldT::conditional_assign(&ct, &x, &z);
    let s4 = FieldT::conditional_assign(&e2, &x, &x);
    let fb = BoolT::from_field(&(&x - &c(2)));
    let fbf = a4.to_field();
    let fb2 = BoolT::from_field(&fbf);
    let fb3 = BoolT::from_field(&c(1));
    let terms = [
        a1.to_field(),
        a2.to_field(),
        a4.to_field(),
        c2.to_field(),
        e1.to_field(),
        iz2.to_field(),
        s1,
        s2,
        s3,
        s4,
        fb.to_field(),
        fb2.to_field(),
        fb3.to_field(),
        n.to_field(),
        a7.to_field(),
        a8.to_field(),
        a9.to_field(),
        a10.to_field(),
        a11.to_field(),
        a12.to_field(),
        c1.to_field(),
        c3.to_field(),
        c4.to_field(),
        e2.to_field(),
        iz.to_field(),
    ];
    let sum = terms[1..].iter().fold(terms[0].clone(), |acc, t| &acc + t);
    sum.assert_equal(&FieldT::from_witness(ctx, sum.get_value()));
}

fn from_witness_point(ctx: &Ctx, p: GrumpkinAffine) -> CycleGroup {
    CycleGroup::from_xy(FieldT::from_witness(ctx, p.x), FieldT::from_witness(ctx, p.y), true)
}

fn cycle_group_add(ctx: &Ctx) {
    let mut p = from_witness_point(ctx, gp(3));
    let q = from_witness_point(ctx, gp(5));
    let mut r = p.add(&q);
    let mut s = r.sub(&p);
    let mut d = p.add(&p);
    let n = q.neg();
    let u = p.unconditional_add(&q, None);
    let mut v = r.dbl(None);
    let cc7 = CycleGroup::constant(gp(7));
    let pc = p.add(&cc7);
    let cp = cc7.sub(&p);
    let cc = cc7.add(&CycleGroup::constant(gp(9)));
    let ucp = cc7.unconditional_add(&p, None);
    let pn = p.add(&n);
    let qq = q.sub(&q);
    let mut z = qq.add(&p);
    let mut e = from_witness_point(ctx, gp(8));
    r.assert_equal(&mut e);
    let mut e2 = from_witness_point(ctx, gp(5));
    s.assert_equal(&mut e2);
    let mut e3 = from_witness_point(ctx, gp(6));
    d.assert_equal(&mut e3);
    let mut e4 = from_witness_point(ctx, gp(16));
    v.assert_equal(&mut e4);
    z.assert_equal(&mut p);
    let ca = CycleGroup::conditional_assign(&wb(ctx, true), &p, &q);
    let cb = CycleGroup::conditional_assign(&BoolT::constant(false), &p, &q);
    let terms = [
        pc.x,
        cp.y,
        cc.x,
        ucp.y,
        pn.x,
        u.x,
        n.y,
        ca.x,
        cb.y,
        pn.is_infinity.to_field(),
    ];
    let sum = terms[1..].iter().fold(terms[0].clone(), |acc, t| &acc + t);
    sum.assert_equal(&FieldT::from_witness(ctx, sum.get_value()));
}

fn cycle_group_mul(ctx: &Ctx, k: u64) {
    let one = CycleGroup::constant(GrumpkinAffine::generator());
    let mut points = vec![];
    let mut scalars = vec![];
    for i in 0..k {
        scalars.push(CycleScalar::new(w(ctx, 12345 + i), w(ctx, 67 + i)));
        points.push(one.clone());
    }
    let mut r = CycleGroup::batch_mul(&points, &scalars);
    let mut e = from_witness_point(ctx, r.get_value());
    r.assert_equal(&mut e);
}

fn cycle_group_mul_witness(ctx: &Ctx) {
    let p = from_witness_point(ctx, gp(3));
    let s = CycleScalar::new(w(ctx, 999), w(ctx, 5));
    let cc = CycleGroup::constant(gp(11));
    let cs = CycleScalar::constant(Fq::from(13u64));
    let mut r = CycleGroup::batch_mul(&[p, cc], &[s, cs]);
    let mut e = from_witness_point(ctx, r.get_value());
    r.assert_equal(&mut e);
}

fn run(ctx: &Ctx, name: &str) {
    let suffix = |prefix: &str| name[prefix.len()..].parse::<u64>().unwrap();
    match name {
        "field_ops" => field_ops(ctx),
        "bool_ops" => bool_ops(ctx),
        "cycle_group_add" => cycle_group_add(ctx),
        "cycle_group_mul_witness" => cycle_group_mul_witness(ctx),
        _ if name.starts_with("cycle_group_mul_") => cycle_group_mul(ctx, suffix("cycle_group_mul_")),
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
    "bool_ops",
    "cycle_group_add",
    "cycle_group_mul_1",
    "cycle_group_mul_3",
    "cycle_group_mul_witness",
];

fn check(name: &str) {
    let dump = common::fixture_dir(&format!("instance/stdlib/{name}"));
    if !dump.join("vk").exists() {
        eprintln!("skipping stdlib/{name}: no dump");
        return;
    }
    let ctx = Rc::new(RefCell::new(Builder::new_mega(Rc::new(
        RefCell::new(EccOpQueue::new()),
    ))));
    run(&ctx, name);
    let mut builder = Rc::try_unwrap(ctx).ok().unwrap().into_inner();
    assert!(builder.failed.is_none(), "{name}: builder failure {:?}", builder.failed);
    let inst = ProverInstance::from_builder(&MEGA_KERNEL, &mut builder, &mut OsRng);
    let expected = ProverInstance::load_dump(&MEGA_KERNEL, &dump);
    assert_eq!(inst.dyadic_size, expected.dyadic_size, "{name}: dyadic size");
    assert_eq!(inst.public_inputs, expected.public_inputs, "{name}: public inputs");
    let compare: Vec<usize> = (0..inst.layout.num_unshifted()).collect();
    common::assert_polys_equal(name, &inst, &expected, &builder, &compare);
    let ck = CommitmentKey::new(inst.max_end_index);
    assert_eq!(
        inst.compute_vk(&ck).to_bytes(),
        std::fs::read(dump.join("vk")).unwrap(),
        "{name}: VK"
    );
}

/// Every program builds a circuit all MegaKernel relations vanish on (bb-independent).
#[test]
fn stdlib_programs_are_satisfied() {
    for name in PROGRAMS {
        let ctx = Rc::new(RefCell::new(Builder::new_mega(Rc::new(
            RefCell::new(EccOpQueue::new()),
        ))));
        run(&ctx, name);
        let mut builder = Rc::try_unwrap(ctx).ok().unwrap().into_inner();
        assert!(builder.failed.is_none(), "{name}: builder failure {:?}", builder.failed);
        let mut inst = ProverInstance::from_builder(&MEGA_KERNEL, &mut builder, &mut OsRng);
        let ck = CommitmentKey::new(inst.max_end_index);
        let vk = inst.compute_vk(&ck);
        let out = prove_oink(&mut inst, &vk, &ck, &mut NativeTranscript::new(), &mut OsRng, true);
        assert_eq!(check_circuit(&inst, &out.params), None, "{name}: relation failure");
    }
}

#[test]
fn stdlib_programs_match_bb() {
    for name in PROGRAMS {
        check(name);
    }
}
