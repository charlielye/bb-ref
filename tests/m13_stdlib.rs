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
use bb_ref::honk::flavor::FlavorDesc;
use bb_ref::honk::{MEGA_APP, MEGA_KERNEL};
use bb_ref::stdlib::bigfield::BigField;
use bb_ref::stdlib::sha256;
use num_bigint::BigUint;
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

/// The programs with lookup gates are dumped as MegaApp (MegaKernel has no lookup entities).
fn flavor_of(name: &str) -> &'static FlavorDesc {
    if name.starts_with("sha256") || name.starts_with("bigfield") {
        &MEGA_APP
    } else {
        &MEGA_KERNEL
    }
}

type P256Fq = BigField<ark_secp256r1::Fq>;

fn p256(limbs: [u64; 4]) -> ark_secp256r1::Fq {
    ark_secp256r1::Fq::from(BigUint::from_slice(&limbs.iter().flat_map(|l| [*l as u32, (*l >> 32) as u32]).collect::<Vec<_>>()))
}

fn bigfield_ops(ctx: &Ctx) {
    let a_n = p256([0x1234567890abcdef, 0xfedcba0987654321, 0x0f0e0d0c0b0a0908, 0x0706050403020100]);
    bb_ref::circuit::builder::trace_phase("bigfield_ops: a_n");
    let c_n = p256([0x00000000000000ff, 0x1111111111111111, 0x2222222222222222, 0x3333333333333333]);
    bb_ref::circuit::builder::trace_phase("bigfield_ops: c_n");
    let a = P256Fq::from_witness(ctx, &a_n);
    bb_ref::circuit::builder::trace_phase("bigfield_ops: a");
    let c = P256Fq::from_witness(ctx, &c_n);
    bb_ref::circuit::builder::trace_phase("bigfield_ops: c");
    let k = P256Fq::from_u64(0x9999);
    bb_ref::circuit::builder::trace_phase("bigfield_ops: k");
    let (t, f) = (wb(ctx, true), wb(ctx, false));
    let s = a.add(&c);
    bb_ref::circuit::builder::trace_phase("bigfield_ops: s");
    let d = a.sub(&c);
    bb_ref::circuit::builder::trace_phase("bigfield_ops: d");
    let m = a.mul(&c);
    bb_ref::circuit::builder::trace_phase("bigfield_ops: m");
    let q = a.div(&c);
    bb_ref::circuit::builder::trace_phase("bigfield_ops: q");
    let sq = a.sqr();
    bb_ref::circuit::builder::trace_phase("bigfield_ops: sq");
    let ma = a.madd(&c, &[s.clone()]);
    bb_ref::circuit::builder::trace_phase("bigfield_ops: ma");
    let mm = P256Fq::mult_madd(&[a.clone(), c.clone()], &[c.clone(), a.clone()], &[m.clone()], false);
    bb_ref::circuit::builder::trace_phase("bigfield_ops: mm");
    let dm = P256Fq::dual_madd(&a, &c, &s, &d, &[sq.clone()]);
    bb_ref::circuit::builder::trace_phase("bigfield_ops: dm");
    let msd = P256Fq::msub_div(&[a.clone()], &[c.clone()], &d, &[s.clone()], true);
    bb_ref::circuit::builder::trace_phase("bigfield_ops: msd");
    let cn = m.conditional_negate(&t);
    bb_ref::circuit::builder::trace_phase("bigfield_ops: cn");
    let cs = P256Fq::conditional_assign(&f, &a, &c);
    bb_ref::circuit::builder::trace_phase("bigfield_ops: cs");
    let ka = k.mul(&a);
    bb_ref::circuit::builder::trace_phase("bigfield_ops: ka");
    let ak = a.add(&k);
    bb_ref::circuit::builder::trace_phase("bigfield_ops: ak");
    let amk = a.sub(&k);
    bb_ref::circuit::builder::trace_phase("bigfield_ops: amk");
    let kq = k.div(&a);
    bb_ref::circuit::builder::trace_phase("bigfield_ops: kq");
    let sm = P256Fq::sum(&[a.clone(), c.clone(), s.clone(), d.clone(), m.clone()]);
    bb_ref::circuit::builder::trace_phase("bigfield_ops: sm");
    let p5 = a.pow(5);
    bb_ref::circuit::builder::trace_phase("bigfield_ops: p5");
    let ng = a.neg();
    bb_ref::circuit::builder::trace_phase("bigfield_ops: ng");
    let inv = a.invert();
    bb_ref::circuit::builder::trace_phase("bigfield_ops: inv");
    let sa = a.sqradd(&[c.clone()]);
    bb_ref::circuit::builder::trace_phase("bigfield_ops: sa");
    let e1 = a.eq(&c);
    bb_ref::circuit::builder::trace_phase("bigfield_ops: e1");
    let e2 = cs.eq(&a);
    bb_ref::circuit::builder::trace_phase("bigfield_ops: e2");
    let lt = a.is_less_than(&P256Fq::modulus());
    bb_ref::circuit::builder::trace_phase("bigfield_ops: lt");
    a.assert_is_in_field();
    bb_ref::circuit::builder::trace_phase("bigfield_ops: a.assert_is_in_field();");
    mm.assert_is_not_equal(&m);
    bb_ref::circuit::builder::trace_phase("bigfield_ops: mm.assert_is_not_equal(&m);");
    inv.mul(&a).assert_equal(&P256Fq::one());
    bb_ref::circuit::builder::trace_phase("bigfield_ops: inv.mul(&a).assert_equal(&P256Fq::one())");
    let r = q.mul(&c);
    bb_ref::circuit::builder::trace_phase("bigfield_ops: r");
    r.reduce_mod_target_modulus();
    bb_ref::circuit::builder::trace_phase("bigfield_ops: r.reduce_mod_target_modulus();");
    r.assert_equal(&a);
    bb_ref::circuit::builder::trace_phase("bigfield_ops: r.assert_equal(&a);");
    let acc = P256Fq::sum(&[sq, ma, mm, dm, msd, cn, ka, ak, amk, kq, sm, p5, ng, sa]);
    bb_ref::circuit::builder::trace_phase("bigfield_ops: acc");
    acc.assert_zero_if(&f);
    bb_ref::circuit::builder::trace_phase("bigfield_ops: acc.assert_zero_if(&f);");
    let out = acc.get_limb(0).element
        .add(&acc.get_limb(1).element)
        .add(&acc.get_limb(2).element)
        .add(&acc.get_limb(3).element)
        .add(&acc.get_prime_basis_limb())
        .add(&e1.to_field())
        .add(&e2.to_field())
        .add(&lt.to_field());
    bb_ref::circuit::builder::trace_phase("bigfield_ops: .add(&lt.to_field());");
    let e = FieldT::from_witness(ctx, out.get_value());
    bb_ref::circuit::builder::trace_phase("bigfield_ops: e");
    out.sub(&e).assert_is_zero();
    bb_ref::circuit::builder::trace_phase("bigfield_ops: out.sub(&e).assert_is_zero();");
}

fn sha256_block(ctx: &Ctx) {
    const IV: [u64; 8] = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    let h: [FieldT; 8] = std::array::from_fn(|i| w(ctx, IV[i]));
    let input: [FieldT; 16] = std::array::from_fn(|i| w(ctx, (i as u64 * 0x01010101 + 0x61626364) & 0xffffffff));
    let out = sha256::sha256_block(&h, &input);
    let words: [u32; 16] = std::array::from_fn(|i| ((i as u64 * 0x01010101 + 0x61626364) & 0xffffffff) as u32);
    let expected = sha256_compress(IV.map(|v| v as u32), &words);
    for (o, e) in out.iter().zip(expected) {
        assert_eq!(o.get_value(), Fr::from(e as u64), "sha256 compression output");
        let e = w(ctx, bb_ref::base::field::u256(&o.get_value()).0[0]);
        o.assert_equal(&e);
    }
}

/// Reference SHA-256 compression function (FIPS 180-4).
fn sha256_compress(h: [u32; 8], block: &[u32; 16]) -> [u32; 8] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98,
        0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
        0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8,
        0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
        0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
        0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut w = [0u32; 64];
    w[..16].copy_from_slice(block);
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ (!e & g);
        let t1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);
        hh = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    let out = [a, b, c, d, e, f, g, hh];
    std::array::from_fn(|i| h[i].wrapping_add(out[i]))
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
        "sha256_block" => sha256_block(ctx),
        "bigfield_ops" => bigfield_ops(ctx),
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
    "sha256_block",
    "bigfield_ops",
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
    let inst = ProverInstance::from_builder(flavor_of(name), &mut builder, &mut OsRng);
    let expected = ProverInstance::load_dump(flavor_of(name), &dump);
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
        let mut inst = ProverInstance::from_builder(flavor_of(name), &mut builder, &mut OsRng);
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
