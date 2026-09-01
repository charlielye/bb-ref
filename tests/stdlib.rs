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
use bb_ref::honk::flavor::FlavorDesc;
use bb_ref::honk::oink_prover::prove_oink;
use bb_ref::honk::prover_instance::ProverInstance;
use bb_ref::honk::{MEGA_APP, MEGA_KERNEL, ULTRA};
use bb_ref::stdlib::bigfield::BigField;
use bb_ref::stdlib::biggroup::{Element, Scalar};
use bb_ref::stdlib::byte_array::ByteArray;
use bb_ref::stdlib::cycle_group::{CycleGroup, CycleScalar};
use bb_ref::stdlib::ecdsa::ecdsa_verify_signature;
use bb_ref::stdlib::field::split_unique;
use bb_ref::stdlib::hash::StdPoseidon2;
use bb_ref::stdlib::io::{AppIo, DataBusDepot, HidingKernelIo, KernelIo, MAX_APPS_PER_KERNEL};
use bb_ref::stdlib::keccak;
use bb_ref::stdlib::logic::create_logic_constraint;
use bb_ref::stdlib::sha256;
use bb_ref::stdlib::{BoolT, Ctx, FieldT, GoblinElement, StdBn254};
use common::eccvm_ops::g1_times;
use num_bigint::BigUint;
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
    if name == "biggroup_bn254_ops" || name == "row_disabling_fq" || name == "wnaf_range_fq" {
        return &ULTRA;
    }
    if [
        "sha256",
        "blake",
        "aes128",
        "bigfield",
        "biggroup",
        "secp256r1",
        "ecdsa",
        "keccak",
        "logic",
    ]
    .iter()
    .any(|p| name.starts_with(p))
    {
        &MEGA_APP
    } else {
        &MEGA_KERNEL
    }
}

type P256Fq = BigField<ark_secp256r1::Fq>;

fn p256(limbs: [u64; 4]) -> ark_secp256r1::Fq {
    ark_secp256r1::Fq::from(BigUint::from_slice(
        &limbs
            .iter()
            .flat_map(|l| [*l as u32, (*l >> 32) as u32])
            .collect::<Vec<_>>(),
    ))
}

fn wnaf_range_fq(ctx: &Ctx) {
    use bb_ref::base::field::{from_u256, U256};
    type FqCt = bb_ref::stdlib::bigfield::BigField<bb_ref::base::Fq>;
    let s = FqCt::from_witness(ctx, &from_u256(U256::new([3, 0, 0, 0])));
    let sc = FqCt::from_witness(ctx, &from_u256(U256::new([0x123456789abcdef, 7, 11, 0])));
    let one = FqCt::from_u64(1);
    let two = FqCt::from_u64(2);
    let s1 = s.sub(&one);
    let sq1 = s1.sqr();
    let a = sq1.sub(&one);
    let s2 = s.sub(&two);
    let sq2 = s2.sqr();
    let bfac = sq2.sub(&one);
    let ab = a.mul(&bfac);
    let r = ab.mul(&sc);
    r.self_reduce();
}

fn row_disabling_fq(ctx: &Ctx) {
    use bb_ref::base::field::from_u256;
    use bb_ref::base::field::U256;
    type FqCt = bb_ref::stdlib::bigfield::BigField<bb_ref::base::Fq>;
    let mut u: Vec<FqCt> = Vec::new();
    for i in 0..15u64 {
        let v: bb_ref::base::Fq = from_u256(U256::new([i * 7 + 3, i + 1, 2 * i + 5, 0]));
        u.push(FqCt::from_witness(ctx, &v));
    }
    let main_factor = bb_ref::honk::sumcheck::row_disabling_main_factor(&u);
    let offset_factor = <FqCt as bb_ref::base::field::FieldLike>::one() - &main_factor;
    main_factor.self_reduce();
    offset_factor.self_reduce();
}

fn bigfield_ops(ctx: &Ctx) {
    let a_n = p256([
        0x1234567890abcdef,
        0xfedcba0987654321,
        0x0f0e0d0c0b0a0908,
        0x0706050403020100,
    ]);
    let c_n = p256([
        0x00000000000000ff,
        0x1111111111111111,
        0x2222222222222222,
        0x3333333333333333,
    ]);
    let a = P256Fq::from_witness(ctx, &a_n);
    let c = P256Fq::from_witness(ctx, &c_n);
    let k = P256Fq::from_u64(0x9999);
    let (t, f) = (wb(ctx, true), wb(ctx, false));
    let s = a.add(&c);
    let d = a.sub(&c);
    let m = a.mul(&c);
    let q = a.div(&c);
    let sq = a.sqr();
    let ma = a.madd(&c, &[s.clone()]);
    let mm = P256Fq::mult_madd(&[a.clone(), c.clone()], &[c.clone(), a.clone()], &[m.clone()], false);
    let dm = P256Fq::dual_madd(&a, &c, &s, &d, &[sq.clone()]);
    let msd = P256Fq::msub_div(&[a.clone()], &[c.clone()], &d, &[s.clone()], true);
    let cn = m.conditional_negate(&t);
    let cs = P256Fq::conditional_assign(&f, &a, &c);
    let ka = k.mul(&a);
    let ak = a.add(&k);
    let amk = a.sub(&k);
    let kq = k.div(&a);
    let sm = P256Fq::sum(&[a.clone(), c.clone(), s.clone(), d.clone(), m.clone()]);
    let p5 = a.pow(5);
    let ng = a.neg();
    let inv = a.invert();
    let sa = a.sqradd(&[c.clone()]);
    let e1 = a.eq(&c);
    let e2 = cs.eq(&a);
    let lt = a.is_less_than(&P256Fq::modulus());
    a.assert_is_in_field();
    mm.assert_is_not_equal(&m);
    inv.mul(&a).assert_equal(&P256Fq::one());
    let r = q.mul(&c);
    r.reduce_mod_target_modulus();
    r.assert_equal(&a);
    let acc = P256Fq::sum(&[sq, ma, mm, dm, msd, cn, ka, ak, amk, kq, sm, p5, ng, sa]);
    acc.assert_zero_if(&f);
    let out = acc
        .get_limb(0)
        .element
        .add(&acc.get_limb(1).element)
        .add(&acc.get_limb(2).element)
        .add(&acc.get_limb(3).element)
        .add(&acc.get_prime_basis_limb())
        .add(&e1.to_field())
        .add(&e2.to_field())
        .add(&lt.to_field());
    let e = FieldT::from_witness(ctx, out.get_value());
    out.sub(&e).assert_is_zero();
}

type P256 = ark_secp256r1::Config;

fn biggroup_ops(ctx: &Ctx) {
    use ark_ec::{AffineRepr, CurveGroup};
    let tr = |l: &str| bb_ref::circuit::builder::trace_phase(&format!("biggroup_ops: {l}"));
    let g = ark_secp256r1::Affine::generator();
    let p_n = (g * ark_secp256r1::Fr::from(7u64)).into_affine();
    let q_n = (g * ark_secp256r1::Fr::from(11u64)).into_affine();
    let p = Element::<P256>::from_witness(ctx, &p_n);
    let q = Element::<P256>::from_witness(ctx, &q_n);
    tr("points");
    let (t, f) = (wb(ctx, true), wb(ctx, false));
    let s = p.add(&q);
    tr("add");
    let d = p.sub(&q);
    tr("sub");
    let dd = p.dbl();
    tr("dbl");
    let n = p.neg();
    let cn = p.conditional_negate(&t);
    let cs = Element::<P256>::conditional_assign(&f, &p, &q);
    tr("conditionals");
    let _res = s.validate_on_curve(false);
    tr("validate");
    let scalar = |limbs: [u64; 4]| {
        ark_secp256r1::Fr::from(BigUint::from_slice(
            &limbs
                .iter()
                .flat_map(|l| [*l as u32, (*l >> 32) as u32])
                .collect::<Vec<_>>(),
        ))
    };
    let u1 = Scalar::<P256>::from_witness(ctx, &scalar([0x1234567890abcdef, 0x0fedcba098765432, 0, 0]));
    let u2 = Scalar::<P256>::from_witness(ctx, &scalar([0xabcdef0123456789, 0x1122334455667788, 0, 0]));
    let (u1_n, u2_n) = (
        scalar([0x1234567890abcdef, 0x0fedcba098765432, 0, 0]),
        scalar([0xabcdef0123456789, 0x1122334455667788, 0, 0]),
    );
    let msm = Element::<P256>::batch_mul(&[p.clone(), q.clone()], &[u1.clone(), u2], 128, false);
    assert_eq!(
        msm.get_value(),
        (p_n * u1_n + q_n * u2_n).into_affine(),
        "biggroup batch_mul value"
    );
    tr("batch_mul");
    let sm = p.scalar_mul(&u1, 128);
    tr("scalar_mul");
    let sum = s.add(&d).add(&dd).add(&n).add(&cn).add(&cs).add(&msm).add(&sm);
    tr("sum");
    let e = Element::<P256>::from_witness(ctx, &sum.get_value());
    sum.incomplete_assert_equal(&e);
    tr("assert");
}

fn biggroup_bn254_ops(ctx: &Ctx) {
    use ark_ec::{AffineRepr, CurveGroup};
    use bb_ref::base::G1Affine;
    bb_ref::base::rng::set_global(Box::new(bb_ref::base::rng::DebugRng::new(12345)));
    type Bn = ark_bn254::g1::Config;
    let tr = |l: &str| bb_ref::circuit::builder::trace_phase(&format!("biggroup_bn254_ops: {l}"));
    let g = G1Affine::generator();
    let p_n = (g * Fr::from(7u64)).into_affine();
    let q_n = (g * Fr::from(11u64)).into_affine();
    let p = Element::<Bn>::from_witness(ctx, &p_n);
    let q = Element::<Bn>::from_witness(ctx, &q_n);
    tr("points");
    let (t, f) = (wb(ctx, true), wb(ctx, false));
    let s = p.add(&q);
    let d = p.sub(&q);
    let dd = p.dbl();
    let n = p.neg();
    let cn = p.conditional_negate(&t);
    let cs = Element::<Bn>::conditional_assign(&f, &p, &q);
    let _res = s.validate_on_curve(false);
    tr("ops");
    let u1 = FieldT::from_witness(
        ctx,
        from_hex("0abc1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab"),
    );
    let u2 = FieldT::from_witness(
        ctx,
        from_hex("00000000000000000000000000000000abcdef0123456789abcdef0123456789"),
    );
    let u3 = FieldT::from_witness(
        ctx,
        from_hex("00000000000000000000000000000000112233445566778899aabbccddeeff00"),
    );
    let m1 = Element::<Bn>::batch_mul(&[p.clone(), q.clone()], &[u1.clone(), u2.clone()], 0, true);
    assert_eq!(
        m1.get_value(),
        (p_n * u1.get_value() + q_n * u2.get_value()).into_affine(),
        "bn254 edgecase batch_mul value"
    );
    tr("batch_mul_edgecases");
    let m2 = Element::<Bn>::batch_mul(&[p.clone(), q.clone()], &[u2.clone(), u3.clone()], 128, false);
    assert_eq!(
        m2.get_value(),
        (p_n * u2.get_value() + q_n * u3.get_value()).into_affine(),
        "bn254 small batch_mul value"
    );
    tr("batch_mul_small");
    let const_g = Element::<Bn>::constant_point(Some(ctx.clone()), &g);
    let m3 = Element::<Bn>::batch_mul(
        &[p.clone(), const_g],
        &[u3.clone(), FieldT::constant(Fr::from(5u64))],
        0,
        false,
    );
    tr("batch_mul_mixed_constant");
    let sm = p.scalar_mul(&u1, 0);
    tr("scalar_mul");
    let sum = s
        .add(&d)
        .add(&dd)
        .add(&n)
        .add(&cn)
        .add(&cs)
        .add(&m1)
        .add(&m2)
        .add(&m3)
        .add(&sm);
    let e = Element::<Bn>::from_witness(ctx, &sum.get_value());
    sum.incomplete_assert_equal(&e);
    tr("assert");
}

fn secp256r1_mul(ctx: &Ctx) {
    use ark_ec::{AffineRepr, CurveGroup};
    let tr = |l: &str| bb_ref::circuit::builder::trace_phase(&format!("secp256r1_mul: {l}"));
    let scalar = |limbs: [u64; 4]| {
        ark_secp256r1::Fr::from(BigUint::from_slice(
            &limbs
                .iter()
                .flat_map(|l| [*l as u32, (*l >> 32) as u32])
                .collect::<Vec<_>>(),
        ))
    };
    let g = ark_secp256r1::Affine::generator();
    let u1_n = scalar([
        0x1234567890abcdef,
        0xfedcba0987654321,
        0x0f0e0d0c0b0a0908,
        0x0706050403020100,
    ]);
    let u1 = Scalar::<P256>::from_witness(ctx, &u1_n);
    let t1 = Element::<P256>::secp256r1_fixed_base_mul(&u1);
    assert_eq!(t1.get_value(), (g * u1_n).into_affine(), "fixed-base mul value");
    tr("fixed_base_mul");
    let q_n = (g * ark_secp256r1::Fr::from(11u64)).into_affine();
    let q = Element::<P256>::from_witness(ctx, &q_n);
    let u2_n = scalar([
        0xabcdef0123456789,
        0x1122334455667788,
        0x99aabbccddeeff00,
        0x0123456789abcdef,
    ]);
    let u2 = Scalar::<P256>::from_witness(ctx, &u2_n);
    let (res, ok) = Element::<P256>::secp256r1_ecdsa_mul(&q, &u1, &u2);
    assert_eq!(
        res.get_value(),
        (g * u1_n + q_n * u2_n).into_affine(),
        "ecdsa mul value"
    );
    tr("ecdsa_mul");
    ok.assert_equal(&BoolT::constant(true));
    let e1 = Element::<P256>::from_witness(ctx, &t1.get_value());
    t1.incomplete_assert_equal(&e1);
    let e2 = Element::<P256>::from_witness(ctx, &res.get_value());
    res.incomplete_assert_equal(&e2);
}

/// The bb `ecdsa_k1` program: RFC6979-deterministic secp256k1 signature over sha256("bbref")
/// under private key 0xd67a…36c2, verified in-circuit (vectors recomputed independently).
fn ecdsa_k1(ctx: &Ctx) {
    use bb_ref::stdlib::biggroup::{Element, Fq as FqOf};
    use bb_ref::stdlib::ecdsa::ecdsa_verify_signature_secp256k1;
    type K1Fq = FqOf<ark_secp256k1::Config>;
    let bytes = |h: &str| ByteArray::from_bytes(ctx, &hex::decode(h).unwrap());
    // Mirrors the C++ program's construction order: each pubkey coordinate's byte array is
    // immediately converted to a bigfield before the next input is created.
    let hashed_message = bytes("69d71da14505d0c5b0c6e07648a158fb1d8f10e1747eb5d60724fe9faae8ecc7");
    let pub_x = K1Fq::from_bytes(&bytes(
        "7ed9c5daf5f460a6fd41b119e24484997ba3685fbfa6a388927ba258a04fbae9",
    ));
    let pub_y = K1Fq::from_bytes(&bytes(
        "02fba55d69d5ef8ca6675106c6892e83403310242ee0350c61777a589ccf1019",
    ));
    let public_key = Element::<ark_secp256k1::Config>::new(pub_x, pub_y, false);
    let r = bytes("723e7496477b809ab69fd8db02c1fb2b410acb4d31a458f1981443d66320b549");
    let s = bytes("14860b4eed233c7bab73483c1ba25b7588689902086fb8597f54add7c7859742");
    let result = ecdsa_verify_signature_secp256k1(&hashed_message, &public_key, &r, &s);
    assert!(result.get_value(), "k1 ecdsa signature should verify");
    result.assert_equal(&BoolT::constant(true));
}

/// The bb `aes128_cbc_<n>` program: n packed 16-byte witness blocks encrypted under a witness
/// iv + key, outputs bound to packed fresh output witnesses (mirroring the dsl arm).
fn aes128_cbc(ctx: &Ctx, num_blocks: usize) {
    use bb_ref::base::field::u256;
    let pack16 = |seed: u64| {
        let mut converted = FieldT::constant(Fr::from(0u64));
        for i in 0..16u64 {
            converted = converted.mul(&FieldT::constant(Fr::from(256u64)));
            let byte = FieldT::from_witness(ctx, Fr::from((seed + i * 5) & 0xff));
            byte.create_range_constraint(8);
            converted = converted.add(&byte);
        }
        converted
    };
    let input: Vec<FieldT> = (0..num_blocks).map(|blk| pack16(blk as u64 * 16 + 1)).collect();
    let iv = pack16(0xa0);
    let key = pack16(0x30);
    let out = bb_ref::stdlib::aes128::encrypt_buffer_cbc(&input, &iv, &key);
    for o in &out {
        let mut converted = FieldT::constant(Fr::from(0u64));
        let v = u256(&o.get_value());
        for i in 0..16u32 {
            converted = converted.mul(&FieldT::constant(Fr::from(256u64)));
            let byte_val = ((v >> (8 * (15 - i))).0[0]) & 0xff;
            let byte = FieldT::from_witness(ctx, Fr::from(byte_val));
            byte.create_range_constraint(8);
            converted = converted.add(&byte);
        }
        o.assert_equal(&converted);
    }
}

/// The bb `blake{2s,3}_hash_<n>` programs: n single-byte witnesses hashed, output bytes bound to
/// fresh witnesses (mirroring the dsl arm's result binding).
fn blake_hash(ctx: &Ctx, n: usize, is_blake3: bool) {
    use bb_ref::stdlib::{blake2s, blake3s};
    let (mult, off) = if is_blake3 { (11, 5) } else { (7, 3) };
    let mut arr = ByteArray::constant_padding(0, 0);
    for i in 0..n {
        let byte = FieldT::from_witness(ctx, Fr::from(((i * mult + off) & 0xff) as u64));
        arr.write(&ByteArray::from_field(&byte, 1));
    }
    let out = if is_blake3 {
        blake3s::hash(&arr)
    } else {
        blake2s::hash(&arr)
    };
    for b in out.bytes() {
        b.assert_equal(&FieldT::from_witness(ctx, b.get_value()));
    }
}

fn ecdsa_r1(ctx: &Ctx) {
    let bytes = |h: &str| ByteArray::from_bytes(ctx, &hex::decode(h).unwrap());
    let hashed_message = bytes("5566778899aabbccddeeff00112233445566778899aabbccddeeff0011223344");
    let pub_x_bytes = bytes("471c3e758c4904285bba7e53118ed0f524adeb0757d25bd2f8e7b0d76dfa714c");
    let pub_y_bytes = bytes("dd520f7aca8a8b917acc37f51de8f0c9bbe3ad858382e702dc25a12d09f7a858");
    let r = bytes("4a5530b043726fbeebd13c58ebc50dcc944fd60e07b714aac9b57eddc6037a88");
    let s = bytes("2b0f47eb371a2580242896f996d17e91d6134517572759d4d9729892c8b4dcd0");
    let pub_x = P256Fq::from_bytes(&pub_x_bytes);
    let pub_y = P256Fq::from_bytes(&pub_y_bytes);
    let public_key = Element::<P256>::new(pub_x, pub_y, false);
    let result = ecdsa_verify_signature(&hashed_message, &public_key, &r, &s);
    assert!(result.get_value(), "ecdsa signature should verify");
    result.assert_equal(&BoolT::constant(true));
}

/// Reference Keccak-f[1600] (FIPS 202).
fn keccak_f1600(state: &mut [u64; 25]) {
    const RC: [u64; 24] = [
        0x0000000000000001,
        0x0000000000008082,
        0x800000000000808a,
        0x8000000080008000,
        0x000000000000808b,
        0x0000000080000001,
        0x8000000080008081,
        0x8000000000008009,
        0x000000000000008a,
        0x0000000000000088,
        0x0000000080008009,
        0x000000008000000a,
        0x000000008000808b,
        0x800000000000008b,
        0x8000000000008089,
        0x8000000000008003,
        0x8000000000008002,
        0x8000000000000080,
        0x000000000000800a,
        0x800000008000000a,
        0x8000000080008081,
        0x8000000000008080,
        0x0000000080000001,
        0x8000000080008008,
    ];
    const ROT: [u32; 25] = [
        0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
    ];
    for rc in RC {
        let c: [u64; 5] = std::array::from_fn(|x| (0..5).fold(0, |acc, y| acc ^ state[y * 5 + x]));
        let d: [u64; 5] = std::array::from_fn(|x| c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1));
        for i in 0..25 {
            state[i] ^= d[i % 5];
        }
        let mut b = [0u64; 25];
        for y in 0..5 {
            for x in 0..5 {
                b[((2 * x + 3 * y) % 5) * 5 + y] = state[y * 5 + x].rotate_left(ROT[y * 5 + x]);
            }
        }
        for y in 0..5 {
            for x in 0..5 {
                state[y * 5 + x] = b[y * 5 + x] ^ (!b[y * 5 + (x + 1) % 5] & b[y * 5 + (x + 2) % 5]);
            }
        }
        state[0] ^= rc;
    }
}

fn keccak_permutation(ctx: &Ctx) {
    let mut native: [u64; 25] = std::array::from_fn(|i| (i as u64 + 1).wrapping_mul(0x9e3779b97f4a7c15));
    let state: [FieldT; 25] = std::array::from_fn(|i| w(ctx, native[i]));
    let out = keccak::permutation_opcode(ctx, &state);
    keccak_f1600(&mut native);
    for (o, e) in out.iter().zip(native) {
        assert_eq!(o.get_value(), Fr::from(e), "keccak-f[1600] output");
        o.assert_equal(&w(ctx, e));
    }
}

fn logic_ops(ctx: &Ctx) {
    let (a, b) = (w(ctx, 0xdeadbeef), w(ctx, 0x12345678));
    let x = create_logic_constraint(&a, &b, 32, true);
    assert_eq!(x.get_value(), Fr::from(0xdeadbeefu64 ^ 0x12345678));
    let y = create_logic_constraint(&a, &b, 32, false);
    assert_eq!(y.get_value(), Fr::from(0xdeadbeefu64 & 0x12345678));
    let (p, q) = (w(ctx, 0x0123456789abcdef), w(ctx, 0xfedcba9876543210));
    let z = create_logic_constraint(&p, &q, 64, true);
    assert_eq!(z.get_value(), Fr::from(0x0123456789abcdefu64 ^ 0xfedcba9876543210));
    let (e, f) = (w(ctx, 0xa5), w(ctx, 0x3c));
    let g = create_logic_constraint(&e, &f, 8, false);
    let h = create_logic_constraint(&e, &c(0x0f), 8, true);
    let sum = FieldT::accumulate(&[x, y, z, g, h]);
    sum.assert_equal(&FieldT::from_witness(ctx, sum.get_value()));
}

fn sha256_block(ctx: &Ctx) {
    const IV: [u64; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];
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
        let t1 = hh
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K[i])
            .wrapping_add(w[i]);
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
        "row_disabling_fq" => row_disabling_fq(ctx),
        "wnaf_range_fq" => wnaf_range_fq(ctx),
        "biggroup_ops" => biggroup_ops(ctx),
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
        "biggroup_bn254_ops" => biggroup_bn254_ops(ctx),
        "secp256r1_mul" => secp256r1_mul(ctx),
        "ecdsa_r1" => ecdsa_r1(ctx),
        "ecdsa_k1" => ecdsa_k1(ctx),
        _ if name.starts_with("aes128_cbc_") => aes128_cbc(ctx, suffix("aes128_cbc_") as usize),
        _ if name.starts_with("blake2s_hash_") => blake_hash(ctx, suffix("blake2s_hash_") as usize, false),
        _ if name.starts_with("blake3_hash_") => blake_hash(ctx, suffix("blake3_hash_") as usize, true),
        "keccak_permutation" => keccak_permutation(ctx),
        "logic_ops" => logic_ops(ctx),
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
    "row_disabling_fq",
    "wnaf_range_fq",
    "biggroup_ops",
    "biggroup_bn254_ops",
    "secp256r1_mul",
    "ecdsa_r1",
    "ecdsa_k1",
    "aes128_cbc_2",
    "blake2s_hash_5",
    "blake2s_hash_65",
    "blake3_hash_5",
    "blake3_hash_65",
    "keccak_permutation",
    "logic_ops",
];

fn check(name: &str) {
    let dump = common::fixture_dir(&format!("instance/stdlib/{name}"));
    if !dump.join("vk").exists() {
        eprintln!("skipping stdlib/{name}: no dump");
        return;
    }
    let ctx = Rc::new(RefCell::new(if std::ptr::eq(flavor_of(name), &ULTRA) {
        Builder::new()
    } else {
        Builder::new_mega(Rc::new(RefCell::new(EccOpQueue::new())))
    }));
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
        let ctx = Rc::new(RefCell::new(if std::ptr::eq(flavor_of(name), &ULTRA) {
            Builder::new()
        } else {
            Builder::new_mega(Rc::new(RefCell::new(EccOpQueue::new())))
        }));
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
