//! secp256k1 ECDSA scalar multiplication (bb `biggroup_secp256k1.hpp` + the k1 parts of
//! `biggroup_nafs.hpp` / `biggroup_tables.hpp`): `u1·G + u2·Q` via the curve's endomorphism —
//! each scalar splits as `k = klo - λ·khi (mod n)` with 129-bit halves, the generator terms read
//! an 8-bit wNAF from precomputed plookup tables, and the pubkey terms read a 4-bit wNAF from
//! in-circuit ROM tables, all folded through the montgomery ladder.

use super::biggroup::{ChainAddAccumulator, Element, Fq, Scalar};
use super::bool::BoolT;
use super::field::{Ctx, FieldT};
use super::plookup::read_pair_from_table;
use crate::base::Fr;
use crate::circuit::ecc_generator_tables::{multitable_id, GeneratorTable, BETA_HEX};
use ark_ff::PrimeField;
use num_bigint::BigUint;

type K1 = ark_secp256k1::Config;
type FqK1 = Fq<K1>;
type FrK1 = Scalar<K1>;
type P1 = Element<K1>;

/// λ: the cube root of unity mod n with `λ·P = (β·x, y)`.
const LAMBDA_HEX: &str = "5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72";

fn scalar_modulus() -> BigUint {
    ark_secp256k1::Fr::MODULUS.into()
}

/// bb `field::compute_endomorphism_k2` + `split_into_endomorphism_scalars` (full-width path):
/// `k = klo - λ·khi (mod n)`, each half returned as (canonical value, was-negated).
fn split_into_endomorphism_scalars(k: &BigUint) -> ((BigUint, bool), (BigUint, bool)) {
    let n = scalar_modulus();
    let lambda = BigUint::parse_bytes(LAMBDA_HEX.as_bytes(), 16).unwrap();
    // The lattice basis constants from bb's secp256k1 FrParams.
    let g1 = (BigUint::from(0xE4437ED6010E8828u64) << 64) + 0x6F547FA90ABFE4C4u64;
    let g2 = (BigUint::from(0x3086D221A7D46BCDu64) << 64) + 0xE86C90E49284EB15u64;
    let minus_b1 = (BigUint::from(0xE4437ED6010E8828u64) << 64) + 0x6F547FA90ABFE4C3u64;
    let b2 = (BigUint::from(0x3086D221A7D46BCDu64) << 64) + 0xe86c90e49284eb15u64;

    let mask = (BigUint::from(1u64) << 256u32) - 1u64;
    let c1 = (&g2 * k) >> 256u32;
    let c2 = (&g1 * k) >> 256u32;
    let q1_lo = (c1 * minus_b1) & &mask;
    let q2_lo = (c2 * b2) & &mask;
    let khi = (&n + q2_lo % &n + &n - q1_lo % &n) % &n;
    let klo = (&khi * &lambda + k) % &n;

    let negate = |v: BigUint| {
        if v.bits() >= 130 {
            ((&n - &v) % &n, true)
        } else {
            (v, false)
        }
    };
    (negate(klo), negate(khi))
}

/// bb `wnaf::fixed_wnaf<num_bits, 1, wnaf_size>`: `wnaf[0]` is the most significant entry; each
/// entry packs a `(wnaf_size-1)`-bit magnitude with the sign in bit 31.
fn fixed_wnaf(k: &BigUint, num_bits: usize, wnaf_size: usize) -> (Vec<u64>, bool) {
    let entries = num_bits.div_ceil(wnaf_size);
    let bits = |position: usize, count: usize| -> u64 {
        let mut v = 0u64;
        for i in 0..count {
            if k.bit((position + i) as u64) {
                v |= 1 << i;
            }
        }
        v
    };
    let skew = !k.bit(0);
    let mut wnaf = vec![0u64; entries];
    let mut previous = bits(0, wnaf_size) + skew as u64;
    for round_i in 1..entries {
        let (slice, index) = if round_i < entries - 1 {
            (bits(round_i * wnaf_size, wnaf_size), entries - round_i)
        } else {
            let final_bits = if num_bits % wnaf_size == 0 {
                wnaf_size
            } else {
                num_bits % wnaf_size
            };
            (bits((entries - 1) * wnaf_size, final_bits), 1)
        };
        let predicate = (slice & 1) == 0;
        let flip = if predicate { u64::MAX } else { 0 };
        wnaf[index] = (((previous.wrapping_sub((predicate as u64) << wnaf_size)) ^ flip) >> 1) & 0xffffffff
            | ((predicate as u64) << 31);
        previous = slice + predicate as u64;
        if round_i == entries - 1 {
            wnaf[0] = previous >> 1;
        }
    }
    if entries == 1 {
        wnaf[0] = previous >> 1;
    }
    (wnaf, skew)
}

/// bb `get_staggered_wnaf_fragment_value`.
fn staggered_wnaf_fragment(
    fragment_u64: u64,
    stagger: usize,
    is_negative: bool,
    wnaf_skew: bool,
    wnaf_size: usize,
) -> (u64, bool) {
    if stagger == 0 {
        return (0, wnaf_skew);
    }
    let mut fragment = fragment_u64 as i64;
    if is_negative {
        fragment = -fragment;
    }
    if !is_negative && wnaf_skew {
        fragment -= 1 << stagger;
    }
    if is_negative && wnaf_skew {
        fragment += 1 << stagger;
    }
    let output_skew = (fragment_u64 & 1) == 0;
    if !is_negative && output_skew {
        fragment += 1;
    } else if is_negative && output_skew {
        fragment -= 1;
    }
    let signed_wnaf_value = fragment / 2;
    let wnaf_window_size = 1i64 << (wnaf_size - 1);
    let output_fragment = if fragment < 0 {
        (wnaf_window_size + signed_wnaf_value - 1) as u64
    } else {
        (wnaf_window_size + signed_wnaf_value) as u64
    };
    (output_fragment, output_skew)
}

/// bb `convert_wnaf_values_to_witnesses`.
fn wnaf_witnesses(
    ctx: &Ctx,
    wnaf_values: &[u64],
    is_negative: bool,
    rounds: usize,
    wnaf_size: usize,
    range_constrain_wnaf: bool,
) -> Vec<FieldT> {
    let wnaf_window_size = 1u64 << (wnaf_size - 1);
    let mut entries = Vec::with_capacity(rounds);
    for &v in &wnaf_values[..rounds] {
        let predicate = (v >> 31) & 1 == 1;
        let magnitude = v & 0x7fffffff;
        let offset_entry = if predicate == is_negative {
            wnaf_window_size + magnitude
        } else {
            wnaf_window_size - magnitude - 1
        };
        let entry = FieldT::from_witness(ctx, Fr::from(offset_entry));
        if range_constrain_wnaf {
            entry.create_range_constraint(wnaf_size as u64);
        }
        entries.push(entry);
    }
    entries
}

/// bb `reconstruct_bigfield_from_wnaf`: `x = x_pos - x_neg`, both parts strictly positive.
fn reconstruct_bigfield_from_wnaf(
    ctx: &Ctx,
    wnaf: &[FieldT],
    positive_skew: &BoolT,
    negative_skew: &BoolT,
    stagger_fragment: &FieldT,
    stagger: usize,
    rounds: usize,
    wnaf_size: usize,
) -> FrK1 {
    let mut accumulator = Vec::with_capacity(rounds);
    for i in 0..rounds {
        let entry = wnaf[rounds - 1 - i].mul(&FieldT::constant(crate::base::field::from_u256(
            crate::base::field::U256::from(1u64) << (i * wnaf_size) as u32,
        )));
        accumulator.push(entry);
    }
    let mut sum = FieldT::accumulate(&accumulator);
    sum = sum.mul(&FieldT::constant(Fr::from(1u64 << stagger)));
    sum = sum.add(stagger_fragment);
    sum = sum.normalize();

    let zero = FieldT::from_witness_index(ctx, ctx.borrow().zero_idx());
    let reconstructed_positive_part = FrK1::from_halves(&sum, &zero, false, 0);
    let reconstructed_positive_part = reconstructed_positive_part
        .add(&reconstructed_positive_part)
        .add_to_lower_limb(&positive_skew.to_field(), &BigUint::from(1u64));

    let wnaf_window_size = 1u64 << (wnaf_size - 1);
    let mut negative_constant_wnaf_offset = BigUint::from(0u64);
    for i in 0..rounds {
        negative_constant_wnaf_offset += BigUint::from(wnaf_window_size * 2 - 1) << (i * wnaf_size);
    }
    negative_constant_wnaf_offset <<= stagger;
    if stagger > 0 {
        negative_constant_wnaf_offset += (1u64 << wnaf_size) - 1;
    }
    let reconstructed_negative_part = FrK1::constant(None, &negative_constant_wnaf_offset)
        .add_to_lower_limb(&negative_skew.to_field(), &BigUint::from(1u64));

    reconstructed_positive_part.sub(&reconstructed_negative_part)
}

/// One 129-bit half's wNAF representation (bb `secp256k1_wnaf`).
pub struct Secp256k1Wnaf {
    pub wnaf: Vec<FieldT>,
    pub positive_skew: BoolT,
    pub negative_skew: BoolT,
    pub least_significant_wnaf_fragment: FieldT,
}

/// bb `compute_secp256k1_single_wnaf`.
#[allow(clippy::too_many_arguments)]
fn compute_secp256k1_single_wnaf(
    ctx: &Ctx,
    scalar: &BigUint,
    wnaf_size: usize,
    stagger: usize,
    is_negative: bool,
    range_constrain_wnaf: bool,
) -> (FrK1, Secp256k1Wnaf) {
    const NUM_BITS: usize = 129;
    let stagger_mask = (1u64 << stagger) - 1;
    let stagger_scalar = if stagger == 0 {
        0
    } else {
        scalar.iter_u64_digits().next().unwrap_or(0) & stagger_mask
    };
    let shifted = scalar >> stagger;
    let (wnaf_values, skew_without_stagger) = fixed_wnaf(&shifted, NUM_BITS - stagger, wnaf_size);

    let num_rounds_excluding_stagger_bits = (NUM_BITS + wnaf_size - 1 - stagger) / wnaf_size;
    let (first_fragment, skew) =
        staggered_wnaf_fragment(stagger_scalar, stagger, is_negative, skew_without_stagger, wnaf_size);

    let wnaf = wnaf_witnesses(
        ctx,
        &wnaf_values,
        is_negative,
        num_rounds_excluding_stagger_bits,
        wnaf_size,
        range_constrain_wnaf,
    );

    let negative_skew = BoolT::from_witness_ranged(ctx, if is_negative { false } else { skew });
    let positive_skew = BoolT::from_witness_ranged(ctx, if is_negative { skew } else { false });
    let both_skews_cannot_be_one = positive_skew.and(&negative_skew).not();
    both_skews_cannot_be_one.assert_equal(&BoolT::constant(true));

    let stagger_fragment = FieldT::from_witness(ctx, Fr::from(first_fragment));
    if stagger == 0 {
        stagger_fragment.assert_equal(&FieldT::constant(Fr::from(0u64)));
    }
    if range_constrain_wnaf {
        stagger_fragment.create_range_constraint(wnaf_size as u64);
    }

    let reconstructed = reconstruct_bigfield_from_wnaf(
        ctx,
        &wnaf,
        &positive_skew,
        &negative_skew,
        &stagger_fragment,
        stagger,
        num_rounds_excluding_stagger_bits,
        wnaf_size,
    );

    (
        reconstructed,
        Secp256k1Wnaf {
            wnaf,
            positive_skew,
            negative_skew,
            least_significant_wnaf_fragment: stagger_fragment,
        },
    )
}

/// bb `compute_secp256k1_endo_wnaf<wnaf_size, lo_stagger, hi_stagger>`.
fn compute_secp256k1_endo_wnaf(
    scalar: &FrK1,
    wnaf_size: usize,
    lo_stagger: usize,
    hi_stagger: usize,
    range_constrain_wnaf: bool,
) -> (Secp256k1Wnaf, Secp256k1Wnaf) {
    let ctx = scalar.ctx().expect("endo wnaf needs a builder");
    let n = scalar_modulus();
    let k = scalar.get_value() % &n;
    let ((klo, klo_negative), (khi, khi_negative)) = split_into_endomorphism_scalars(&k);
    assert!(klo.bits() < 130 && khi.bits() < 130, "endo split exceeds 129 bits");

    let (klo_reconstructed, klo_out) =
        compute_secp256k1_single_wnaf(&ctx, &klo, wnaf_size, lo_stagger, klo_negative, range_constrain_wnaf);
    let (khi_reconstructed, khi_out) =
        compute_secp256k1_single_wnaf(&ctx, &khi, wnaf_size, hi_stagger, khi_negative, range_constrain_wnaf);

    let lambda = BigUint::parse_bytes(LAMBDA_HEX.as_bytes(), 16).unwrap();
    let minus_lambda = FrK1::constant(None, &(&n - &lambda));
    let reconstructed_scalar = khi_reconstructed.madd(&minus_lambda, &[klo_reconstructed]);

    if scalar.is_constant() {
        reconstructed_scalar.self_reduce();
    }
    scalar.assert_equal(&reconstructed_scalar);

    (klo_out, khi_out)
}

/// bb `eight_bit_fixed_base_table` (SECP256K1): the wNAF multiples of `G` (or `λ·G`) as plookup
/// reads of the precomputed generator tables.
struct EightBitFixedBaseTable {
    use_endomorphism: bool,
}

impl EightBitFixedBaseTable {
    fn read(&self, index: &FieldT) -> P1 {
        let (xlo_id, xhi_id, xyprime_id) = if self.use_endomorphism {
            (
                GeneratorTable::XloEndo,
                GeneratorTable::XhiEndo,
                GeneratorTable::XyPrimeEndo,
            )
        } else {
            (GeneratorTable::Xlo, GeneratorTable::Xhi, GeneratorTable::XyPrime)
        };
        let xlo = read_pair_from_table(multitable_id(xlo_id), index);
        let xhi = read_pair_from_table(multitable_id(xhi_id), index);
        let ylo = read_pair_from_table(multitable_id(GeneratorTable::Ylo), index);
        let yhi = read_pair_from_table(multitable_id(GeneratorTable::Yhi), index);
        let xyprime = read_pair_from_table(multitable_id(xyprime_id), index);
        let x = FqK1::unsafe_construct_from_limbs_with_prime(&xlo.0, &xlo.1, &xhi.0, &xhi.1, &xyprime.0, false);
        let mut y = FqK1::unsafe_construct_from_limbs_with_prime(&ylo.0, &ylo.1, &yhi.0, &yhi.1, &xyprime.1, false);
        if self.use_endomorphism {
            y = y.neg();
        }
        P1::with_infinity(x, y, &BoolT::constant(false), false)
    }

    fn read_constant(&self, index: usize) -> P1 {
        self.read(&FieldT::constant(Fr::from(index as u64)))
    }
}

/// bb `four_bit_table_plookup`: ROM tables of the 16 odd wNAF multiples `{-15·P, …, 15·P}`.
struct FourBitTable {
    tables: [super::memory::TwinRomTable; 5],
    limb_max: [BigUint; 8],
}

impl FourBitTable {
    fn read(&mut self, index: &FieldT) -> P1 {
        P1::read_group_element_rom_tables(&mut self.tables, index, &self.limb_max)
    }
}

/// bb `create_endo_pair_four_bit_table_plookup`.
fn create_endo_pair_four_bit_table(input: &P1) -> (FourBitTable, FourBitTable) {
    let d2 = input.dbl();
    let mut table: Vec<P1> = Vec::with_capacity(16);
    table.resize(16, input.clone());
    for i in 9..16 {
        table[i] = table[i - 1].add(&d2);
    }
    for i in 0..8 {
        table[i] = table[15 - i].neg();
    }
    let beta = FqK1::constant(None, &BigUint::parse_bytes(BETA_HEX.as_bytes(), 16).unwrap());
    let mut endo_table: Vec<P1> = Vec::with_capacity(16);
    for i in 0..16 {
        // endo x is filled below; start from the mirrored-y point.
        endo_table.push(P1::with_infinity(
            table[i].x().clone(),
            table[15 - i].y().clone(),
            &BoolT::constant(false),
            false,
        ));
    }
    let mut endo_xs: Vec<FqK1> = Vec::with_capacity(8);
    for i in 0..8 {
        endo_xs.push(table[i].x().mul(&beta));
    }
    for i in 0..8 {
        let x = endo_xs[i].clone();
        endo_table[i] = P1::with_infinity(x.clone(), endo_table[i].y().clone(), &BoolT::constant(false), false);
        endo_table[15 - i] = P1::with_infinity(x, endo_table[15 - i].y().clone(), &BoolT::constant(false), false);
    }
    let build = |elements: &[P1]| {
        let mut limb_max: [BigUint; 8] = Default::default();
        let tables = P1::create_group_element_rom_tables(elements, &mut limb_max);
        FourBitTable { tables, limb_max }
    };
    (build(&table), build(&endo_table))
}

/// bb `element::secp256k1_ecdsa_mul`: `u1·G + u2·Q` via staggered endo wNAFs, the 8-bit fixed-base
/// generator tables and 4-bit variable-base ROM tables, folded with the montgomery ladder.
pub fn secp256k1_ecdsa_mul(pubkey: &P1, u1: &FrK1, u2: &FrK1) -> P1 {
    let ctx = pubkey.ctx().expect("secp256k1_ecdsa_mul needs a builder");
    let (u1_lo_wnaf, u1_hi_wnaf) = compute_secp256k1_endo_wnaf(u1, 8, 2, 3, false);
    let (u2_lo_wnaf, u2_hi_wnaf) = compute_secp256k1_endo_wnaf(u2, 4, 0, 1, false);

    let p1 = P1::one(&ctx);
    let p1_table = EightBitFixedBaseTable {
        use_endomorphism: false,
    };
    let endo_p1_table = EightBitFixedBaseTable { use_endomorphism: true };
    let (mut p2_table, mut endo_p2_table) = create_endo_pair_four_bit_table(pubkey);

    let mut accumulator = p2_table.read(&u2_lo_wnaf.wnaf[0]);

    for i in 0..16 {
        accumulator = accumulator.dbl();
        accumulator = accumulator.dbl();

        let add_1 = endo_p2_table.read(&u2_hi_wnaf.wnaf[2 * i]);
        let add_2 = p2_table.read(&u2_lo_wnaf.wnaf[2 * i + 1]);
        let add_3 = endo_p1_table.read(&u1_hi_wnaf.wnaf[i]);
        let add_4 = p1_table.read(&u1_lo_wnaf.wnaf[i]);
        let add_5 = endo_p2_table.read(&u2_hi_wnaf.wnaf[2 * i + 1]);
        let add_6 = p2_table.read(&u2_lo_wnaf.wnaf[2 * i + 2]);

        accumulator = accumulator.multiple_montgomery_ladder(&[
            ChainAddAccumulator::from_element(&add_1),
            ChainAddAccumulator::from_element(&add_2),
            ChainAddAccumulator::from_element(&add_3),
        ]);
        accumulator = accumulator.multiple_montgomery_ladder(&[
            ChainAddAccumulator::from_element(&add_4),
            ChainAddAccumulator::from_element(&add_5),
            ChainAddAccumulator::from_element(&add_6),
        ]);
    }

    let add_1 = endo_p1_table.read(&u1_hi_wnaf.least_significant_wnaf_fragment);
    let add_2 = endo_p2_table.read(&u2_hi_wnaf.least_significant_wnaf_fragment);
    let add_3 = p1_table.read(&u1_lo_wnaf.least_significant_wnaf_fragment);
    accumulator = accumulator.add(&add_1);
    accumulator = accumulator.add(&add_2);
    accumulator = accumulator.add(&add_3);

    let conditional_add = |accumulator: &P1, base_point: &P1, positive_skew: &BoolT, negative_skew: &BoolT| {
        let to_add = base_point.conditional_negate(negative_skew);
        let result = accumulator.add(&to_add);
        let skew_combined = positive_skew.xor(negative_skew);
        accumulator.conditional_select(&result, &skew_combined)
    };

    accumulator = conditional_add(&accumulator, &p1, &u1_lo_wnaf.positive_skew, &u1_lo_wnaf.negative_skew);
    accumulator = conditional_add(
        &accumulator,
        &endo_p1_table.read_constant(128),
        &u1_hi_wnaf.positive_skew,
        &u1_hi_wnaf.negative_skew,
    );
    accumulator = conditional_add(
        &accumulator,
        pubkey,
        &u2_lo_wnaf.positive_skew,
        &u2_lo_wnaf.negative_skew,
    );
    accumulator = conditional_add(
        &accumulator,
        &endo_p2_table.read(&FieldT::constant(Fr::from(8u64))),
        &u2_hi_wnaf.positive_skew,
        &u2_hi_wnaf.negative_skew,
    );

    accumulator
}
