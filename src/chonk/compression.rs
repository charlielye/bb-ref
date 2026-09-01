//! bb `ProofCompressor` (`chonk/proof_compression.hpp`): a Chonk proof as compact bytes.
//!
//! Every element of the proof becomes exactly 32 bytes, whatever its type: a curve point keeps only
//! its x-coordinate plus a sign bit in the top bit, and a field element that the proof carries as a
//! (lo, hi) limb pair is reassembled into one 256-bit value. Nothing is inferred from the bytes --
//! the layout below IS the format, walked identically when compressing and decompressing, which is
//! why the two directions cannot drift apart.

use crate::base::field::to_bytes_be;
use crate::base::{Fq, Fr};
use crate::chonk::proof::ChonkProof;
use crate::goblin::eccvm::{CONST_ECCVM_LOG_N, NUM_ALL_ENTITIES as ECCVM_NUM_ALL, NUM_WITNESS as ECCVM_NUM_WITNESS};
use crate::goblin::translator::{
    CONST_TRANSLATOR_LOG_N, FULL_CIRCUIT_ENTITIES, LOG_MINI_CIRCUIT_SIZE, NUM_MINICIRCUIT_EVALUATIONS,
};
use ark_ff::{AdditiveGroup, Field, PrimeField};

/// bb `NUM_SMALL_IPA_TRANSCRIPT_EVALS`.
const NUM_SMALL_IPA_TRANSCRIPT_EVALS: usize = 4;
/// bb `NUM_TRANSLATION_EVALUATIONS` (op, Px, Py, z1, z2).
const NUM_TRANSLATION_EVALUATIONS: usize = 5;
/// bb `ECCVMFlavor::NUM_MASKING_POLYNOMIALS`.
const ECCVM_NUM_MASKING: usize = 1;
/// bb `MegaZKFlavor::NUM_WITNESS_ENTITIES` / `NUM_ALL_ENTITIES`, taken from the flavor layout so a
/// flavor change cannot silently desynchronise the compression format from the proof it describes.
fn mega_zk_num_witness() -> usize {
    crate::honk::flavor::MEGA_ZK.layout().num_witness
}
fn mega_zk_num_all() -> usize {
    crate::honk::flavor::MEGA_ZK.layout().num_all()
}
/// bb `ProofLength::Oink<MegaZKFlavor>::LENGTH_WITHOUT_PUB_INPUTS`: the commitments alone.
fn mega_zk_oink_length_without_pub_inputs() -> usize {
    mega_zk_num_witness() * 4
}
/// bb `TranslatorFlavor::NUM_COMMITMENTS_IN_PROOF` = NUM_CONCATENATED_POLYS + NUM_ORDERED_RANGE
/// (`ordered_range_constraints_0..4`).
const TRANSLATOR_NUM_COMMITMENTS_IN_PROOF: usize = crate::goblin::translator::NUM_CONCATENATED_POLYS + 5;

/// One step of a proof layout: the walkers below emit these in proof order, and both directions
/// consume the same sequence.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Elem {
    Bn254Scalar,
    Bn254Commitment,
    GrumpkinScalar,
    GrumpkinCommitment,
}
use Elem::*;

/// bb `walk_mega_zk_oink_proof`: in the batched protocol the MegaZK proof carries only Oink --
/// public inputs, then witness commitments; sumcheck and PCS live in the joint proof.
fn walk_mega_zk_oink(out: &mut Vec<Elem>, num_public_inputs: usize) {
    out.extend(std::iter::repeat(Bn254Scalar).take(num_public_inputs));
    out.extend(std::iter::repeat(Bn254Commitment).take(mega_zk_num_witness()));
}

/// bb `walk_merge_proof` (42 Fr, all BN254).
fn walk_merge(out: &mut Vec<Elem>) {
    out.extend(std::iter::repeat(Bn254Commitment).take(4));
    out.push(Bn254Commitment); // reversed batched left tables
    out.extend(std::iter::repeat(Bn254Scalar).take(13));
    out.push(Bn254Commitment); // Shplonk Q
    out.push(Bn254Commitment); // KZG W
}

/// bb `walk_eccvm_proof` (all Grumpkin).
fn walk_eccvm(out: &mut Vec<Elem>) {
    out.extend(std::iter::repeat(GrumpkinCommitment).take(ECCVM_NUM_WITNESS + ECCVM_NUM_MASKING));
    out.push(GrumpkinCommitment); // Libra concatenation
    out.push(GrumpkinScalar); // Libra sum
    for _ in 0..CONST_ECCVM_LOG_N {
        out.push(GrumpkinCommitment); // round univariate commitment
        out.push(GrumpkinScalar); // eval at 0
        out.push(GrumpkinScalar); // eval at 1
    }
    out.extend(std::iter::repeat(GrumpkinScalar).take(ECCVM_NUM_ALL));
    out.push(GrumpkinScalar); // Libra claimed evaluation
    out.push(GrumpkinCommitment); // Libra grand sum
    out.push(GrumpkinCommitment); // Libra quotient
    out.extend(std::iter::repeat(GrumpkinScalar).take(NUM_SMALL_IPA_TRANSCRIPT_EVALS));

    // Translation section.
    out.push(GrumpkinCommitment); // translator concatenated masking
    out.extend(std::iter::repeat(GrumpkinScalar).take(NUM_TRANSLATION_EVALUATIONS));
    out.push(GrumpkinScalar); // translation masking term evaluation
    out.push(GrumpkinCommitment); // translation grand sum
    out.push(GrumpkinCommitment); // translation quotient
    out.extend(std::iter::repeat(GrumpkinScalar).take(NUM_SMALL_IPA_TRANSCRIPT_EVALS));
    out.push(GrumpkinCommitment); // TripleIPA pow-tensor masking
    out.push(GrumpkinScalar); // its evaluation
    out.push(GrumpkinCommitment); // Shplonk Q
}

/// bb `walk_ipa_proof` (TripleIPA, all Grumpkin).
fn walk_ipa(out: &mut Vec<Elem>) {
    out.extend(std::iter::repeat(GrumpkinScalar).take(3)); // cross sums
    for _ in 0..CONST_ECCVM_LOG_N {
        out.push(GrumpkinCommitment); // L_i
        out.push(GrumpkinCommitment); // R_i
    }
    out.push(GrumpkinCommitment); // G_0
    out.push(GrumpkinScalar); // a_0
}

/// bb `walk_joint_proof`: translator Oink, the joint 17-round sumcheck over MegaZK + translator,
/// and the joint Shplemini/KZG reduction (all BN254).
fn walk_joint(out: &mut Vec<Elem>) {
    out.push(Bn254Commitment); // Gemini masking poly
    out.extend(std::iter::repeat(Bn254Commitment).take(TRANSLATOR_NUM_COMMITMENTS_IN_PROOF));
    out.push(Bn254Commitment); // Z_PERM

    out.push(Bn254Commitment); // Libra concatenation
    out.push(Bn254Scalar); // Libra sum
    for round in 0..CONST_TRANSLATOR_LOG_N {
        // The minicircuit evaluations are sent in the middle of the rounds, not at the end.
        if round == LOG_MINI_CIRCUIT_SIZE {
            out.extend(std::iter::repeat(Bn254Scalar).take(NUM_MINICIRCUIT_EVALUATIONS));
        }
        out.push(Bn254Commitment); // round univariate commitment
        out.push(Bn254Scalar); // eval at 0
        out.push(Bn254Scalar); // eval at 1
    }
    out.extend(std::iter::repeat(Bn254Scalar).take(mega_zk_num_all()));
    out.extend(std::iter::repeat(Bn254Scalar).take(FULL_CIRCUIT_ENTITIES.len()));

    out.push(Bn254Scalar); // Libra claimed evaluation
    out.push(Bn254Commitment); // Libra grand sum
    out.push(Bn254Commitment); // Libra quotient

    out.extend(std::iter::repeat(Bn254Commitment).take(CONST_TRANSLATOR_LOG_N - 1)); // Gemini folds
    out.extend(std::iter::repeat(Bn254Scalar).take(CONST_TRANSLATOR_LOG_N)); // fold evaluations
    out.extend(std::iter::repeat(Bn254Scalar).take(NUM_SMALL_IPA_TRANSCRIPT_EVALS));
    out.push(Bn254Commitment); // Shplonk Q
    out.push(Bn254Commitment); // KZG W
}

/// bb `walk_chonk_proof`: hiding_oink (BN254) | merge (BN254) | eccvm (Grumpkin) | ipa (Grumpkin)
/// | joint (BN254).
fn walk_chonk(mega_num_public_inputs: usize) -> Vec<Elem> {
    let mut out = Vec::new();
    walk_mega_zk_oink(&mut out, mega_num_public_inputs);
    walk_merge(&mut out);
    walk_eccvm(&mut out);
    walk_ipa(&mut out);
    walk_joint(&mut out);
    out
}

/// Field elements each element occupies in the uncompressed proof.
fn field_elements(e: Elem) -> usize {
    match e {
        Bn254Scalar => 1,
        Bn254Commitment => 4,    // Fq x and y, each as a (lo, hi) Fr pair
        GrumpkinScalar => 2,     // an Fq carried as a (lo, hi) Fr pair
        GrumpkinCommitment => 2, // x and y, each one Fr
    }
}

const BYTES_PER_ELEMENT: usize = 32;
/// Fq values ride in the proof as (lo, hi) Fr pairs split at 2 * NUM_LIMB_BITS.
const FQ_SPLIT_BITS: u32 = 136;

fn sign_bit_set(bytes: &[u8; 32]) -> bool {
    bytes[0] & 0x80 != 0
}

/// bb `y_is_negative`: y sits in the upper half of its field.
fn y_is_negative<F: PrimeField>(y: &F) -> bool {
    y.into_bigint() > F::MODULUS_MINUS_ONE_DIV_TWO
}

fn reconstruct_fq(lo: Fr, hi: Fr) -> Fq {
    let lo = num_bigint::BigUint::from(lo.into_bigint());
    let hi = num_bigint::BigUint::from(hi.into_bigint());
    Fq::from(lo + (hi << FQ_SPLIT_BITS))
}

fn split_fq(v: Fq) -> (Fr, Fr) {
    let v = num_bigint::BigUint::from(v.into_bigint());
    let mask = (num_bigint::BigUint::from(1u8) << FQ_SPLIT_BITS) - num_bigint::BigUint::from(1u8);
    (Fr::from(v.clone() & mask), Fr::from(v >> FQ_SPLIT_BITS))
}

/// bb `ProofCompressor::compress_chonk_proof`.
pub fn compress_chonk_proof(proof: &ChonkProof) -> Vec<u8> {
    let flat = proof.to_fields();
    let mega_num_public_inputs = proof
        .hiding_oink_proof
        .len()
        .checked_sub(mega_zk_oink_length_without_pub_inputs())
        .expect("hiding oink proof shorter than its fixed part");
    let layout = walk_chonk(mega_num_public_inputs);
    let mut out = Vec::with_capacity(layout.len() * BYTES_PER_ELEMENT);
    let mut i = 0usize;
    for e in &layout {
        match e {
            Bn254Scalar => out.extend_from_slice(&to_bytes_be(&flat[i])),
            Bn254Commitment => {
                let is_infinity = flat[i..i + 4].iter().all(|f| *f == Fr::ZERO);
                if is_infinity {
                    out.extend_from_slice(&[0u8; 32]);
                } else {
                    let x = reconstruct_fq(flat[i], flat[i + 1]);
                    let y = reconstruct_fq(flat[i + 2], flat[i + 3]);
                    let mut b = to_bytes_be(&x);
                    if y_is_negative(&y) {
                        b[0] |= 0x80;
                    }
                    out.extend_from_slice(&b);
                }
            }
            GrumpkinCommitment => {
                let (x, y) = (flat[i], flat[i + 1]);
                if x == Fr::ZERO && y == Fr::ZERO {
                    out.extend_from_slice(&[0u8; 32]);
                } else {
                    let mut b = to_bytes_be(&x);
                    if y_is_negative(&y) {
                        b[0] |= 0x80;
                    }
                    out.extend_from_slice(&b);
                }
            }
            GrumpkinScalar => {
                let v = reconstruct_fq(flat[i], flat[i + 1]);
                out.extend_from_slice(&to_bytes_be(&v));
            }
        }
        i += field_elements(*e);
    }
    assert_eq!(i, flat.len(), "compress did not consume all proof elements");
    out
}

/// bb `ProofCompressor::decompress_chonk_proof`. Errors rather than panics: the input is untrusted
/// bytes, and bb reports the same conditions as verification failures.
pub fn decompress_chonk_proof(compressed: &[u8], mega_num_public_inputs: usize) -> Result<ChonkProof, String> {
    let layout = walk_chonk(mega_num_public_inputs);
    if compressed.len() != layout.len() * BYTES_PER_ELEMENT {
        return Err(format!(
            "proof_compression: expected {} bytes, got {}",
            layout.len() * BYTES_PER_ELEMENT,
            compressed.len()
        ));
    }
    let mut flat: Vec<Fr> = Vec::with_capacity(layout.iter().map(|e| field_elements(*e)).sum());
    for (n, e) in layout.iter().enumerate() {
        let mut word: [u8; 32] = compressed[n * 32..(n + 1) * 32].try_into().unwrap();
        let sign = sign_bit_set(&word);
        word[0] &= 0x7f;
        match e {
            Bn254Scalar => flat.push(fr_from_bytes(&word)?),
            Bn254Commitment => {
                // A point at infinity is all zeros; unambiguous because x = 0 is not on the curve.
                if word == [0u8; 32] && !sign {
                    flat.extend([Fr::from(0u8); 4]);
                    continue;
                }
                let x = fq_from_bytes(&word)?;
                let y = recover_y_bn254(x, sign)?;
                let (x_lo, x_hi) = split_fq(x);
                let (y_lo, y_hi) = split_fq(y);
                flat.extend([x_lo, x_hi, y_lo, y_hi]);
            }
            GrumpkinCommitment => {
                if word == [0u8; 32] && !sign {
                    flat.extend([Fr::from(0u8); 2]);
                    continue;
                }
                let x = fr_from_bytes(&word)?;
                let y = recover_y_grumpkin(x, sign)?;
                flat.extend([x, y]);
            }
            GrumpkinScalar => {
                let v = fq_from_bytes(&word)?;
                let (lo, hi) = split_fq(v);
                flat.extend([lo, hi]);
            }
        }
    }
    Ok(ChonkProof::from_fields(&flat))
}

fn fr_from_bytes(b: &[u8; 32]) -> Result<Fr, String> {
    let v = num_bigint::BigUint::from_bytes_be(b);
    if v >= Fr::MODULUS.into() {
        return Err("proof_compression: BN254 scalar out of range".into());
    }
    Ok(Fr::from(v))
}

fn fq_from_bytes(b: &[u8; 32]) -> Result<Fq, String> {
    let v = num_bigint::BigUint::from_bytes_be(b);
    if v >= Fq::MODULUS.into() {
        return Err("proof_compression: BN254 x-coordinate out of range".into());
    }
    Ok(Fq::from(v))
}

/// y from x on `y^2 = x^3 + b`, with the branch the sign bit selected.
fn recover_y_bn254(x: Fq, sign: bool) -> Result<Fq, String> {
    let b = <ark_bn254::g1::Config as ark_ec::short_weierstrass::SWCurveConfig>::COEFF_B;
    let y2 = x * x * x + b;
    let y = y2.sqrt().ok_or("proof_compression: BN254 point not on curve")?;
    Ok(if y_is_negative(&y) != sign { -y } else { y })
}

fn recover_y_grumpkin(x: Fr, sign: bool) -> Result<Fr, String> {
    let b = <ark_grumpkin::GrumpkinConfig as ark_ec::short_weierstrass::SWCurveConfig>::COEFF_B;
    let y2 = x * x * x + b;
    let y = y2.sqrt().ok_or("proof_compression: Grumpkin point not on curve")?;
    Ok(if y_is_negative(&y) != sign { -y } else { y })
}

/// bb `ProofCompressor::compressed_mega_num_public_inputs`: the wire command carries only bytes, so
/// the hiding kernel's public-input count is recovered from the length -- everything else in the
/// layout is fixed size.
pub fn mega_num_public_inputs_from_len(compressed_bytes: usize) -> Result<usize, String> {
    if compressed_bytes % BYTES_PER_ELEMENT != 0 {
        return Err("proof_compression: compressed size not aligned to 32 bytes".into());
    }
    let total = compressed_bytes / BYTES_PER_ELEMENT;
    let fixed = walk_chonk(0).len();
    total
        .checked_sub(fixed)
        .ok_or_else(|| "proof_compression: compressed proof too short".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chonk::proof::{ECCVM_PROOF_LENGTH, JOINT_PROOF_LENGTH, TRIPLE_IPA_PROOF_LENGTH};
    use crate::goblin::merge::MERGE_PROOF_SIZE;

    fn frs(walk: impl Fn(&mut Vec<Elem>)) -> usize {
        let mut v = Vec::new();
        walk(&mut v);
        v.iter().map(|e| field_elements(*e)).sum()
    }

    /// bb guards the layout with static_asserts against the proof-length constants; the walkers
    /// define the compression format, so a drift here silently corrupts every compressed proof.
    #[test]
    fn walk_lengths_match_proof_constants() {
        assert_eq!(
            frs(|o| walk_mega_zk_oink(o, 0)),
            mega_zk_oink_length_without_pub_inputs(),
            "oink"
        );
        assert_eq!(frs(walk_merge), MERGE_PROOF_SIZE, "merge");
        assert_eq!(frs(walk_eccvm), ECCVM_PROOF_LENGTH, "eccvm");
        assert_eq!(frs(walk_ipa), TRIPLE_IPA_PROOF_LENGTH, "ipa");
        assert_eq!(frs(walk_joint), JOINT_PROOF_LENGTH, "joint");
    }
}

#[cfg(test)]
mod roundtrip_tests {
    use super::*;
    use crate::base::codec::Transcriptable;
    use crate::base::{Fr, G1Affine, GrumpkinAffine};
    use ark_ec::AffineRepr;
    use ark_ff::UniformRand;

    /// A synthetic proof whose field layout follows the walk exactly: random scalars, real curve
    /// points (compression recovers y from x, so points must be on-curve).
    fn synthetic_proof(mega_num_public_inputs: usize) -> ChonkProof {
        let mut rng = ark_std::test_rng();
        let mut flat: Vec<Fr> = Vec::new();
        for e in walk_chonk(mega_num_public_inputs) {
            match e {
                Bn254Scalar => flat.push(Fr::rand(&mut rng)),
                Bn254Commitment => {
                    let p: G1Affine = (G1Affine::generator() * Fr::rand(&mut rng)).into();
                    flat.extend(Transcriptable::<Fr>::to_fields(&p));
                }
                GrumpkinScalar => {
                    let v = Fq::rand(&mut rng);
                    let (lo, hi) = split_fq(v);
                    flat.extend([lo, hi]);
                }
                GrumpkinCommitment => {
                    let p: GrumpkinAffine = (GrumpkinAffine::generator() * Fq::rand(&mut rng)).into();
                    flat.extend(Transcriptable::<Fr>::to_fields(&p));
                }
            }
        }
        ChonkProof::from_fields(&flat)
    }

    #[test]
    fn compress_decompress_roundtrips() {
        let proof = synthetic_proof(3);
        let compressed = compress_chonk_proof(&proof);
        assert_eq!(mega_num_public_inputs_from_len(compressed.len()), Ok(3));
        let back = decompress_chonk_proof(&compressed, 3).unwrap();
        assert_eq!(back.to_fields(), proof.to_fields());
        // and the other direction: bytes -> proof -> the same bytes
        assert_eq!(compress_chonk_proof(&back), compressed);
    }

    #[test]
    fn malformed_bytes_rejected_not_panicking() {
        let compressed = compress_chonk_proof(&synthetic_proof(1));
        // truncation mid-element
        assert!(decompress_chonk_proof(&compressed[..compressed.len() - 1], 1).is_err());
        // a scalar >= r
        let mut c = compressed.clone();
        c[..32].copy_from_slice(&[0xffu8; 32]);
        c[0] = 0x7f; // clear the sign bit so it parses as a scalar, not a point
        assert!(decompress_chonk_proof(&c, 1).is_err());
        // an x-coordinate that is not on the curve, in the first commitment slot
        let b = <ark_bn254::g1::Config as ark_ec::short_weierstrass::SWCurveConfig>::COEFF_B;
        let off_curve_x = (1u8..)
            .map(Fq::from)
            .find(|x| (*x * x * x + b).sqrt().is_none())
            .unwrap();
        let first_comm = walk_chonk(1).iter().position(|e| *e == Bn254Commitment).unwrap();
        let mut c = compressed.clone();
        let mut w = crate::base::field::to_bytes_be(&off_curve_x);
        w[0] &= 0x7f;
        c[first_comm * 32..(first_comm + 1) * 32].copy_from_slice(&w);
        assert!(decompress_chonk_proof(&c, 1).is_err());
    }
}
