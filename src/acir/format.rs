//! Serde shapes of the ACIR `Program` and `WitnessStack` as Noir serializes them (msgpack, format
//! marker 2 or 3: structs as maps or positional arrays, enums as `{Variant: payload}` or a bare
//! variant name).

use crate::base::rng::Rng;
use crate::base::Fr;
use base64::Engine;
use serde::de::{Deserializer, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::Deserialize;
use std::io::Read;

#[derive(Deserialize, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Witness(pub u32);

/// A field constant, decoded from its 32 big-endian bytes (msgpack `bin`) straight to `Fr`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Const(pub Fr);

impl<'de> Deserialize<'de> for Const {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Const;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a 32-byte field element")
            }
            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Const, E> {
                Ok(Const(field(v)))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Const, A::Error> {
                let mut v = Vec::with_capacity(32);
                while let Some(b) = seq.next_element::<u8>()? {
                    v.push(b);
                }
                Ok(Const(field(&v)))
            }
        }
        d.deserialize_bytes(V)
    }
}

#[derive(Deserialize, Debug, Clone)]
pub struct Expression {
    pub mul_terms: Vec<(Const, Witness, Witness)>,
    pub linear_combinations: Vec<(Const, Witness)>,
    pub q_c: Const,
}

#[derive(Deserialize, Debug, Clone)]
pub enum FunctionInput {
    Constant(Const),
    Witness(Witness),
}

#[derive(Deserialize, Debug, Clone)]
pub struct Sha256Compression {
    pub inputs: Vec<FunctionInput>,
    pub hash_values: Vec<FunctionInput>,
    pub outputs: Vec<Witness>,
}

#[derive(Deserialize, Debug, Clone)]
pub enum BlackBoxFuncCall {
    AES128Encrypt(Aes128Encrypt),
    AND(Logic),
    XOR(Logic),
    RANGE {
        input: FunctionInput,
        num_bits: u32,
    },
    Blake2s(BlakeHash),
    Blake3(BlakeHash),
    EcdsaSecp256k1(EcdsaSecp256r1),
    EcdsaSecp256r1(EcdsaSecp256r1),
    MultiScalarMul(MultiScalarMul),
    EmbeddedCurveAdd(EmbeddedCurveAdd),
    Keccakf1600(Keccakf1600),
    RecursiveAggregation(RecursiveAggregation),
    Poseidon2Permutation {
        inputs: Vec<FunctionInput>,
        outputs: Vec<Witness>,
    },
    Sha256Compression(Sha256Compression),
}

/// Bitwise XOR/AND of two `num_bits`-bit inputs.
#[derive(Deserialize, Debug, Clone)]
pub struct Logic {
    pub lhs: FunctionInput,
    pub rhs: FunctionInput,
    pub num_bits: u32,
    pub output: Witness,
}

/// Keccak-f[1600] over 25 64-bit lanes.
#[derive(Deserialize, Debug, Clone)]
pub struct Keccakf1600 {
    pub inputs: Vec<FunctionInput>,
    pub outputs: Vec<Witness>,
}

/// secp256r1 ECDSA verification over byte-wise inputs (32 bytes per coordinate, 64 per signature).
#[derive(Deserialize, Debug, Clone)]
pub struct Aes128Encrypt {
    pub inputs: Vec<FunctionInput>,
    pub iv: Vec<FunctionInput>,
    pub key: Vec<FunctionInput>,
    pub outputs: Vec<Witness>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct BlakeHash {
    pub inputs: Vec<FunctionInput>,
    pub outputs: Vec<Witness>,
}

/// Shared by the EcdsaSecp256r1 and EcdsaSecp256k1 opcodes (identical payloads).
#[derive(Deserialize, Debug, Clone)]
pub struct EcdsaSecp256r1 {
    pub public_key_x: Vec<FunctionInput>,
    pub public_key_y: Vec<FunctionInput>,
    pub signature: Vec<FunctionInput>,
    pub hashed_message: Vec<FunctionInput>,
    pub predicate: FunctionInput,
    pub output: Witness,
}

/// Grumpkin MSM: `points` and `scalars` are flat `(x, y)` / `(lo, hi)` pairs.
#[derive(Deserialize, Debug, Clone)]
pub struct MultiScalarMul {
    pub points: Vec<FunctionInput>,
    pub scalars: Vec<FunctionInput>,
    pub predicate: FunctionInput,
    pub outputs: [Witness; 2],
}

#[derive(Deserialize, Debug, Clone)]
pub struct EmbeddedCurveAdd {
    pub input1: [FunctionInput; 2],
    pub input2: [FunctionInput; 2],
    pub predicate: FunctionInput,
    pub outputs: [Witness; 2],
}

/// `std::verify_proof_with_type`: a proof of `proof_type` under the key held in `verification_key`.
#[derive(Deserialize, Debug, Clone)]
pub struct RecursiveAggregation {
    pub verification_key: Vec<FunctionInput>,
    pub proof: Vec<FunctionInput>,
    pub public_inputs: Vec<FunctionInput>,
    pub key_hash: FunctionInput,
    pub proof_type: u32,
    pub predicate: FunctionInput,
}

#[derive(Deserialize, Debug, Clone)]
pub enum BlockType {
    Memory,
    CallData(u32),
    ReturnData,
}

#[derive(Deserialize, Debug, Clone)]
pub struct MemOp {
    /// Despite the name, `true` means a write (Noir's `MemOpKind` serialized as a bool).
    pub read: bool,
    pub index: Witness,
    pub value: Witness,
}

#[derive(Deserialize, Debug, Clone)]
pub enum Opcode {
    AssertZero(Expression),
    BlackBoxFuncCall(BlackBoxFuncCall),
    MemoryOp {
        block_id: u32,
        op: MemOp,
    },
    MemoryInit {
        block_id: u32,
        init: Vec<Witness>,
        block_type: BlockType,
    },
    BrilligCall(IgnoredAny),
    Call(IgnoredAny),
}

#[derive(Deserialize, Debug, Clone)]
pub struct Circuit {
    pub function_name: String,
    pub opcodes: Vec<Opcode>,
    pub private_parameters: Vec<Witness>,
    pub public_parameters: Vec<Witness>,
    pub return_values: Vec<Witness>,
    pub assert_messages: IgnoredAny,
}

#[derive(Deserialize, Debug)]
struct Program {
    functions: Vec<Circuit>,
    #[allow(dead_code)]
    unconstrained_functions: IgnoredAny,
}

#[derive(Deserialize, Debug)]
struct StackItem {
    #[allow(dead_code)]
    index: u32,
    witness: WitnessMap,
}

/// The witness map as `(index, value)` pairs, each value converted straight from the borrowed
/// `bin` bytes (serde's `Vec<u8>` reads a `bin` byte by byte, and a `BTreeMap` node per entry).
#[derive(Debug, Default)]
struct WitnessMap(Vec<(u32, Fr)>);

impl<'de> Deserialize<'de> for WitnessMap {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = WitnessMap;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("witness map")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut m: A) -> Result<WitnessMap, A::Error> {
                let mut v = Vec::with_capacity(m.size_hint().unwrap_or(0));
                while let Some((k, c)) = m.next_entry::<u32, Const>()? {
                    v.push((k, c.0));
                }
                // bb writes a `std::map`, so the keys already ascend; the sort only guards that.
                if !v.is_sorted_by_key(|e| e.0) {
                    v.sort_by_key(|e| e.0);
                }
                Ok(WitnessMap(v))
            }
        }
        d.deserialize_map(V)
    }
}

#[derive(Deserialize, Debug)]
struct WitnessStack {
    stack: Vec<StackItem>,
}

pub fn field(bytes: &[u8]) -> Fr {
    assert_eq!(bytes.len(), 32, "field element must be 32 bytes");
    crate::base::field::from_bytes_be_canonical(bytes)
}

pub fn gunzip(data: &[u8]) -> Vec<u8> {
    let mut out = vec![];
    flate2::read::GzDecoder::new(data)
        .read_to_end(&mut out)
        .expect("gzip decode");
    out
}

/// Strip the 1-byte format marker and msgpack-decode the payload.
fn decode_msgpack<T: for<'a> Deserialize<'a>>(buf: &[u8]) -> T {
    assert!(
        matches!(buf.first(), Some(2 | 3)),
        "expected msgpack ACIR format marker 2 or 3"
    );
    rmp_serde::from_slice(&buf[1..]).expect("msgpack decode")
}

/// The single circuit of a Noir `program.json` artifact (`bytecode` = base64(gzip(marker ++ msgpack))).
pub fn decode_program(program_json: &[u8]) -> Circuit {
    let json: serde_json::Value = serde_json::from_slice(program_json).expect("program.json");
    let b64 = json["bytecode"].as_str().expect("bytecode field");
    decode_program_gz(&base64::engine::general_purpose::STANDARD.decode(b64).expect("base64"))
}

/// The single circuit of gzipped ACIR bytecode.
pub fn decode_program_gz(bytecode_gz: &[u8]) -> Circuit {
    decode_program_raw(&gunzip(bytecode_gz))
}

/// The single circuit of a decompressed (marker ++ msgpack) ACIR buffer — the form bytecode takes
/// on the bbapi wire.
pub fn decode_program_raw(bytecode: &[u8]) -> Circuit {
    let mut program: Program = decode_msgpack(bytecode);
    assert_eq!(program.functions.len(), 1, "expected a single ACIR function");
    program.functions.remove(0)
}

/// The witness vector of a `witness.gz` artifact. Indices absent from the (sparse) map are
/// unconstrained; like bb, they get random values so an accidental use shows up (and the prover's
/// randomness is consumed the same way).
pub fn decode_witness(witness_gz: &[u8], rng: &mut dyn Rng) -> Vec<Fr> {
    decode_witness_raw(&gunzip(witness_gz), rng)
}

/// A decompressed witness-stack buffer — the form witnesses take on the bbapi wire.
pub fn decode_witness_raw(raw: &[u8], rng: &mut dyn Rng) -> Vec<Fr> {
    decode_witness_with(raw, |_| rng.fr())
}

/// `decode_witness` with the gaps left zero, and their indices in draw order: the random fill is
/// made later, at the point of the draw sequence where `decode_witness` would have made it.
pub fn decode_witness_gaps(witness_gz: &[u8]) -> (Vec<Fr>, Vec<u32>) {
    let mut gaps = vec![];
    let v = decode_witness_with(&gunzip(witness_gz), |k| {
        gaps.push(k as u32);
        Fr::from(0u64)
    });
    (v, gaps)
}

fn decode_witness_with(raw: &[u8], mut gap: impl FnMut(usize) -> Fr) -> Vec<Fr> {
    let mut stack: WitnessStack = decode_msgpack(raw);
    assert_eq!(stack.stack.len(), 1, "expected a single witness map");
    let map = std::mem::take(&mut stack.stack[0].witness).0;
    let mut v = Vec::with_capacity(map.last().map_or(0, |(k, _)| *k as usize + 1));
    for (k, x) in map {
        while v.len() < k as usize {
            v.push(gap(v.len()));
        }
        v.push(x);
    }
    v
}
