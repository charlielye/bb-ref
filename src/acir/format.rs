//! Serde shapes of the ACIR `Program` and `WitnessStack` as Noir serializes them (msgpack, format
//! marker 2 or 3: structs as maps or positional arrays, enums as `{Variant: payload}` or a bare
//! variant name). Only the opcodes bb-ref lowers are modelled; everything else is skipped.

use crate::base::field::from_bytes_be;
use crate::base::Fr;
use base64::Engine;
use serde::de::IgnoredAny;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::io::Read;

#[derive(Deserialize, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Witness(pub u32);

#[derive(Deserialize, Debug, Clone)]
pub struct Expression {
    pub mul_terms: Vec<(Vec<u8>, Witness, Witness)>,
    pub linear_combinations: Vec<(Vec<u8>, Witness)>,
    pub q_c: Vec<u8>,
}

#[derive(Deserialize, Debug, Clone)]
pub enum FunctionInput {
    Constant(Vec<u8>),
    Witness(Witness),
}

#[derive(Deserialize, Debug, Clone)]
pub enum BlackBoxFuncCall {
    AES128Encrypt(IgnoredAny),
    AND(IgnoredAny),
    XOR(IgnoredAny),
    RANGE { input: FunctionInput, num_bits: u32 },
    Blake2s(IgnoredAny),
    Blake3(IgnoredAny),
    EcdsaSecp256k1(IgnoredAny),
    EcdsaSecp256r1(IgnoredAny),
    MultiScalarMul(IgnoredAny),
    EmbeddedCurveAdd(IgnoredAny),
    Keccakf1600(IgnoredAny),
    RecursiveAggregation(IgnoredAny),
    Poseidon2Permutation { inputs: Vec<FunctionInput>, outputs: Vec<Witness> },
    Sha256Compression(IgnoredAny),
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
    MemoryOp { block_id: u32, op: MemOp },
    MemoryInit { block_id: u32, init: Vec<Witness>, block_type: BlockType },
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
    witness: BTreeMap<u32, Vec<u8>>,
}

#[derive(Deserialize, Debug)]
struct WitnessStack {
    stack: Vec<StackItem>,
}

pub fn field(bytes: &[u8]) -> Fr {
    assert_eq!(bytes.len(), 32, "field element must be 32 bytes");
    from_bytes_be(bytes)
}

fn gunzip(data: &[u8]) -> Vec<u8> {
    let mut out = vec![];
    flate2::read::GzDecoder::new(data).read_to_end(&mut out).expect("gzip decode");
    out
}

/// Strip the 1-byte format marker and msgpack-decode the payload.
fn decode_msgpack<T: for<'a> Deserialize<'a>>(buf: &[u8]) -> T {
    assert!(matches!(buf.first(), Some(2 | 3)), "expected msgpack ACIR format marker 2 or 3");
    rmp_serde::from_slice(&buf[1..]).expect("msgpack decode")
}

/// The single circuit of a Noir `program.json` artifact (`bytecode` = base64(gzip(marker ++ msgpack))).
pub fn decode_program(program_json: &[u8]) -> Circuit {
    let json: serde_json::Value = serde_json::from_slice(program_json).expect("program.json");
    let b64 = json["bytecode"].as_str().expect("bytecode field");
    let raw = gunzip(&base64::engine::general_purpose::STANDARD.decode(b64).expect("base64"));
    let mut program: Program = decode_msgpack(&raw);
    assert_eq!(program.functions.len(), 1, "expected a single ACIR function");
    program.functions.remove(0)
}

/// The witness vector of a `witness.gz` artifact; indices absent from the map are zero.
pub fn decode_witness(witness_gz: &[u8]) -> Vec<Fr> {
    let raw = gunzip(witness_gz);
    let mut stack: WitnessStack = decode_msgpack(&raw);
    assert_eq!(stack.stack.len(), 1, "expected a single witness map");
    let map = std::mem::take(&mut stack.stack[0].witness);
    let len = map.keys().next_back().map_or(0, |k| *k as usize + 1);
    let mut v = vec![Fr::from(0u64); len];
    for (k, bytes) in map {
        v[k as usize] = field(&bytes);
    }
    v
}
