//! bb's on-disk formats for proofs and public inputs: a plain concatenation of 32-byte big-endian
//! field elements (bb `to_buffer(std::vector<uint256_t>)`), with no length prefix.

use super::field::{from_bytes_be, to_bytes_be, Fr};
use std::path::Path;

pub fn decode_fields(bytes: &[u8]) -> Vec<Fr> {
    assert_eq!(bytes.len() % 32, 0, "field file length is not a multiple of 32");
    bytes.chunks(32).map(from_bytes_be::<Fr>).collect()
}

pub fn encode_fields(fields: &[Fr]) -> Vec<u8> {
    fields.iter().flat_map(to_bytes_be).collect()
}

pub fn read_fields(path: impl AsRef<Path>) -> Vec<Fr> {
    let path = path.as_ref();
    decode_fields(&std::fs::read(path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display())))
}

pub fn write_fields(path: impl AsRef<Path>, fields: &[Fr]) {
    std::fs::write(path, encode_fields(fields)).expect("write failed");
}
