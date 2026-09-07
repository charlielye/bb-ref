//! bb's on-disk formats for proofs and public inputs: a plain concatenation of 32-byte big-endian
//! field elements (bb `to_buffer(std::vector<uint256_t>)`), with no length prefix.

use super::field::{from_bytes_be, to_bytes_be, Fr};

pub fn decode_fields(bytes: &[u8]) -> Vec<Fr> {
    assert_eq!(bytes.len() % 32, 0, "field file length is not a multiple of 32");
    bytes.chunks(32).map(from_bytes_be::<Fr>).collect()
}

pub fn encode_fields(fields: &[Fr]) -> Vec<u8> {
    fields.iter().flat_map(to_bytes_be).collect()
}
