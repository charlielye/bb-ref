//! M0 exit: bb's `vk` file round-trips byte-for-byte and hashes to bb's `vk_hash`.
use crate::common;
use bb_ref::base::field::{from_bytes_be, Fr};
use bb_ref::base::{Bn254, Vk};

#[test]
fn ultra_vk_roundtrip_and_hash() {
    for prog in ["a_1_mul", "array_dynamic"] {
        for mode in ["nozk", "zk"] {
            let bytes = common::read(&format!("ultra/{prog}/{mode}/vk"));
            assert_eq!(bytes.len(), 3680);
            let vk = Vk::<Bn254>::from_bytes(&bytes, 28);
            assert_eq!(
                vk.to_bytes(),
                bytes,
                "{prog}/{mode}: VK does not re-serialize identically"
            );
            let expected_hash: Fr = from_bytes_be(&common::read(&format!("ultra/{prog}/{mode}/vk_hash")));
            assert_eq!(vk.hash(), expected_hash, "{prog}/{mode}: VK hash mismatch");
        }
    }
}
