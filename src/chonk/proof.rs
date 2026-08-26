//! bb `ChonkProof`: the five sub-proofs of a Chonk proof, as a field vector or as msgpack.

use crate::base::field::{from_bytes_be, to_bytes_be};
use crate::base::Fr;
use crate::goblin::merge::MERGE_PROOF_SIZE;
use serde::de::{Deserializer, Visitor};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};

/// bb `ECCVMFlavor::PROOF_LENGTH` and `TRIPLE_IPA_PROOF_LENGTH`.
pub const ECCVM_PROOF_LENGTH: usize = 556;
pub const TRIPLE_IPA_PROOF_LENGTH: usize = 70;
/// bb `TranslatorFlavor::COMMITTED_SUMCHECK_PROOF_LENGTH + MegaZKFlavor::NUM_ALL_ENTITIES`.
pub const JOINT_PROOF_LENGTH: usize = 478;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChonkProof {
    /// Hiding kernel Oink (public inputs and witness commitments).
    pub hiding_oink_proof: Vec<Fr>,
    pub merge_proof: Vec<Fr>,
    pub eccvm_proof: Vec<Fr>,
    pub ipa_proof: Vec<Fr>,
    /// Translator Oink, joint sumcheck and joint PCS.
    pub joint_proof: Vec<Fr>,
}

impl ChonkProof {
    pub fn to_fields(&self) -> Vec<Fr> {
        [&self.hiding_oink_proof, &self.merge_proof, &self.eccvm_proof, &self.ipa_proof, &self.joint_proof]
            .into_iter()
            .flatten()
            .copied()
            .collect()
    }

    /// The Oink proof takes whatever is not accounted for by the fixed-size sub-proofs.
    pub fn from_fields(fields: &[Fr]) -> Self {
        let fixed = MERGE_PROOF_SIZE + ECCVM_PROOF_LENGTH + TRIPLE_IPA_PROOF_LENGTH + JOINT_PROOF_LENGTH;
        assert!(fields.len() >= fixed, "Chonk proof too short: {} < {fixed}", fields.len());
        let mut rest = fields;
        let mut take = |n: usize| {
            let (head, tail) = rest.split_at(n);
            rest = tail;
            head.to_vec()
        };
        let hiding_oink_proof = take(fields.len() - fixed);
        let merge_proof = take(MERGE_PROOF_SIZE);
        let eccvm_proof = take(ECCVM_PROOF_LENGTH);
        let ipa_proof = take(TRIPLE_IPA_PROOF_LENGTH);
        let joint_proof = take(JOINT_PROOF_LENGTH);
        Self {
            hiding_oink_proof,
            merge_proof,
            eccvm_proof,
            ipa_proof,
            joint_proof,
        }
    }

    /// bb `to_msgpack_buffer`: a map of the five field names to arrays of 32-byte big-endian fields.
    pub fn to_msgpack(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let mut s = rmp_serde::Serializer::new(&mut out).with_struct_map();
        Wire::from(self).serialize(&mut s).unwrap();
        out
    }

    pub fn from_msgpack(bytes: &[u8]) -> Self {
        let w: Wire = rmp_serde::from_slice(bytes).expect("Chonk proof msgpack");
        let f = |v: Vec<Bin32>| v.into_iter().map(|b| from_bytes_be(&b.0)).collect();
        Self {
            hiding_oink_proof: f(w.hiding_oink_proof),
            merge_proof: f(w.merge_proof),
            eccvm_proof: f(w.eccvm_proof),
            ipa_proof: f(w.ipa_proof),
            joint_proof: f(w.joint_proof),
        }
    }
}

/// A field element as a msgpack `bin` of 32 big-endian bytes (bb `field::msgpack_pack`).
struct Bin32([u8; 32]);

impl Serialize for Bin32 {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for Bin32 {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Bin32;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("32 bytes")
            }
            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Bin32, E> {
                v.try_into().map(Bin32).map_err(|_| E::custom("expected 32 bytes"))
            }
        }
        d.deserialize_bytes(V)
    }
}

#[derive(Serialize, Deserialize)]
struct Wire {
    hiding_oink_proof: Vec<Bin32>,
    merge_proof: Vec<Bin32>,
    eccvm_proof: Vec<Bin32>,
    ipa_proof: Vec<Bin32>,
    joint_proof: Vec<Bin32>,
}

impl From<&ChonkProof> for Wire {
    fn from(p: &ChonkProof) -> Self {
        let f = |v: &[Fr]| v.iter().map(|x| Bin32(to_bytes_be(x))).collect();
        Wire {
            hiding_oink_proof: f(&p.hiding_oink_proof),
            merge_proof: f(&p.merge_proof),
            eccvm_proof: f(&p.eccvm_proof),
            ipa_proof: f(&p.ipa_proof),
            joint_proof: f(&p.joint_proof),
        }
    }
}
