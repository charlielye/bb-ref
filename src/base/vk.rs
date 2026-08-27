//! Verification key: precomputed-polynomial commitments plus three metadata fields
//! (bb `NativeVerificationKey_` / `StdlibVerificationKey_`).

use super::codec::Transcriptable;
use super::field::{from_bytes_be, to_bytes_be, Fr};
use super::group::{Bn254, Curve};
use super::poseidon2::Hasher;

#[derive(Clone, Debug, PartialEq)]
pub struct Vk<C: Curve> {
    pub log_circuit_size: C::Fr,
    pub num_public_inputs: C::Fr,
    pub pub_inputs_offset: C::Fr,
    pub comms: Vec<C::G>,
}

impl<C: Curve> Vk<C> {
    pub fn num_fields(num_comms: usize) -> usize {
        3 * C::Fr::num_fields() + num_comms * C::G::num_fields()
    }

    /// `[log_circuit_size, num_public_inputs, pub_inputs_offset, comm_0, ..., comm_{n-1}]`.
    pub fn to_fields(&self) -> Vec<C::TF> {
        let mut out = self.log_circuit_size.to_fields();
        out.extend(self.num_public_inputs.to_fields());
        out.extend(self.pub_inputs_offset.to_fields());
        for c in &self.comms {
            out.extend(c.to_fields());
        }
        out
    }

    pub fn from_fields(fields: &[C::TF], num_comms: usize) -> Self {
        assert_eq!(
            fields.len(),
            Self::num_fields(num_comms),
            "VK has the wrong number of fields"
        );
        let f = C::Fr::num_fields();
        let g = C::G::num_fields();
        let comms = (0..num_comms)
            .map(|i| C::G::from_fields(&fields[3 * f + i * g..3 * f + (i + 1) * g]))
            .collect();
        Self {
            log_circuit_size: C::Fr::from_fields(&fields[0..f]),
            num_public_inputs: C::Fr::from_fields(&fields[f..2 * f]),
            pub_inputs_offset: C::Fr::from_fields(&fields[2 * f..3 * f]),
            comms,
        }
    }

    /// The VK hash; the first thing bound into every proof's transcript.
    pub fn hash(&self) -> C::TF {
        C::Hash::hash(&self.to_fields())
    }
}

impl Vk<Bn254> {
    /// bb's on-disk `vk` file: every field element as 32 big-endian bytes.
    pub fn from_bytes(bytes: &[u8], num_comms: usize) -> Self {
        assert_eq!(bytes.len() % 32, 0, "VK byte length not a multiple of 32");
        let fields: Vec<Fr> = bytes.chunks(32).map(from_bytes_be::<Fr>).collect();
        Self::from_fields(&fields, num_comms)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.to_fields().iter().flat_map(to_bytes_be).collect()
    }

    pub fn log_n(&self) -> usize {
        super::codec::fr_to_usize(&self.log_circuit_size)
    }
    pub fn num_public_inputs_usize(&self) -> usize {
        super::codec::fr_to_usize(&self.num_public_inputs)
    }
}
