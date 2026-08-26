//! Fiat-Shamir transcript (bb `BaseTranscript<Codec, Hash>`): a running duplex where
//! `c_{i+1} = H(c_i || round_data)`. Generic over the transcript field so the same code drives
//! native and in-circuit verifiers.

use super::codec::{ChallengeField, FromChallenge, Transcriptable};
use super::field::FieldLike;
use super::poseidon2::Hasher;
use std::marker::PhantomData;

#[derive(Debug, Clone, PartialEq)]
pub enum ManifestKind {
    Entry,
    HashBuffer,
    Challenge,
}

#[derive(Debug, Clone)]
pub struct ManifestEntry {
    pub round: usize,
    pub kind: ManifestKind,
    pub label: String,
    pub num_fields: usize,
}

/// Debug-only record of the transcript schedule, for diffing against bb's `TranscriptManifest`.
#[derive(Debug, Default, Clone)]
pub struct Manifest {
    pub entries: Vec<ManifestEntry>,
}

pub struct Transcript<TF: FieldLike, H: Hasher<TF>> {
    proof_data: Vec<TF>,
    proof_start: usize,
    num_written: usize,
    num_read: usize,
    round_data: Vec<TF>,
    prev_challenge: Option<TF>,
    round_index: usize,
    in_challenge_phase: bool,
    pub manifest: Option<Manifest>,
    _h: PhantomData<H>,
}

impl<TF: FieldLike, H: Hasher<TF>> Default for Transcript<TF, H> {
    fn default() -> Self {
        Self::new()
    }
}

impl<TF: FieldLike, H: Hasher<TF>> Transcript<TF, H> {
    pub fn new() -> Self {
        Self {
            proof_data: Vec::new(),
            proof_start: 0,
            num_written: 0,
            num_read: 0,
            round_data: Vec::new(),
            prev_challenge: None,
            round_index: 0,
            in_challenge_phase: false,
            manifest: None,
            _h: PhantomData,
        }
    }

    /// Verifier constructor.
    pub fn from_proof(proof: &[TF]) -> Self {
        let mut t = Self::new();
        t.load_proof(proof);
        t
    }

    pub fn enable_manifest(&mut self) {
        self.manifest = Some(Manifest::default());
    }

    pub fn load_proof(&mut self, proof: &[TF]) {
        self.proof_data.extend_from_slice(proof);
    }

    /// Prover: the elements written since the last export (lets several provers share a transcript).
    pub fn export_proof(&mut self) -> Vec<TF> {
        let out = self.proof_data[self.proof_start..self.proof_start + self.num_written].to_vec();
        self.proof_start += self.num_written;
        self.num_written = 0;
        out
    }

    pub fn proof_size(&self) -> usize {
        self.proof_data.len()
    }

    fn record(&mut self, kind: ManifestKind, label: &str, num_fields: usize) {
        if let Some(m) = &mut self.manifest {
            m.entries.push(ManifestEntry { round: self.round_index, kind, label: label.to_string(), num_fields });
        }
    }

    fn begin_data_phase(&mut self) {
        if self.in_challenge_phase {
            self.in_challenge_phase = false;
            self.round_index += 1;
        }
    }

    fn next_challenge_hash(&mut self) -> TF {
        let mut buffer = Vec::with_capacity(self.round_data.len() + 1);
        match &self.prev_challenge {
            Some(c) => buffer.push(c.clone()),
            None => assert!(!self.round_data.is_empty(), "first challenge requested before any data was sent"),
        }
        buffer.append(&mut self.round_data);
        let c = H::hash(&buffer);
        self.prev_challenge = Some(c.clone());
        c
    }

    /// Prover: append `element` to the proof and to the hash buffer.
    pub fn send<T: Transcriptable<TF>>(&mut self, label: &str, element: &T) {
        self.begin_data_phase();
        let fields = element.to_fields();
        self.record(ManifestKind::Entry, label, fields.len());
        self.num_written += fields.len();
        self.round_data.extend_from_slice(&fields);
        self.proof_data.extend(fields);
    }

    /// Verifier: read the next element from the proof and add it to the hash buffer.
    pub fn receive<T: Transcriptable<TF>>(&mut self, label: &str) -> T {
        let fields = self.receive_fields(label, T::num_fields());
        T::from_fields(&fields)
    }

    /// Verifier: read `count` consecutive elements sent as one labelled object (arrays, univariates).
    pub fn receive_vec<T: Transcriptable<TF>>(&mut self, label: &str, count: usize) -> Vec<T> {
        let n = T::num_fields();
        let fields = self.receive_fields(label, count * n);
        (0..count).map(|i| T::from_fields(&fields[i * n..(i + 1) * n])).collect()
    }

    fn receive_fields(&mut self, label: &str, n: usize) -> Vec<TF> {
        assert!(self.num_read + n <= self.proof_data.len(), "transcript: proof too short at '{label}'");
        self.begin_data_phase();
        let fields = self.proof_data[self.num_read..self.num_read + n].to_vec();
        self.num_read += n;
        self.record(ManifestKind::Entry, label, n);
        self.round_data.extend_from_slice(&fields);
        fields
    }

    /// Add to the hash buffer without writing to the proof (e.g. the VK hash).
    pub fn add_to_hash_buffer<T: Transcriptable<TF>>(&mut self, label: &str, element: &T) {
        self.begin_data_phase();
        let fields = element.to_fields();
        self.record(ManifestKind::HashBuffer, label, fields.len());
        self.round_data.extend(fields);
    }

    /// One full-width challenge per label.
    pub fn challenges<C: FromChallenge<TF>>(&mut self, labels: &[&str]) -> Vec<C> {
        for l in labels {
            self.record(ManifestKind::Challenge, l, 1);
        }
        let out = labels.iter().map(|_| C::full(self.next_challenge_hash())).collect();
        self.in_challenge_phase = true;
        out
    }

    pub fn challenge<C: FromChallenge<TF>>(&mut self, label: &str) -> C {
        self.challenges(&[label]).pop().unwrap()
    }

    /// One challenge δ, then `[δ, δ², δ⁴, ...]` (n entries) by repeated squaring.
    pub fn dyadic_powers<C: FromChallenge<TF> + FieldLike>(&mut self, label: &str, n: usize) -> Vec<C> {
        assert!(n > 0);
        let mut pows = Vec::with_capacity(n);
        pows.push(self.challenge::<C>(label));
        for i in 1..n {
            let next = pows[i - 1].sqr();
            pows.push(next);
        }
        pows
    }
}

impl<TF: ChallengeField, H: Hasher<TF>> Transcript<TF, H> {
    /// Short (127-bit) challenges: each hash output is split into two limbs, yielding two challenges.
    pub fn short_challenges<C: FromChallenge<TF>>(&mut self, labels: &[&str]) -> Vec<C> {
        for l in labels {
            self.record(ManifestKind::Challenge, l, 1);
        }
        let n = labels.len();
        let mut out = Vec::with_capacity(n);
        for _ in 0..n / 2 {
            let [lo, hi] = self.next_challenge_hash().split_challenge();
            out.push(C::short(lo));
            out.push(C::short(hi));
        }
        if n % 2 == 1 {
            let [lo, _] = self.next_challenge_hash().split_challenge();
            out.push(C::short(lo));
        }
        self.in_challenge_phase = true;
        out
    }

    pub fn short_challenge<C: FromChallenge<TF>>(&mut self, label: &str) -> C {
        self.short_challenges(&[label]).pop().unwrap()
    }
}

/// The native transcript: bn254 Fr with Poseidon2.
pub type NativeTranscript = Transcript<super::field::Fr, super::poseidon2::Poseidon2>;
