//! Fiat-Shamir transcript (bb `BaseTranscript<Codec, Hash>`): a running duplex where
//! `c_{i+1} = H(c_i || round_data)`. Generic over the transcript field so the same code drives
//! native and in-circuit verifiers.

use super::codec::{ChallengeField, FromChallenge, TranscriptData, Transcriptable};
use super::field::FieldLike;
use super::poseidon2::Hasher;
use std::marker::PhantomData;

pub struct Transcript<TF: TranscriptData, H: Hasher<TF>> {
    proof_data: Vec<TF>,
    proof_start: usize,
    num_written: usize,
    num_read: usize,
    round_data: Vec<TF>,
    prev_challenge: Option<TF>,
    _h: PhantomData<H>,
}

impl<TF: TranscriptData, H: Hasher<TF>> Default for Transcript<TF, H> {
    fn default() -> Self {
        Self::new()
    }
}

impl<TF: TranscriptData, H: Hasher<TF>> Transcript<TF, H> {
    pub fn new() -> Self {
        Self {
            proof_data: Vec::new(),
            proof_start: 0,
            num_written: 0,
            num_read: 0,
            round_data: Vec::new(),
            prev_challenge: None,
            _h: PhantomData,
        }
    }

    /// Verifier constructor.
    pub fn from_proof(proof: &[TF]) -> Self {
        let mut t = Self::new();
        t.load_proof(proof);
        t
    }

    /// The next proof segment of a shared transcript; the previous one must be fully read.
    pub fn load_proof(&mut self, proof: &[TF]) {
        assert!(
            self.num_read == self.proof_data.len(),
            "Transcript: load_proof called before the previous proof segment was fully consumed"
        );
        self.proof_data.extend_from_slice(proof);
    }

    /// bb `enforce_proof_fully_consumed`: elements the verifier never read are not bound by
    /// Fiat-Shamir, so a proof with trailing data is rejected.
    pub fn enforce_proof_fully_consumed(&self, context: &str) {
        assert!(
            self.num_read == self.proof_data.len(),
            "{context}: proof contains trailing data not consumed by the transcript"
        );
    }

    /// Prover: the elements written since the last export (lets several provers share a transcript).
    pub fn export_proof(&mut self) -> Vec<TF> {
        let out = self.proof_data[self.proof_start..self.proof_start + self.num_written].to_vec();
        self.proof_start += self.num_written;
        self.num_written = 0;
        out
    }

    fn next_challenge_hash(&mut self) -> TF {
        let mut buffer = Vec::with_capacity(self.round_data.len() + 1);
        match &self.prev_challenge {
            Some(c) => buffer.push(c.clone()),
            None => assert!(
                !self.round_data.is_empty(),
                "first challenge requested before any data was sent"
            ),
        }
        buffer.append(&mut self.round_data);
        let c = H::hash(&buffer);
        self.prev_challenge = Some(c.clone());
        c
    }

    /// Prover: append `element` to the proof and to the hash buffer.
    pub fn send<T: Transcriptable<TF>>(&mut self, _label: &str, element: &T) {
        let fields = element.to_fields();
        self.num_written += fields.len();
        self.round_data.extend_from_slice(&fields);
        self.proof_data.extend(fields);
    }

    /// Prover: send `elements` as one labelled object (arrays, univariates).
    pub fn send_vec<T: Transcriptable<TF>>(&mut self, _label: &str, elements: &[T]) {
        let fields: Vec<TF> = elements.iter().flat_map(|e| e.to_fields()).collect();
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
        (0..count)
            .map(|i| T::from_fields(&fields[i * n..(i + 1) * n]))
            .collect()
    }

    fn receive_fields(&mut self, label: &str, n: usize) -> Vec<TF> {
        assert!(
            self.num_read + n <= self.proof_data.len(),
            "transcript: proof too short at '{label}'"
        );
        let fields = self.proof_data[self.num_read..self.num_read + n].to_vec();
        self.num_read += n;
        self.round_data.extend_from_slice(&fields);
        fields
    }

    /// Add to the hash buffer without writing to the proof (e.g. the VK hash).
    pub fn add_to_hash_buffer<T: Transcriptable<TF>>(&mut self, _label: &str, element: &T) {
        let fields = element.to_fields();
        self.round_data.extend(fields);
    }

    /// One full-width challenge per label.
    pub fn challenges<C: FromChallenge<TF>>(&mut self, labels: &[&str]) -> Vec<C> {
        let out = labels.iter().map(|_| C::full(self.next_challenge_hash())).collect();
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
        out
    }

    pub fn short_challenge<C: FromChallenge<TF>>(&mut self, label: &str) -> C {
        self.short_challenges(&[label]).pop().unwrap()
    }
}

/// The native transcript: bn254 Fr with Poseidon2.
pub type NativeTranscript = Transcript<super::field::Fr, super::poseidon2::Poseidon2>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::field::FieldLike;
    use crate::base::Fr;

    fn fr(n: u64) -> Fr {
        Fr::from(n)
    }

    /// Prover and verifier drive the same duplex: sending x then challenging equals loading the
    /// exported proof and receiving x then challenging.
    #[test]
    fn prover_verifier_symmetry() {
        let mut p = NativeTranscript::new();
        p.send("a", &fr(7));
        p.send_vec("b", &[fr(8), fr(9)]);
        let pc: Fr = p.challenge("alpha");
        let proof = p.export_proof();

        let mut v = NativeTranscript::from_proof(&proof);
        assert_eq!(v.receive::<Fr>("a"), fr(7));
        assert_eq!(v.receive_vec::<Fr>("b", 2), vec![fr(8), fr(9)]);
        assert_eq!(v.challenge::<Fr>("alpha"), pc);
    }

    /// The duplex chains: a later challenge depends on the previous challenge, not only on the
    /// current round's data.
    #[test]
    fn challenges_chain_across_rounds() {
        let run = |first: u64| {
            let mut t = NativeTranscript::new();
            t.send("a", &fr(first));
            let _: Fr = t.challenge("c1");
            t.send("b", &fr(5));
            t.challenge::<Fr>("c2")
        };
        assert_ne!(run(1), run(2), "same round-2 data must not collapse distinct histories");
    }

    /// Fiat-Shamir tamper sensitivity: flipping any sent element changes the challenge.
    #[test]
    fn tampered_element_changes_challenge() {
        let challenge_for = |x: Fr| {
            let mut t = NativeTranscript::new();
            t.send("a", &x);
            t.challenge::<Fr>("c")
        };
        let c = challenge_for(fr(3));
        assert_ne!(challenge_for(fr(3) + Fr::one()), c);
        assert!(!c.is_zero());
    }

    /// Unwritten data (`add_to_hash_buffer`, e.g. the VK hash) binds the challenge without
    /// entering the proof.
    #[test]
    fn hash_buffer_binds_but_does_not_write() {
        let mut a = NativeTranscript::new();
        a.add_to_hash_buffer("vk", &fr(1));
        a.send("x", &fr(9));
        let ca: Fr = a.challenge("c");
        assert_eq!(a.export_proof(), vec![fr(9)]);

        let mut b = NativeTranscript::new();
        b.add_to_hash_buffer("vk", &fr(2));
        b.send("x", &fr(9));
        assert_ne!(b.challenge::<Fr>("c"), ca);
    }

    /// One hash yields two short challenges (lo/hi limbs); an odd request rolls a fresh hash for
    /// the last one and both limbs of a pair differ.
    #[test]
    fn short_challenges_split_and_differ() {
        let mut t = NativeTranscript::new();
        t.send("a", &fr(4));
        let cs: Vec<Fr> = t.short_challenges(&["u", "v", "w"]);
        assert_eq!(cs.len(), 3);
        assert!(cs[0] != cs[1] && cs[1] != cs[2] && cs[0] != cs[2]);
    }

    #[test]
    fn dyadic_powers_square_repeatedly() {
        let mut t = NativeTranscript::new();
        t.send("a", &fr(11));
        let d: Vec<Fr> = t.dyadic_powers("delta", 3);
        assert_eq!(d[1], d[0].sqr());
        assert_eq!(d[2], d[1].sqr());
    }

    #[test]
    #[should_panic(expected = "proof too short")]
    fn over_read_panics_with_label() {
        let mut v = NativeTranscript::from_proof(&[fr(1)]);
        let _ = v.receive_vec::<Fr>("univariate", 2);
    }

    #[test]
    #[should_panic(expected = "first challenge requested before any data")]
    fn challenge_before_data_panics() {
        let mut t = NativeTranscript::new();
        let _: Fr = t.challenge("c");
    }
}
