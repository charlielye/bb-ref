//! M7 exit: the TripleIPA over Grumpkin reproduces bb byte-for-byte on deterministic inputs
//! (`BbRefDump.TripleIpa` fixtures) and the Rust verifier accepts it.
mod common;
use bb_ref::base::io::decode_fields;
use bb_ref::base::poly::{eq_table, Polynomial};
use bb_ref::base::{Fq, GrumpkinKey, NativeTranscript};
use bb_ref::goblin::ipa::{rho_powers, triple_ipa_prove, triple_ipa_verify, TripleIpaClaims, TripleIpaInput};

fn make_polys(log_n: usize) -> Vec<Polynomial<Fq>> {
    let n = 1 << log_n;
    (0..5)
        .map(|k| Polynomial::from_coeffs((0..n).map(|i| Fq::from(((k + 1) * 1000 + i + 1) as u64)).collect()))
        .collect()
}

fn input<'a>(log_n: usize, ck: &GrumpkinKey, polys: &'a [Polynomial<Fq>]) -> TripleIpaInput<'a> {
    let n = 1 << log_n;
    let u: Vec<Fq> = (0..log_n).map(|i| Fq::from(7 + i as u64)).collect();
    let eq = eq_table(&u, log_n);
    let evaluations: Vec<Fq> = polys.iter().map(|p| p.evaluate_mle(&u)).collect();
    let commitments = polys.iter().map(|p| ck.commit(p)).collect::<Vec<_>>();
    let shifted_eval = |p: &Polynomial<Fq>| (0..n - 1).map(|i| eq[i] * p.coeffs[i + 1]).sum::<Fq>();
    let sources = [1usize, 3];
    let univariate = Polynomial::from_coeffs((0..n).map(|i| Fq::from(500 + i as u64)).collect());
    let x = Fq::from(17u64);
    TripleIpaInput {
        claims: TripleIpaClaims {
            unshifted_commitments: commitments.clone(),
            unshifted_evaluations: evaluations.clone(),
            unshifted_rho_powers: rho_powers(&Fq::from(11u64), 5, 0),
            shifted_commitments: sources.iter().map(|&s| commitments[s]).collect(),
            shifted_source_evaluations: sources.iter().map(|&s| evaluations[s]).collect(),
            shifted_evaluations: sources.iter().map(|&s| shifted_eval(&polys[s])).collect(),
            shifted_rho_powers: rho_powers(&Fq::from(13u64), 2, 0),
            multilinear_challenge: u,
            univariate_commitment: ck.commit(&univariate),
            univariate_challenge: x,
            univariate_evaluation: univariate.evaluate(&x),
        },
        shifted_polys: sources.iter().map(|&s| &polys[s]).collect(),
        unshifted_polys: polys.iter().collect(),
        univariate_poly: univariate,
    }
}

fn check(log_n: usize) {
    let dump = common::fixture_dir(&format!("instance/ipa/log_{log_n}"));
    if !dump.join("triple_ipa_proof.bin").exists() {
        eprintln!("skipping ipa/log_{log_n}: no dump");
        return;
    }
    let ck = GrumpkinKey::new(1 << log_n);
    let polys = make_polys(log_n);
    let input = input(log_n, &ck, &polys);
    let mut t = NativeTranscript::new();
    triple_ipa_prove(&ck, &input, &mut t);
    let proof = t.export_proof();
    assert_eq!(
        proof,
        decode_fields(&std::fs::read(dump.join("triple_ipa_proof.bin")).unwrap()),
        "TripleIPA proof"
    );
    let claim = input.claims.batch();
    assert!(triple_ipa_verify(
        &ck,
        &claim,
        &mut NativeTranscript::from_proof(&proof)
    ));
    let mut tampered = proof.clone();
    tampered[5] += bb_ref::base::Fr::from(1u64);
    assert!(!triple_ipa_verify(
        &ck,
        &claim,
        &mut NativeTranscript::from_proof(&tampered)
    ));
}

#[test]
fn triple_ipa_log_4() {
    check(4);
}

#[test]
fn triple_ipa_log_15() {
    check(15);
}
