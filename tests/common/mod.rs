//! Shared helpers for differential tests against bb fixtures.
#![allow(dead_code)]
use std::path::PathBuf;

pub const PIN: &str = "9df414e";

pub fn fixture_dir(rel: &str) -> PathBuf {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/data").join(PIN);
    root.join(rel)
}

pub fn read(rel: &str) -> Vec<u8> {
    let p = fixture_dir(rel);
    std::fs::read(&p).unwrap_or_else(|e| panic!("missing fixture {}: {e}", p.display()))
}

pub mod eccvm_ops;
pub mod script;
