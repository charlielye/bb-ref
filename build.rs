//! A wasi `cdylib` of bb-ref (the `ffi` feature: tools/build_bb_ref_js.sh) is linked as a reactor.
//! rustc links a wasi `cdylib` like a command, so wasm-ld wraps every export to run the static
//! constructors and destructors around each call, which leaves nothing alive between FFI calls.
//! wasi-libc's `crt1-reactor.o` defines `_initialize`, which the host calls once, and with it
//! wasm-ld exports the functions as they are. The link args apply to the cdylib only.
//!
//! The `bb-avm` feature links bb's `libbb-external-avm.a` (`./pin/build.sh --avm-lib`, or from
//! `$BB_AVM_LIB_DIR`) and the C++ runtime it was built against (`$BB_AVM_CXX_LIB`: `stdc++`, or
//! `c++` for bb's release builds).
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    if std::env::var_os("CARGO_FEATURE_BB_AVM").is_some() {
        println!("cargo:rerun-if-env-changed=BB_AVM_LIB_DIR");
        println!("cargo:rerun-if-env-changed=BB_AVM_CXX_LIB");
        let dir = std::env::var("BB_AVM_LIB_DIR").unwrap_or_else(|_| {
            let repo = std::env::var("AZTEC_REPO")
                .unwrap_or(format!("{}/pin/aztec-packages", std::env::var("CARGO_MANIFEST_DIR").unwrap()));
            format!("{repo}/barretenberg/cpp/build/lib")
        });
        println!("cargo:rerun-if-changed={dir}/libbb-external-avm.a");
        println!("cargo:rustc-link-search=native={dir}");
        println!("cargo:rustc-link-lib=static=bb-external-avm");
        println!("cargo:rustc-link-lib=dylib={}", std::env::var("BB_AVM_CXX_LIB").unwrap_or("stdc++".into()));
    }
    let target = std::env::var("TARGET").unwrap();
    if !target.starts_with("wasm32-wasi") || std::env::var_os("CARGO_FEATURE_FFI").is_none() {
        return;
    }
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".into());
    let out = std::process::Command::new(rustc).args(["--print", "sysroot"]).output().expect("rustc --print sysroot");
    let sysroot = String::from_utf8(out.stdout).unwrap();
    let crt = std::path::Path::new(sysroot.trim())
        .join("lib/rustlib")
        .join(&target)
        .join("lib/self-contained/crt1-reactor.o");
    assert!(crt.exists(), "missing {}", crt.display());
    println!("cargo:rustc-cdylib-link-arg={}", crt.display());
    println!("cargo:rustc-cdylib-link-arg=--export=_initialize");
}
