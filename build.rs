//! A wasi `cdylib` of bb-ref (the `ffi` feature: tools/build_bb_ref_js.sh) is linked as a reactor.
//! rustc links a wasi `cdylib` like a command, so wasm-ld wraps every export to run the static
//! constructors and destructors around each call, which leaves nothing alive between FFI calls.
//! wasi-libc's `crt1-reactor.o` defines `_initialize`, which the host calls once, and with it
//! wasm-ld exports the functions as they are. The link args apply to the cdylib only.
//!
//! The `bb-avm` feature links bb's AVM simulation and trace generation, `libbb-avm-sim.a`
//! (`./pin/build.sh --avm-lib`, which applies `pin/bb-avm-sim.patch`; or from
//! `$BB_AVM_LIB_DIR`) and the C++ runtime it was built against: `$BB_AVM_CXX_LIB`, comma-separated
//! rustc link specs, default `c++` (bb's release preset uses libc++; barretenberg-rs links
//! `bb-external` the same way). A portable binary links like bb's release `bb-avm`, through zig with
//! its bundled libc++ and glibc 2.35 symbols (runs on Debian 12 / Ubuntu 22.04):
//! `CXXSTDLIB=c++ cargo zigbuild --release --features bb-avm --target x86_64-unknown-linux-gnu.2.35`.
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    if std::env::var_os("CARGO_FEATURE_BB_AVM").is_some() {
        println!("cargo:rerun-if-env-changed=BB_AVM_LIB_DIR");
        println!("cargo:rerun-if-env-changed=BB_AVM_CXX_LIB");
        println!("cargo:rerun-if-env-changed=BB_AVM_CXX_LIB_DIR");
        let dir = std::env::var("BB_AVM_LIB_DIR").unwrap_or_else(|_| {
            let repo = std::env::var("AZTEC_REPO")
                .unwrap_or(format!("{}/pin/aztec-packages", std::env::var("CARGO_MANIFEST_DIR").unwrap()));
            format!("{repo}/barretenberg/cpp/build-avm-sim/lib")
        });
        println!("cargo:rerun-if-changed={dir}/libbb-avm-sim.a");
        println!("cargo:rustc-link-search=native={dir}");
        println!("cargo:rustc-link-lib=static=bb-avm-sim");
        if let Ok(cxx_dir) = std::env::var("BB_AVM_CXX_LIB_DIR") {
            println!("cargo:rustc-link-search=native={cxx_dir}");
        }
        for lib in std::env::var("BB_AVM_CXX_LIB").unwrap_or("c++".into()).split(',') {
            println!("cargo:rustc-link-lib={lib}");
        }
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
