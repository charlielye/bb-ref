//! A wasi `cdylib` of bb-ref (the `ffi` feature: tools/build_bb_ref_js.sh) is linked as a reactor.
//! rustc links a wasi `cdylib` like a command, so wasm-ld wraps every export to run the static
//! constructors and destructors around each call, which leaves nothing alive between FFI calls.
//! wasi-libc's `crt1-reactor.o` defines `_initialize`, which the host calls once, and with it
//! wasm-ld exports the functions as they are. The link args apply to the cdylib only.
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
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
