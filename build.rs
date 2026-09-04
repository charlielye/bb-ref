// With --features bbkernel (wasm targets only), compiles bb's q1s1 VectorField kernels with the
// wasi-sdk toolchain — the scheduling barriers in bb's mul body are clang-level and cannot be
// reproduced from Rust/LLVM (bench-results/LADDER.md) — and links them in. Requires /opt/wasi-sdk
// and the pinned barretenberg checkout (BBREF_BB_CPP overrides the default sibling path).
fn main() {
    println!("cargo:rerun-if-changed=csrc/bb_kernel.cpp");
    if std::env::var_os("CARGO_FEATURE_BBKERNEL").is_none() {
        return;
    }
    let target = std::env::var("TARGET").unwrap_or_default();
    if !target.starts_with("wasm32") {
        return;
    }
    let bb = std::env::var("BBREF_BB_CPP").unwrap_or_else(|_| "../aztec-packages2/barretenberg/cpp".into());
    let sdk = "/opt/wasi-sdk";
    assert!(
        std::path::Path::new(sdk).exists() && std::path::Path::new(&bb).exists(),
        "bbkernel needs {sdk} and the bb checkout at {bb}"
    );
    let out = std::env::var("OUT_DIR").unwrap();
    for (src, obj) in [
        ("csrc/bb_kernel.cpp".to_string(), "bb_kernel.o"),
        (format!("{bb}/src/barretenberg/ecc/fields/vector_field_wasm.cpp"), "vector_field_wasm.o"),
    ] {
        let status = std::process::Command::new(format!("{sdk}/bin/clang++"))
            .args([
                &format!("--sysroot={sdk}/share/wasi-sysroot"),
                "--target=wasm32-wasi-threads",
                "-DDISABLE_ASM=1",
                "-DMSGPACK_NO_BOOST",
                "-DNO_PAR_ALGOS",
                "-D_WASI_EMULATED_PROCESS_CLOCKS=1",
                "-DBB_NO_EXCEPTIONS",
                "-DNDEBUG",
                &format!("-I{bb}/src"),
                &format!("-I{bb}/build-wasm-threads/_deps/tracy-src/public"),
                &format!("-I{bb}/build-wasm-threads/_deps/msgpack-c/src/msgpack-c/include"),
                "-Oz",
                "-std=gnu++20",
                "-fPIC",
                "-msimd128",
                "-fbracket-depth=1024",
                "-fno-exceptions",
                "-fno-slp-vectorize",
                "-pthread",
                "-fno-c++-static-destructors",
                "-c",
                &src,
                "-o",
                &format!("{out}/{obj}"),
            ])
            .status()
            .expect("wasi-sdk clang++ not runnable");
        assert!(status.success(), "bbkernel compile failed: {src}");
    }
    let status = std::process::Command::new(format!("{sdk}/bin/llvm-ar"))
        .args(["crs", &format!("{out}/libbbkernel.a"), &format!("{out}/bb_kernel.o"), &format!("{out}/vector_field_wasm.o")])
        .status()
        .unwrap();
    assert!(status.success());
    println!("cargo:rustc-link-search=native={out}");
    println!("cargo:rustc-link-lib=static=bbkernel");
}
