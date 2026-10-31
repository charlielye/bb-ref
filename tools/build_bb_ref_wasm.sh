#!/usr/bin/env bash
# bb-ref's two wasm modules for bb-ref.js, into <dir> (bb-ref-threads.wasm,
# bb-ref-wide-threads.wasm): tools/build_bb_ref_js.sh, and CI's bench-page update, which needs
# nothing else of the package.
#
#   tools/build_bb_ref_wasm.sh <dir>
set -euo pipefail
OUT=$(realpath -m "${1:?usage: build_bb_ref_wasm.sh <dir>}")
cd "$(dirname "$0")/.."
mkdir -p "$OUT"
# bb-ref's library as a cdylib: the crate is an rlib + bin, so the crate type is chosen here.
PKG_ARGS=(--cfg chonk_only -C link-arg=--strip-all)
cargo rustc --quiet --lib --crate-type cdylib --features ffi --profile lto --target wasm32-wasip1-threads -- "${PKG_ARGS[@]}"
tools/wasm_check.sh target/wasm32-wasip1-threads/lto/bb_ref.wasm
cp target/wasm32-wasip1-threads/lto/bb_ref.wasm "$OUT/bb-ref-threads.wasm"
# RUSTFLAGS replaces .cargo/config.toml's wasm flags, so they are all restated; its own target dir
# keeps the default build's artifacts.
RUSTFLAGS="-C target-feature=+simd128,+wide-arithmetic -C link-arg=--max-memory=4294967296 -C llvm-args=-max-store-memcpy=48 -C llvm-args=-max-store-memset=48 --cfg wasm_wide" \
  CARGO_TARGET_DIR=target/wide cargo rustc --quiet --lib --crate-type cdylib --features ffi --profile lto --target wasm32-wasip1-threads -- "${PKG_ARGS[@]}"
tools/wasm_check.sh target/wide/wasm32-wasip1-threads/lto/bb_ref.wasm
cp target/wide/wasm32-wasip1-threads/lto/bb_ref.wasm "$OUT/bb-ref-wide-threads.wasm"

