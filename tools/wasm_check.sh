#!/usr/bin/env bash
# Fails a bb-ref.wasm built without .cargo/config.toml's wasm flags (a RUSTFLAGS variable silently
# replaces them). The visible trace is the module's `memory.copy` count (opcode bytes FC 0A 00 00):
# the inline memcpy expansion halves it (at 5991e08: lto 13,654 -> 6,904, release 12,374 -> 5,315).
#
#   tools/wasm_check.sh [module.wasm]     (no module: build bb-ref.wasm with the lto profile first)
set -euo pipefail
cd "$(dirname "$0")/.."
m=${1:-target/wasm32-wasip1-threads/lto/bb-ref.wasm}
[ $# -gt 0 ] || cargo build --profile lto --target wasm32-wasip1-threads --bin bb-ref
n=$(python3 -c 'import sys; print(open(sys.argv[1], "rb").read().count(b"\xfc\x0a\x00\x00"))' "$m")
if [ "$n" -gt 10000 ]; then
    echo "wasm_check: $m has $n memory.copy (limit 10000): built without the wasm rustflags?" >&2
    exit 1
fi
echo "wasm_check: $m ok ($n memory.copy)"
