#!/bin/bash
# Regenerate src/msgpack/generated/ from the pin's schema via the pin's ipc-codegen, and show what
# changed. Run after moving the pin. bb_types/bb_server/bb_client/bb_ffi are generated verbatim;
# error.rs, backend.rs and mod.rs are static siblings (error.rs is the ipc-codegen rust template
# minus its thiserror dependency) and are left alone.
set -euo pipefail

here=$(cd "$(dirname "$0")/.." && pwd)
repo=${AZTEC_REPO:-$here/pin/aztec-packages}
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT

node --experimental-strip-types --experimental-transform-types --no-warnings \
  "$repo/ipc-codegen/src/generate.ts" \
  --schema "$repo/barretenberg/cpp/src/barretenberg/bbapi/bb_schema.json" \
  --lang rust \
  --out "$out" \
  --server --client --ffi

for f in bb_types.rs bb_server.rs bb_client.rs bb_ffi.rs; do
  if ! cmp -s "$out/$f" "$here/src/msgpack/generated/$f"; then
    cp "$out/$f" "$here/src/msgpack/generated/$f"
    echo "updated src/msgpack/generated/$f"
  fi
done
echo "regen_msgpack: done (schema hash $(grep -o 'SCHEMA_HASH: &str = \"[a-f0-9]*\"' "$here/src/msgpack/generated/bb_types.rs" | cut -d'"' -f2 | head -c 12)…)"
