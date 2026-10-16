#!/usr/bin/env bash
# Regenerate tests/data/<pin>/vk_sha256_mega_app/<program>: the sha256 of bb's MegaApp (chonk app) VK for every
# acir_tests program whose opcodes are within the bb-ref subset (AssertZero, RANGE, Poseidon2, memory).
# Usage: tools/regen/regen_vk_hashes.sh [acir_tests_dir] [bb_binary]
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
source "$here/env.sh"
pin=$PIN7
acir=${1:-$REPO/barretenberg/acir_tests/acir_tests}
bb=${2:-$BUILD/bin/bb}
out="$DATA/vk_sha256_mega_app"
mkdir -p "$out"
tmp=$(mktemp -d)
python3 - "$acir" <<'PY' > "$tmp/programs"
import json, base64, gzip, os, sys, msgpack
root = sys.argv[1]
ok = {'AssertZero', 'BB:RANGE', 'BB:Poseidon2Permutation', 'BB:Sha256Compression', 'BB:EcdsaSecp256r1', 'BB:XOR', 'BB:AND', 'BB:Keccakf1600', 'MemoryInit', 'MemoryOp', 'BrilligCall'}
for p in sorted(os.listdir(root)):
    f = os.path.join(root, p, 'target', 'program.json')
    if not os.path.exists(f):
        continue
    raw = gzip.decompress(base64.b64decode(json.load(open(f))['bytecode']))
    o = msgpack.unpackb(raw[1:], raw=False, strict_map_key=False)
    funcs = o[0] if raw[0] == 3 else o['functions']
    if len(funcs) != 1:
        continue
    opcodes = funcs[0][1] if raw[0] == 3 else funcs[0]['opcodes']
    if len(opcodes) == 0 or len(opcodes) > 100000:
        continue
    kinds = set()
    for op in opcodes:
        k = op if isinstance(op, str) else next(iter(op))
        if k == 'BlackBoxFuncCall':
            v = op[k]
            k = 'BB:' + (v if isinstance(v, str) else next(iter(v)))
        kinds.add(k)
    if kinds <= ok:
        print(p)
PY
n=0
while read -r prog; do
  if "$bb" write_vk --scheme chonk --circuit_kind app -b "$acir/$prog/target/program.json" -o "$tmp/$prog" >/dev/null 2>&1; then
    sha256sum "$tmp/$prog/vk" | cut -d" " -f1 > "$out/$prog"
    n=$((n + 1))
  else
    echo "bb write_vk failed for $prog (skipped)" >&2
  fi
done < "$tmp/programs"
rm -rf "$tmp"
echo "wrote $n VK sha256s to $out"
