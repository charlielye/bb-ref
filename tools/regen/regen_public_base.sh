#!/usr/bin/env bash
# Regenerates the public tx base rollup fixture under tests/data/<pin7>/instance/public_tx_base/
# (gitignored, ~60 MB) from one recorded CircuitProve frame payload for PublicTxBase (e.g. a jaws
# capture: `*-req-BbCircuitProve.msgpack`). The witness embeds a real AVM proof, which the repo's
# sample Prover.toml does not.
#
#   regen_public_base.sh <BbCircuitProve payload>
#
# Writes program.json and witness.gz (the frame's bytecode and witness), and bb's VK and seeded,
# single-threaded proof (BB_RNG_SEED=7; the inner ECCVM/Translator are ZK, so bb also needs
# HARDWARE_CONCURRENCY=1 to be reproducible).
set -euo pipefail
F=$(cd "$(dirname "$0")" && pwd)
source "$F/env.sh"
[ $# -eq 1 ] || { echo "usage: regen_public_base.sh <BbCircuitProve payload>" >&2; exit 2; }
BB=$BUILD/bin/bb-avm
OUT=$DATA/instance/public_tx_base
mkdir -p "$OUT"
python3 -I - "$1" "$OUT" <<'PY'
import base64, gzip, json, sys
import msgpack
frame, out = sys.argv[1], sys.argv[2]
cmd = msgpack.unpackb(open(frame, "rb").read(), raw=False, strict_map_key=False)[0]
assert cmd[0] == "BbCircuitProve", cmd[0]
body = cmd[1]
settings = body["settings"]
assert settings["ipa_accumulation"] and settings["disable_zk"], settings
program = {"bytecode": base64.b64encode(gzip.compress(body["circuit"]["bytecode"], 1)).decode(), "abi": {}}
json.dump(program, open(f"{out}/program.json", "w"))
open(f"{out}/witness.gz", "wb").write(gzip.compress(body["witness"], 1))
PY
"$BB" write_vk -t noir-rollup-no-zk -b "$OUT/program.json" -o "$OUT"
BB_RNG_SEED=7 HARDWARE_CONCURRENCY=1 "$BB" prove -t noir-rollup-no-zk -b "$OUT/program.json" -w "$OUT/witness.gz" -k "$OUT/vk" -o "$OUT"
echo "regen_public_base: wrote $OUT"
