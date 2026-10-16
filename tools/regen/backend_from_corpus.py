#!/usr/bin/env python3
"""Real-witness rollup circuits out of the conformance corpus, as backend fixtures.

    tools/regen/backend_from_corpus.py <corpus.zst> <out: tests/data/<pin7>/backend>

The corpus is the exact stream a prover sent to bb proving whole epochs (tools/regen/regen_corpus.sh),
so its CircuitProve frames carry every rollup circuit's bytecode with a real witness: the first
frame of each circuit becomes <out>/<name>/{program.json, witness.gz, settings.json}, in the layout
of a nargo artifact the rest of the tooling reads (program.json's "bytecode" is base64 of gzip).
"""
import base64
import gzip
import json
import os
import re
import subprocess
import sys

import msgpack


def fixture_name(artifact: str) -> str:
    """`PrivateTxBaseRollupArtifact` -> `rollup_tx_base_private`, as the protocol target names them."""
    stem = artifact.removesuffix("Artifact")
    if stem.startswith("InboxParity"):
        return "inbox_parity_" + stem.removeprefix("InboxParity")
    if stem == "PrivateTxBaseRollup":
        return "rollup_tx_base_private"
    if stem == "PublicTxBaseRollup":
        return "rollup_tx_base_public"
    words = re.findall(r"[A-Z][a-z]*|\d+", stem.removesuffix("Rollup"))
    return "rollup_" + "_".join(w.lower() for w in words)


def main():
    corpus, out = sys.argv[1], sys.argv[2]
    stream = subprocess.run(["zstd", "-dc", corpus], check=True, capture_output=True).stdout
    seen = set()
    i = 0
    while i < len(stream):
        n = int.from_bytes(stream[i : i + 4], "little")
        payload = stream[i + 12 : i + 4 + n]
        i += 4 + n
        [[tag, cmd]] = msgpack.unpackb(payload, raw=False, strict_map_key=False)
        if tag != "BbCircuitProve":
            continue
        name = fixture_name(cmd["circuit"]["name"])
        if name in seen:
            continue
        seen.add(name)
        d = os.path.join(out, name)
        os.makedirs(d, exist_ok=True)
        bytecode = base64.b64encode(gzip.compress(cmd["circuit"]["bytecode"], mtime=0)).decode()
        with open(os.path.join(d, "program.json"), "w") as f:
            json.dump({"name": name, "bytecode": bytecode}, f)
        with open(os.path.join(d, "witness.gz"), "wb") as f:
            f.write(gzip.compress(cmd["witness"], mtime=0))
        with open(os.path.join(d, "settings.json"), "w") as f:
            json.dump(cmd["settings"], f, sort_keys=True)
        print(f"{name}  ipa={cmd['settings']['ipa_accumulation']} oracle={cmd['settings']['oracle_hash_type']}")


if __name__ == "__main__":
    main()
