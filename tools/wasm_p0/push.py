#!/usr/bin/env python3
"""Push local modules to bbbench as content-addressed ~/ab-bin/p0-<name>.<sha12>.wasm; print the remote paths.

    push.py name=local.wasm ...
"""
import hashlib, subprocess, sys

for a in sys.argv[1:]:
    name, path = a.split("=", 1)
    h = hashlib.sha256(open(path, "rb").read()).hexdigest()[:12]
    remote = f"ab-bin/p0-{name}.{h}.wasm"
    subprocess.run(["rsync", "-a", "--checksum", path, f"bbbench:{remote}"], check=True)
    print(f"{name}=~/{remote}")
