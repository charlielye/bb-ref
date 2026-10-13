#!/usr/bin/env python3
"""Liftoff vs TurboFan split from `perf report --sort sym` over a node --perf-basic-prof run (prof.sh).

    perf_tier.py <perf-sym.txt> [-n 25]

V8's perf map names wasm code "<name>-<func index>-liftoff" / "-turbofan"; everything else is JS/
builtins/V8 runtime ([.] native symbols) or kernel ([k]). Prints the share per tier and the top
symbols of each wasm tier (the same function can appear in both tiers: time spent before tier-up).
"""
import re, subprocess, sys
from collections import defaultdict

n = int(sys.argv[sys.argv.index("-n") + 1]) if "-n" in sys.argv else 25
tier = defaultdict(float); top = defaultdict(list); fn_tiers = defaultdict(lambda: defaultdict(float))
for l in open(sys.argv[1], errors="replace"):
    m = re.match(r"\s*([\d.]+)%\s+\[(.)\]\s+(.*)$", l)
    if not m:
        continue
    pct, kind, sym = float(m.group(1)), m.group(2), m.group(3).strip()
    t = re.search(r"-(\d+)-(liftoff|turbofan)$", sym)
    if t:
        k = t.group(2); base = sym[: t.start()]
        fn_tiers[base][k] += pct
    elif kind == "k":
        k = "kernel"; base = sym
    elif sym.startswith(("JS:", "Builtin:", "BytecodeHandler:")) or "wasm-to-js" in sym or "js-to-wasm" in sym:
        k = "JS/builtins/wrappers"; base = sym
    else:
        k = "native (V8 runtime, GC, libc, node)"; base = sym
    tier[k] += pct
    top[k].append((pct, base))
tot = sum(tier.values())
print(f"total attributed {tot:.1f}% of samples")
for k, v in sorted(tier.items(), key=lambda kv: -kv[1]):
    print(f"  {k:40s} {v:6.2f}%")
wasm = tier["liftoff"] + tier["turbofan"]
if wasm:
    print(f"  wasm time in Liftoff code: {100 * tier['liftoff'] / wasm:.1f}% of wasm samples")
names = list(fn_tiers)
dem = subprocess.run(["/opt/wasi-sdk/bin/llvm-cxxfilt"], input="\n".join(re.sub(r"^JS:", "", x).lstrip("$") for x in names), capture_output=True,
                     text=True).stdout.splitlines()
dem = {a: re.sub(r"::h[0-9a-f]{16}$", "", b) for a, b in zip(names, dem)}
for k in ("liftoff", "turbofan"):
    print(f"\ntop {k} symbols (% of all samples)")
    for pct, base in sorted(top[k], reverse=True)[:n]:
        print(f"  {pct:6.2f}%  {dem.get(base, base)[:150]}")
print("\nfunctions with the most Liftoff time (liftoff% / turbofan%)")
for base, d in sorted(fn_tiers.items(), key=lambda kv: -kv[1]["liftoff"])[:n]:
    print(f"  {d['liftoff']:6.2f}% / {d['turbofan']:6.2f}%  {dem.get(base, base)[:140]}")
