#!/usr/bin/env python3
"""Top self-time functions over every worker's V8 .cpuprofile (WASI_CPU_PROF output of runwasi_threads.mjs).

    cpuprof_top.py <dir> [-n 40] [--by-worker]

Self time = sum of the sample time deltas attributed to a node, summed over all workers (so 8 busy
threads for 1 s count 8 s). Wasm function names come from the module's name section (Rust legacy
mangling, demangled with llvm-cxxfilt). '(idle)'/'(program)'/'(garbage collector)' are V8's own.
Also groups by a coarse bucket (first path segments) to see which module owns the CPU.
"""
import glob, json, os, re, subprocess, sys
from collections import defaultdict

d = sys.argv[1]
n = int(sys.argv[sys.argv.index("-n") + 1]) if "-n" in sys.argv else 40
self_t = defaultdict(float); per_worker = []
for f in sorted(glob.glob(os.path.join(d, "*.cpuprofile"))):
    p = json.load(open(f))
    nodes = {x["id"]: x for x in p["nodes"]}
    w = defaultdict(float)
    for sid, dt in zip(p["samples"], p["timeDeltas"]):
        cf = nodes[sid]["callFrame"]
        name = cf["functionName"] or f"(anon {cf['url']})"
        w[name] += dt / 1e6
    for k, v in w.items():
        self_t[k] += v
    per_worker.append((os.path.basename(f), sum(v for k, v in w.items() if k != "(idle)"), w.get("(idle)", 0)))
names = list(self_t)
cxxfilt = "/opt/wasi-sdk/bin/llvm-cxxfilt"
dem = dict(zip(names, subprocess.run([cxxfilt], input="\n".join(n.lstrip("$") for n in names), capture_output=True,
                                     text=True).stdout.splitlines())) if os.path.exists(cxxfilt) else {k: k for k in names}
dem = {k: re.sub(r"::h[0-9a-f]{16}$", "", v) for k, v in dem.items()}
busy = sum(v for k, v in self_t.items() if k != "(idle)")
print(f"workers {len(per_worker)}; busy (non-idle) CPU {busy:.2f}s; idle {self_t.get('(idle)', 0):.2f}s")
if "--by-worker" in sys.argv:
    for f, b, i in per_worker:
        print(f"  {f}: busy {b:.2f}s idle {i:.2f}s")
print(f"\n{'self s':>8} {'%busy':>6}  function")
for k, v in sorted(self_t.items(), key=lambda kv: -kv[1])[:n]:
    print(f"{v:8.3f} {100 * v / busy if k != '(idle)' else 0:6.1f}  {dem.get(k, k)[:160]}")
