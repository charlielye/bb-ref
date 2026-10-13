#!/usr/bin/env python3
"""Attribute wasm linear-memory growth (runwasi_memtrace.mjs log) to prover phases.

    memphase.py <memtrace.log> [--bb]

bb-ref (BBREF_TIMING=1): a `[timing] <label>: <s>` line closes the phase it names, so growth seen
before it belongs to that label; `== <step>` lines open a chonk step. bb: lines carrying `(mem: X MiB)`
are bb's own progress marks — growth is charged to the last mark seen before it ("after <mark>").
Prints growth per (step, phase) and where the high-water mark (last growth) landed.
"""
import re, sys
from collections import OrderedDict

log, bb = sys.argv[1], "--bb" in sys.argv
lines = open(log, errors="replace").read().splitlines()
step, pending, prev = "startup", [], 0
rows = []  # [step, label, grown, n, t_first, bytes_after]; consecutive same (step, label) merged
nstep = 0
last_mark = "startup"
hw = None


def charge(label):
    global pending
    for t, b, d in pending:
        if not rows or rows[-1][:2] != [f"#{nstep} {step}", label]:
            rows.append([f"#{nstep} {step}", label, 0, 0, t, b])
        r = rows[-1]
        r[2] += d; r[3] += 1; r[5] = b
    pending = []


for l in lines:
    m = re.match(r"\[memtrace\] ([\d.]+) (\d+)", l)
    if m:
        t, b = float(m.group(1)), int(m.group(2))
        pending.append((t, b, b - prev)); prev = b
        hw = (t, b)
        if bb:
            charge("after: " + last_mark)
        continue
    if bb:
        if "(mem:" in l:
            last_mark = re.sub(r"\s*\(mem:.*", "", l).strip()[:90]
            if "accumulating" in l or "ChonkProve" in l:
                if step != last_mark: nstep += 1
                step = last_mark
        continue
    m = re.match(r"\[timing\]\s+(.*?):?\s*([\d.]+s)?(\s+rss=.*)?$", l)
    if m:
        label = m.group(1).strip()
        if label.startswith("== "):
            charge("(step boundary)")
            step = label[3:]; nstep += 1
        else:
            charge(label)
charge("(end)")
tot = 0
print(f"{'MiB grown':>9} {'cum MiB':>8} {'t ms':>8}  step / phase")
for s, lab, d, n, t, b in rows:
    tot += d
    print(f"{d / 2**20:9.1f} {b / 2**20:8.1f} {t:8.0f}  {s[:60]} / {lab}")
print(f"high-water {hw[1] / 2**20:.1f} MiB at {hw[0]:.0f} ms")
