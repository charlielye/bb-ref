#!/usr/bin/env python3
"""Print bb's --bench_out_hierarchical JSON as an indented tree (time_max, s), children by time.

    bbtree.py file.hjson [min_ms] [max_depth]
"""
import json, sys

d = json.load(open(sys.argv[1]))
min_ns = float(sys.argv[2] if len(sys.argv) > 2 else 5) * 1e6
maxd = int(sys.argv[3]) if len(sys.argv) > 3 else 6
kids = {}
for name, lst in d.items():
    for e in lst:
        kids.setdefault(e.get("parent", "_root"), []).append((e["time_max"], name, e["count"], e["num_threads"]))


def pr(p, depth, seen):
    for t, n, c, th in sorted(kids.get(p, []), reverse=True):
        if t < min_ns or depth > maxd:
            continue
        print("  " * depth + f"{n:<{76 - 2 * depth}s} {t / 1e9:7.3f}s  x{c:<5d} thr {th}")
        if n not in seen:
            pr(n, depth + 1, seen | {n})


pr("_root", 0, set())
