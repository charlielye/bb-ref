#!/usr/bin/env python3
"""11-flow table from wasm_bench.py's results.jsonl.

    table.py results.jsonl

Per flow and module: wall min/median (plain modules), proving-only median (instrumented modules),
wasm linear-memory peak (max over reps, plain modules), node peak RSS (max). Totals = sum of per-flow
min wall / median proving. Paired ratios over (flow, rep).
"""
import json, sys, statistics as st
from collections import defaultdict

R = [json.loads(l) for l in open(sys.argv[1])]
W = defaultdict(list); P = defaultdict(list); M = defaultdict(list); S = defaultdict(list); G = defaultdict(set)
for r in R:
    k = (r["flow"], r["name"].rstrip("P"))
    if r["mode"] == "wall":
        W[k].append(r["wall"]); M[k].append(r["wasm_mem"]); S[k].append(r["rss_kb"])
    else:
        P[k].append(r["proving"])
    G[k].add(r["sha"][:12] + ("=golden" if r["golden"] else "") )
mods = ["ref-base", "ref-port", "pinbb", "golfbb"]
flows = sorted({r["flow"] for r in R})
GB = 2 ** 30
print("wall (best of n, s) | proving-only (median, s) | wasm linear-memory peak (max, GiB) | node RSS (max, GiB)")
hdr = f"{'flow':52s}" + "".join(f"{m:>10s}" for m in mods)
for title, D, f, fmt in [("WALL min", W, min, "{:10.2f}"), ("WALL median", W, st.median, "{:10.2f}"),
                         ("PROVING median", P, st.median, "{:10.3f}"),
                         ("WASM MEM max", M, lambda v: max(v) / GB, "{:10.3f}"),
                         ("WASM MEM min", M, lambda v: min(v) / GB, "{:10.3f}"),
                         ("NODE RSS max", S, lambda v: max(v) / 2 ** 20, "{:10.3f}")]:
    print(f"\n== {title}\n" + hdr)
    tot = defaultdict(float)
    for fl in flows:
        row = f"{fl[:52]:52s}"
        for m in mods:
            v = D.get((fl, m))
            x = f(v) if v else float("nan")
            tot[m] += x
            row += fmt.format(x)
        print(row)
    if title.startswith(("WALL", "PROVING")):
        print(f"{'TOTAL':52s}" + "".join(fmt.format(tot[m]) for m in mods))
        base = tot["ref-base"]
        print(f"{'  vs ref-base':52s}" + "".join(f"{tot[m] / base:10.3f}" for m in mods))
        print(f"{'  vs golfbb':52s}" + "".join(f"{tot[m] / tot['golfbb']:10.3f}" for m in mods))
        print(f"{'  vs pinbb':52s}" + "".join(f"{tot[m] / tot['pinbb']:10.3f}" for m in mods))


def paired(D, a, b):
    rs = []
    for fl in flows:
        for x, y in zip(D[(fl, a)], D[(fl, b)]):
            rs.append(x / y)
    return st.median(rs), sum(r < 1 for r in rs), len(rs)


print("\n== paired ratios (median over flow x rep, wins = a faster)")
for a, b in [("ref-port", "ref-base"), ("ref-port", "golfbb"), ("ref-port", "pinbb"), ("golfbb", "pinbb"), ("ref-base", "pinbb")]:
    for nm, D in [("wall", W), ("proving", P)]:
        m, w, n = paired(D, a, b)
        print(f"  {nm:8s} {a:9s}/{b:9s} {m:.3f}  wins {w}/{n}")
print("\n== memory ratios per flow (max wasm mem)")
for fl in flows:
    mm = {m: max(M[(fl, m)]) for m in mods}
    print(f"{fl[:52]:52s} port/base {mm['ref-port'] / mm['ref-base']:.3f}  port/golf {mm['ref-port'] / mm['golfbb']:.3f}  port/pin {mm['ref-port'] / mm['pinbb']:.3f}  golf/pin {mm['golfbb'] / mm['pinbb']:.3f}")
print("\n== proof hashes per (flow, module) — '=golden' marks the single-threaded pin-bb golden")
for fl in flows:
    for m in mods:
        print(f"{fl[:52]:52s} {m:9s} {len(G[(fl, m)])} distinct: {' '.join(sorted(G[(fl, m)]))}")
