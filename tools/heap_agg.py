#!/usr/bin/env python3
"""Aggregate a dhat-heap.json (from --features heap-profile) by allocation site.

Reports bytes live at the global heap peak (`gb` per program point) grouped by the
first meaningful bb_ref/ark frame, i.e. what the peak is made of.

  usage: heap_agg.py dhat-heap.json [-n TOP] [--full]
"""
import json, sys, re
from collections import defaultdict

path = sys.argv[1] if len(sys.argv) > 1 else "dhat-heap.json"
top = int(sys.argv[sys.argv.index("-n") + 1]) if "-n" in sys.argv else 30
full = "--full" in sys.argv

d = json.load(open(path))
ftbl = d["ftbl"]

SKIP = re.compile(
    r"alloc::|__rust_alloc|dhat::|core::|std::|<alloc|RawVec|raw_vec|finish_grow"
    r"|reserve|allocate|Vec<T>|exchange_malloc|::vec::|from_iter|spec_extend"
    r"|to_vec|slice::|iter::|clone\b|Clone::clone"
)


def tag(fs):
    names = [ftbl[i] for i in fs]
    picked = []
    for n in names:
        # strip leading "0x...: " addr prefix
        n = re.sub(r"^0x[0-9a-f]+: ", "", n)
        if SKIP.search(n) and not picked:
            continue
        picked.append(re.sub(r" \(.*\)$", "", n))
        if len(picked) >= (6 if full else 2):
            break
    return " <- ".join(picked) if picked else names[-1]


agg = defaultdict(lambda: [0, 0])
for pp in d["pps"]:
    gb = pp.get("gb", 0)
    if not gb:
        continue
    t = tag(pp["fs"])
    agg[t][0] += gb
    agg[t][1] += pp.get("gbk", 0)

total = sum(v[0] for v in agg.values())
print(f"live at global peak: {total/1e6:.1f} MB in {sum(v[1] for v in agg.values())} blocks\n")
for t, (b, k) in sorted(agg.items(), key=lambda kv: -kv[1][0])[:top]:
    print(f"{b/1e6:9.1f} MB {k:8d} blk  {t}")
