#!/usr/bin/env python3
"""Aligned phase table, bb-ref (BBREF_BENCH=1 logs) vs bb (ENABLE_WASM_BENCH --bench_out_hierarchical).

    phase_cmp.py <flowdir> [ref=ref-portP] [ref2=ref-baseP] [bb=golfbbP] [bb2=pinbbP]

<flowdir> is wasm_bench.py's OUTDIR/<flow> (files <name>.<rep>.log / .hjson). Values are time_max in
seconds (bb's reported scope time is the largest single thread's total), median over reps. Scopes are
keyed (name, parent); a term `name` sums over all parents, `name@parent` picks one. Part 1: the reconciled
phase map (docs/performance.md "Benchmarking traps"); part 2: every scope name present on both sides,
summed over parents. Each part sorted by gap = ref - bb.
"""
import glob, json, os, re, statistics as st, sys
from collections import defaultdict

fd = sys.argv[1]
names = dict(ref="ref-portP", ref2="ref-baseP", bb="golfbbP", bb2="pinbbP")
for a in sys.argv[2:]:
    k, v = a.split("="); names[k] = v


def ref_tree(path):
    out = defaultdict(float); stack = []; on = False
    for l in open(path, errors="replace"):
        if l.startswith("scope  ") and "time_max" in l:
            on = True; continue
        if not on:
            continue
        m = re.match(r"( *)(.+?)\s+([\d.]+)s\s+([\d.]+)s\s+(\d+)\s+(\d+)\s*$", l)
        if not m:
            if l.startswith("["): break
            continue
        depth = len(m.group(1)) // 2
        stack = stack[:depth]
        parent = stack[-1] if stack else "_root"
        key = (m.group(2).strip(), parent)
        out.setdefault(key, float(m.group(3)))  # a (name,parent) pair repeats under every copy of its parent
        stack.append(m.group(2).strip())
    return out


def bb_tree(path):
    out = {}
    for name, lst in json.load(open(path)).items():
        for e in lst:
            out[(name, e.get("parent", "_root"))] = e["time_max"] / 1e9
    return out


def load(name, kind):
    fs = sorted(glob.glob(os.path.join(fd, f"{name}.[0-9]*.{'log' if kind == 'ref' else 'hjson'}")))
    return [ref_tree(f) if kind == "ref" else bb_tree(f) for f in fs]


runs = {k: load(v, "ref" if k.startswith("ref") else "bb") for k, v in names.items()}


def val(tree, terms):
    s = 0.0
    for sign, t in terms:
        n, _, p = t.partition("@")
        s += sign * sum(v for (nn, pp), v in tree.items() if nn == n and (not p or pp == p))
    return s


def med(k, terms):
    return st.median(val(t, terms) for t in runs[k]) if runs[k] else float("nan")


P = lambda *ts: [(1, t) for t in ts]
ALIGN = [  # label, ref terms, bb terms
    ("TOTAL proving (create_circuit-decode + accumulate + prove-verify)",
     P("create_circuit", "Chonk::accumulate", "ChonkProve") + [(-1, "create_circuit/decode_witness")],
     P("create_circuit", "Chonk::accumulate", "ChonkProve") + [(-1, "ChonkVerifier::verify")]),
    ("create_circuit (excl. witness decode)", P("create_circuit") + [(-1, "create_circuit/decode_witness")], P("create_circuit")),
    ("  recursion constraints + kernel logic", P("acir::recursion_constraints"),
     P("acir::recursion_constraints", "Chonk::complete_kernel_circuit_logic")),
    ("Chonk::accumulate", P("Chonk::accumulate"), P("Chonk::accumulate")),
    ("  prover instance construction", P("ProverInstance::from_builder", "inst/wires_selectors_cycles@Chonk::accumulate",
                                         "inst/sigma_id@Chonk::accumulate", "inst/tables_bus_masking@Chonk::accumulate"),
     P("ProverInstance(Circuit&)")),
    ("  Oink, all instances (incl. hiding kernel)", P("OinkProver::prove", "HidingKernel::oink"), P("OinkProver::prove")),
    ("    commit_to_wires", P("OinkProver::commit_to_wires"), P("OinkProver::commit_to_wires")),
    ("    commit_to_z_perm", P("OinkProver::commit_to_z_perm"), P("OinkProver::commit_to_z_perm")),
    ("    commit_to_lookup_counts_and_w4", P("OinkProver::commit_to_lookup_counts_and_w4"), P("OinkProver::commit_to_lookup_counts_and_w4")),
    ("    commit_to_logderiv_inverses", P("OinkProver::commit_to_logderiv_inverses"), P("OinkProver::commit_to_logderiv_inverses")),
    ("  HypernovaFoldingProver::sumcheck", P("HypernovaFoldingProver::sumcheck"), P("HypernovaFoldingProver::sumcheck")),
    ("  sumcheck_output_to_accumulator", P("HypernovaFoldingProver::sumcheck_output_to_accumulator"),
     P("HypernovaFoldingProver::sumcheck_output_to_accumulator")),
    ("  multilinear batching (ref prove_multilinear_batching / bb Hypernova finalize)", P("Chonk::prove_multilinear_batching"),
     P("HypernovaFoldingProver::finalize")),
    ("  HypernovaDeciderProver::construct_proof", P("HypernovaDeciderProver::construct_proof"), P("HypernovaDeciderProver::construct_proof")),
    ("ChonkProve (excl. self-verify)", P("ChonkProve"), P("ChonkProve") + [(-1, "ChonkVerifier::verify")]),
    ("  ECCVMProver::construct_proof", P("ECCVMProver::construct_proof"), P("ECCVMProver::construct_proof")),
    ("    IPA (ref TripleIPA incl. claim reduction / bb IPA::compute_opening_proof)", P("ECCVM::TripleIPA"), P("IPA::compute_opening_proof")),
    ("    execute_wire_commitments_round", P("ECCVMProver::execute_wire_commitments_round"), P("ECCVMProver::execute_wire_commitments_round")),
    ("    execute_relation_check_rounds", P("ECCVMProver::execute_relation_check_rounds"), P("ECCVMProver::execute_relation_check_rounds")),
    ("  ECCVMProver(CircuitBuilder&)", P("ECCVMProver(CircuitBuilder&)"), P("ECCVMProver(CircuitBuilder&)")),
    ("  joint MegaZK+Translator proof (ref construct_proof / bb ::prove)", P("BatchedHonkTranslatorProver::construct_proof"),
     P("BatchedHonkTranslatorProver::prove")),
    ("  hiding-kernel oink (ref HidingKernel::oink / bb prove_mega_zk_oink)", P("HidingKernel::oink"),
     P("BatchedHonkTranslatorProver::prove_mega_zk_oink")),
    ("  translator proving key", P("TranslatorProvingKey"), P("TranslatorProvingKey(TranslatorCircuit&)")),
    ("  TranslatorCircuitBuilder::constructor", P("TranslatorCircuitBuilder::constructor"), P("TranslatorCircuitBuilder::constructor")),
    ("  Goblin::prove_merge", P("Goblin::prove_merge"), P("Goblin::prove_merge")),
]
cols = ["ref", "bb", "ref2", "bb2"]
hdr = f"{'scope':78s}" + "".join(f"{names[c]:>10s}" for c in cols) + f"{'gap(ref-bb)':>12s}{'ratio':>7s}"
print(f"# {os.path.basename(fd.rstrip('/'))}: time_max seconds, median of {[len(runs[c]) for c in cols]} reps\n")
print("## reconciled phase map (indentation = nesting), tree order\n" + hdr)
rows = []
for lab, rt, bt in ALIGN:
    v = {c: med(c, rt if c.startswith("ref") else bt) for c in cols}
    rows.append((lab, v))
    print(f"{lab[:78]:78s}" + "".join(f"{v[c]:10.3f}" for c in cols) + f"{v['ref'] - v['bb']:12.3f}{v['ref'] / v['bb'] if v['bb'] else 0:7.2f}")
print("\n## same rows sorted by gap\n" + hdr)
for lab, v in sorted(rows[1:], key=lambda r: -(r[1]["ref"] - r[1]["bb"])):
    print(f"{lab.strip()[:78]:78s}" + "".join(f"{v[c]:10.3f}" for c in cols) + f"{v['ref'] - v['bb']:12.3f}{v['ref'] / v['bb'] if v['bb'] else 0:7.2f}")
common = set(n for t in runs["ref"] for n, _ in t) & set(n for t in runs["bb"] for n, _ in t)
print(f"\n## all {len(common)} scope names present on both sides (summed over parents), sorted by gap\n" + hdr)
auto = []
for n in common:
    v = {c: med(c, P(n)) for c in cols}
    auto.append((n, v))
for n, v in sorted(auto, key=lambda r: -(r[1]["ref"] - r[1]["bb"])):
    if max(v["ref"], v["bb"]) < 0.003:
        continue
    print(f"{n[:78]:78s}" + "".join(f"{v[c]:10.3f}" for c in cols) + f"{v['ref'] - v['bb']:12.3f}{v['ref'] / v['bb'] if v['bb'] else 0:7.2f}")
