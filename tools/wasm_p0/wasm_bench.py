# Wasm chonk baseline runner (on bbbench, run under flock ~/bench.lock):
#
#   python3 wasm_bench.py REPS FLOWRE OUTDIR name=mode:path ...
#
# mode: wall   plain run through tools/runwasi_threads.mjs (production tiering, plain node):
#              wall (%e), node peak RSS (%M), wasm linear-memory peak ([wasm-mem]), proof sha256
#       refprv BBREF_BENCH=1 bb-ref run: stderr flat/tree scope tables (proving-only = create_circuit
#              - create_circuit/decode_witness + Chonk::accumulate + ChonkProve)
#       bbprv  ENABLE_WASM_BENCH bb run with --bench_out/--bench_out_hierarchical/--print_bench
#              (proving-only = create_circuit + Chonk::accumulate + ChonkProve - ChonkVerifier::verify)
# Every run's proof sha is recorded; names starting ref* must equal ~/golf-goldens/<flow>.sha (the
# single-threaded pin-bb golden) or the run aborts. Order is shuffled per (flow, rep); one untimed
# warmup run per flow (page cache). Raw logs kept in OUTDIR/<flow>/<name>.<rep>.*; results appended
# to OUTDIR/results.jsonl.
import os, sys, subprocess, random, re, glob, json, hashlib, time

reps, flowre, outdir = int(sys.argv[1]), sys.argv[2], os.path.expanduser(sys.argv[3])
mods = {}
for a in sys.argv[4:]:
    name, rest = a.split("=", 1)
    mode, path = rest.split(":", 1)
    mods[name] = (mode, os.path.expanduser(path))
HARNESS = os.path.expanduser("~/wasm-p0/runwasi_threads.mjs")
flows = sorted(d for d in glob.glob(os.path.expanduser("~/chonk-pinned-flows/*/"))
               if os.path.exists(d + "ivc-inputs.msgpack") and re.search(flowre, d))
env = dict(os.environ, BB_RNG_SEED="12345", HARDWARE_CONCURRENCY="8", RAYON_NUM_THREADS="8",
           CRS_PATH=os.path.expanduser("~/.bb-crs"), WASM_MAX_PAGES="65536", PATH="/usr/local/bin:" + os.environ["PATH"])
os.makedirs(outdir, exist_ok=True)
res = open(os.path.join(outdir, "results.jsonl"), "a")


def secs_ref(log):
    v = {}
    for l in open(log):
        m = re.match(r"(create_circuit|create_circuit/decode_witness|Chonk::accumulate|ChonkProve)\s+([\d.]+)s", l)
        if m and m.group(1) not in v:
            v[m.group(1)] = float(m.group(2))
    return v.get("create_circuit", 0) - v.get("create_circuit/decode_witness", 0) + v.get("Chonk::accumulate", 0) + v.get("ChonkProve", 0)


def secs_bb(js):
    d = {k: v / 1e9 for k, v in json.load(open(js)).items()}
    return d.get("create_circuit", 0) + d.get("Chonk::accumulate", 0) + d.get("ChonkProve", 0) - d.get("ChonkVerifier::verify", 0)


def run(name, flow, rep, timed=True):
    mode, path = mods[name]
    fname = os.path.basename(flow.rstrip("/"))
    d = os.path.join(outdir, fname); os.makedirs(d, exist_ok=True)
    stem = os.path.join(d, f"{name}.{rep}")
    pout = stem + ".out"
    e = dict(env)
    extra = []
    if mode == "refprv":
        e["BBREF_BENCH"] = "1"
    elif mode == "bbprv":
        extra = ["--bench_out", stem + ".json", "--bench_out_hierarchical", stem + ".hjson", "--print_bench"]
    cmd = ["/usr/bin/time", "-f", "%e %M", "-o", stem + ".time", "node", HARNESS, path, "prove", "--scheme", "chonk",
           "--ivc_inputs_path", flow + "ivc-inputs.msgpack", "-o", pout] + extra
    with open(stem + ".log", "w") as lf:
        r = subprocess.run(cmd, env=e, stdout=subprocess.DEVNULL, stderr=lf)
    if r.returncode:
        sys.exit(f"{name} failed on {fname} (see {stem}.log)")
    wall, rss = open(stem + ".time").read().split()
    log = open(stem + ".log").read()
    mem = int(re.findall(r"\[wasm-mem\] (\d+)", log)[-1])
    sha = hashlib.sha256(open(pout + "/proof", "rb").read()).hexdigest()
    rec = dict(flow=fname, name=name, mode=mode, rep=rep, wall=float(wall), rss_kb=int(rss), wasm_mem=mem, sha=sha,
               t=time.time())
    if mode == "refprv":
        rec["proving"] = secs_ref(stem + ".log")
    elif mode == "bbprv":
        rec["proving"] = secs_bb(stem + ".json")
    golden = open(os.path.expanduser(f"~/golf-goldens/{fname}.sha")).read().strip()
    rec["golden"] = sha == golden
    if timed:
        res.write(json.dumps(rec) + "\n"); res.flush()
    if name.startswith("ref") and not rec["golden"]:
        sys.exit(f"PROOF MISMATCH vs golden on {fname}: {name} rep {rep} {sha}")
    return rec


fg = subprocess.run(["pgrep", "-c", "-f", "prove --scheme|cargo|rustc"], capture_output=True, text=True).stdout.strip()
print(f"reps {reps}, flows {len(flows)}, modules {list(mods)}; foreign procs: {fg}; load {os.getloadavg()}", flush=True)
for flow in flows:
    run(next(iter(mods)), flow, "warm", timed=False)
    for rep in range(reps):
        order = list(mods); random.shuffle(order)
        for n in order:
            r = run(n, flow, rep)
            print(f"{r['flow'][:50]:50s} {n:14s} rep {rep} wall {r['wall']:6.2f} prv {r.get('proving', 0):6.3f} "
                  f"mem {r['wasm_mem'] / 2**30:.3f}G rss {r['rss_kb'] / 2**20:.3f}G golden {r['golden']}", flush=True)
print("DONE", flush=True)
