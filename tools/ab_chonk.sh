#!/usr/bin/env bash
# Interleaved A/B(/C...) of chonk proving binaries on the bench box: the paired test that
# docs/performance.md's noise rules ask for (n interleaved reps, paired median, win count).
#
#   tools/ab_chonk.sh [--reps n] [--threads t] [--flows regex] name=path [name=path ...]
#
# Paths are on the bench host ($BENCH_HOST, default bbbench); a local path is rsync'd over first
# (as ~/ab-bin/<name>.<content hash>). bb and bb-ref take the same CLI and seed. bb-ref's seeded proof is
# thread-count independent and equals single-threaded bb's; bb's own seeded proof is NOT
# deterministic above one thread (its parallel random-polynomial draws race on the engine), so
# binaries named bb* are exempt and every other binary's proof must equal the golden in
# ~/golf-goldens/<flow>.sha (single-threaded pin bb) on every run -- the byte-identity gate.
# Run order is shuffled per (flow, rep). Prints per-flow min/median wall, peak RSS, and for each
# binary after the first: paired-median ratio vs the first and its win count.
set -euo pipefail
cd "$(dirname "$0")/.."

HOST=${BENCH_HOST:-bbbench}
HOME_LOCK=/home/ubuntu/bench.lock
REPS=5
THREADS=8
FLOWS='.'
BINS=()
while [ $# -gt 0 ]; do
    case "$1" in
    --reps) REPS=$2; shift 2 ;;
    --threads) THREADS=$2; shift 2 ;;
    --flows) FLOWS=$2; shift 2 ;;
    *=*) BINS+=("$1"); shift ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done
[ ${#BINS[@]} -ge 1 ] || { echo "usage: ab_chonk.sh [--reps n] [--threads t] [--flows re] name=path ..." >&2; exit 2; }

REMOTE=()
ssh "$HOST" mkdir -p ab-bin
for b in "${BINS[@]}"; do
    name=${b%%=*} path=${b#*=}
    if [ -e "$path" ]; then  # content-addressed: concurrent runs reusing a name never clobber each other
        remote="ab-bin/$name.$(sha256sum "$path" | cut -c1-12)"
        rsync -az --checksum "$path" "$HOST:$remote"
        path=$remote
    fi
    REMOTE+=("$name=$path")
done

# flock: one timing job on the box at a time (agents share it); waits rather than overlapping.
ssh "$HOST" "REPS=$REPS THREADS=$THREADS FLOWS='$FLOWS' flock $HOME_LOCK python3 - ${REMOTE[*]}" <<'PY'
import os, random, statistics, subprocess, sys, tempfile, hashlib, glob, collections
bins = dict(a.split("=", 1) for a in sys.argv[1:])
names = list(bins)
reps, threads = int(os.environ["REPS"]), os.environ["THREADS"]
import re
flows = sorted(d for d in glob.glob(os.path.expanduser("~/chonk-pinned-flows/*/"))
               if os.path.exists(d + "ivc-inputs.msgpack") and re.search(os.environ["FLOWS"], d))
env = dict(os.environ, BB_RNG_SEED="12345", HARDWARE_CONCURRENCY=threads, RAYON_NUM_THREADS=threads)
tmp = tempfile.mkdtemp()
wall = collections.defaultdict(list); rss = collections.defaultdict(list)
def run(name, flow):
    out = f"{tmp}/{name}"
    t = f"{tmp}/time"
    r = subprocess.run(["/usr/bin/time", "-f", "%e %M", "-o", t, os.path.expanduser(bins[name]), "prove",
                        "--scheme", "chonk", "--ivc_inputs_path", flow + "ivc-inputs.msgpack", "-o", out],
                       env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    if r.returncode:
        sys.exit(f"{name} failed on {flow}:\n{r.stderr.decode()[-2000:]}")
    e, m = open(t).read().split()
    return float(e), int(m) / 1048576, hashlib.sha256(open(out + "/proof", "rb").read()).hexdigest()
print(f"threads {threads}, reps {reps}, flows {len(flows)}, binaries {names}", flush=True)
procs = subprocess.run(["pgrep", "-c", "-f", "prove --scheme|cargo|rustc|node "], capture_output=True, text=True).stdout.strip()
if procs not in ("", "0"):  # we hold the lock, so anything else proving/building is foreign
    print(f"WARNING: {procs} foreign prover/build processes on the box -- numbers suspect", flush=True)
for flow in flows:
    for n in names:  # untimed warmup per (binary, flow): page cache, CRS
        run(n, flow)
    for rep in range(reps):
        order = names[:]; random.shuffle(order)
        hashes = {}
        for n in order:
            e, m, h = run(n, flow)
            wall[(flow, n)].append(e); rss[(flow, n)].append(m); hashes[n] = h
        golden = open(os.path.expanduser(f"~/golf-goldens/{os.path.basename(flow.rstrip('/'))}.sha")).read().strip()
        bad = {n: h for n, h in hashes.items() if not n.startswith("bb") and h != golden}
        if bad:
            sys.exit(f"PROOF MISMATCH vs golden {golden} on {flow}: {bad}")
    f = os.path.basename(flow.rstrip("/"))
    cols = "  ".join(f"{n} {min(wall[(flow, n)]):6.2f}/{statistics.median(wall[(flow, n)]):6.2f} {max(rss[(flow, n)]):.2f}G"
                     for n in names)
    print(f"{f[:58]:58s} {cols}", flush=True)
base = names[0]
print(f"\nevery non-bb proof equal to the single-threaded bb golden on every run")
for n in names:
    tot = sum(min(wall[(fl, n)]) for fl in flows)
    line = f"{n:>14s}: sum of per-flow min wall {tot:8.2f}s"
    if n != base:
        ratios = [w / wb for fl in flows for w, wb in zip(wall[(fl, n)], wall[(fl, base)])]
        wins = sum(r < 1 for r in ratios)
        line += (f"  ratio vs {base}: {tot / sum(min(wall[(fl, base)]) for fl in flows):.3f} (min-sum), "
                 f"paired median {statistics.median(ratios):.3f}, wins {wins}/{len(ratios)}")
    print(line)
PY
