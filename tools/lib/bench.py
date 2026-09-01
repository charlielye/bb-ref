#!/usr/bin/env python3
"""Drive a corpus through a msgpack server one frame at a time and report per-operation timings.

Writes a frame, waits for its response, records the interval: the server is doing exactly the work
the recorded prover asked for, in the same order, so the totals are a rollup benchmark taken from
production traffic rather than a synthetic harness. Run against bb and bb-ref for a comparable
pair -- same corpus, same seed, same thread policy.
"""
import collections
import msgpack
import struct
import subprocess
import sys
import time

sys.path.insert(0, __file__.rsplit("/", 1)[0])
from replay import describe, frames, read  # noqa: E402


def run(corpus_path, binary, extra_args):
    data = read(corpus_path)
    server = subprocess.Popen(
        [binary, "msgpack", "run", "--input", "-", *extra_args],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    rows = []
    # bb handles SIGINT gracefully (it finishes the in-flight proof first), so Ctrl-C must kill the
    # child outright; a clean end of the corpus still lets it exit on stdin EOF.
    try:
        # Unmeasured warmup: server startup (SRS preload, allocator growth) must not bill the
        # first frame. A one-word Poseidon2Hash round-trips through the whole pipeline.
        warmup = msgpack.packb([["BbPoseidon2Hash", {"inputs": [b"\x00" * 32]}]], use_bin_type=True)
        server.stdin.write(struct.pack("<I", 8 + len(warmup)) + struct.pack("<Q", 0) + warmup)
        server.stdin.flush()
        wlen = struct.unpack("<I", server.stdout.read(4))[0]
        server.stdout.read(wlen)
        for request_id, payload, raw in frames(data):
            start = time.perf_counter()
            server.stdin.write(raw)
            server.stdin.flush()
            header = server.stdout.read(4)
            if len(header) < 4:
                raise SystemExit(f"server closed after {len(rows)} frames (id={request_id})")
            length = struct.unpack("<I", header)[0]
            body = b""
            while len(body) < length:
                chunk = server.stdout.read(length - len(body))
                if not chunk:
                    raise SystemExit("truncated response")
                body += chunk
            rows.append((describe(payload), time.perf_counter() - start, len(raw), len(body)))
    except BaseException:
        server.kill()
        raise
    server.stdin.close()
    try:
        server.wait(timeout=10)
    except subprocess.TimeoutExpired:
        server.kill()
    return rows


def totals_of(rows):
    totals, counts = collections.Counter(), collections.Counter()
    for name, elapsed, _, _ in rows:
        totals[name] += elapsed
        counts[name] += 1
    return totals, counts


def print_single(binary, rows):
    totals, counts = totals_of(rows)
    width = max(len(n) for n in totals)
    print(f"\n{binary}   {len(rows)} operations, {sum(totals.values()):.1f}s total\n")
    print(f"{'operation':{width}}  {'n':>3}  {'total':>9}  {'mean':>9}")
    print("-" * (width + 26))
    for name, total in totals.most_common():
        print(f"{name:{width}}  {counts[name]:3}  {total:8.2f}s  {total / counts[name]:8.2f}s")
    print("-" * (width + 26))
    print(f"{'TOTAL':{width}}  {len(rows):3}  {sum(totals.values()):8.2f}s")


def print_both(rows_bb, rows_ref):
    t_bb, counts = totals_of(rows_bb)
    t_ref, _ = totals_of(rows_ref)
    width = max(len(n) for n in t_bb)
    print(f"\nbb vs bb-ref (concurrent replay of the same corpus)\n")
    print(f"{'operation':{width}}  {'n':>3}  {'bb':>9}  {'bb-ref':>9}  {'ref/bb':>7}")
    print("-" * (width + 36))
    for name, total in t_bb.most_common():
        ratio = t_ref[name] / total if total else float("inf")
        print(f"{name:{width}}  {counts[name]:3}  {total:8.2f}s  {t_ref[name]:8.2f}s  {ratio:6.2f}x")
    print("-" * (width + 36))
    sb, sr = sum(t_bb.values()), sum(t_ref.values())
    print(f"{'TOTAL':{width}}  {len(rows_bb):3}  {sb:8.2f}s  {sr:8.2f}s  {sr / sb:6.2f}x")


def main():
    corpus_path, binary, extra_args = sys.argv[1], sys.argv[2], sys.argv[3:]
    if binary == "--both":
        # Concurrent replays contend for cpu: only meaningful with ~2x THREADS of spare cores.
        from concurrent.futures import ThreadPoolExecutor

        with ThreadPoolExecutor(2) as pool:
            f_bb = pool.submit(run, corpus_path, "./bin/bb", extra_args)
            f_ref = pool.submit(run, corpus_path, "./target/release/bb-ref", extra_args)
            print_both(f_bb.result(), f_ref.result())
        return
    print_single(binary, run(corpus_path, binary, extra_args))


if __name__ == "__main__":
    main()
