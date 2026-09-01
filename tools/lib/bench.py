#!/usr/bin/env python3
"""Drive a corpus through a msgpack server one frame at a time and report per-operation timings.

Writes a frame, waits for its response, records the interval: the server is doing exactly the work
the recorded prover asked for, in the same order, so the totals are a rollup benchmark taken from
production traffic rather than a synthetic harness. Run against bb and bb-ref for a comparable
pair -- same corpus, same seed, same thread policy.
"""
import collections
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


def main():
    corpus_path, binary, extra_args = sys.argv[1], sys.argv[2], sys.argv[3:]
    rows = run(corpus_path, binary, extra_args)

    totals, counts = collections.Counter(), collections.Counter()
    for name, elapsed, _, _ in rows:
        totals[name] += elapsed
        counts[name] += 1
    width = max(len(n) for n in totals)
    print(f"\n{binary}   {len(rows)} operations, {sum(totals.values()):.1f}s total\n")
    print(f"{'operation':{width}}  {'n':>3}  {'total':>9}  {'mean':>9}")
    print("-" * (width + 26))
    for name, total in totals.most_common():
        print(f"{name:{width}}  {counts[name]:3}  {total:8.2f}s  {total / counts[name]:8.2f}s")
    print("-" * (width + 26))
    print(f"{'TOTAL':{width}}  {len(rows):3}  {sum(totals.values()):8.2f}s")


if __name__ == "__main__":
    main()
