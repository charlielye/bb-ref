#!/usr/bin/env python3
"""Corpus utilities: inspect a recorded wire stream, locate a divergence, cut a frame out of it.

A corpus is the exact bytes a prover sent to bb: `[u32 len][u64 request_id][payload]` frames, the
length covering id and payload. bb and bb-ref both read that framing from a file or stdin, so the
corpus needs no format of its own and no rehydration step -- what we replay is what the node sent.

    replay.py --list    <corpus>                     frames with their command and circuit
    replay.py --count   <stream>                     number of frames in a stream
    replay.py --diff    <corpus> <bb.resp> <ref.resp>  first divergence, by frame
    replay.py --extract <corpus> <n> -o <out>        frames 0..=n as a standalone corpus
"""
import gzip
import struct
import sys

try:
    import msgpack
except ImportError:
    msgpack = None


def read(path):
    data = open(path, "rb").read() if path != "-" else sys.stdin.buffer.read()
    if data[:4] == b"\x28\xb5\x2f\xfd":  # zstd magic
        import subprocess
        data = subprocess.run(["zstd", "-dcq", path], capture_output=True, check=True).stdout
    elif data[:2] == b"\x1f\x8b":
        data = gzip.decompress(data)
    return data


def frames(data):
    """Yield (request_id, payload, raw_frame_bytes)."""
    i = 0
    while i + 12 <= len(data):
        length = struct.unpack("<I", data[i : i + 4])[0]
        request_id = struct.unpack("<Q", data[i + 4 : i + 12])[0]
        yield request_id, data[i + 12 : i + 4 + length], data[i : i + 4 + length]
        i += 4 + length


def describe(payload):
    """Command name and circuit of a request payload, for reporting."""
    if msgpack is None:
        return "<msgpack unavailable>"
    try:
        command, args = msgpack.unpackb(payload, raw=False)[0]
    except Exception:
        return "<undecodable>"
    circuit = ""
    if isinstance(args, dict):
        circuit = (args.get("circuit") or {}).get("name", "") if isinstance(args.get("circuit"), dict) else ""
    return f"{command}{f' {circuit}' if circuit else ''}"


def main():
    mode = sys.argv[1]
    if mode == "--count":
        print(sum(1 for _ in frames(read(sys.argv[2]))))
    elif mode == "--list":
        for n, (rid, payload, raw) in enumerate(frames(read(sys.argv[2]))):
            print(f"{n:4} id={rid:<20} {len(raw):>12,} B  {describe(payload)}")
    elif mode == "--diff":
        requests = list(frames(read(sys.argv[2])))
        left = list(frames(read(sys.argv[3])))
        right = list(frames(read(sys.argv[4])))
        bad = 0
        for n, (a, b) in enumerate(zip(left, right)):
            if a[1] != b[1]:
                bad += 1
                where = next((i for i, (x, y) in enumerate(zip(a[1], b[1])) if x != y), min(len(a[1]), len(b[1])))
                what = describe(requests[n][1]) if n < len(requests) else "?"
                print(f"frame {n} ({what}): differs at byte {where} (bb {len(a[1])} B, bb-ref {len(b[1])} B)")
        print(f"\n{bad}/{len(left)} responses diverged")
        if bad:
            print("repro one:  replay.py --extract <corpus> <frame> -o frame.corpus")
        return
        if len(left) != len(right):
            print(f"response count differs: bb {len(left)}, bb-ref {len(right)}")
    elif mode == "--extract":
        upto = int(sys.argv[3])
        out = sys.argv[sys.argv.index("-o") + 1] if "-o" in sys.argv else f"frame{upto}.corpus"
        all_frames = list(frames(read(sys.argv[2])))
        # Chonk commands mutate session state, so such a frame only replays behind its
        # predecessors. Everything else is self-contained and extracts alone -- which is the
        # difference between a 22 KB repro and a 1.7 GB one.
        stateful = any(describe(p).startswith("BbChonk") for _, p, _ in all_frames[:upto])
        selected = all_frames[: upto + 1] if stateful else [all_frames[upto]]
        with open(out, "wb") as f:
            for _, _, raw in selected:
                f.write(raw)
        span = f"0..={upto}" if stateful else f"{upto}"
        print(f"wrote frame(s) {span} ({len(selected)}) -> {out}")
    else:
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
