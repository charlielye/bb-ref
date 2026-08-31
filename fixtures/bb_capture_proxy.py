#!/usr/bin/env python3
"""Record the frames exchanged with bb by interposing on BB_BINARY_PATH.

The caller spawns what it thinks is bb; this proxy starts the real bb on a shadow socket and
forwards every byte in both directions, teeing each connection to IPC_FRAME_CAPTURE_DIR as
`<pid>-connN.req` / `.resp`. The wire format is self-framing ([u32 len][u64 request_id][payload])
and request ids are client-assigned and merely echoed back, so a recorded request stream replays
verbatim into any server speaking the protocol. Neither bb nor its clients are modified — which is
the point: the server under test is never the one doing the recording.

    BB_BINARY_PATH=fixtures/bb_capture_proxy.py IPC_FRAME_CAPTURE_DIR=/dir <run the prover>
    BB_REAL=/path/to/bb   # defaults to ./bin/bb

Only `msgpack run --input <path>.sock` is proxied; anything else (shared memory, the offline file
mode, plain CLI subcommands) execs the real bb directly, so an unproxyable transport degrades to
"no capture", never to a broken run.

For a corpus that byte-compares, the traffic must also be SERIAL: with several requests in flight
on one connection, response order is nondeterministic even against the same bb. Run the prover
with a bb pool of one and agent concurrency one; per-connection recording here is the safety net.
"""
import ctypes
import os
import signal
import socket
import subprocess
import sys
import threading
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
REAL_BB = os.environ.get("BB_REAL") or str(REPO / "bin" / "bb")
CAPTURE_DIR = os.environ.get("IPC_FRAME_CAPTURE_DIR")


def pump(src: socket.socket, dst: socket.socket, sink) -> None:
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            sink.write(data)
            sink.flush()
            dst.sendall(data)
    except OSError:
        pass
    finally:
        for s in (src, dst):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def main() -> int:
    args = sys.argv[1:]
    sock_path = None
    if CAPTURE_DIR and args[:2] == ["msgpack", "run"] and "--input" in args:
        candidate = args[args.index("--input") + 1]
        if candidate.endswith(".sock"):
            sock_path = candidate
    if sock_path is None:
        os.execv(REAL_BB, [REAL_BB] + args)

    # The real bb listens on a shadow path; we take the one the client was told. The suffix must
    # stay ".sock" — bb selects its transport from it, and anything else is read as a file.
    shadow = sock_path[: -len(".sock")] + ".real.sock"
    for stale in (sock_path, shadow):
        Path(stale).unlink(missing_ok=True)
    real_args = list(args)
    real_args[real_args.index("--input") + 1] = shadow

    # The caller manages *us* as if we were bb — destroying its backend kills this process, so the
    # real bb must die with us or every proof leaks a 16-thread orphan. PDEATHSIG covers SIGKILL of
    # the proxy; the handlers cover graceful termination.
    def _die_with_parent():
        ctypes.CDLL("libc.so.6", use_errno=True).prctl(1, signal.SIGKILL)  # PR_SET_PDEATHSIG

    child = subprocess.Popen([REAL_BB] + real_args, preexec_fn=_die_with_parent)
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, lambda *_: (child.kill(), sys.exit(0)))

    Path(CAPTURE_DIR).mkdir(parents=True, exist_ok=True)
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(sock_path)
    listener.listen(64)
    listener.settimeout(1.0)

    conn_id = 0
    try:
        while child.poll() is None:
            try:
                client, _ = listener.accept()
            except socket.timeout:
                continue
            upstream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            for _ in range(100):  # the real bb may still be binding
                try:
                    upstream.connect(shadow)
                    break
                except OSError:
                    threading.Event().wait(0.1)
            else:
                client.close()
                continue

            stem = f"{os.getpid()}-conn{conn_id}"
            conn_id += 1
            req = open(Path(CAPTURE_DIR) / f"{stem}.req", "wb")
            resp = open(Path(CAPTURE_DIR) / f"{stem}.resp", "wb")
            for a, b, sink in ((client, upstream, req), (upstream, client, resp)):
                threading.Thread(target=pump, args=(a, b, sink), daemon=True).start()
    finally:
        listener.close()
        Path(sock_path).unlink(missing_ok=True)
    return child.wait()


if __name__ == "__main__":
    sys.exit(main())
