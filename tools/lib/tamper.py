#!/usr/bin/env python3
"""Rejection frames for a corpus (tools/conformance.sh): every BbCircuitVerify that bb accepted,
again with its first public input changed, and the answer bb gives it, `verified: false`.

    tamper.py <corpus.req> <goldens.resp> <out.req> <out.resp>

A changed public input leaves the request well-formed, so the verifier itself must reject it.
The corpus's BbInit (if any) leads, as in the recording. Prints the number of tampered frames.
"""
import sys

import msgpack
from avm_corpus import frames, pack, write


def main():
    corpus, goldens, out_req, out_resp = sys.argv[1:]
    requests, answers = [], []
    for (_, req), (_, resp) in zip(frames(corpus), frames(goldens)):
        (name, body), = msgpack.unpackb(req, raw=False)
        tag, answer = msgpack.unpackb(resp, raw=False)
        if name == "BbInit":
            requests.append(req)
            answers.append(resp)
        elif name == "BbCircuitVerify" and answer == {"verified": True}:
            pi = body["public_inputs"]
            assert pi, "a rollup proof with no public inputs"
            pi[0] = pi[0][:-1] + bytes([pi[0][-1] ^ 1])
            requests.append(pack([[name, body]]))
            answers.append(pack([tag, {"verified": False}]))
    n = len(requests) - sum(msgpack.unpackb(r, raw=False)[0][0] == "BbInit" for r in requests)
    write(out_req, requests if n else [])
    write(out_resp, answers if n else [])
    print(n)


if __name__ == "__main__":
    main()
