#!/usr/bin/env python3
"""Frames for the AVM corpus (tools/regen/regen_avm_corpus.sh), in the corpus wire framing
([u32 len][u64 request_id][payload]):

    avm_corpus.py prove  <out.req> <avm_inputs.bin>...           AvmProve, AvmCheckCircuit per input
    avm_corpus.py verify <out.req> <prove.req> <prove.resp>       per proof: AvmVerify, and a tampered one
    avm_corpus.py goldens <out.resp> <resp>...                    bb's responses, AVM stats emptied

bb's AVM responses carry its stage timings (`stats`), which no two runs share; the goldens keep
everything else byte for byte, and bb-ref answers with no stats.
"""
import struct
import sys

import msgpack


def frames(path):
    data = open(path, "rb").read()
    i = 0
    while i < len(data):
        n = struct.unpack_from("<I", data, i)[0]
        yield struct.unpack_from("<Q", data, i + 4)[0], data[i + 12 : i + 4 + n]
        i += 4 + n


def write(path, payloads, first_id=0):
    with open(path, "wb") as f:
        for k, p in enumerate(payloads):
            f.write(struct.pack("<IQ", 8 + len(p), first_id + k) + p)


def pack(obj):
    return msgpack.packb(obj, use_bin_type=True)


def command(name, body):
    return pack([[name, body]])


def main():
    mode, out, *rest = sys.argv[1:]
    if mode == "prove":
        payloads = []
        for path in rest:
            inputs = open(path, "rb").read()
            payloads += [command("BbAvmProve", {"inputs": inputs}), command("BbAvmCheckCircuit", {"inputs": inputs})]
        write(out, payloads)
    elif mode == "verify":
        requests, responses = list(frames(rest[0])), list(frames(rest[1]))
        payloads = []
        for (_, req), (_, resp) in zip(requests, responses):
            name, body = msgpack.unpackb(req, raw=False)[0]
            if name != "BbAvmProve":
                continue
            tag, answer = msgpack.unpackb(resp, raw=False)
            assert tag == "BbAvmProveResponse", tag
            public_inputs = pack(msgpack.unpackb(body["inputs"], raw=False)["publicInputs"])
            proof = answer["proof"]
            tampered = proof[:-10] + [proof[-10][:-1] + bytes([proof[-10][-1] ^ 1])] + proof[-9:]
            for p in (proof, tampered):
                payloads.append(command("BbAvmVerify", {"proof": p, "public_inputs": public_inputs}))
        write(out, payloads, first_id=len(requests))
    elif mode == "goldens":
        payloads = []
        for path in rest:
            for _, resp in frames(path):
                obj = msgpack.unpackb(resp, raw=False)
                assert pack(obj) == resp, "msgpack re-encode is not exact"
                if isinstance(obj[1], dict) and "stats" in obj[1]:
                    obj[1]["stats"] = []
                payloads.append(pack(obj))
        write(out, payloads)
    else:
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
