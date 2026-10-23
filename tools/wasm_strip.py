#!/usr/bin/env python3
"""Remove every custom section (id 0: name, DWARF, producers, ...) from a wasm module.

    wasm_strip.py in.wasm out.wasm [--keep name]

Code is untouched, so the stripped module proves identically; only load time changes.
"""
import sys


def leb(b, i):
    r = s = 0
    while True:
        x = b[i]; i += 1
        r |= (x & 0x7F) << s; s += 7
        if x < 0x80:
            return r, i


def sections(b):
    i = 8
    while i < len(b):
        sid = b[i]
        size, j = leb(b, i + 1)
        yield sid, i, j, j + size
        i = j + size


def main():
    src, dst = sys.argv[1], sys.argv[2]
    keep = set(sys.argv[i + 1] for i, a in enumerate(sys.argv) if a == "--keep")
    b = open(src, "rb").read()
    out = bytearray(b[:8])
    for sid, start, body, end in sections(b):
        if sid == 0:
            n, k = leb(b, body)
            if b[k:k + n].decode() not in keep:
                continue
        out += b[start:end]
    open(dst, "wb").write(out)


if __name__ == "__main__":
    main()
