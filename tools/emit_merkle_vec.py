#!/usr/bin/env python3
"""emit_merkle_vec.py — regenerate the hardcoded vectors in test_merkle.c.

Reads tests/c/test_merkle.c, replaces everything between
  /* BEGIN-GENERATED-VECTORS */ and /* END-GENERATED-VECTORS */
with freshly computed values (Python hashlib, independent of the C code).
Run from repo root:
  python tools/emit_merkle_vec.py   (dev helper; committed for provenance)
The committed test file already contains one such generated block.
"""
import hashlib
import re
import sys

H = lambda *ps: hashlib.sha256(b"".join(ps)).digest()


def leaf(cls, counter, reading: bytes) -> bytes:
    return H(b"QC-ATTEST", bytes([cls]), counter.to_bytes(8, "big"), reading)


def fold_level(lvl):
    nxt = []
    for i in range(0, len(lvl) - 1, 2):
        nxt.append(H(lvl[i], lvl[i + 1]))
    if len(lvl) % 2 == 1:
        nxt.append(lvl[-1])
    return nxt


def root(leaves):
    lvl = list(leaves)
    while len(lvl) > 1:
        lvl = fold_level(lvl)
    return lvl[0]


def proof(leaves, index):
    out, lvl, pos = [], list(leaves), index
    while len(lvl) > 1:
        if not (len(lvl) % 2 == 1 and pos == len(lvl) - 1):
            out.append(lvl[pos ^ 1])
        lvl, pos = fold_level(lvl), pos // 2
    return out


def c_array(name, data: bytes) -> str:
    lines = [f"static const uint8_t {name}[{len(data)}] = {{"]
    for i in range(0, len(data), 8):
        chunk = data[i:i + 8]
        lines.append("    " + ", ".join(f"0x{b:02x}" for b in chunk) + ",")
    lines.append("};")
    return "\n".join(lines)


def main(path):
    readings = [b"r0", b"reading-one", b"", b"r3-longer-payload-data", b"r4"]
    leaves = [leaf(1, i, r) for i, r in enumerate(readings)]
    r = root(leaves)
    p = proof(leaves, 3)
    assert len(p) == 3
    block = ["/* BEGIN-GENERATED-VECTORS",
             " * Python hashlib, see tools/emit_merkle_vec.py. DO NOT EDIT. */"]
    for i, lv in enumerate(leaves):
        block.append(c_array(f"WL{i}", lv))
    block.append(c_array("WROOT", r))
    block.append(c_array("WSIB1", p[1]))
    block.append("/* END-GENERATED-VECTORS */")
    text = "\n".join(block) + "\n"

    src = open(path, encoding="utf-8").read()
    pat = re.compile(r"/\* BEGIN-GENERATED-VECTORS.*?END-GENERATED-VECTORS \*/\n?",
                     re.DOTALL)
    assert len(pat.findall(src)) == 1, "marker pair not found exactly once"
    open(path, "w", encoding="utf-8", newline="").write(pat.sub(text, src))
    print("regenerated vectors in", path)


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "tests/c/test_merkle.c")
