"""Fragmentation tests (B-42.4): vectors, bounds, timeouts, orphans.
Deterministic (fixed bytes/clocks throughout)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "server"))

from qcgw.frag import Reassembler, split_frame  # noqa: E402

MAXF = 4096


def _frame(cls, counter, nbytes):
    hdr = (bytes([0xD0 + (i % 16) for i in range(16)]) +
           bytes([cls, 1]) + counter.to_bytes(8, "big") + bytes(32) +
           (0).to_bytes(8, "big") + (0).to_bytes(8, "big"))
    return hdr + nbytes.to_bytes(4, "big") + bytes([0xA5]) * nbytes + \
        bytes(16)


def test_split_shapes():
    f = _frame(1, 7, 100)  # 74+4+100+16 = 194 B
    assert len(f) == 194
    frags = split_frame(f, 64, MAXF)
    # First carries kind+total+count; count covers all bytes exactly.
    assert frags[0][0] == 0
    assert int.from_bytes(frags[0][1:5], "big") == 194
    assert int.from_bytes(frags[0][5:7], "big") == len(frags)
    assert int.from_bytes(frags[0][7:9], "big") == 0
    assert frags[1][0] == 1  # others carry kind+index only
    assert all(len(x) <= 64 for x in frags)
    assert sum(len(x) - (9 if i == 0 else 3) for i, x in
               enumerate(frags)) == 194
    # Single-fragment small frame.
    small = _frame(0, 0, 4)
    one = split_frame(small, 1024, MAXF)
    assert len(one) == 1 and int.from_bytes(one[0][5:7], "big") == 1
    # Guards: empty, tiny mtu, oversize.
    try:
        split_frame(b"", 64, MAXF)
        assert False
    except ValueError:
        pass
    try:
        split_frame(f, 8, MAXF)
        assert False
    except ValueError:
        pass
    try:
        split_frame(f, 64, 100)
        assert False
    except ValueError:
        pass


def test_roundtrip_ordered():
    f = _frame(1, 7, 100)
    frags = split_frame(f, 64, MAXF)
    r = Reassembler(MAXF)
    out = None
    for i, x in enumerate(frags):
        status, got = r.feed(b"peer", 3, x, now=float(i))
        if i < len(frags) - 1:
            assert status == "incomplete" and got is None
        else:
            assert status == "complete"
            out = got
    assert out == f
    assert r.counters["completed"] == 1


def test_reversed_and_duplicates():
    f = _frame(2, 9, 200)
    frags = split_frame(f, 50, MAXF)
    r = Reassembler(MAXF)
    # Fully reversed delivery still completes (orphan pen works).
    for x in reversed(frags):
        status, got = r.feed(b"peer", 3, x, now=1.0)
    assert status == "complete" and got == f
    # Duplicate index: first wins, counted, no poisoning.
    r = Reassembler(MAXF)
    assert r.feed(b"p", 0, frags[0], now=0.0)[0] == "incomplete"
    status, _ = r.feed(b"p", 0, frags[0], now=0.0)
    assert status == "incomplete"
    assert r.counters["duplicates"] == 1
    for x in frags[1:]:
        status, got = r.feed(b"p", 0, x, now=0.0)
    assert status == "complete" and got == f


def test_interleave_and_bounds():
    fa = _frame(0, 1, 60)
    fb = _frame(1, 2, 60)
    aa = split_frame(fa, 64, MAXF)
    ab = split_frame(fb, 64, MAXF)
    r = Reassembler(MAXF, max_slots=4)
    # Interleave frag-for-frag: both complete independently.
    got = {}
    for i in range(max(len(aa), len(ab))):
        if i < len(aa):
            s, g = r.feed(b"p", 0, aa[i], now=0.0)
            if s == "complete":
                got["a"] = g
        if i < len(ab):
            s, g = r.feed(b"p", 0, ab[i], now=0.0)
            if s == "complete":
                got["b"] = g
    assert got == {"a": fa, "b": fb}
    # Slot bound: 6 concurrent frames in a 2-slot box drop oldest.
    r = Reassembler(MAXF, max_slots=2)
    heads = [split_frame(_frame(0, k, 60), 64, MAXF)[0]
             for k in range(6)]
    for h in heads:
        assert r.feed(b"p", 0, h, now=0.0)[0] == "incomplete"
    assert r.counters["bound_drops"] == 4
    # Timeout drop + sweep counting.
    r = Reassembler(MAXF, timeout_s=5.0)
    assert r.feed(b"p", 0, heads[0], now=0.0)[0] == "incomplete"
    assert r.sweep(now=4.9) == 0
    assert r.sweep(now=5.0) == 1
    assert r.counters["timeout_drops"] == 1


def test_malformed_and_oversize():
    r = Reassembler(MAXF)
    assert r.feed(b"p", 0, b"x", now=0.0)[0] == "drop-malformed"
    # Declared total over max: dropped pre-buffer, nothing stored.
    big = bytes([0]) + (99999).to_bytes(4, "big") + \
        (1).to_bytes(2, "big") + (0).to_bytes(2, "big") + bytes(30)
    assert r.feed(b"p", 0, big, now=0.0)[0] == "drop-oversize"
    assert r.counters["oversize"] == 1
    # Trailing garbage past total: malformed on completion.
    f = _frame(0, 0, 10)
    frags = split_frame(f, 64, MAXF)
    assert len(frags) == 2  # 74+4+10+16=104 > 64-9
    bad0 = bytearray(frags[0])
    bad0[1:5] = (200).to_bytes(4, "big")  # lie total upward
    status, _ = r.feed(b"p", 0, bytes(bad0), now=0.0)
    assert status == "incomplete"
    status, _ = r.feed(b"p", 0, frags[1], now=0.0)
    assert status == "drop-malformed"


def test_middle_frag_never_aliases_first():
    # Regression: the old length-based discrimination misparsed any
    # middle fragment with zero bytes at 6:8 as index-0 (data-dependent
    # black hole). With kind flags, a zero-laden middle fragment parks
    # as an orphan and the frame still completes.
    f = _frame(1, 7, 100)
    frags = split_frame(f, 64, MAXF)
    assert len(frags) >= 3
    # frags[1] covers zero header ranges — the old alias trigger.
    assert frags[1][0] == 1
    r = Reassembler(MAXF)
    assert r.feed(b"p", 0, frags[1], now=0.0)[0] == "incomplete"
    for x in (frags[0], frags[2], frags[3]):
        status, got = r.feed(b"p", 0, x, now=0.0)
    assert status == "complete" and got == f


def test_dup_after_complete_drops_replay():
    # Regression (audit-found poison): a duplicate tail arriving AFTER
    # its frame completed must drop as a replay — never park as an
    # orphan and never adopt into the next frame's slot (pre-fix the
    # adopted replay delivered wrong-but-well-formed bytes; with
    # distinct tails the reassembly even went drop-malformed).
    f0 = _frame(1, 7, 100)
    f1 = _frame(1, 8, 101)  # distinct tail/length so poisoning is visible
    a0 = split_frame(f0, 64, MAXF)
    a1 = split_frame(f1, 64, MAXF)
    r = Reassembler(MAXF)
    for x in a0:
        status, got = r.feed(b"p", 0, x, now=0.0)
    assert status == "complete" and got == f0
    # Duplicate tail after complete: replay, not a parkable orphan.
    # Same-tick feed (within timeout — the graveyard window is one
    # timeout wide by design; expiry is covered by the bounds test).
    dup = a0[-1]
    assert dup[0] == 1
    status, got = r.feed(b"p", 0, dup, now=1.0)
    assert status == "incomplete" and got is None
    assert r.counters["duplicates"] == 1
    assert r._orphans.get((b"p", 0), []) == []
    # Next frame still completes exactly (no poisoning).
    out = None
    for x in a1:
        status, out = r.feed(b"p", 0, x, now=1.0)
    assert status == "complete" and out == f1
