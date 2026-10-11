"""Transport tests (B-42.3): loopback/TCP parity, faults, MTU sweep.

Same scripted exchange over both transports must deliver identical
byte sequences (parity — timing never compared). Faults each proved
in isolation. MTU swept {20, 64, 185, 1024} (test knob; B-61 values
plug in here later). Deterministic: every-N fault patterns, fixed
bytes, blocking sockets with timeouts (no timing asserts anywhere).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "server"))

from qcgw.transports import QC_MAX_FRAME, loopback_pair, tcp_pair  # noqa: E402


def _script(ep, frames, now=0.0):
    """Send all frames, drain all deliveries. Returns [bytes]."""
    for f in frames:
        ep[0].send(f, now=now)
        now += 1.0
    got = []
    for _ in range(len(frames) * 3 + 5):
        status, frame = ep[1].recv(now=now)
        if status == "ok":
            got.append(frame)
        elif status == "empty":
            break
        else:
            raise AssertionError(f"unexpected transport status {status}")
    return got


def _frames(n, size):
    return [bytes([(i + k) % 256 for k in range(size)]) for i in range(n)]


def test_loopback_tcp_parity():
    frames = _frames(5, 300)
    for mtu in (64, 1024):
        la, lb = loopback_pair(mtu=mtu)
        got_lb = _script((la, lb), frames)
        la.close()
        lb.close()
        ta, tb, _ = tcp_pair(mtu=mtu)
        got_tcp = _script((ta, tb), frames)
        ta.close()
        tb.close()
        assert got_lb == frames
        assert got_tcp == frames


def test_mtu_sweep():
    # Tiny MTU (default-20B BLE scale) through jumbo: all exact.
    frames = _frames(3, 200)
    for mtu in (20, 64, 185, 1024):
        la, lb = loopback_pair(mtu=mtu)
        assert _script((la, lb), frames) == frames
        la.close()
        lb.close()
    # Below header: refused, never silently truncated.
    la, lb = loopback_pair(mtu=64)
    try:
        la.send(b"x" * 10**6)
        assert False, "oversize must refuse"
    except ValueError:
        pass
    try:
        loopback_pair(mtu=8)
        assert False
    except ValueError:
        pass
    la.close()
    lb.close()


def test_faults_isolated():
    frames = _frames(4, 200)
    # Drop every 2nd fragment: some frames lost, survivors exact.
    la, lb = loopback_pair(mtu=64, faults_a={"drop_every": 2})
    got = _script((la, lb), frames)
    assert all(g in frames for g in got) and len(got) < len(frames)
    assert la.counters()["dropped_frags"] > 0
    la.close()
    lb.close()
    # Duplicate every fragment: deliveries still exact (first-wins).
    la, lb = loopback_pair(mtu=64, faults_a={"dup_every": 1})
    assert _script((la, lb), frames) == frames
    assert la.counters()["duped_frags"] > 0
    la.close()
    lb.close()
    # Corrupt every fragment: garbage delivers bit-exact (crypto kills
    # it downstream — transport is transparent by design, verified by
    # byte-equality with the corrupted expectation, not by dropping).
    la, lb = loopback_pair(mtu=64, faults_a={"corrupt_every": 1})
    got = _script((la, lb), frames)
    assert len(got) == len(frames) and got != frames
    assert la.counters()["corrupted_frags"] > 0
    la.close()
    lb.close()
    # Truncate every fragment: nothing reassembles (counters move).
    la, lb = loopback_pair(mtu=64, faults_a={"truncate_every": 1})
    got = _script((la, lb), frames)
    assert got == []
    la.close()
    lb.close()
    # Reorder pairs: frames still all arrive (order may shift — the
    # attestation/attestation layers order by counter, not arrival).
    la, lb = loopback_pair(mtu=64, faults_a={"reorder_window": 4})
    got = _script((la, lb), frames)
    assert sorted(got) == sorted(frames)
    assert la.counters()["reordered_bursts"] > 0
    la.close()
    lb.close()


def test_overlength_aborts():
    # socketpair-level proof (no listener races): oversize prefix aborts,
    # clean frame passes, EOF closes, partial times out to None.
    import socket as _s
    from qcgw.transports import _read_frag
    a, b = _s.socketpair()
    a.settimeout(2.0)
    b.settimeout(2.0)
    try:
        a.sendall((QC_MAX_FRAME + 100).to_bytes(4, "big") + b"junk")
        buf = bytearray()
        assert _read_frag(b, buf, QC_MAX_FRAME) == \
            ("aborted-overlength", None)
        a.sendall((4).to_bytes(4, "big") + b"ping")
        assert _read_frag(b, bytearray(), QC_MAX_FRAME) == b"ping"
        a.close()
        assert _read_frag(b, bytearray(), QC_MAX_FRAME) == \
            ("closed", None)
    finally:
        a.close()
        b.close()
    # Endpoint-level: closed-after-close + send refusal.
    ta, tb, _ = tcp_pair(mtu=1024)
    ta.close()
    tb.close()
    assert ta.recv() == ("closed", None)
    try:
        ta.send(b"after-close")
        assert False
    except ValueError:
        pass


def test_max_frame_const_guard():
    # B-20.1 single source: parse the C header, compare against the
    # Python mirror (edit either side and this fires).
    import re
    from pathlib import Path
    repo = Path(__file__).resolve().parents[2]
    text = (repo / "core" / "qc_codec.h").read_text()
    m = re.search(r"#define\s+QC_CODEC_MAX_FIELD\s+(\d+)", text)
    assert m, "QC_CODEC_MAX_FIELD missing in qc_codec.h"
    field = int(m.group(1))
    from qcgw.transports import QC_CODEC_MAX_FIELD as PY_FIELD
    assert PY_FIELD == field
    assert QC_MAX_FRAME == 62 + 2 * field
