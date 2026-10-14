"""Staging tests (B-43 Chunk 3): batch/Merkle/manifest verbs, guard units.

Servant-backed (needs build/server/srv_crypto): run under WSL/CI.
Guard unit tests are pure-Python (run anywhere).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "sim"))

from qcsim._guard import check_package, scan_source  # noqa: E402
from qcsim.device import _batch_count  # noqa: E402
from qcsim.device import (_batch_insert, _batch_new, _batch_pop,
                          _batch_ready, _mft_check, _merkle_leaf,
                          _merkle_root)  # noqa: E402

import subprocess  # noqa: E402


def _srv(*args):
    exe = (Path(__file__).resolve().parents[2] / "build" / "server" /
           "srv_crypto")
    p = subprocess.run([str(exe), *[str(a) for a in args]],
                       capture_output=True, text=True, timeout=180)
    assert p.returncode == 0, (args[0], p.stderr[:200])
    return p.stdout.split()


def test_batch_roundtrip():
    b = _batch_new()
    assert _batch_count(b) == 0
    for i in range(3):
        b = _batch_insert(b, b"r%d" % i, i % 2)
    assert _batch_count(b) == 3
    assert _batch_ready(b, 8, 60, 300, 200) == "0"  # OPEN
    assert _batch_ready(b, 3, 60, 300, 200) == "1"  # COUNT
    seen = []
    while _batch_count(b) > 0:
        rc, b, got = _batch_pop(b)
        assert rc == 0 and got is not None
        seen.append(got[0])
    assert seen == [b"r0", b"r1", b"r2"]  # FIFO
    assert _batch_count(b) == 0
    # C2 refused (bypass, not stored); empty pop is EMPTY.
    rc, b2, got = _batch_pop(b)
    assert rc != 0 and got is None
    b = _batch_new()
    out = _srv("sim-batch-insert", b, b"x".hex(), "2", "200")
    assert out[0] == "3", out  # C2_BYPASS
    assert _batch_count(out[1]) == 0


def test_merkle_roundtrip_and_tamper():
    leaves = [_merkle_leaf(0, i, b"r%d" % i) for i in range(4)]
    root = _merkle_root(leaves)
    assert len(bytes.fromhex(root)) == 32
    out = _srv("sim-merkle-prove", "".join(leaves), "2")
    depth, proof = int(out[0]), out[1]
    assert depth > 0
    rc = subprocess.run(
        [str(Path(__file__).resolve().parents[2] / "build" / "server" /
             "srv_crypto"), "sim-merkle-verify", leaves[2], "4", "2",
         proof, root]).returncode
    assert rc == 0
    bad = ("00" if proof[:2] != "00" else "ff") + proof[2:]
    rc = subprocess.run(
        [str(Path(__file__).resolve().parents[2] / "build" / "server" /
             "srv_crypto"), "sim-merkle-verify", leaves[2], "4", "2",
         bad, root]).returncode
    assert rc != 0  # tampered proof fails closed


def test_mft_roundtrip_and_stale():
    assert _mft_check() == 0  # fixture: make/sign/enroll/verify-apply
    # Stale re-verify: store holds v2, v1 re-applied refuses pre-verify
    # (zero public-key work on the stale path — the gate, not the sig).
    seed = bytes([0xA5]) * 32
    out = _srv("dsa-keypair", "65", seed.hex())
    pk, sk = bytes.fromhex(out[0]), bytes.fromhex(out[1])
    rnd = (bytes([0x1B]) * 32).hex()
    out = _srv("sim-mft-init", "65", pk.hex())
    assert out[0] == "0", out
    store = out[1]
    bodies = []
    for ver, now in (("1", "5000"), ("2", "5010")):
        out = _srv("sim-mft-make", ver, "000101020203", "07", "100",
                   "60", "50", "none")
        body = out[0]
        bodies.append(body)
        out = _srv("dsa-sign", "65", sk.hex(), body, rnd)
        out = _srv("sim-mft-verify", store, body, out[0], now)
        assert out[0] == "0", (ver, out)
        store = out[1]
    out = _srv("dsa-sign", "65", sk.hex(), bodies[0], rnd)
    out = _srv("sim-mft-verify", store, bodies[0], out[0], "5020")
    assert out[0] != "0", out  # STALE refuses (3 verifies < 6/hour cap)


def test_guard_units():
    assert scan_source("import os\nx = 1\n") == (0, 0)
    assert scan_source("import time\n") == (1, 0)
    assert scan_source("# import time\n") == (0, 0)
    assert scan_source('x = "import time"\n') == (0, 0)
    assert scan_source('"""doc\nimport time\n"""\n') == (0, 0)
    assert scan_source("a = os.urandom(16)\n") == (0, 1)
    assert scan_source("a = os.urandom(16)  # seeder\n") == (0, 1)
    # CI pattern pairing: every documented CI pattern is covered.
    from qcsim._guard import CI_PATTERNS
    for pat in CI_PATTERNS:
        b, _ = scan_source(pat + "\n")
        assert b == 1, pat


def test_guard_live_package():
    import qcsim
    assert check_package(
        Path(qcsim.__file__).resolve().parent) is True


def test_device_run_stages():
    """End-to-end wiring: batch close -> Merkle root, mft applied."""
    from qcsim import DeviceModel, SimClock
    from qcsim.streams import RNGStreams
    from qcsim.traces import generate_traces
    seed = "0123456789abcdef0123456789abcdef"
    dev_id = bytes(range(16))
    kdev = bytes([0xD0 + (i % 16) for i in range(32)])
    system = {"system_id": "S5", "controller": True,
              "floor_bypass": False, "backend": "host-build-staging",
              "kind": "adaptive", "profile": {}}
    trace = generate_traces("E7gen", seed, n=1)[0]
    trace = dict(trace, vectors=trace["vectors"][:6])
    model = DeviceModel(dev_id, kdev, seed,
                        energy={"e_hs": 1.5, "e_frame": 0.1})
    metrics = model.run(system, trace, RNGStreams(seed), SimClock())
    assert metrics["ok"] == metrics["frames"] == 6, metrics
    assert metrics["mft"] == 0, metrics
    assert metrics["batches"] >= 1, metrics
    assert len(metrics["roots"]) == metrics["batches"], metrics
    assert all(len(bytes.fromhex(r)) == 32 for r in metrics["roots"])
    assert len(metrics["decisions"]) == 6, metrics
