"""Network-model tests (B-43.3): delivery, impairments, configs, reuse.

Deterministic (fixed seeds). Proves reuse, not re-implementation:
reassembly + relay + max-frame all resolve to the real qcgw objects.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "sim"))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "server"))

from qcsim import NetworkModel  # noqa: E402

SEED = "0123456789abcdef0123456789abcdef"


def _frames(n, size):
    return [bytes([(i + k) % 256 for k in range(size)]) for i in range(n)]


def _routable(n, size):
    frames = []
    for i in range(n):
        hdr = (bytes([(i * 7 + k) % 256 for k in range(16)]) +
               bytes([1, 2]) + (1000 + i).to_bytes(8, "big") +
               bytes(32) + (0).to_bytes(8, "big") + (0).to_bytes(8, "big"))
        body = bytes([(i + k) % 256 for k in range(size - len(hdr))])
        frames.append(hdr + body)
    return frames


def test_e2e_lossless_exact_and_deterministic():
    frames = _frames(4, 200)
    first, log1 = NetworkModel(SEED).send(frames)
    assert first == frames
    second, log2 = NetworkModel(SEED).send(frames)
    assert second == frames and log2 == log1  # bit-identical rerun
    assert all(e["fate"] == "sent" for e in log1)
    for mtu in (64, 1024):
        got, _ = NetworkModel(SEED, mtu=mtu).send(frames)
        assert got == frames


def test_loss_and_link_loss():
    frames = _frames(4, 200)
    got, log = NetworkModel(SEED, loss_rate=1.0).send(frames)
    assert got == [] and all(e["fate"] == "lost" for e in log)
    # Link-loss interval swallows the first two frames only.
    got, log = NetworkModel(SEED, loss_rate=0.0).send(
        frames, link_loss=[(0, 15000)])
    assert [e["fate"] for e in log] == ["link-loss", "link-loss",
                                        "sent", "sent"]
    assert got == frames[2:]


def test_trusted_config_routes_and_refuses():
    frames = _routable(3, 120)
    got, log = NetworkModel(SEED, config="trusted-gateway").send(frames)
    assert got == frames
    assert all(e["fate"] == "sent" for e in log)
    # Sub-header inputs refuse loudly (never padded into fakes).
    try:
        NetworkModel(SEED, config="trusted-gateway").send([b"short"])
        assert False
    except ValueError:
        pass
    for bad in ({"config": "bulk"}, {"loss_rate": 1.5}):
        try:
            NetworkModel(SEED, **bad)
            assert False
        except ValueError:
            pass


def test_real_qcgw_reuse():
    import qcgw.transports as qcgt
    import qcsim.network as qn
    assert qn.QC_MAX_FRAME == qcgt.QC_MAX_FRAME  # single source, cited
    assert qn.Reassembler is __import__(
        "qcgw.frag", fromlist=["Reassembler"]).Reassembler
    assert qn.E2ERelay is __import__(
        "qcgw.relay", fromlist=["E2ERelay"]).E2ERelay
