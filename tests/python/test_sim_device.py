"""Device-model tests (B-43.2): handshake + telemetry loop, determinism.

Servant-backed (needs build/server/srv_crypto): run under WSL/CI,
never skipped silently — without the servant these FAIL (bridge
raises), exactly as specified. Deterministic fixtures throughout.
"""
import inspect
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "sim"))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "server"))

from qcsim import DeviceModel, SimClock, generate_traces  # noqa: E402
from qcsim.streams import RNGStreams  # noqa: E402

SEED = "0123456789abcdef0123456789abcdef"
DEV_ID = bytes(range(16))
KDEV = bytes([0xD0 + (i % 16) for i in range(32)])
SYSTEM = {"system_id": "S5", "controller": True, "floor_bypass": False,
          "backend": "host-build-b43-device-2",
          "kind": "adaptive", "profile": {}}


def _tiny_trace(nvectors=6):
    trace = generate_traces("E7gen", SEED, n=1)[0]
    trace = dict(trace, vectors=trace["vectors"][:nvectors])
    return trace


def test_interface_matches_runner_contract():
    sig = inspect.signature(DeviceModel.run)
    assert list(sig.parameters) == ["self", "system", "trace",
                                    "streams", "clock"]


def test_handshake_and_telemetry_loop():
    model = DeviceModel(DEV_ID, KDEV, SEED,
                        energy={"e_hs": 1.5, "e_frame": 0.1})
    metrics = model.run(SYSTEM, _tiny_trace(),
                        RNGStreams(SEED), SimClock())
    assert metrics["handshake"] == "m2"
    assert metrics["frames"] == 6 and metrics["ok"] == 6
    assert metrics["energy_j"] == 1.5 + 6 * 0.1
    assert metrics["assumptions"] == "b43-device-2"
    assert model.counters["handshakes"] == 1
    assert model.counters["frames_ok"] == 6


def test_deterministic_double_run():
    trace = _tiny_trace()
    first = DeviceModel(DEV_ID, KDEV, SEED).run(
        SYSTEM, trace, RNGStreams(SEED), SimClock())
    second = DeviceModel(DEV_ID, KDEV, SEED).run(
        SYSTEM, trace, RNGStreams(SEED), SimClock())
    assert first == second


def test_bad_args_refuse():
    for dev, kdev in ((b"short", KDEV), (DEV_ID, b"short")):
        try:
            DeviceModel(dev, kdev, SEED)
            assert False
        except ValueError:
            pass
