"""Control-loop tests (B-43.2 Chunk 2 / B-43.7 device-model evidence).

Servant-backed (needs build/server/srv_crypto): run under WSL/CI.
Crafted fixture traces (no Markov luck): exact step counts derived
from the sim config (W=2/ne=2/nx=2/dwell=2, cmax=10, INC attack=10).

Covers B-43.7's device-model trio: floor enforcement, hysteresis
transitions, bucket shed/restore gating (the mechanical restore-step
is pure math in the C suite; here we prove the gate).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "sim"))

from qcsim.control import ControlLoop  # noqa: E402


def _vec(s, ts, q=1.0):
    return {"S": s, "ts": ts, "Q": q, "M": 1024, "B": 1.0, "soc": 100,
            "R": 0.05, "C": 1.0, "L_rssi": -60, "L_retries": 0}


# Clocks start past tcool=60 (last_switch=0 at init): steps at now=0
# would HOLD on cooldown and prove nothing about argmin/bucket.
T0 = 61_000_000


def test_band_offset_pin():
    loop = ControlLoop()
    loop.prime(_vec(0, T0), "61")
    d = loop.step(_vec(0, T0))
    assert d["rc"] == "0", d
    assert d["band"] == 0, d  # fresh init reads NORMAL at byte 200


def test_floor_enforcement():
    loop = ControlLoop()
    loop.prime(_vec(0, T0), "61")
    for i in range(6):
        d = loop.step(_vec(0, T0 + i * 1_000_000))
        assert d["rc"] in ("0", "4"), d
        # HOLD keeps a_prev (profile 3); staged profiles face C1 floor.
        eff = d["staged"] if d["staged"] is not None else 3
        assert eff >= 2, d  # C1 floor admits SL2/SL3 only


def test_hysteresis_transitions():
    loop = ControlLoop()
    loop.prime(_vec(0, T0), "61")
    seq = ([_vec(0, T0 + i * 1_000_000) for i in range(3)] +
           [_vec(1, T0 + (3 + i) * 1_000_000) for i in range(4)] +
           [_vec(0, T0 + (7 + i) * 1_000_000) for i in range(8)])
    bands = [loop.step(v)["band"] for v in seq]
    assert bands[0] == 0, bands
    assert 1 in bands[3:7], bands  # attack region enters HIGH
    assert bands[-1] == 0, bands  # flush + streak exits
    joined = "".join(map(str, bands))
    assert "01" in joined and "10" in joined, bands


def test_shed_then_restore_gate():
    loop = ControlLoop(taumax=1e-6)
    loop.prime(_vec(0, T0), "61")
    d = loop.step(_vec(0, T0))
    assert d["rc"] == "3", d  # SHED: es dwarfs the tiny bucket
    assert d["staged"] is not None, d
    assert loop.counters["sheds"] == 1
    applied = loop.apply_shed(d["raw"][3], now=61)
    assert applied["exhausted"] == "0", applied
    loop.refill(ehat_j=0.0, dt_s=3600.0)
    assert loop.restore_ready(2000, 60) == "1", "refill + dwell opens"


def test_double_run_deterministic():
    def once():
        loop = ControlLoop()
        loop.prime(_vec(0, T0), "61")
        return [(d["rc"], d["band"])
                for d in (loop.step(_vec(i % 2, T0 + i * 1_000_000))
                          for i in range(4))]
    assert once() == once()
