"""Sim control loop (B-43.2 Chunk 2): per-vector controller decisions.

Calls the servant composite `decide` verb once per trace vector, so the
sim runs the FROZEN controller C (B-30-B-35) instead of replaying S/R/Q
as inputs (assumption b43-device-1, superseded here by b43-device-2).

SIM-OWNED CONFIG (not spec values, documented, never shipped as
measurements): risk W=2/ne=2/nx=2/dwell=2 for transitions inside short
traces (spec starts W=10/3/5/10); floors C0->L1/C1->L2/C2->L3 (demo-C
STUB table); gov tau_max large so normal runs never shed (shed tests
use tiny tau_max); workload fixed except Q-driven msg rate.

VECTOR MAPPING (trace vector -> decide args, all documented):
  inc24: [S*10, 0,0,0,0,0] — attack state becomes counter increments
    on channel 0 (the device observes attacks as counter bumps).
  hint: 1 iff a type-0 (risk-transition) event fires at this vector ts.
  profile: 1 (base traffic); risk band steps the floor basis up.
  msg_per_h: Q*3600; resend 0; msg_bytes M; tpq/tr/ta fixed
    3600/1800/60; taev/c2/readings/transcript/dsaverify fixed small.
  now: ts_us // 1_000_000 (trace clock is us; policy clock is s).
  admitted "010101"; lambda 0.0; margin 1.0; dtw 60.0; ebase 0.5;
  ectrl 0.2 (test_srv_ctl.py precedent).
"""
import struct
import subprocess
from pathlib import Path

ASSUMPTION_VERSION = "b43-device-2"

FTABLE = bytes([1, 2, 3, 1, 1, 1]).hex()  # min C0->L1/C1->L2/C2->L3,
# has all rows (the demo-C mapping, real here — not a STUB claim).
FCFG_H = ((3600).to_bytes(4, "big") + (600).to_bytes(4, "big") +
          (60).to_bytes(4, "big") + bytes([8])).hex()
RES_H = ((4096).to_bytes(4, "big") + (8192).to_bytes(4, "big") * 3 +
         (1).to_bytes(4, "big") * 4).hex()
_W6 = b"".join(struct.pack(">f", 1.0) for _ in range(6)).hex()
_CMAX6 = b"".join(struct.pack(">f", 10.0) for _ in range(6)).hex()
# W=2 (sim-owned; spec starts at 10): transitions fit short traces.
RISKFGC_SIM = (_W6 + _CMAX6 + struct.pack(">f", 0.7).hex() +
               struct.pack(">f", 0.3).hex() +
               (2).to_bytes(2, "big").hex() +
               (2).to_bytes(2, "big").hex() +
               (2).to_bytes(2, "big").hex() + bytes([2]).hex() +
               struct.pack(">f", 0.3).hex())
APREV = (bytes([3]) + (3600).to_bytes(4, "big") +
         (1800).to_bytes(4, "big") +
         (-1).to_bytes(4, "big", signed=True) + bytes([8])).hex()


def _f32(x):
    return struct.pack(">f", x).hex()


def _f64(x):
    return struct.pack(">d", x).hex()


def _repo():
    return Path(__file__).resolve().parents[2]


def _srv(*args):
    exe = _repo() / "build" / "server" / "srv_crypto"
    p = subprocess.run([str(exe), *[str(a) for a in args]],
                       capture_output=True, text=True, timeout=180)
    return p.returncode, p.stdout.split(), p.stderr


class ControlLoop:
    """One controller instance per campaign run (init once, decide/step)."""

    def __init__(self, taumax=100.0, rho=1.0, frac=0.5, dwell=3,
                 hmax=100, tcool=60):
        rc, out, err = _srv(
            "ctl-init", FTABLE, FCFG_H, RES_H, RISKFGC_SIM,
            _f32(taumax), _f64(rho), _f32(frac), str(dwell), str(hmax),
            str(tcool), APREV, "0")
        if rc != 0 or not out or out[0] != "0":
            raise RuntimeError(f"ctl-init failed: rc={rc} err={err[:200]}")
        self._blob = out[1]
        rc, out, err = _srv("ctl-energy-priors")
        if rc != 0 or len(out) < 2:
            raise RuntimeError("ctl-energy-priors failed")
        self._coeff = out[1]
        self.counters = {"decides": 0, "holds": 0, "sheds": 0,
                         "failsecures": 0, "queued": 0, "high_steps": 0}

    def _sample(self, comp, v0, v1, now="0"):
        rc, out, err = _srv("ctl-state-sample", self._blob, str(comp),
                            v0, v1, now)
        if rc != 0 or out[0] != "0":
            raise RuntimeError(f"state-sample c{comp} failed: {err[:200]}")
        self._blob = out[1]

    def prime(self, vector, now="0"):
        """Sample full state once from vector 0 (class C1 routine).

        Per-step dynamics ride risk increments + hints through decide;
        re-sampling static comps every step would 8x the hot path for
        no new information (documented, not hidden).
        """
        self._sample(0, _f32(float(vector["B"])), str(vector["soc"]),
                     now)
        self._sample(1, _f32(float(vector["R"])), "0", now)
        self._sample(2, "1", "0", now)
        self._sample(3, _f32(float(vector["C"])), "0", now)
        self._sample(4, "400000", "0", now)  # trace M is a replay stub
        # (1024); res.base_ram needs 4096, so provision realistic RAM.
        # Memory dynamics stay hardware scope (B-60), documented.
        self._sample(5, str(vector["L_rssi"]),
                     str(vector["L_retries"]), now)
        self._sample(6, _f32(float(vector["Q"])), "7", now)

    def refill(self, ehat_j=0.0, dt_s=3600.0):
        """Accrue rho*dt with no spend (idle refill for restore tests)."""
        rc, out, err = _srv("ctl-gov-charge", self._blob,
                            _f64(ehat_j), _f64(dt_s))
        if rc != 0:
            raise RuntimeError(f"gov-charge failed: {err[:200]}")
        self._blob = out[1]

    def apply_shed(self, action_hex, c0rate=1.0, c0min=0.5, tacap=600,
                   now=61):
        """Apply one shed step (stamps has_shed/last_shed for restore).

        A decide SHED code only RECOMMENDS; the governor records the
        application here (qc_gov_shed stamps last_shed). Returns the
        shed directive + exhausted flag.
        """
        rc, out, err = _srv("ctl-gov-shed", self._blob, _f64(c0rate),
                            action_hex, _f64(c0min), str(tacap), str(now))
        if rc != 0:
            raise RuntimeError(f"gov-shed failed: {err[:200]}")
        self._blob = out[1]
        return {"directive": out[2], "exhausted": out[3],
                "action": out[4]}

    def restore_ready(self, now, delta):
        rc, out, err = _srv("ctl-gov-restore-ready", self._blob,
                            str(now), str(delta))
        if rc != 0:
            raise RuntimeError(f"restore-ready failed: {err[:200]}")
        return out[1]

    def step(self, vector, hint=0):
        """Run one decide. Returns dict(rc, staged_profile|None, band)."""
        inc = ((vector["S"] * 10).to_bytes(4, "big") +
               (0).to_bytes(4, "big") * 5).hex()
        now = str(vector["ts"] // 1_000_000)
        args = [self._blob, inc, str(hint), "1",
                _f64(vector["Q"] * 3600.0), _f64(0.0),
                _f64(float(vector["M"])), "3600", "1800", "60",
                _f64(0.0), _f64(0.0), _f64(60.0), _f64(100.0),
                _f64(0.0), _f64(0.0), _f64(1.0), now, _f64(60.0),
                "010101", self._coeff, _f64(0.5), _f64(0.2)]
        rc, out, err = _srv("ctl-decide", *args)
        if rc != 0:
            raise RuntimeError(f"ctl-decide usage: {err[:200]}")
        self.counters["decides"] += 1
        code, blob = out[0], out[1]
        self._blob = blob
        staged, band = None, None
        if code == "0":
            staged = int(bytes.fromhex(out[3])[0])
        elif code == "1":
            pass
        elif code == "2":
            self.counters["failsecures"] += 1
        elif code == "3":
            self.counters["sheds"] += 1
            staged = int(bytes.fromhex(out[3])[0])
        elif code == "4":
            self.counters["holds"] += 1
        elif code == "5":
            self.counters["queued"] += 1
        else:
            raise RuntimeError(f"unknown decide code {code}")
        # Band reads out of the returned blob: magic(6) + state(126) +
        # riskcfg(67) = 199, then risk init(1)/state(1) -> byte 200.
        # Layout is versioned + exact-size-checked servant-side; the
        # init-band test below pins the offset (fresh init reads 0).
        band = int(bytes.fromhex(blob)[200:201].hex(), 16)
        if band == 1:
            self.counters["high_steps"] += 1
        return {"rc": code, "staged": staged, "band": band,
                "raw": out}
