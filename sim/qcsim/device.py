"""Device model (B-43.2): executable protocol+controller composition.

Composes B-20-B-26 (handshake per B-20.2 wire math, KDF per B-21
order, pipeline checks per B-22 order via the verbs, epoch/counters
per B-23 values, framing per B-24 layout, ratchet per B-26 advance)
with the controller loop shape per B-34 order (B-31/B-32/B-33/B-35
enter as policy inputs, not re-implementations — cited, and the
assumption log below says exactly what is stubbed).

Functional crypto links the host backend through the servant
(subprocess isolation, identical primitives both ends — the same
math the demos run green): real algorithms for correctness-relevant
behavior (formats parse, tags verify, replays drop). Energy and time
come from caller-supplied model params (B-33 ASSUMED priors —
flagged in every manifest via the assumption version, never shipped
as measurements); host timing excluded (virtual clock only).

Implements the runner step_fn signature (system, trace, streams,
clock) so campaigns plug it in directly. One DeviceModel instance =
one device+server pair in a single process (no TCP here — transport
belongs to B-42/network layers, composed by the caller, never
rebuilt). Deterministic fixtures (fixed coins/keys) labeled; same
math as production, honest label.

ASSUMPTIONS (versioned model assumptions, B-43.2: stated per release,
never silent; tech-lead review at phase gate gives accept-or-rework):
  b43-device-1: single-process loop (no TCP/process split — see Demo D
    for the distributed proof); fixed handshake coins (fixtures);
    trace vectors carried as telemetry payloads (environment replay,
    not sensor sampling); energy from caller params (ASSUMED B-33
    priors); controller floor/risk/governor policies consumed as
    trace-supplied inputs (S/R/Q fields), not re-solved per step.
  b43-device-2: per-vector `decide` calls through sim/qcsim/control.py
    (frozen B-30-B-35 via the servant composite verb): staged profile
    + band recorded per step; S/R/Q still carried as telemetry
    payloads; mapping S->increments/Q->msg-rate documented in
    control.py; handshake + telemetry path unchanged.
"""
import subprocess
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .streams import RNGStreams

ASSUMPTION_VERSION = "b43-device-2"
LEVEL = 768


def _repo():
    return Path(__file__).resolve().parents[2]


def _srv(*args):
    exe = _repo() / "build" / "server" / "srv_crypto"
    p = subprocess.run([str(exe), *[str(a) for a in args]],
                       capture_output=True, text=True, timeout=180)
    if p.returncode != 0:
        raise RuntimeError(f"servant failed: {args[0]}")
    return p.stdout.split()


def _hx(b):
    return b.hex()


def _coins(*vals):
    return bytes(vals * 32)[:32]


def _sim(*args):
    exe = _repo() / "build" / "server" / "srv_crypto"
    p = subprocess.run([str(exe), *[str(a) for a in args]],
                       capture_output=True, text=True, timeout=180)
    if p.returncode != 0:
        raise RuntimeError(f"servant failed: {args[0]}: "
                           f"{p.stderr[:200]}")
    return p.stdout.split()


def _batch_new():
    out = _sim("sim-batch-new")
    assert out[0] == "0" and len(out) == 2, out
    return out[1]


def _batch_insert(blob, pt, cls, now=200):
    out = _sim("sim-batch-insert", blob, pt.hex(), str(cls), str(int(now)))
    assert out[0] == "0", out  # sim telemetry is C0/C1, tiny: never
    return out[1]              # FULL/C2_BYPASS (fail loud otherwise)


def _batch_ready(blob, nb, tc0=60, tc1=300, now=200):
    out = _sim("sim-batch-ready", blob, str(int(nb)), str(int(tc0)),
               str(int(tc1)), str(int(now)))
    return out[0]  # "0" OPEN / "1" COUNT / "2" LATENCY


def _batch_pop(blob, cap=4096, now=200):
    out = _sim("sim-batch-pop", blob, str(int(cap)), str(int(now)))
    rc = int(out[0])
    if rc != 0:
        return rc, out[1], None
    pt = bytes.fromhex(out[2])
    return rc, out[1], (pt, int(out[3]), int(out[4]))


def _batch_count(blob):
    out = _sim("sim-batch-count", blob)
    return int(out[0])


def _merkle_leaf(cls, counter, reading):
    out = _sim("sim-merkle-leaf", str(cls), str(counter),
               reading.hex())
    return out[0]


def _merkle_root(leaves):
    assert leaves, "never root an empty batch (caller policy)"
    out = _sim("sim-merkle-root", "".join(leaves))
    return out[0]


def _mft_check():
    """Fixture manifest roundtrip (deterministic): keypair, make v1,
    sign, enroll, verify-apply. Returns the verify rc (0 == applied)."""
    seed = bytes([0xA5]) * 32
    out = _srv("dsa-keypair", "65", seed.hex())
    pk, sk = bytes.fromhex(out[0]), bytes.fromhex(out[1])
    out = _sim("sim-mft-make", "1", "000101020203", "07", "100", "60",
               "50", "none")
    body = out[0]
    out = _srv("dsa-sign", "65", sk.hex(), body,
               (bytes([0x1B]) * 32).hex())
    sig = out[0]
    out = _sim("sim-mft-init", "65", pk.hex())
    assert out[0] == "0", out
    out = _sim("sim-mft-verify", out[1], body, sig, "5000")
    return int(out[0])


class DeviceModel:
    """Handshake once, then telemetry per trace vector (see module doc)."""

    def __init__(self, dev_id, kdev, seed_hex, energy=None):
        if not isinstance(dev_id, (bytes, bytearray)) or len(dev_id) != 16:
            raise ValueError("dev_id must be 16 bytes")
        if not isinstance(kdev, (bytes, bytearray)) or len(kdev) != 32:
            raise ValueError("kdev must be 32 bytes")
        self._dev_id = bytes(dev_id)
        self._kdev = bytes(kdev)
        self._streams = RNGStreams(seed_hex)
        self._energy = dict(energy or {"e_hs": 0.0, "e_frame": 0.0})
        self.assumptions = ASSUMPTION_VERSION
        self.counters = {"handshakes": 0, "frames_ok": 0,
                         "frames_dropped": 0, "replays_dropped": 0}

    def _m1(self, dev_ek, srv_pk, epoch, counter):
        out = _srv("sizes", "kem", str(LEVEL))
        pk_len, _, _ = int(out[0]), int(out[1]), int(out[2])
        assert len(dev_ek) == pk_len
        out = _srv("kem-encaps", str(LEVEL), srv_pk.hex(),
                   _hx(_coins(0x11)))
        ct_s, k1 = bytes.fromhex(out[0]), bytes.fromhex(out[1])
        nw = epoch.to_bytes(4, "big") + counter.to_bytes(8, "big")
        body = bytes([1]) + self._dev_id + bytes([2]) + dev_ek + ct_s + nw
        out = _srv("hmac", self._kdev.hex(), body.hex())
        return body + bytes.fromhex(out[0]), k1, nw

    def run(self, system, trace, streams, clock):
        """Execute one campaign run. Returns metrics dict (deterministic).

        Signature matches the runner step_fn contract (system, trace,
        streams, clock). The streams seed propagates into metrics as a
        recorded salt (pairing evidence) with zero crypto effect —
        handshake coins stay fixtures by design (see module doc).
        """
        from qcsrv import Registry
        from qcsrv.handshake import srv_handshake
        from qcsrv.ingress import srv_ingest
        from qcsim.control import ControlLoop
        import asyncio

        salt = streams.next_bytes("device", 8).hex()

        async def go():
            out = _srv("kem-keypair", str(LEVEL), _hx(bytes([7]) * 64))
            srv_pk, srv_sk = bytes.fromhex(out[0]), bytes.fromhex(out[1])
            ctx = {"registry": Registry(capacity=8, idle_timeout_s=10000),
                   "kem": {LEVEL: {"pk": srv_pk, "sk": srv_sk}},
                   "kdevs": {self._dev_id: self._kdev},
                   "floor": 1, "config": "E2E"}
            await ctx["registry"].enroll(self._dev_id, config="E2E",
                                         now=0.0)
            out = _srv("kem-keypair", str(LEVEL), _hx(bytes([8]) * 64))
            dev_ek, dev_sk = bytes.fromhex(out[0]), bytes.fromhex(out[1])
            m1, k1_dev, nw = self._m1(dev_ek, srv_pk, 1, 5)
            code, m2 = await srv_handshake(
                m1, ctx, coins_ns=_coins(0x22), coins_k2=_coins(0x33),
                now=100.0)
            assert code == "m2", code
            self.counters["handshakes"] += 1
            out = _srv("sizes", "kem", str(LEVEL))
            ct_len = int(out[2])
            ct_w, ns, mac = (m2[1:1 + ct_len],
                             m2[1 + ct_len:1 + ct_len + 32],
                             m2[1 + ct_len + 32:])
            out = _srv("kem-decaps", str(LEVEL), ct_w.hex(), dev_sk.hex())
            k2_dev = bytes.fromhex(out[0])
            out = _srv("hkdf-extract", _hx(nw + ns),
                       _hx(b"QC-HS" + k1_dev + k2_dev + self._kdev))
            prk = bytes.fromhex(out[0])
            out = _srv("sha256", _hx(m1 + m2[:-32]))
            th = bytes.fromhex(out[0])
            out = _srv("hkdf-expand", prk.hex(),
                       _hx(b"QC-TRANSCRIPT" + b"\x00" + th), "128")
            okm = bytes.fromhex(out[0])
            out = _srv("hmac", okm[96:128].hex(), _hx(m1 + m2[:-32]))
            assert bytes.fromhex(out[0]) == mac
            chain = okm[64:96]
            energy = self._energy["e_hs"]
            mft_rc = _mft_check()
            ok = 0
            ctl = ControlLoop()
            ctl.prime(trace["vectors"][0])
            hint_ts = {e["ts"] for e in trace.get("events", [])
                       if e.get("type") == 0}
            trail = []
            batch = _batch_new()
            rks = {}
            leaves = []
            roots = []
            batches = 0
            for ctr, vec in enumerate(trace["vectors"]):
                dec = ctl.step(vec, hint=1 if vec["ts"] in hint_ts else 0)
                trail.append({"staged": dec["staged"], "band": dec["band"],
                              "rc": dec["rc"]})
                pt = b"up-%d" % ctr
                out = _srv("hkdf-expand", chain.hex(),
                           _hx(b"ratchet" + (ctr + 1).to_bytes(8, "big")),
                           "96")
                chain = bytes.fromhex(out[0])[0:32]
                rks[ctr] = bytes.fromhex(out[0])[32:64]
                batch = _batch_insert(batch, pt, vec["S"])
                nb = dec["nb"] if dec["nb"] is not None else 8
                # TEST-BOUNDS tc0/tc1 (60/300, test values, labeled —
                # B-31 values these; the mechanism, not the numbers,
                # is what's under test here).
                if _batch_ready(batch, nb, 60, 300,
                                200.0 + ctr) != "0":
                    mark = len(leaves)
                    while _batch_count(batch) > 0:
                        rc, batch, got = _batch_pop(batch)
                        assert got is not None, "count>0 but pop failed"
                        p2, cls2, _age = got
                        # Self-describing payloads (up-<ctr>) recover
                        # the vector's key/counter — no parallel FIFO
                        # to desynchronize (asserted on every pop).
                        c2 = int(p2.split(b"-")[1])
                        assert p2 == b"up-%d" % c2, (p2, c2)
                        hdr = (self._dev_id + bytes([0, 1]) +
                               c2.to_bytes(8, "big") + bytes(32) +
                               (0).to_bytes(16))
                        nonce = ((1).to_bytes(4, "big") +
                                 c2.to_bytes(8, "big"))
                        ct = AESGCM(rks[c2]).encrypt(nonce, p2, hdr)
                        frame = (hdr + len(p2).to_bytes(4, "big") + ct)
                        code, reading = await srv_ingest(
                            frame, ctx, direction="c2s", now=200.0 + c2)
                        leaves.append(_merkle_leaf(cls2, c2, p2))
                        if code == "ok" and reading["payload"] == p2:
                            ok += 1
                            self.counters["frames_ok"] += 1
                            energy += self._energy["e_frame"]
                        else:
                            self.counters["frames_dropped"] += 1
                    roots.append(_merkle_root(leaves[mark:]))
                    batches += 1
            # End-of-run flush (session-close semantic): undrained
            # readings must still flow, preserving ok == frames.
            if _batch_count(batch) > 0:
                mark = len(leaves)
                while _batch_count(batch) > 0:
                    rc, batch, got = _batch_pop(batch)
                    assert got is not None, "count>0 but pop failed"
                    p2, cls2, _age = got
                    c2 = int(p2.split(b"-")[1])
                    assert p2 == b"up-%d" % c2, (p2, c2)
                    hdr = (self._dev_id + bytes([0, 1]) +
                           c2.to_bytes(8, "big") + bytes(32) +
                           (0).to_bytes(16))
                    nonce = ((1).to_bytes(4, "big") +
                             c2.to_bytes(8, "big"))
                    ct = AESGCM(rks[c2]).encrypt(nonce, p2, hdr)
                    frame = hdr + len(p2).to_bytes(4, "big") + ct
                    code, reading = await srv_ingest(
                        frame, ctx, direction="c2s", now=200.0 + c2)
                    leaves.append(_merkle_leaf(cls2, c2, p2))
                    if code == "ok" and reading["payload"] == p2:
                        ok += 1
                        self.counters["frames_ok"] += 1
                        energy += self._energy["e_frame"]
                    else:
                        self.counters["frames_dropped"] += 1
                roots.append(_merkle_root(leaves[mark:]))
                batches += 1
            # metrics (functional dispositions + ASSUMED-model energy)
            return {"system": system["system_id"],
                    "trace": trace["trace_id"], "handshake": "m2",
                    "frames": len(trace["vectors"]), "ok": ok,
                    "energy_j": round(energy, 9), "seed_salt": salt,
                    "assumptions": self.assumptions,
                    "decisions": trail,
                    "ctl": dict(ctl.counters),
                    "batches": batches, "roots": roots, "mft": mft_rc}

        return asyncio.run(go())
