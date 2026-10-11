"""No-plaintext discipline test (B-40 module boundary): key material
and telemetry plaintext must appear NOWHERE outside the session-
termination module (live registry RAM + returned sink readings).

Method: run a full handshake + ingress with MARKED secrets, snapshot
every persisted/logged/retained byte to a directory, and scan for the
markers in raw AND hex form. Markers must be ABSENT from audit JSONL,
logs, manifests, retention files — and PRESENT in the sink readings
and registry snapshot (proving the scan is not vacuous).
Deterministic (fixed coins/keys throughout).
"""
import asyncio
import hashlib
import logging
import pickle
import sys
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "server"))

from qcsrv import AuditStore, Registry  # noqa: E402
from qcsrv.handshake import srv_handshake  # noqa: E402
from qcsrv.ingress import srv_ingest  # noqa: E402
from qcsrv.verifier import srv_verify  # noqa: E402
from test_handshake import _dev_ek, _m1, _coins  # noqa: E402
from test_srv_crypto import hx, run  # noqa: E402

KDEV = b"KDEV-MARKER-0123456789abcdef" + bytes([0xD0, 0xD1, 0xD2,
                                                           0xD3])
assert len(KDEV) == 32
PT1 = b"PLAINTEXT-MARKER-frame-zero-000"
PT2 = b"PLAINTEXT-MARKER-frame-one-1111"
DEV_ID = bytes(range(16))
LEVEL = 768


def _scan_marker(root, markers):
    """Return {marker: [files containing it raw or hex]}."""
    found = {m: [] for m in markers}
    for path in sorted(Path(root).rglob("*")):
        if not path.is_file():
            continue
        data = path.read_bytes()
        for m in markers:
            if m in data or m.hex().encode() in data:
                found[m].append(str(path))
    return found


def test_no_plaintext_outside_module(tmp_path):
    async def go():
        # Logging capture (module loggers only; root handler here).
        log_path = tmp_path / "server.log"
        handler = logging.FileHandler(log_path, encoding="utf-8")
        root = logging.getLogger()
        root.addHandler(handler)
        root.setLevel(logging.INFO)
        try:
            # Provision + handshake with marked Kdev.
            rc, out, _ = run("kem-keypair", str(LEVEL),
                          hx(bytes([7]) * 64))
            assert rc == 0
            srv_pk, srv_sk = (bytes.fromhex(out[0]),
                              bytes.fromhex(out[1]))
            ctx = {
                "registry": Registry(capacity=8, idle_timeout_s=10000),
                "kem": {LEVEL: {"pk": srv_pk, "sk": srv_sk}},
                "kdevs": {DEV_ID: KDEV},
                "floor": 1,
                "config": "E2E",
            }
            reg = ctx["registry"]
            assert await reg.enroll(DEV_ID, config="E2E", now=0.0) == "ok"
            dev_ek, _ = _dev_ek()
            m1, _, _, _ = _m1(dev_ek, srv_pk, 1, 5, KDEV, _coins(0x11))
            code, m2 = await srv_handshake(
                m1, ctx, coins_ns=_coins(0x22), coins_k2=_coins(0x33),
                now=100.0)
            assert code == "m2"
            ent = reg.get(DEV_ID)
            sess_keys = [ent.session_keys["k_c2s"],
                         ent.session_keys["k_s2c"],
                         ent.session_keys["k_rat"]]
            # Ingress two marked payloads (chain from K_rat, servant
            # HKDF exactly like the verifier-side derivation).
            chain = ent.session_keys["k_rat"]
            readings = []
            wire_frames = []
            for ctr, pt in ((0, PT1), (1, PT2)):
                rc, out, _ = run(
                    "hkdf-expand", chain.hex(),
                    hx(b"ratchet" + (ent.ratchet_r + 1).to_bytes(
                        8, "big")), "96")
                assert rc == 0
                o96 = bytes.fromhex(out[0])
                chain = o96[0:32]
                kc = o96[32:64]
                hdr = (DEV_ID + bytes([0, 1]) +
                       ctr.to_bytes(8, "big") + bytes(32) +
                       (0).to_bytes(16))
                nonce = (1).to_bytes(4, "big") + \
                    ctr.to_bytes(8, "big")
                ct = AESGCM(kc).encrypt(nonce, pt, hdr)
                frame = hdr + len(pt).to_bytes(4, "big") + ct
                wire_frames.append(frame)
                code, reading = await srv_ingest(
                    frame, ctx, direction="c2s", now=200.0 + ctr)
                assert code == "ok"
                readings.append(reading)
            # Audit records (hashes only — never secrets).
            audit = AuditStore(str(tmp_path / "audit.jsonl"))
            audit.append(300.0, "handshake", "m2-issued", DEV_ID.hex(),
                         hashlib.sha256(m2).hexdigest(), 1)
            audit.append(301.0, "erasure", "keys-erased", DEV_ID.hex(),
                         hashlib.sha256(b"classes-only").hexdigest(), 2)
            # Verifier retention (wire ciphertext only).
            vctx = {"audit": audit}
            code, _ = await srv_verify("retain", vctx, device="dev",
                                       frames=wire_frames)
            assert code == "ok"
            return readings, sess_keys
        finally:
            root.removeHandler(handler)
            handler.close()

    readings, sess_keys = asyncio.run(go())
    # Sink outputs carry plaintext (decrypt works — not vacuous)...
    assert readings[0]["payload"] == PT1
    assert readings[1]["payload"] == PT2
    # ...and the in-module RAM snapshot carries keys AND sink readings
    # (both allowed in-module; snapshotting the readings also keeps the
    # PT scan non-vacuous — audit fix: sink outputs otherwise never
    # touch disk by design, which made the PT scan meaningless).
    snap = tmp_path / "ram-snapshot.pkl"
    snap.write_bytes(pickle.dumps({"keys": sess_keys, "kdev": KDEV,
                                   "sink": readings}))
    markers = [KDEV, PT1, PT2, *sess_keys]
    found = _scan_marker(tmp_path, markers)
    # The ONLY file allowed to contain markers is the RAM snapshot.
    for m in markers:
        others = [p for p in found[m] if Path(p).name != snap.name]
        assert others == [], (m[:16], others)
    assert found[KDEV] != [] and found[PT1] != []  # scan not vacuous
    # The audit file itself carries hashes, never secrets.
    audit_raw = (tmp_path / "audit.jsonl").read_bytes()
    assert b"KDEV-MARKER" not in audit_raw
    assert b"PLAINTEXT-MARKER" not in audit_raw
