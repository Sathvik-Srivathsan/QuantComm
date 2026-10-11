"""Ingress verb tests (B-40.3): AEAD open, window, ratchet receive.

The device harness advances an identical ratchet chain locally (manual
HKDF over hashlib — independent construction of the same spec text, so
roundtrips prove interop, not self-agreement). Deterministic throughout.
"""
import hashlib
import hmac as hmac_mod
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "server"))

from qcsrv import Registry  # noqa: E402
from qcsrv.ingress import srv_ingest  # noqa: E402
from test_handshake import (  # noqa: E402
    DEV_ID, KDEV, LEVEL, _dev_ek, _enroll, _m1, _world, _coins,
)

EPOCH = 1


def _hkdf_expand(prk, info, length):
    okm, t = b"", b""
    i = 1
    while len(okm) < length:
        t = hmac_mod.new(prk, t + info + bytes([i]),
                         hashlib.sha256).digest()
        okm += t
        i += 1
    return okm[:length]


class _Device:
    """Device-side harness (chain + counters mirror the server)."""

    def __init__(self, k_rat, epoch):
        self.chain = k_rat
        self.r = 0
        self.epoch = epoch

    def frame(self, cls, counter, payload, key_dir="c2s"):
        # Advance to r = counter+1 (may skip forward, capped by server).
        # Backward builds keep zero keys: the server gates them before
        # crypto, so their key bytes are never used (audit-noted).
        kc, ks = bytes(32), bytes(32)
        while self.r < counter + 1:
            self.r += 1
            blob = _hkdf_expand(self.chain, b"ratchet" +
                                self.r.to_bytes(8, "big"), 96)
            self.chain = blob[0:32]
            kc, ks = blob[32:64], blob[64:96]
        hdr = (DEV_ID + bytes([cls, 1]) + counter.to_bytes(8, "big") +
               bytes(32) + (0).to_bytes(8, "big") +
               (0).to_bytes(8, "big"))
        assert len(hdr) == 74
        key = kc if key_dir == "c2s" else ks
        nonce = self.epoch.to_bytes(4, "big") + \
            counter.to_bytes(8, "big")
        ct = AESGCM(key).encrypt(nonce, payload, hdr)
        return hdr + len(payload).to_bytes(4, "big") + ct


async def _established():
    ctx = _world()
    await _enroll(ctx)
    dev_ek, _ = _dev_ek()
    m1, _, _, _ = _m1(dev_ek, ctx["kem"][LEVEL]["pk"], EPOCH, 5,
                      KDEV, _coins(0x11))
    code, _ = await __import__(
        "qcsrv.handshake", fromlist=["srv_handshake"]
    ).srv_handshake(m1, ctx, coins_ns=_coins(0x22),
                    coins_k2=_coins(0x33), now=100.0)
    assert code == "m2"
    ent = ctx["registry"].get(DEV_ID)
    dev = _Device(ent.session_keys["k_rat"], EPOCH)
    return ctx, dev


@pytest.mark.asyncio
async def test_ok_and_fields():
    ctx, dev = await _established()
    f = dev.frame(1, 0, b"hello-0")
    code, reading = await srv_ingest(f, ctx, direction="c2s", now=200.0)
    assert code == "ok"
    assert reading["device"] == DEV_ID.hex()
    assert reading["class"] == 1 and reading["counter"] == 0
    assert reading["payload"] == b"hello-0"
    f = dev.frame(0, 1, b"hello-1")
    code, reading = await srv_ingest(f, ctx, direction="c2s", now=201.0)
    assert code == "ok" and reading["payload"] == b"hello-1"
    ent = ctx["registry"].get(DEV_ID)
    assert ent.ratchet_r == 2 and ent.window_high == 1


@pytest.mark.asyncio
async def test_s2c_direction():
    ctx, dev = await _established()
    f = dev.frame(1, 0, b"down-0", key_dir="s2c")
    code, reading = await srv_ingest(f, ctx, direction="s2c", now=200.0)
    assert code == "ok" and reading["payload"] == b"down-0"
    # Fresh s2c frame read as c2s: new counter, wrong key -> drop-auth.
    f2 = dev.frame(1, 1, b"down-1", key_dir="s2c")
    code, _ = await srv_ingest(f2, ctx, direction="c2s", now=201.0)
    assert code == "drop-auth"
    assert ctx["_counters"].get("auth-fail", 0) >= 1


@pytest.mark.asyncio
async def test_duplicate_stale_tamper():
    ctx, dev = await _established()
    f = dev.frame(1, 0, b"dup-0")
    code, reading = await srv_ingest(f, ctx, now=200.0)
    assert code == "ok" and reading["payload"] == b"dup-0"
    # Identical replay: duplicate (counter-gated before crypto).
    code, _ = await srv_ingest(f, ctx, now=201.0)
    assert code == "drop-duplicate"
    # Fresh counter, flipped ct byte: tag fails -> drop-auth.
    f3 = dev.frame(1, 6, b"new-6")
    bad = bytearray(f3)
    bad[80] ^= 1
    code, _ = await srv_ingest(bytes(bad), ctx, now=202.0)
    assert code == "drop-auth"
    assert ctx["_counters"].get("auth-fail", 0) == 1
    # Advance past it honestly, then seed a far horizon (white-box).
    code, _ = await srv_ingest(f3, ctx, now=203.0)
    assert code == "ok"
    ctx["registry"].get(DEV_ID).window_high = 1000
    # Counter 2 was never seen (not in window) and sits below the
    # horizon: stale (gated before crypto — device keys irrelevant).
    fgap = dev.frame(1, 2, b"gap-2")
    code, _ = await srv_ingest(fgap, ctx, now=204.0)
    assert code == "drop-stale"


@pytest.mark.asyncio
async def test_skip_and_overskip():
    ctx, dev = await _established()
    f = dev.frame(1, 0, b"s0")
    assert (await srv_ingest(f, ctx, now=200.0))[0] == "ok"
    # Jump +3 (within max-skip 16): fast-forward accepts.
    f = dev.frame(1, 3, b"s3")
    code, reading = await srv_ingest(f, ctx, now=201.0)
    assert code == "ok" and reading["payload"] == b"s3"
    assert ctx["registry"].get(DEV_ID).ratchet_r == 4
    # Jump +100: over-skip rejects (rekey orchestration is future).
    f = dev.frame(1, 103, b"s103")
    code, _ = await srv_ingest(f, ctx, now=202.0)
    assert code == "drop-overskip"


@pytest.mark.asyncio
async def test_shapes_and_nokey():
    ctx = _world()
    code, _ = await srv_ingest(b"short", ctx)
    assert code == "drop-malformed"
    code, _ = await srv_ingest(bytes(200), ctx)
    assert code == "drop-malformed"
    # Unknown device (valid structure, foreign identity).
    hdr = (b"\xEE" * 16 + bytes([0, 1]) + (0).to_bytes(8, "big") +
           bytes(32) + (0).to_bytes(16))
    f = hdr + (4).to_bytes(4, "big") + bytes(4 + 16)
    code, _ = await srv_ingest(f, ctx)
    assert code == "drop-unknown"
    # Enrolled but pre-handshake (no chain/keys): no session.
    await _enroll(ctx)
    f2 = DEV_ID + bytes([0, 1]) + (0).to_bytes(8, "big") + bytes(32) + \
        (0).to_bytes(16) + (4).to_bytes(4, "big") + bytes(4 + 16)
    code, _ = await srv_ingest(f2, ctx)
    assert code == "drop-nokey"
    with pytest.raises(ValueError):
        await srv_ingest(b"\x00" * 100, {})
