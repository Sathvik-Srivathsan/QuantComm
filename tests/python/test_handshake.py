"""Handshake verb tests (B-40.1 service): full device roundtrip plus
the disposition matrix. The device role runs in the harness over the
same servant (identical primitives both ends). Deterministic: fixed
coins/keys throughout; N_S and K2 coins explicit per call.
"""
import asyncio
import hashlib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "server"))

from qcsrv import Registry  # noqa: E402
from qcsrv.handshake import srv_handshake  # noqa: E402
from test_srv_crypto import hx, run  # noqa: E402

LEVEL = 768
WIRE = 2
KDEV = bytes([0xD0 + (i % 16) for i in range(32)])
DEV_ID = bytes(range(16))
FLOOR = 1


def _sizes():
    rc, out, _ = run("sizes", "kem", str(LEVEL))
    assert rc == 0
    return int(out[0]), int(out[1]), int(out[2])


def _server_keys():
    rc, out, _ = run("kem-keypair", str(LEVEL), hx(bytes([7]) * 64))
    assert rc == 0
    return {"pk": bytes.fromhex(out[0]), "sk": bytes.fromhex(out[1])}


def _dev_ek():
    rc, out, _ = run("kem-keypair", str(LEVEL), hx(bytes([8]) * 64))
    assert rc == 0
    return bytes.fromhex(out[0]), bytes.fromhex(out[1])


def _m1(dev_ek, srv_pk, epoch, counter, kdev, coins_w):
    pk_len, _, ct_len = _sizes()
    assert len(dev_ek) == pk_len
    rc, out, _ = run("kem-encaps", str(LEVEL), srv_pk.hex(), coins_w.hex())
    assert rc == 0
    ct_s, k1 = bytes.fromhex(out[0]), bytes.fromhex(out[1])
    nw = epoch.to_bytes(4, "big") + counter.to_bytes(8, "big")
    body = (bytes([1]) + DEV_ID + bytes([WIRE]) + dev_ek + ct_s + nw)
    rc, out, _ = run("hmac", kdev.hex(), body.hex())
    assert rc == 0
    return body + bytes.fromhex(out[0]), k1, ct_s, nw


def _world():
    sk = _server_keys()
    ctx = {
        "registry": Registry(capacity=8, idle_timeout_s=10000),
        "kem": {LEVEL: sk},
        "kdevs": {DEV_ID: KDEV},
        "floor": FLOOR,
        "config": "E2E",
    }
    return ctx


async def _enroll(ctx):
    reg = ctx["registry"]
    assert await reg.enroll(DEV_ID, config="E2E", now=0.0) == "ok"


def _coins(*vals):
    return bytes(vals * 32)[:32]


@pytest.mark.asyncio
async def test_full_roundtrip():
    ctx = _world()
    await _enroll(ctx)
    dev_ek, dev_sk = _dev_ek()
    m1, k1_dev, _, nw = _m1(dev_ek, ctx["kem"][LEVEL]["pk"], 1, 5,
                            KDEV, _coins(0x11))
    code, m2 = await srv_handshake(m1, ctx, coins_ns=_coins(0x22),
                                   coins_k2=_coins(0x33), now=100.0)
    assert code == "m2" and m2 is not None
    # Device side: parse M2, decaps K2, recompute KDF, verify confirm.
    _, _, ct_len = _sizes()
    assert m2[0] == 1 and len(m2) == 1 + ct_len + 32 + 32
    ct_w, ns, mac = m2[1:1 + ct_len], m2[1 + ct_len:1 + ct_len + 32], \
        m2[1 + ct_len + 32:]
    assert ns == _coins(0x22)
    rc, out, _ = run("kem-decaps", str(LEVEL), ct_w.hex(), dev_sk.hex())
    assert rc == 0
    k2_dev = bytes.fromhex(out[0])
    rc, out, _ = run("hkdf-extract", hx(nw + ns),
                  hx(b"QC-HS" + k1_dev + k2_dev + KDEV))
    assert rc == 0
    prk = bytes.fromhex(out[0])
    transcript = m1 + m2[:-32]
    rc, out, _ = run("sha256", hx(transcript))
    assert rc == 0
    th = bytes.fromhex(out[0])
    rc, out, _ = run("hkdf-expand", prk.hex(),
                  hx(b"QC-TRANSCRIPT" + b"\x00" + th), "128")
    assert rc == 0
    okm = bytes.fromhex(out[0])
    k_conf = okm[96:128]
    rc, out, _ = run("hmac", k_conf.hex(), hx(transcript))
    assert rc == 0 and bytes.fromhex(out[0]) == mac
    # Server-side keys match the device's.
    ent = ctx["registry"].get(DEV_ID)
    assert ent.session_keys["k_c2s"] == okm[0:32]
    assert ent.session_keys["k_rat"] == okm[64:96]
    assert ent.hs_epoch == 1 and ent.ratchet_r == 0
    assert bytes(ent.r_chain) == okm[64:96]
    assert ctx["_counters"]["handshake-attempt"] == 1
    # Identical retry resends identical M2 (no fresh crypto).
    code2, m2b = await srv_handshake(m1, ctx, coins_ns=_coins(0x99),
                                     coins_k2=_coins(0x99), now=101.0)
    assert code2 == "resend" and m2b == m2


@pytest.mark.asyncio
async def test_parse_matrix():
    ctx = _world()
    await _enroll(ctx)
    dev_ek, _ = _dev_ek()
    m1, _, _, _ = _m1(dev_ek, ctx["kem"][LEVEL]["pk"], 1, 5, KDEV,
                      _coins(0x11))
    assert await srv_handshake(b"short", ctx, coins_ns=_coins(1),
                               coins_k2=_coins(2)) == ("drop-parse", None)
    bad = bytearray(m1)
    bad[0] = 2
    assert await srv_handshake(bytes(bad), ctx, coins_ns=_coins(1),
                               coins_k2=_coins(2)) == ("drop-parse", None)
    bad = bytearray(m1)
    bad[17] = 9
    assert await srv_handshake(bytes(bad), ctx, coins_ns=_coins(1),
                               coins_k2=_coins(2)) == ("drop-parse", None)
    assert await srv_handshake(m1[:-1], ctx, coins_ns=_coins(1),
                               coins_k2=_coins(2)) == ("drop-parse", None)
    assert await srv_handshake("not-bytes", ctx, coins_ns=_coins(1),
                               coins_k2=_coins(2)) == ("drop-parse", None)
    assert ctx["_counters"]["parse-fail"] == 5


@pytest.mark.asyncio
async def test_admission_matrix():
    ctx = _world()
    dev_ek, _ = _dev_ek()
    m1, _, _, _ = _m1(dev_ek, ctx["kem"][LEVEL]["pk"], 1, 5, KDEV,
                      _coins(0x11))
    # Unknown first (no enrollment at all).
    code, _ = await srv_handshake(m1, ctx, coins_ns=_coins(1),
                                  coins_k2=_coins(2))
    assert code == "drop-unknown"
    await _enroll(ctx)
    await ctx["registry"].blacklist(DEV_ID, True)
    code, _ = await srv_handshake(m1, ctx, coins_ns=_coins(1),
                                  coins_k2=_coins(2))
    assert code == "drop-blacklisted"
    await ctx["registry"].blacklist(DEV_ID, False)
    code, _ = await srv_handshake(m1, ctx, coins_ns=_coins(1),
                                  coins_k2=_coins(2), now=10.0)
    # Cross-config: entry E2E vs server trusted-gateway.
    ctx["config"] = "trusted-gateway"
    code, _ = await srv_handshake(m1, ctx, coins_ns=_coins(1),
                                  coins_k2=_coins(2))
    assert code == "drop-config"
    ctx["config"] = "E2E"
    # Identical retry with different caller coins: coins are irrelevant
    # on a cache hit (no crypto runs) -> resend, not drop-auth (audit
    # correction: first cut expected the coins check first, but the
    # cache short-circuit precedes it by design).
    code, m2b = await srv_handshake(m1, ctx, coins_ns=b"short",
                                    coins_k2=_coins(2))
    assert code == "resend" and m2b is not None
    # Fresh key with bad coins reaches the KEM stage -> drop-auth.
    m1n, _, _, _ = _m1(dev_ek, ctx["kem"][LEVEL]["pk"], 9, 1, KDEV,
                       _coins(0x21))
    code, _ = await srv_handshake(m1n, ctx, coins_ns=b"short",
                                  coins_k2=_coins(2), now=20.0)
    assert code == "drop-auth"


@pytest.mark.asyncio
async def test_auth_epoch_replay_floor():
    ctx = _world()
    await _enroll(ctx)
    dev_ek, _ = _dev_ek()
    pk_len, _, ct_len = _sizes()
    m1, _, _, _ = _m1(dev_ek, ctx["kem"][LEVEL]["pk"], 1, 5, KDEV,
                      _coins(0x11))
    # Bad HMAC.
    bad = bytearray(m1)
    bad[-1] ^= 1
    assert await srv_handshake(bytes(bad), ctx, coins_ns=_coins(1),
                               coins_k2=_coins(2)) == ("drop-auth", None)
    assert ctx["_counters"]["auth-fail"] == 1
    # Good epoch-2 first, then epoch-1 is old.
    m1b, _, _, _ = _m1(dev_ek, ctx["kem"][LEVEL]["pk"], 2, 1, KDEV,
                       _coins(0x12))
    code, _ = await srv_handshake(m1b, ctx, coins_ns=_coins(0x21),
                                  coins_k2=_coins(0x31), now=100.0)
    assert code == "m2"
    code, _ = await srv_handshake(m1, ctx, coins_ns=_coins(1),
                                  coins_k2=_coins(2), now=101.0)
    assert code == "drop-epoch"
    # Equal pair, different bytes: replay-ambiguous, drop safe.
    m1c, _, _, _ = _m1(dev_ek, ctx["kem"][LEVEL]["pk"], 2, 1, KDEV,
                       _coins(0x13))
    assert m1c != m1b  # different coins, same epoch/counter
    code, _ = await srv_handshake(m1c, ctx, coins_ns=_coins(1),
                                  coins_k2=_coins(2), now=102.0)
    assert code == "drop-epoch"
    # Expired resend window: identical M1 past t_hs drops + counts.
    code, _ = await srv_handshake(m1b, ctx, coins_ns=_coins(1),
                                  coins_k2=_coins(2), now=10000.0)
    assert code == "drop-replay"
    assert ctx["_counters"]["replay-drop"] == 1
    # Floor: L=2 below floor 3 (valid M1, honest level).
    ctx["floor"] = 3
    m1d, _, _, _ = _m1(dev_ek, ctx["kem"][LEVEL]["pk"], 3, 1, KDEV,
                       _coins(0x14))
    code, _ = await srv_handshake(m1d, ctx, coins_ns=_coins(1),
                                  coins_k2=_coins(2), now=103.0)
    assert code == "drop-floor"
    assert ctx["_counters"]["floor-refusal"] == 1


@pytest.mark.asyncio
async def test_kem_faults_end_to_end():
    ctx = _world()
    await _enroll(ctx)
    dev_ek, _ = _dev_ek()
    # Tampered ct_S (white-box re-MAC): server returns m2 (cannot tell),
    # but device-side keys diverge (implicit rejection, end to end).
    m1, k1_dev, _, nw = _m1(dev_ek, ctx["kem"][LEVEL]["pk"], 5, 1,
                            KDEV, _coins(0x11))
    pk_len, _, ct_len = _sizes()
    off = 1 + 16 + 1 + pk_len
    bad = bytearray(m1)
    bad[off + 3] ^= 1
    rc, out, _ = run("hmac", KDEV.hex(), bytes(bad[:-32]).hex())
    assert rc == 0
    m1t = bytes(bad[:-32]) + bytes.fromhex(out[0])
    code, m2t = await srv_handshake(m1t, ctx, coins_ns=_coins(0x22),
                                    coins_k2=_coins(0x33), now=200.0)
    assert code == "m2" and m2t is not None
    ent = ctx["registry"].get(DEV_ID)
    # Precise proof: same handshake cleanly in ctx2 must yield
    # different session keys (server decapsulated tampered ct here).
    ctx2 = _world()
    await _enroll(ctx2)
    code, m2c = await srv_handshake(m1, ctx2, coins_ns=_coins(0x22),
                                    coins_k2=_coins(0x33), now=200.0)
    assert code == "m2"
    assert ctx2["registry"].get(DEV_ID).session_keys != \
        ent.session_keys
    # Modulus-invalid ek (all 0xFF fails canonical check) aborts.
    # Fresh epoch (evades both the bar and the tampered-ct cache key).
    badek = bytearray(m1)
    badek[18:18 + pk_len] = b"\xff" * pk_len
    nw_off = 18 + pk_len + ct_len
    badek[nw_off:nw_off + 4] = (6).to_bytes(4, "big")
    badek[nw_off + 4:nw_off + 12] = (1).to_bytes(8, "big")
    rc, out, _ = run("hmac", KDEV.hex(), bytes(badek[:-32]).hex())
    assert rc == 0
    code, _ = await srv_handshake(bytes(badek[:-32]) +
                                  bytes.fromhex(out[0]), ctx,
                                  coins_ns=_coins(1), coins_k2=_coins(2),
                                  now=201.0)
    assert code == "abort-encaps"


@pytest.mark.asyncio
async def test_cache_lru_bounded():
    # Audit note: eviction is white-box asserted (key absence), never
    # dispositionally — the epoch bar shadows evicted entries (any
    # re-offered older M1 drops on epoch first), so no disposition can
    # distinguish evicted from cached for old keys. Design consequence,
    # documented, not a gap: the cache serves retries, the bar kills
    # replays; both verified on their own paths above.
    ctx = _world()
    ctx["cache_cap"] = 2
    await _enroll(ctx)
    dev_ek, _ = _dev_ek()
    pk_len, _, ct_len = _sizes()
    keys = []
    for ep in (1, 2, 3):
        m1, _, _, _ = _m1(dev_ek, ctx["kem"][LEVEL]["pk"], ep, 1,
                          KDEV, bytes([ep]) * 32)
        code, _ = await srv_handshake(m1, ctx,
                                      coins_ns=bytes([ep + 9]) * 32,
                                      coins_k2=bytes([ep + 19]) * 32,
                                      now=100.0 * ep)
        assert code == "m2"
        off = 18 + pk_len
        nw = m1[off + ct_len:off + ct_len + 12]
        hct = hashlib.sha256(m1[off:off + ct_len]).digest()
        keys.append(DEV_ID + ep.to_bytes(4, "big") + nw + hct)
    assert len(ctx["_cache"]) == 2
    assert keys[0] not in ctx["_cache"]  # LRU victim
    assert keys[1] in ctx["_cache"] and keys[2] in ctx["_cache"]
