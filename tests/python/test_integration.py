"""Full-stack integration (B-40+B-42 composition): device M1 through
TCP to the handshake verb, M2 back, then telemetry through relay+TCP
into ingress. Bootstrap M1 travels direct (association binds only
after HMAC-verified identity — the relay refuses unverified bindings
by design); everything after rides the relay. Deterministic (fixed
coins/keys throughout).
"""
import asyncio
import hashlib
import sys
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "server"))

from qcsrv import Registry  # noqa: E402
from qcsrv.handshake import srv_handshake  # noqa: E402
from qcsrv.ingress import srv_ingest  # noqa: E402
from qcgw.relay import E2ERelay  # noqa: E402
from qcgw.transports import tcp_pair  # noqa: E402
from test_handshake import _coins, _dev_ek, _m1  # noqa: E402
from test_srv_crypto import hx, run  # noqa: E402

DEV_ID = bytes(range(16))
KDEV = bytes([0xD0 + (i % 16) for i in range(32)])
LEVEL = 768


def _keys(level, seed_byte):
    rc, out, _ = run("kem-keypair", str(level),
                     hx(bytes([seed_byte]) * 64))
    assert rc == 0
    return bytes.fromhex(out[0]), bytes.fromhex(out[1])


def _send_recv(pair, payload):
    ep_send, ep_recv = pair
    ep_send.send(payload)
    for _ in range(20):
        status, got = ep_recv.recv()
        assert status in ("ok", "empty"), status
        if status == "ok":
            return got
    raise AssertionError("transport never delivered")


def test_handshake_over_tcp():
    async def go():
        srv_pk, srv_sk = _keys(LEVEL, 7)
        ctx = {
            "registry": Registry(capacity=8, idle_timeout_s=10000),
            "kem": {LEVEL: {"pk": srv_pk, "sk": srv_sk}},
            "kdevs": {DEV_ID: KDEV},
            "floor": 1,
            "config": "E2E",
        }
        await ctx["registry"].enroll(DEV_ID, config="E2E", now=0.0)
        dev_ek, dev_sk = _keys(LEVEL, 8)
        m1, k1_dev, _, _ = _m1(dev_ek, srv_pk, 1, 5, KDEV,
                               _coins(0x11))
        # Bootstrap direct over TCP (no association exists yet).
        ta, tb, _ = tcp_pair(mtu=1024)
        try:
            got = _send_recv((ta, tb), m1)
            code, m2 = await srv_handshake(
                got, ctx, coins_ns=_coins(0x22), coins_k2=_coins(0x33),
                now=100.0)
            assert code == "m2"
            back = _send_recv((tb, ta), m2)
            # Device verifies M2 fully (parse + decaps + KDF + MAC).
            _, _, ct_len = _sizes()
            assert back[0] == 1
            ct_w = back[1:1 + ct_len]
            ns = back[1 + ct_len:1 + ct_len + 32]
            mac = back[1 + ct_len + 32:]
            assert ns == _coins(0x22)
            rc, out, _ = run("kem-decaps", str(LEVEL), ct_w.hex(),
                             dev_sk.hex())
            assert rc == 0
            return ctx, (ta, tb), (m1, m2)
        finally:
            ta.close()
            tb.close()

    def _sizes():
        rc, out, _ = run("sizes", "kem", str(LEVEL))
        assert rc == 0
        return int(out[0]), int(out[1]), int(out[2])

    asyncio.run(go())


def test_session_through_relay_tcp():
    async def go():
        srv_pk, srv_sk = _keys(LEVEL, 7)
        ctx = {
            "registry": Registry(capacity=8, idle_timeout_s=10000),
            "kem": {LEVEL: {"pk": srv_pk, "sk": srv_sk}},
            "kdevs": {DEV_ID: KDEV},
            "floor": 1,
            "config": "E2E",
        }
        await ctx["registry"].enroll(DEV_ID, config="E2E", now=0.0)
        dev_ek, _ = _keys(LEVEL, 8)
        m1, _, _, _ = _m1(dev_ek, srv_pk, 1, 5, KDEV, _coins(0x11))
        code, m2 = await srv_handshake(
            m1, ctx, coins_ns=_coins(0x22), coins_k2=_coins(0x33),
            now=100.0)
        assert code == "m2"
        ent = ctx["registry"].get(DEV_ID)
        # Relay binds AFTER verified identity (the honest order).
        relay = E2ERelay()
        assert relay.associate("ble-1", DEV_ID.hex(), verified=True)
        ta, tb, _ = tcp_pair(mtu=256)
        try:
            chain = ent.session_keys["k_rat"]
            for ctr, pt in ((0, b"up-0"), (1, b"up-1")):
                rc, out, _ = run(
                    "hkdf-expand", chain.hex(),
                    hx(b"ratchet" + (ent.ratchet_r + 1).to_bytes(
                        8, "big")), "96")
                assert rc == 0
                o96 = bytes.fromhex(out[0])
                chain = o96[0:32]
                hdr = (DEV_ID + bytes([0, 1]) +
                       ctr.to_bytes(8, "big") + bytes(32) +
                       (0).to_bytes(16))
                nonce = (1).to_bytes(4, "big") + \
                    ctr.to_bytes(8, "big")
                ct = AESGCM(o96[32:64]).encrypt(nonce, pt, hdr)
                frame = hdr + len(pt).to_bytes(4, "big") + ct
                # Device -> relay -> TCP -> server ingress.
                code, relayed = relay.relay(frame, "ble-1")
                assert code == "relayed" and relayed == frame
                at_srv = _send_recv((ta, tb), relayed)
                code, reading = await srv_ingest(
                    at_srv, ctx, direction="c2s", now=200.0 + ctr)
                assert code == "ok"
                assert reading["payload"] == pt
                assert reading["counter"] == ctr
            assert relay.counters["relayed"] == 2
            assert relay.counters["drop_unknown"] == 0
        finally:
            ta.close()
            tb.close()

    asyncio.run(go())
