"""Policy verb tests (B-40.2): issuance, monotonicity, divergence,
rotation, structural refusal. Signing roundtrips through the servant
(identical DSA); custody boundary asserted (no key retention probed
by handle swap). Deterministic (fixed seeds/rnd). Async verbs driven
synchronously (no marker needed in this file).
"""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "server"))

from qcsrv.policy import encode_manifest, srv_policy  # noqa: E402
from test_srv_crypto import hx, run  # noqa: E402


def _keys44(seed_byte=1):
    rc, out, _ = run("dsa-keypair", "44", hx(bytes([seed_byte]) * 32))
    assert rc == 0
    return bytes.fromhex(out[0]), bytes.fromhex(out[1])


def _fields(version=3):
    return {
        "version": version,
        "floors": [(0, 1), (1, 2), (2, 3)],
        "profiles": [1, 2, 3],
        "hmax": 10,
        "t_cool": 3600,
        "c2_threshold": 50,
        "next_key": b"",
    }


async def _issue(ctx, version, sk, rnd):
    return await srv_policy("issue", ctx, fields=_fields(version),
                            sk=sk, level=44, rnd=rnd)


def test_issue_roundtrip():
    async def go():
        ctx = {}
        pk, sk = _keys44()
        rnd = bytes([2]) * 32
        code, payload = await _issue(ctx, 3, sk, rnd)
        assert code == "issued"
        body_hex, sig_hex = payload
        # Servant verifies what the verb signed (identical DSA).
        rc, _, _ = run("dsa-verify", "44", pk.hex(),
                       bytes.fromhex(body_hex).hex(), sig_hex)
        assert rc == 0
        # Monotonic: re-signing older-or-equal refuses, emits nothing.
        code, payload = await _issue(ctx, 3, sk, rnd)
        assert code == "refuse-stale" and payload is None
        code, payload = await _issue(ctx, 2, sk, rnd)
        assert code == "refuse-stale" and payload is None
        code, payload = await _issue(ctx, 5, sk, rnd)
        assert code == "issued" and payload is not None

    asyncio.run(go())


def test_divergence():
    async def go():
        ctx = {}
        _, sk = _keys44()
        await _issue(ctx, 3, sk, bytes([2]) * 32)
        code, v = await srv_policy("check", ctx, device_version=1)
        assert code == "issue-current" and v == 3
        code, v = await srv_policy("check", ctx, device_version=3)
        assert code == "issue-current" and v == 3
        code, v = await srv_policy("check", ctx, device_version=9)
        assert code == "hold-ahead" and v == 3  # never downgrade
        assert ctx["_ahead_alarms"] == 1

    asyncio.run(go())


def test_repin_custody():
    async def go():
        ctx = {}
        pk1, sk1 = _keys44(1)
        pk2, sk2 = _keys44(9)
        code, _ = await srv_policy("repin", ctx, level=44, pk=pk1,
                                   sk=sk1)
        assert code == "repinned"
        assert ctx["_signing"]["pk"] == pk1
        # Old handle fully replaced (nothing retained).
        code, _ = await srv_policy("repin", ctx, level=44, pk=pk2,
                                   sk=sk2)
        assert code == "repinned"
        assert ctx["_signing"]["pk"] == pk2
        assert ctx["_signing"]["sk"] == sk2
        code, _ = await srv_policy("repin", ctx, level=44, pk=None,
                                   sk=sk2)
        assert code == "malformed"

    asyncio.run(go())


def test_structural_refusal():
    async def go():
        ctx = {}
        _, sk = _keys44()
        rnd = bytes([2]) * 32

        async def bad(**kw):
            fields = _fields(3)
            fields.update(kw)
            return await srv_policy("issue", ctx, fields=fields,
                                    sk=sk, level=44, rnd=rnd)

        assert (await bad(floors=[(1, 2), (0, 1)]))[0] == "malformed"
        assert (await bad(floors=[]))[0] == "malformed"
        assert (await bad(profiles=[]))[0] == "malformed"
        assert (await bad(version=0))[0] == "malformed"
        code, _ = await srv_policy("issue", ctx, fields=_fields(3),
                                   sk=sk, level=99, rnd=rnd)
        assert code == "malformed"
        code, _ = await srv_policy("issue", ctx, fields=_fields(3),
                                   sk=sk, level=44, rnd=b"short")
        assert code == "malformed"
        code, _ = await srv_policy("nope", ctx)
        assert code == "bad-op"
        assert encode_manifest({}) is None

    asyncio.run(go())
