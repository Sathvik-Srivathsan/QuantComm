"""Verifier verb tests (B-40.4): retention, roots, absence, C2.

Leaf/tree recomputed here with hashlib (independent construction of
the same spec text — agreement with the servant-built leaves proves
interop, not self-agreement). Signatures via the servant (fixed
seed/rnd). Deterministic throughout.
"""
import asyncio
import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "server"))

from qcsrv import AuditStore  # noqa: E402
from qcsrv.verifier import srv_verify  # noqa: E402
from test_srv_crypto import hx, run  # noqa: E402

DEV = "dev-B"
ID = bytes([0xB0 + i for i in range(16)])


def _frame(cls, counter, payload):
    hdr = (ID + bytes([cls, 1]) + counter.to_bytes(8, "big") +
           bytes(32) + (0).to_bytes(8, "big") + (0).to_bytes(8, "big"))
    return hdr + len(payload).to_bytes(4, "big") + payload + bytes(16)


def _root(frames):
    leaves = []
    for f, cls, counter in frames:
        h = hashlib.sha256()
        h.update(b"QC-ATTEST")
        h.update(bytes([cls]))
        h.update(counter.to_bytes(8, "big"))
        h.update(f)
        leaves.append(h.digest())
    cur = leaves
    while len(cur) > 1:
        nxt = []
        for i in range(0, len(cur), 2):
            if i + 1 < len(cur):
                h = hashlib.sha256()
                h.update(cur[i])
                h.update(cur[i + 1])
                nxt.append(h.digest())
            else:
                nxt.append(cur[i])
        cur = nxt
    return cur[0]


def _keys44seed(seed_byte):
    rc, out, _ = run("dsa-keypair", "44", hx(bytes([seed_byte]) * 32))
    assert rc == 0
    return bytes.fromhex(out[0]), bytes.fromhex(out[1])


def _keys44():
    return _keys44seed(5)


def test_absence_and_stale():
    async def go():
        ctx = {}
        code, _ = await srv_verify("submit", ctx, device=DEV, root=None,
                                   sig=None, pk=None, level=44)
        assert code == "absence-ok"
        code, _ = await srv_verify("retain", ctx, device=DEV,
                                   frames=[_frame(0, 0, b"r0")])
        assert code == "ok"
        code, _ = await srv_verify("submit", ctx, device=DEV, root=None,
                                   sig=None, pk=None, level=44)
        assert code == "alarm-stale"
        code, _ = await srv_verify("retain", ctx, device="x",
                                   frames=["nope"])
        assert code == "malformed"

    asyncio.run(go())


def test_verified_tamper_absence_sig():
    async def go():
        ctx = {}
        frames = [(f, c, k) for k, (f, c) in enumerate([
            (_frame(0, 0, b"a0"), 0),
            (_frame(1, 1, b"a1"), 1),
            (_frame(0, 2, b"a2"), 0),
        ])]
        raws = [f for f, _, _ in frames]
        code, dropped = await srv_verify("retain", ctx, device=DEV,
                                         frames=raws)
        assert code == "ok" and dropped == 0
        root = _root([(f, c, k) for f, c, k in frames])
        pk, sk = _keys44()
        rc, out, _ = run("dsa-sign", "44", sk.hex(), root.hex(),
                      hx(bytes([6]) * 32))
        assert rc == 0
        code, _ = await srv_verify("submit", ctx, device=DEV,
                                   root=root.hex(), sig=out[0],
                                   pk=pk.hex(), level=44, now=100.0)
        assert code == "verified"
        # Retained batch cleared after verify.
        code, _ = await srv_verify("submit", ctx, device=DEV,
                                   root=None, sig=None, pk=None,
                                   level=44)
        assert code == "absence-ok"
        # Tampered root: recompute mismatch (no DSA involved).
        await srv_verify("retain", ctx, device=DEV, frames=raws)
        bad = bytearray(root)
        bad[0] ^= 1
        code, _ = await srv_verify("submit", ctx, device=DEV,
                                   root=bytes(bad).hex(), sig=out[0],
                                   pk=pk.hex(), level=44)
        assert code == "alarm-tamper"
        # Right root, wrong signature: DSA rejects.
        rc, out2, _ = run("dsa-sign", "44", sk.hex(), root.hex(),
                       hx(bytes([7]) * 32))
        assert rc == 0
        bad2 = bytearray(bytes.fromhex(out2[0]))
        bad2[3] ^= 1
        code, _ = await srv_verify("submit", ctx, device=DEV,
                                   root=root.hex(),
                                   sig=bytes(bad2).hex(), pk=pk.hex(),
                                   level=44)
        assert code == "verify-fail"
        # Unsigned root never verifies (sig required when root given).
        code, _ = await srv_verify("submit", ctx, device=DEV,
                                   root=root.hex(), sig=None,
                                   pk=pk.hex(), level=44)
        assert code == "alarm-stale"

    asyncio.run(go())


async def _with_audit(audit):
    ctx = {"audit": audit}
    pk, sk = _keys44()
    frames = [_frame(0, 0, b"z0")]
    await srv_verify("retain", ctx, device=DEV, frames=frames)
    root = _root([(frames[0], 0, 0)])
    rc, out, _ = run("dsa-sign", "44", sk.hex(), root.hex(),
                      hx(bytes([6]) * 32))
    assert rc == 0
    code, _ = await srv_verify("submit", ctx, device=DEV,
                               root=root.hex(), sig=out[0],
                               pk=pk.hex(), level=44, now=50.0)
    assert code == "verified"
    recs = audit.query(source="verifier")
    assert len(recs) == 1 and recs[0]["hash_hex"] == root.hex()


def test_capacity_liveness_c2_audit():
    async def go():
        ctx = {"ret_cap": 2}
        frames = [_frame(0, k, bytes([k]) * 4) for k in range(4)]
        code, dropped = await srv_verify("retain", ctx, device=DEV,
                                         frames=frames)
        assert code == "ok" and dropped == 2
        assert ctx["_counters"]["retention-drops"] == 1
        # Liveness: nothing verified yet -> absence regime ok.
        code, _ = await srv_verify("liveness", ctx, device=DEV,
                                   now=999.0, ta_s=60)
        assert code == "ok"
        # C2 paths (AEAD pre-established by hypothesis here).
        pk, sk = _keys44()
        code, _ = await srv_verify("c2", ctx, sig=None, pk=None,
                                   level=44, msg="")
        assert code == "c2-unsigned-ok"
        rc, out, _ = run("dsa-sign", "44", sk.hex(), hx(b"alarm-bytes"),
                      hx(bytes([6]) * 32))
        assert rc == 0
        code, _ = await srv_verify("c2", ctx, sig=out[0], pk=pk.hex(),
                                   level=44, msg=hx(b"alarm-bytes"))
        assert code == "c2-signed-ok"
        pk9, _ = _keys44seed(9)
        code, _ = await srv_verify("c2", ctx, sig=out[0], pk=pk9.hex(),
                                   level=44, msg=hx(b"alarm-bytes"))
        assert code == "c2-bad-sig"

    import tempfile
    with tempfile.TemporaryDirectory() as td:
        audit = AuditStore(td + "/a.jsonl")
        asyncio.run(_with_audit(audit))

    asyncio.run(go())
