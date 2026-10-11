"""Provisioning ceremony tests (B-41.2-.5): enrollment atomicity,
rotation discipline, pins, compromise recovery, audit without secrets.

Ceremony model: generate (fixed vectors) -> write device NVS ->
readback-verify -> register server record (registry + credential store
+ manifest v1) -> confirm. Any step faulted -> unprovisioned (halt,
never partial). Deterministic throughout (no live randomness; nonces
and coins fixed and labeled).
"""
import asyncio
import hashlib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "server"))

from qcsrv import AuditStore, Registry  # noqa: E402
from qcsrv.handshake import srv_handshake  # noqa: E402
from qcsrv.policy import srv_policy  # noqa: E402
from qcsrv.registry import CredentialStore  # noqa: E402
from prov_helpers import (  # noqa: E402
    DeviceNVS, KdevSlots, unwrap_kdev, version_carry, wrap_kdev,
)
from test_handshake import _dev_ek, _m1, _coins  # noqa: E402
from test_srv_crypto import hx, run  # noqa: E402

DEV_ID = bytes(range(16))
KDEV = bytes([0xE0 + (i % 16) for i in range(32)])
STORE_MASTER = bytes([0xA5]) * 32
PRK_STUB = bytes([0xBE]) * 32  # stand-in session PRK (labeled stub)
NONCE = bytes(range(12))


def _srv_keys44(seed_byte=21):
    rc, out, _ = run("dsa-keypair", "44", hx(bytes([seed_byte]) * 32))
    assert rc == 0
    return bytes.fromhex(out[0]), bytes.fromhex(out[1])


def _mft_fields(version):
    return {
        "version": version,
        "floors": [(0, 1), (1, 2), (2, 3)],
        "profiles": [1, 2, 3],
        "hmax": 10,
        "t_cool": 3600,
        "c2_threshold": 50,
        "next_key": b"",
    }


async def _ceremony(tmp_path, fault=None, pre_enrolled=False):
    """Run the enrollment ceremony. fault names a step to break:
    write/readback/register/confirm. Returns (ok, state dict)."""
    nvs = DeviceNVS(str(tmp_path / "device.nvs"))
    reg = Registry(capacity=8, idle_timeout_s=10000)
    store = CredentialStore(STORE_MASTER)
    pk_s, sk_s = _srv_keys44()
    pk_sign, sk_sign = _srv_keys44(22)
    state = {"reg": reg, "store": store, "pk_s": pk_s, "sk_s": sk_s,
             "pk_sign": pk_sign, "sk_sign": sk_sign, "nvs": nvs}
    if pre_enrolled:
        assert await reg.enroll(DEV_ID, config="E2E", now=0.0) == "ok"
    # 1. generate (fixed vectors here; prod uses B-13 DRBG).
    kdev = KDEV
    # 2. write device NVS (id + kdev + root placeholder image).
    image = DEV_ID + kdev
    if fault == "write":
        nvs.fail_write = True
    if not nvs.write(image):
        return False, state
    # 3. readback-verify.
    if fault == "readback":
        nvs.corrupt_read = True
    if nvs.read() != image:
        return False, state
    # 4. register server record.
    if fault == "register":
        # Simulate a taken ID (duplicate): pre-enroll first.
        assert await reg.enroll(DEV_ID, config="E2E", now=0.0) in (
            "ok", "exists")
        return False, state
    if await reg.enroll(DEV_ID, config="E2E", now=1.0) != "ok":
        return False, state
    store.put(DEV_ID, kdev, "provisioning", NONCE)
    pctx = {}
    code, payload = await srv_policy(
        "issue", pctx, fields=_mft_fields(1), sk=sk_sign, level=44,
        rnd=bytes([3]) * 32)
    if code != "issued":
        return False, state
    state["manifest"] = payload
    # 5. confirm — refused confirmation rolls the WHOLE ceremony back
    # (registry entry removed WITHOUT tombstone, credential dropped,
    # device NVS wiped): halt means unprovisioned, never partial.
    if fault == "confirm":
        await reg.rollback_enroll(DEV_ID)
        store.delete(DEV_ID, "provisioning")
        nvs.wipe()
        return False, state
    return True, state


def test_ceremony_happy(tmp_path):
    async def go():
        ok, st = await _ceremony(tmp_path)
        assert ok is True
        ent = st["reg"].get(DEV_ID)
        assert ent is not None and ent.config == "E2E"
        assert st["store"].get(DEV_ID, "provisioning") == KDEV
        body_hex, sig_hex = st["manifest"]
        rc, _, _ = run("dsa-verify", "44", st["pk_sign"].hex(),
                       bytes.fromhex(body_hex).hex(), sig_hex)
        assert rc == 0
        assert st["nvs"].read() == DEV_ID + KDEV

    asyncio.run(go())


@pytest.mark.parametrize("fault",
                         ["write", "readback", "register", "confirm"])
def test_ceremony_atomicity(tmp_path, fault):
    async def go():
        ok, st = await _ceremony(tmp_path, fault=fault)
        assert ok is False
        # Unprovisioned: no usable server record or credential.
        ent = st["reg"].get(DEV_ID)
        assert ent is None or fault == "register"
        if fault != "register":
            assert st["store"].get(DEV_ID, "provisioning") is None

    asyncio.run(go())


def test_duplicate_and_tombstone(tmp_path):
    async def go():
        ok, st = await _ceremony(tmp_path)
        assert ok is True
        # Second ceremony for the same live ID refuses.
        ok2, _ = await _ceremony(tmp_path, pre_enrolled=True)
        assert ok2 is False
        # Decommission wipes NVS (verified) + tombstones.
        assert await st["reg"].decommission(DEV_ID) is True
        assert st["nvs"].wipe() is True
        assert st["reg"].get(DEV_ID) is None
        # Re-enrollment of a tombstoned ID refuses forever.
        assert await st["reg"].enroll(DEV_ID, now=2.0) == \
            "refuse-tombstoned"

    asyncio.run(go())


def test_store_roundtrip_and_roles():
    # CredentialStore over the servant (identical AES-GCM): roundtrip,
    # role separation, wrong-key refusal. Runs where servant runs.
    store = CredentialStore(STORE_MASTER)
    nonce = bytes(range(12))
    assert store.get(DEV_ID, "handshake") is None  # absent, not error
    assert store.put(DEV_ID, KDEV, "provisioning", nonce) is True
    assert store.get(DEV_ID, "handshake") == KDEV
    assert store.get(DEV_ID, "provisioning") == KDEV
    # Ciphertext is opaque and nonce-bound (never plaintext at rest).
    blob = store._blobs[DEV_ID]
    assert blob[1] != KDEV and blob[0] == nonce
    # Same Kdev under a fresh nonce differs (no nonce reuse observably).
    store.put(DEV_ID, KDEV, "provisioning", bytes([9]) * 12)
    assert store._blobs[DEV_ID][1] != blob[1]


def test_store_access_control(tmp_path):
    store = CredentialStore(STORE_MASTER)
    assert store.put(DEV_ID, KDEV, "provisioning", NONCE) is True
    assert store.get(DEV_ID, "handshake") == KDEV
    assert store.get(DEV_ID, "provisioning") == KDEV
    import pytest as _pt
    with _pt.raises(PermissionError):
        store.get(DEV_ID, "audit")
    with _pt.raises(PermissionError):
        store.put(DEV_ID, KDEV, "handshake", NONCE)
    with _pt.raises(PermissionError):
        store.delete(DEV_ID, "handshake")
    assert store.delete(DEV_ID, "provisioning") is True
    assert store.get(DEV_ID, "provisioning") is None
    with _pt.raises(ValueError):
        CredentialStore(b"short")
    with _pt.raises(ValueError):
        store.put(b"short", KDEV, "provisioning", NONCE)


def test_wrap_unwrap_roundtrip():
    nonce = bytes(range(12))
    new_k = bytes([0xF0 + (i % 16) for i in range(32)])
    n, ct, tag = wrap_kdev(PRK_STUB, DEV_ID, 5, new_k, nonce)
    assert unwrap_kdev(PRK_STUB, DEV_ID, 5, n, ct, tag) == new_k
    # Wrong version AAD fails closed (the operative manifest binding).
    assert unwrap_kdev(PRK_STUB, DEV_ID, 4, n, ct, tag) is None
    # Flipped ct fails closed.
    bad = bytearray(ct)
    bad[0] ^= 1
    assert unwrap_kdev(PRK_STUB, DEV_ID, 5, n, bytes(bad), tag) is None
    # Wrong device fails closed.
    assert unwrap_kdev(PRK_STUB, bytes([9]) * 16, 5, n, ct,
                       tag) is None


def test_swap_discipline_and_power_loss(tmp_path):
    slots = KdevSlots()
    k2 = bytes([0xF0 + (i % 16) for i in range(32)])
    slots.provision(KDEV)
    assert slots.active_key() == KDEV
    # Staged never authenticates.
    assert slots.stage(k2) is True
    assert slots.active_key() == KDEV
    # Power loss mid-swap (persisted image restored): old still live.
    snap = slots.snapshot()
    slots2 = KdevSlots()
    slots2.restore(snap)
    assert slots2.active_key() == KDEV
    # Confirm swaps atomically + erases old (verified).
    assert slots.confirm() is True
    assert slots.active_key() == k2
    # Confirm-timeout path keeps the old (fresh staged, no confirm).
    slots3 = KdevSlots()
    slots3.provision(KDEV)
    assert slots3.stage(k2) is True
    assert slots3.confirm_timeout() is True
    assert slots3.active_key() == KDEV
    assert slots3.staged() is None
    # Confirm with nothing staged refuses.
    assert slots3.confirm() is False
    _ = tmp_path


def test_rotation_full_path(tmp_path):
    async def go():
        # Enrolled world with a live handshake on old Kdev.
        ok, st = await _ceremony(tmp_path)
        assert ok is True
        reg, store = st["reg"], st["store"]
        # Rotation manifest v2 + wrapped new Kdev (session PRK stub).
        new_k = bytes([0xF0 + (i % 16) for i in range(32)])
        pctx = {}
        code, payload = await srv_policy(
            "issue", pctx, fields=_mft_fields(2), sk=st["sk_sign"],
            level=44, rnd=bytes([4]) * 32)
        assert code == "issued"
        body_hex, sig_hex = payload
        # Device verifies under the ENROLLED key, then unwraps.
        rc, _, _ = run("dsa-verify", "44", st["pk_sign"].hex(),
                       bytes.fromhex(body_hex).hex(), sig_hex)
        assert rc == 0
        n, ct, tag = wrap_kdev(PRK_STUB, DEV_ID, 2, new_k,
                               bytes([5]) * 12)
        assert unwrap_kdev(PRK_STUB, DEV_ID, 2, n, ct, tag) == new_k
        # Old-version rotation manifest refuses (version gate).
        code, _ = await srv_policy(
            "issue", pctx, fields=_mft_fields(1), sk=st["sk_sign"],
            level=44, rnd=bytes([4]) * 32)
        assert code == "refuse-stale"
        # Swap + confirm on the device model; server store rotates.
        slots = KdevSlots()
        slots.provision(KDEV)
        assert slots.stage(new_k) is True
        assert slots.confirm() is True
        assert slots.active_key() == new_k
        store.put(DEV_ID, new_k, "provisioning", bytes([6]) * 12)
        # New Kdev authenticates end-to-end (compromise recovered)...
        from qcsrv.handshake import srv_handshake
        rc, out, _ = run("kem-keypair", "768", hx(bytes([8]) * 64))
        assert rc == 0
        dev_ek = bytes.fromhex(out[0])
        rc, out, _ = run("kem-keypair", "768", hx(bytes([77]) * 64))
        assert rc == 0
        srv_pk, srv_sk = bytes.fromhex(out[0]), bytes.fromhex(out[1])
        hctx = {
            "registry": reg,
            "kem": {768: {"pk": srv_pk, "sk": srv_sk}},
            "kdevs": store,
            "floor": 1,
            "config": "E2E",
        }

        from test_handshake import _m1 as _mk

        def _mk1(kdev, epoch, coins):
            return _mk(dev_ek, srv_pk, epoch, 1, kdev, coins)

        m_new, _, _, _ = _mk1(new_k, 9, bytes([0x31]) * 32)
        code, m2 = await srv_handshake(m_new, hctx,
                                       coins_ns=bytes([0x32]) * 32,
                                       coins_k2=bytes([0x33]) * 32,
                                       now=900.0)
        assert code == "m2" and m2 is not None
        # ...and the OLD Kdev no longer does (superseded on sight).
        m_old, _, _, _ = _mk1(KDEV, 10, bytes([0x41]) * 32)
        code, _ = await srv_handshake(m_old, hctx,
                                      coins_ns=bytes([0x42]) * 32,
                                      coins_k2=bytes([0x43]) * 32,
                                      now=901.0)
        assert code == "drop-auth"

    asyncio.run(go())


def test_pin_and_compromise(tmp_path):
    async def go():
        ok, st = await _ceremony(tmp_path)
        assert ok is True
        # Untrusted pin: rotation manifest under the WRONG key refuses.
        _, sk_bad = _srv_keys44(99)
        pctx = {}
        code, payload = await srv_policy(
            "issue", pctx, fields=_mft_fields(2), sk=sk_bad, level=44,
            rnd=bytes([4]) * 32)
        assert code == "issued"  # signed, but not by the enrolled key
        rc, _, _ = run("dsa-verify", "44", st["pk_sign"].hex(),
                       bytes.fromhex(payload[0]).hex(), payload[1])
        assert rc == 4  # device-side pin check refuses (BAD_SIG)
        # Trusted re-pin path accepts (policy repin under ceremony).
        pk2, sk2 = _srv_keys44(23)
        code, _ = await srv_policy("repin", pctx, level=44, pk=pk2,
                                   sk=sk2)
        assert code == "repinned"
        # Server compromise: halt signing, sessions unaffected shape.
        code, _ = await srv_policy("halt", pctx)
        assert code == "halted"
        code, _ = await srv_policy(
            "issue", pctx, fields=_mft_fields(3), sk=sk2, level=44,
            rnd=bytes([4]) * 32)
        assert code == "halted"
        code, _ = await srv_policy("resume", pctx)
        assert code == "resumed"
        code, _ = await srv_policy(
            "issue", pctx, fields=_mft_fields(3), sk=sk2, level=44,
            rnd=bytes([4]) * 32)
        assert code == "issued"

    asyncio.run(go())


def test_version_carry_and_audit(tmp_path):
    from qcsrv import AuditStore
    from prov_helpers import version_carry
    assert version_carry(None, 7) == 8      # loss route
    assert version_carry(None, 0) == 1      # fresh genesis
    assert version_carry(5, 7) == 7         # never below a known max
    assert version_carry(9, 7) == 9
    with pytest.raises(ValueError):
        version_carry(0, 7)
    # Ceremony audit records carry IDs/versions, never secrets.
    audit = AuditStore(str(tmp_path / "ceremony.jsonl"))
    audit.append(1.0, "provision", "enrolled", DEV_ID.hex(),
                 hashlib.sha256(b"floor-table").hexdigest(), 1)
    audit.append(2.0, "rotation", "kdev-confirmed", DEV_ID.hex(),
                 hashlib.sha256(b"manifest-v2").hexdigest(), 2)
    raw = (tmp_path / "ceremony.jsonl").read_bytes()
    assert KDEV not in raw and KDEV.hex().encode() not in raw
    recs = audit.query(source="provision")
    assert len(recs) == 1 and recs[0]["dev_seq"] == 1
