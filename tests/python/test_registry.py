"""Registry unit tests (B-40.1): admission gates, lifecycle, silence,
capacity, concurrency. Deterministic (fixed IDs/clocks, asyncio only).
"""
import asyncio
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "server"))

from qcsrv import Registry  # noqa: E402

ID_A = bytes(range(16))
ID_B = bytes([0xFF - i for i in range(16)])


def _ids(n, base=0x30):
    return [bytes([base + i] * 16) for i in range(n)]


@pytest.mark.asyncio
async def test_enroll_admit_happy():
    reg = Registry(capacity=4, idle_timeout_s=100)
    assert await reg.enroll(ID_A, config="E2E", now=10.0) == "ok"
    assert await reg.enroll(ID_A) == "exists"
    code, ent = await reg.admit(ID_A, "E2E")
    assert code == "ok"
    assert ent.device_id == ID_A
    assert ent.config == "E2E"


@pytest.mark.asyncio
async def test_enroll_validation():
    reg = Registry(capacity=4, idle_timeout_s=100)
    with pytest.raises(ValueError):
        await reg.enroll(b"short", "E2E")
    with pytest.raises(ValueError):
        await reg.enroll("not-bytes", "E2E")
    with pytest.raises(ValueError):
        await reg.enroll(ID_A, config="nope")
    with pytest.raises(ValueError):
        Registry(capacity=0, idle_timeout_s=100)
    with pytest.raises(ValueError):
        Registry(capacity=4, idle_timeout_s=0)


@pytest.mark.asyncio
async def test_admission_gates():
    reg = Registry(capacity=4, idle_timeout_s=100)
    code, ent = await reg.admit(ID_A)
    assert code == "drop-unknown" and ent is None
    assert reg.counters["unknown_drops"] == 1
    await reg.enroll(ID_A, config="E2E", now=0.0)
    await reg.blacklist(ID_A, True)
    code, ent = await reg.admit(ID_A)
    assert code == "drop-blacklisted" and ent is None
    assert reg.counters["blacklist_drops"] == 1
    assert await reg.blacklist(b"\x00" * 16) is False
    await reg.blacklist(ID_A, False)
    code, _ = await reg.admit(ID_A, "trusted-gateway")
    assert code == "drop-config"
    assert reg.counters["config_drops"] == 1
    code, ent = await reg.admit(ID_A, "E2E")
    assert code == "ok" and ent is not None


@pytest.mark.asyncio
async def test_capacity_refuses_live():
    reg = Registry(capacity=2, idle_timeout_s=100)
    assert await reg.enroll(ID_A, now=0.0) == "ok"
    assert await reg.enroll(ID_B, now=0.0) == "ok"
    assert await reg.enroll(bytes([7] * 16), now=0.0) == "refuse-full"
    assert reg.counters["full_refusals"] == 1
    assert len(reg) == 2


@pytest.mark.asyncio
async def test_heartbeat_seq_evict_silence():
    reg = Registry(capacity=4, idle_timeout_s=100)
    await reg.enroll(ID_A, now=0.0, interval=50.0)
    assert await reg.heartbeat(b"\x01" * 16, 10.0) is False
    assert await reg.heartbeat(ID_A, 10.0, epoch=7) is True
    ent = reg.get(ID_A)
    assert ent.last_contact == 10.0 and ent.epoch_last == 7
    assert reg.next_audit_seq(ent) == 1
    assert reg.next_audit_seq(ent) == 2
    assert await reg.evict_idle(50.0) == []
    assert await reg.evict_idle(200.0) == [ID_A]
    assert reg.counters["evictions"] == 1
    assert len(reg) == 0
    # Silence: interval exceeded flags + reports duration.
    await reg.enroll(ID_B, now=0.0, interval=50.0)
    assert await reg.silence_check(10.0) == []
    late = await reg.silence_check(100.0)
    assert late == [(ID_B, 100.0)]
    assert reg.get(ID_B).silence is True
    assert await reg.heartbeat(ID_B, 100.0) is True
    assert reg.get(ID_B).silence is False


@pytest.mark.asyncio
async def test_concurrent_admits_atomic():
    reg = Registry(capacity=8, idle_timeout_s=100)
    await reg.enroll(ID_A, now=0.0)
    results = await asyncio.gather(
        *[reg.admit(ID_A) for _ in range(30)]
    )
    assert all(code == "ok" for code, _ in results)
    assert len({id(ent) for _, ent in results}) == 1


@pytest.mark.asyncio
async def test_concurrent_enrolls_bounded():
    reg = Registry(capacity=5, idle_timeout_s=100)
    ids = _ids(10)
    results = await asyncio.gather(*[reg.enroll(i) for i in ids])
    assert results.count("ok") == 5
    assert results.count("refuse-full") == 5
    assert len(reg) == 5
    assert reg.counters["full_refusals"] == 5
