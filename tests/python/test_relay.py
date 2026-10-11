"""Relay tests (B-42.1/.2/.5): transparency, association, configs,
ciphertext-only, registration. Deterministic (fixed bytes)."""
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "server"))

from qcgw.relay import (  # noqa: E402
    E2ERelay, GatewayRegistry, TrustedRelay, check_gateway,
)

DEV = "aa" * 16


def test_e2e_transparency_and_association(tmp_path):
    r = E2ERelay(relay_budget_ms=5)
    # Unknown association drops (trusted-leg frames have none here).
    code, out = r.relay(b"\x00" * 100, "link-9")
    assert code == "drop-unknown" and out is None
    assert r.counters["drop_unknown"] == 1
    # Unverified binding refuses (hijack-proof association).
    try:
        r.associate("link-1", DEV, verified=False)
        assert False
    except ValueError:
        pass
    assert r.associate("link-1", DEV, verified=True) is True
    # Byte-transparent relay (adversarial bytes pass through verbatim).
    evil = bytes([(i * 37 + 11) % 256 for i in range(300)])
    code, out = r.relay(evil, "link-1", latency_ms=1)
    assert code == "relayed" and out == evil
    # Over-budget counts, never drops.
    code, out = r.relay(evil, "link-1", latency_ms=99)
    assert code == "relayed" and out == evil
    assert r.counters["over_budget"] == 1
    assert r.counters["relayed"] == 2
    # Dissociate ends the binding.
    assert r.dissociate("link-1") is True
    assert r.dissociate("link-1") is False
    code, _ = r.relay(evil, "link-1")
    assert code == "drop-unknown"
    # Bad args fail fast.
    try:
        r.associate("", DEV)
        assert False
    except ValueError:
        pass
    # No key material anywhere on the object (ciphertext-only proof).
    assert not any("key" in k.lower() for k in vars(r))
    assert not any("key" in k.lower() for k in r.counters)


def test_trusted_config_and_routing():
    r = TrustedRelay(config="trusted-gateway", gateway_id_hex="bb" * 16)
    assert r.config == "trusted-gateway"
    # Immutable: no setter exists (AttributeError on assignment).
    try:
        r.config = "E2E"
        assert False, "config must be read-only"
    except AttributeError:
        pass
    assert r.bind_leg("W-G", "cc" * 16) is True
    assert r.bind_leg("G-S", "dd" * 16) is True
    try:
        r.bind_leg("X-Y", "cc" * 16)
        assert False
    except ValueError:
        pass
    # Routing exposes class/level/counter with zero decryption.
    hdr = (bytes([0xD0 + i for i in range(16)]) + bytes([2, 3]) +
           (41).to_bytes(8, "big") + bytes(32) + (0).to_bytes(16))
    frame = hdr + (8).to_bytes(4, "big") + bytes(8 + 16)
    code, info = r.route(frame, "W-G")
    assert code == "routed"
    assert info == {"class": 2, "level": 3, "counter": 41,
                    "peer": "cc" * 16}
    # Unknown leg drops (no-intermix: E2E frames have no leg here).
    code, _ = r.route(frame, "G-X")
    assert code == "drop-unknown"
    code, _ = r.route(b"short", "W-G")
    assert code == "drop-malformed"
    try:
        TrustedRelay(config="bulk")
        assert False
    except ValueError:
        pass


def test_registration_both_sides():
    reg = GatewayRegistry()
    assert reg.check("aa" * 16) is False
    assert reg.counters["unknown"] == 1
    assert reg.register("aa" * 16) is True
    assert reg.check("aa" * 16) is True
    assert reg.revoke("aa" * 16) is True
    assert reg.check("aa" * 16) is False
    assert reg.revoke("aa" * 16) is False
    assert check_gateway(["aa" * 16, "bb" * 16], "bb" * 16) is True
    assert check_gateway(["aa" * 16], "cc" * 16) is False
    try:
        check_gateway("not-a-list", "aa" * 16)
        assert False
    except ValueError:
        pass
    try:
        reg.register("")
        assert False
    except ValueError:
        pass


def test_gateway_logs_carry_no_payloads(tmp_path, caplog):
    import logging as _l
    r = E2ERelay()
    assert r.associate("link-7", DEV) is True
    secret = b"SECRET-PAYLOAD-0123456789abcdef"
    with caplog.at_level(_l.INFO, logger="qcgw.relay"):
        r.relay(secret * 4, "link-7")
    text = caplog.text
    assert "SECRET-PAYLOAD" not in text
    assert DEV in text  # metadata (link/device) is fine
