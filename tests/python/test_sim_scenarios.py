"""Attacker-scenario tests (B-43.4): schema gate, primitives, conflicts,
determinism, crypto-never-broken. Deterministic throughout."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "sim"))

from qcsim import parse_scenario, play_scenario  # noqa: E402

SEED = "0123456789abcdef0123456789abcdef"

BASE = """
scenario_id = "night-raid"
[version]
major = 1
minor = 0
"""


def _toml(*prims):
    body = "\n".join("[[primitives]]\n" + p for p in prims)
    return BASE + body


def test_schema_gate():
    good = _toml('op = "drop"\nat_us = 1000')
    scenario = parse_scenario(good)
    assert scenario["scenario_id"] == "night-raid"
    assert scenario["version"] == {"major": 1, "minor": 0}
    assert scenario["primitives"][0]["params"] == {}
    # Higher minor accepted (unknown fields ignored is covered by TOML).
    assert parse_scenario(BASE.replace("minor = 0", "minor = 3"))
    # Major mismatch, unknown op, bad clock, unknown key: all refuse.
    # (Unknown top-level key goes BEFORE any [table] header — TOML
    # would otherwise scope it into [version], where minor-tolerance
    # deliberately ignores extras.)
    for bad in (
        BASE.replace("major = 1", "major = 2"),
        _toml('op = "time_travel"\nat_us = 5'),
        _toml('op = "drop"\nat_us = -1'),
        'weapons = "yes"\n' + BASE,
        "not toml {{{",
    ):
        try:
            parse_scenario(bad)
            assert False, bad[:40]
        except ValueError:
            pass
    # Param contracts: delay needs delay_us, flood needs count>=1,
    # hints within the B-25.4 cap of 6, gateway profile enumerated.
    assert parse_scenario(_toml(
        'op = "delay"\nat_us = 1\n[primitives.params]\ndelay_us = 50'))
    for bad in (
        _toml('op = "delay"\nat_us = 1'),
        _toml('op = "handshake_flood"\nat_us = 1\n'
              '[primitives.params]\ncount = 0'),
        _toml('op = "hint_spoof"\nat_us = 1\n[primitives.params]\n'
              'hints = 7'),
        _toml('op = "gateway_compromise"\nat_us = 1\n'
              '[primitives.params]\nprofile = "decrypt"'),
    ):
        try:
            parse_scenario(bad)
            assert False
        except ValueError:
            pass


def test_primitives_fire_deterministically():
    scenario = parse_scenario(_toml(
        'op = "drop"\nat_us = 100',
        'op = "drop"\nat_us = 200',
        'op = "inject"\nat_us = 300',
        'op = "modify"\nat_us = 400',
        'op = "replay"\nat_us = 500',
        'op = "delay"\nat_us = 600\n[primitives.params]\ndelay_us = 5',
        'op = "handshake_flood"\nat_us = 700\n[primitives.params]\n'
        'count = 10',
        'op = "reboot_reset"\nat_us = 800',
        'op = "hint_spoof"\nat_us = 900\n[primitives.params]\n'
        'hints = 3',
        'op = "manifest_replay"\nat_us = 1000',
        'op = "gateway_compromise"\nat_us = 1100\n'
        '[primitives.params]\nprofile = "drop"',
    ))
    frames = [bytes([i]) * 32 for i in range(6)]
    out1, log1, conflicts1 = play_scenario(scenario, frames, SEED)
    out2, log2, conflicts2 = play_scenario(scenario, frames, SEED)
    assert out1 == out2 and log1 == log2  # bit-identical double run
    assert [e["op"] for e in log1] == [
        "drop", "drop", "inject", "modify", "replay", "delay",
        "handshake_flood", "reboot_reset", "hint_spoof",
        "manifest_replay", "gateway_compromise"]
    assert [e["ts"] for e in log1] == sorted(e["ts"] for e in log1)
    assert conflicts1 == []
    # Drops removed two of six; inject and replay each added one back;
    # flood adds no frames.
    assert len(out1) == 6 - 2 + 1 + 1
    # Duplicate drops fired their OWN params (index dispatch, not first):
    # both drops counted separately.
    assert [e for e in log1 if e["op"] == "drop"] == [
        {"op": "drop", "ts": 100, "dropped": 1},
        {"op": "drop", "ts": 200, "dropped": 1}]
    # Gateway log carries metadata only, never frame bytes.
    assert log1[-1] == {"op": "gateway_compromise", "ts": 1100,
                        "profile": "drop", "availability_only": True}


def test_conflicts_and_crypto_never_broken():
    scenario = parse_scenario(_toml('op = "drop"\nat_us = 1000'))
    frames = [b"\x00" * 16, b"\xff" * 16]
    out, log, conflicts = play_scenario(
        scenario, frames, SEED, trace_events=[(1000, "link-loss")])
    assert conflicts == [{"ts": 1000, "trace": "link-loss", "op": "drop"}]
    assert out == [b"\xff" * 16]  # scenario overrode, trace kept in log
    # Attacker outputs stay opaque bytes; logs carry metadata only.
    assert all(isinstance(f, bytes) for f in out)
    assert all("key" not in k.lower() for e in log for k in e)
