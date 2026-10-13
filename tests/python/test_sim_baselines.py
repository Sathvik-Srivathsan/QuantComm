"""Baseline tests (B-44.1-.4): definitions, S4 rule, bypass records,
validity, anchor selection, oracle bound, H3 inputs. Deterministic."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "sim"))

from qcsim import (ExperimentRunner, baseline_systems, check_comparison,  # noqa: E402
                   check_oracle_bound, generate_traces, h3_input_record,
                   select_anchor)
from qcsim.systems import s4_profile, violation_record  # noqa: E402
from qcsim.runner import check_pairing  # noqa: E402

SEED = "0123456789abcdef0123456789abcdef"
BACKEND = "host-build-b43-foundations-1"


def test_definitions_match_spec():
    systems, psk = baseline_systems(BACKEND, seed_hex=SEED)
    assert len(psk) == 64  # 32-B campaign PSK hex
    by_id = {s["system_id"]: s for s in systems}
    assert set(by_id) == {"S0", "S1", "S2-SL1", "S2-SL2", "S2-SL3",
                          "S3", "S4", "S5", "S6"}
    # Runner interface on every definition (extra keys allowed).
    for system in systems:
        for key in ("system_id", "controller", "floor_bypass", "backend"):
            assert key in system
        assert system["backend"] == BACKEND
    # Bypass exactly S0/S1/S4; S5 enforced; S6 analysis-only oracle.
    assert {s["system_id"] for s in systems if s["floor_bypass"]} == \
        {"S0", "S1", "S4"}
    assert by_id["S5"]["controller"] is True
    assert by_id["S5"]["floor_bypass"] is False
    assert by_id["S6"]["profile"]["future"] is True
    assert by_id["S6"]["profile"]["compute"] == "excluded-from-energy"
    # PSK deterministic per seed, distinct across seeds.
    _, psk2 = baseline_systems(BACKEND, seed_hex=SEED)
    _, psk3 = baseline_systems(BACKEND, seed_hex="ff" * 16)
    assert psk2 == psk and psk3 != psk
    # Bypass outside experiment configs refused.
    try:
        baseline_systems(BACKEND, experiment=False, seed_hex=SEED)
        assert False
    except ValueError:
        pass


def test_s4_rule_and_violation_records():
    assert s4_profile(100) == "SL3"
    assert s4_profile(51) == "SL3"
    assert s4_profile(49) == "SL2"
    assert s4_profile(24) == "SL1"
    assert s4_profile(0) == "SL1"
    rec = violation_record("S4", "trace-1", 7, "C1", 2)
    assert rec == {"system": "S4", "trace": "trace-1", "window": 7,
                   "constraint": "C1", "magnitude": 2}
    for bad in (("S4", "t", 0, "C9", 1), ("S4", "t", 0, "C1", -1)):
        try:
            violation_record(*bad)
            assert False
        except ValueError:
            pass


def test_validity_gates():
    systems, _ = baseline_systems(BACKEND, seed_hex=SEED)
    traces = generate_traces("E7gen", SEED, n=10)
    runner = ExperimentRunner(SEED, mode="E7", output_tag="SIM-e7")
    manifests, _ = runner.run(systems[:2], traces, runs=10)
    assert check_comparison(systems[:2], manifests) is True
    assert check_pairing(manifests) is True
    # Composition: baseline definitions (with extra kind/profile keys)
    # satisfy the runner interface unmodified — bypassed S0 plus
    # enforced S5 run end to end.
    pair = [s for s in systems if s["system_id"] in ("S0", "S5")]
    manifests_b, stats_b = runner.run(pair, traces, runs=10)
    assert len(manifests_b) == 20 and len(stats_b) == 20
    assert check_comparison(pair, manifests_b) is True
    # Cross-implementation comparison refused.
    mixed = [dict(systems[0]),
             {"system_id": "SX", "controller": False,
              "floor_bypass": False, "backend": "other-build"}]
    try:
        check_comparison(mixed, manifests)
        assert False
    except ValueError:
        pass


def test_anchor_selection():
    means = {"S2-SL1": 10.0, "S2-SL2": 9.0, "S2-SL3": 11.0, "S3": 12.0}
    eligible = set(means)
    anchor, why = select_anchor(means, eligible)
    assert anchor == "S2-SL2" and "min-energy" in why
    # Tie breaks toward lower SL.
    tied = dict(means, **{"S2-SL1": 9.0})
    assert select_anchor(tied, eligible)[0] == "S2-SL1"
    # else-S3 fallback when no S2 variant is in the campaign.
    anchor, why = select_anchor(
        {"S3": 12.0}, {"S3"}, campaign_ids=["S0", "S3"])
    assert anchor == "S3" and "else-S3" in why
    # No eligible candidate refuses.
    try:
        select_anchor(means, set())
        assert False
    except ValueError:
        pass


def test_oracle_bound_and_h3_records():
    assert check_oracle_bound(9.0, 8.0) is True
    try:
        check_oracle_bound(7.0, 8.0)
        assert False, "S5 beating S6 must alarm"
    except ValueError:
        pass
    rec = h3_input_record("trace-1", "S2-SL2", "min-energy", 7.0, 9.0,
                          0, 8.0, [SEED], "codehash")
    assert rec["violations"] == 0 and rec["anchor_id"] == "S2-SL2"
    try:
        h3_input_record("trace-1", "S2-SL2", "r", 7.0, 9.0,
                        2, 8.0, [SEED], "codehash")
        assert False, "nonzero S5 violations must refuse"
    except ValueError:
        pass
