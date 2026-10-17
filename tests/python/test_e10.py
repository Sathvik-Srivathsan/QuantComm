"""B-53 data surface: TOutcome, energy capture, epsilon pre-registration.

Every test drives a production function. E10's per-T EXECUTORS are TO
BUILD (they need the servant runner); this module covers the surface
they write into, and says so rather than implying coverage it lacks.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "sim"))

import pytest

from qcsim.attacks import (AttackError, EpsilonRegistration, MANIFEST_FORGERY_TYPES,
                           TAMPER_POSITIONS, T_TESTS, T_ATTACK_PER_CLASS_S,
                           TOwncome, epsilon, excess_energy, excess_rate_J_per_h,
                           h4_input)


def _out(t, accept=True, path="dropped", energy=1.0, base=0.4):
    return TOwncome(t, "sc-%s" % t, 1, accept, path, energy, base,
                    {"drops": 3}, {"gate_preflight": "g-1"}, (1, 2))


def test_t_matrix_covers_t1_to_t13():
    assert len(T_TESTS) == 13
    assert sorted(T_TESTS) == sorted("T%d" % i for i in range(1, 14))


def test_tamper_positions_are_the_wire_regions():
    assert set(TAMPER_POSITIONS) == {"header", "plen", "ct", "tag"}
    from qcsim import attacks
    assert attacks.FRAME_PLEN_OFF == 74
    assert attacks.FRAME_CT_OFF == 78


def test_manifest_forgery_has_four_types():
    assert len(MANIFEST_FORGERY_TYPES) == 4
    assert len(set(MANIFEST_FORGERY_TYPES)) == 4


def test_outcome_carries_every_spec_field():
    d = _out("T1").as_dict()
    for k in ("t_id", "scenario_id", "scenario_version", "accept",
              "accept_path", "energy_J_per_h", "baseline_J_per_h",
              "excess_J_per_h", "counters"):
        assert k in d, k
    assert "verdict" not in d, "B-64 owns verdicts"


def test_excess_is_attack_minus_baseline():
    assert excess_energy(2.5, 0.5) == 2.0


def test_rate_is_not_accumulated():
    """A rate over the window, never summed."""
    assert excess_rate_J_per_h(2.0, 1.0, 3600) == 1.0
    assert excess_rate_J_per_h(2.0, 1.0, 60) == 1.0


def test_rate_rejects_nonpositive_window():
    with pytest.raises(AttackError):
        excess_rate_J_per_h(1.0, 0.0, 0)


def test_epsilon_computed_from_live_values():
    v = epsilon(10, 0.001, 120.0, 300.0)
    assert v > 0


def test_epsilon_rejects_nonpositive_inputs():
    with pytest.raises(AttackError):
        epsilon(0, 0.001, 120.0, 300.0)


def _eps():
    e = EpsilonRegistration(epsilon(10, 0.001, 120.0, 300.0),
                            10, 0.001, 120.0, 300.0)
    e.epsilon_at = 100
    return e


def test_epsilon_order_holds_when_registered_first():
    e = _eps()
    e.record_first_run(200)
    assert e.check_order() is True


def test_epsilon_after_first_run_is_refused():
    e = _eps()
    e.record_first_run(50)
    with pytest.raises(AttackError):
        e.check_order()


def test_no_run_recorded_is_refused():
    with pytest.raises(AttackError):
        _eps().check_order()


def test_h4_input_requires_t3_t4_t5():
    with pytest.raises(AttackError):
        h4_input([_out("T3")], _eps())


def test_h4_input_is_inputs_only_never_a_verdict():
    ins = h4_input([_out("T3"), _out("T4"), _out("T5"), _out("T6")], _eps())
    for k in ("T3_accept", "T4_accept", "T5_accept", "T6_excess_rate",
              "T7_excess_rate", "epsilon_snapshot", "T_attack_per_class"):
        assert k in ins, k
    assert not any(k.startswith("verdict") or k == "h4" for k in ins)


def test_t_attack_is_stated_per_class():
    assert T_ATTACK_PER_CLASS_S == 86400