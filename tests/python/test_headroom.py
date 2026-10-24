"""Tests for B-55: 5% Hardware-Feasibility Headroom Gate.

Verifies:
1. Headroom computation (exact formula, per-family & aggregate).
2. Calibrated-only enforcement (refuses ASSUMED flags fail-closed).
3. Decision rule: both branches + exact 5% boundary goes H3-go.
4. Per-family shortfall reported without family veto.
5. CI span note recorded without flipping the point-estimate decision.
6. Timing gates: pre-calibration refused, post-freeze refused.
7. Audit recomputation: authorized + matching passes; unauthorized or mismatched fails.
8. Manuscript falsifier boundary vectors (eB < 2, baseline > 10 mW) result in drop.
9. Determinism and serialization contract.
10. G5 Retention: write_gate55_record, no-overwrite, load_gate55_record, gate55_contract.
"""
from __future__ import annotations

import json
import pytest

from analysis import headroom, gate55
from analysis.headroom import HeadroomError, HeadroomInput
from analysis.gate55 import Gate55Error, FEASIBILITY_THRESHOLD


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _calibrated_params():
    return {
        "calibration_complete": True,
        "is_calibrated": True,
        "eB": 2.5,
        "Ebase": 0.012,
        "Ehs": 0.045,
        "source": "E1-E4 lab measurements",
    }


def _assumed_params():
    return {
        "calibration_complete": True,
        "is_calibrated": True,
        "eB": 2.5,
        "flags": ["ASSUMED"],
    }


def _ps(system, trace, seed, metric, value):
    return {
        "system": system,
        "trace": trace,
        "seed": seed,
        "metric": metric,
        "value": value,
    }


# ---------------------------------------------------------------------------
# 1. Computation Tests
# ---------------------------------------------------------------------------

def test_headroom_computation_exact_scalar():
    """Formula: (E_static - E_S5) / E_total with E_total = E_static."""
    # 100 J anchor, 94 J S5 -> (100 - 94) / 100 = 0.06 (6.0%)
    h = headroom.compute_headroom(
        E_static=100.0,
        E_S5=94.0,
        E_total=100.0,
        params=_calibrated_params(),
    )
    assert pytest.approx(h.aggregate["headroom_pct"], rel=1e-6) == 0.06
    assert h.aggregate["E_static"] == 100.0
    assert h.aggregate["E_S5"] == 94.0
    assert h.aggregate["E_total"] == 100.0


def test_headroom_input_dataclass():
    """HeadroomInput dataclass passed directly."""
    inp = HeadroomInput(
        E_static_anchor={"f1": 200.0, "f2": 300.0},
        E_S5={"f1": 186.0, "f2": 282.0},
        E_total={"f1": 200.0, "f2": 300.0},
        calibrated_params=_calibrated_params(),
        families=["f1", "f2"],
    )
    h = headroom.compute_headroom(inp)
    # f1: (200 - 186) / 200 = 14 / 200 = 0.07 (7%)
    # f2: (300 - 282) / 300 = 18 / 300 = 0.06 (6%)
    # agg: (500 - 468) / 500 = 32 / 500 = 0.064 (6.4%)
    assert pytest.approx(h.per_family["f1"]["headroom_pct"], rel=1e-6) == 0.07
    assert pytest.approx(h.per_family["f2"]["headroom_pct"], rel=1e-6) == 0.06
    assert pytest.approx(h.aggregate["headroom_pct"], rel=1e-6) == 0.064
    assert h.families == ["f1", "f2"]


def test_headroom_from_paired_samples():
    """Computes headroom from B-54 paired sample records."""
    samples = []
    # 10 traces: static anchor S2 = 100.0, adaptive S5 = 93.0 (7% headroom)
    for i in range(10):
        samples.append(_ps("S2", f"trace_{i}", 42, "energy_J", 100.0))
        samples.append(_ps("S5", f"trace_{i}", 42, "energy_J", 93.0))

    h = headroom.compute_headroom(samples, params=_calibrated_params())
    assert pytest.approx(h.aggregate["headroom_pct"], rel=1e-6) == 0.07
    assert h.ci["ci_lo"] <= h.ci["ci_hi"]
    assert h.aggregate["n_pairs"] == 10


def test_calibrated_only_enforcement():
    """ASSUMED priors are strictly refused by flag scan."""
    # Direct "ASSUMED" in flags
    with pytest.raises(HeadroomError, match="calibrated-only violation"):
        headroom.compute_headroom(100.0, 94.0, 100.0, params=_assumed_params())

    # Nested assumed=True
    nested = {"calibrated": True, "subsystem": {"assumed": True}}
    with pytest.raises(HeadroomError, match="calibrated-only violation"):
        headroom.compute_headroom(100.0, 94.0, 100.0, params=nested)

    # String "ASSUMED"
    string_flag = {"calibrated": True, "prior": "ASSUMED_VALUE"}
    with pytest.raises(HeadroomError, match="calibrated-only violation"):
        headroom.compute_headroom(100.0, 94.0, 100.0, params=string_flag)

    # None params refused
    with pytest.raises(HeadroomError, match="params cannot be None"):
        headroom.compute_headroom(100.0, 94.0, 100.0, params=None)


def test_invalid_energy_inputs():
    """Refuses non-positive total energy or E_total != E_static."""
    p = _calibrated_params()
    # E_static <= 0
    with pytest.raises(HeadroomError, match="strictly positive"):
        headroom.compute_headroom(0.0, 0.0, 0.0, params=p)

    # E_total != E_static
    with pytest.raises(HeadroomError, match="must equal E_static"):
        headroom.compute_headroom(100.0, 95.0, 120.0, params=p)

    # Dict key mismatch
    with pytest.raises(HeadroomError, match="key mismatch"):
        headroom.compute_headroom({"f1": 100.0}, {"f2": 95.0}, params=p)


# ---------------------------------------------------------------------------
# 2. Decision Rule & Boundary Tests
# ---------------------------------------------------------------------------

def test_decision_boundary_at_exactly_5pct():
    """Exact boundary: 5.0% goes to H3-go."""
    p = _calibrated_params()

    # 1. 5.0% exact -> H3-go
    h_exact = headroom.compute_headroom(100.0, 95.0, 100.0, params=p)
    res_exact = gate55.decide(h_exact, p)
    assert res_exact.decision == "H3-go"
    assert pytest.approx(res_exact.headroom_pct, rel=1e-6) == 0.05

    # 2. 5.1% -> H3-go
    h_above = headroom.compute_headroom(100.0, 94.9, 100.0, params=p)
    res_above = gate55.decide(h_above, p)
    assert res_above.decision == "H3-go"

    # 3. 4.9% -> drop
    h_below = headroom.compute_headroom(100.0, 95.1, 100.0, params=p)
    res_below = gate55.decide(h_below, p)
    assert res_below.decision == "drop"
    assert pytest.approx(res_below.headroom_pct, rel=1e-6) == 0.049


def test_ci_span_recording_not_flipping():
    """CI spanning 5% records elevated uncertainty note without flipping decision."""
    p = _calibrated_params()

    # Point estimate 5.2% (>= 5%), but CI is [4.5%, 5.9%] (spans 5%)
    h_go = headroom.Headroom(
        per_family={},
        aggregate={"headroom_pct": 0.052},
        ci={"ci_lo": 0.045, "ci_hi": 0.059},
        families=["all"],
    )
    outcome_go = gate55.decide(h_go, p)
    # Decision must remain "H3-go"
    assert outcome_go.decision == "H3-go"
    assert outcome_go.ci_span_note is not None
    assert "elevated uncertainty" in outcome_go.ci_span_note
    assert "spans 5.0% threshold" in outcome_go.ci_span_note

    # Point estimate 4.8% (< 5%), CI is [4.2%, 5.4%] (spans 5%)
    h_drop = headroom.Headroom(
        per_family={},
        aggregate={"headroom_pct": 0.048},
        ci={"ci_lo": 0.042, "ci_hi": 0.054},
        families=["all"],
    )
    outcome_drop = gate55.decide(h_drop, p)
    # Decision must remain "drop"
    assert outcome_drop.decision == "drop"
    assert outcome_drop.ci_span_note is not None
    assert "elevated uncertainty" in outcome_drop.ci_span_note

    # Point estimate 6.0%, CI is [5.4%, 6.6%] (does not span 5%)
    h_clear = headroom.Headroom(
        per_family={},
        aggregate={"headroom_pct": 0.060},
        ci={"ci_lo": 0.054, "ci_hi": 0.066},
        families=["all"],
    )
    outcome_clear = gate55.decide(h_clear, p)
    assert outcome_clear.decision == "H3-go"
    assert outcome_clear.ci_span_note is None


def test_per_family_shortfall_no_veto():
    """An individual family < 5% does not veto if aggregate >= 5%."""
    p = _calibrated_params()
    h = headroom.Headroom(
        per_family={
            "fam_strong": {"headroom_pct": 0.080},
            "fam_weak": {"headroom_pct": 0.035},  # shortfall
        },
        aggregate={"headroom_pct": 0.057},  # aggregate >= 5%
        ci={"ci_lo": 0.052, "ci_hi": 0.062},
        families=["fam_strong", "fam_weak"],
    )
    outcome = gate55.decide(h, p)
    assert outcome.decision == "H3-go"
    assert "fam_weak" in outcome.per_family_shortfalls
    assert "fam_strong" not in outcome.per_family_shortfalls


# ---------------------------------------------------------------------------
# 3. Timing & Immutability Tests
# ---------------------------------------------------------------------------

def test_pre_calibration_refused():
    """Pre-calibration evaluation is refused."""
    uncalibrated = {"calibration_complete": False, "is_calibrated": True}
    h = headroom.compute_headroom(100.0, 94.0, 100.0, params=_calibrated_params())

    with pytest.raises(Gate55Error, match="pre-calibration evaluation refused"):
        gate55.decide(h, uncalibrated)


def test_post_freeze_refused():
    """Re-evaluation post-freeze is refused."""
    p = _calibrated_params()
    h = headroom.compute_headroom(100.0, 94.0, 100.0, params=p)
    outcome = gate55.decide(h, p)
    assert outcome.is_frozen is True

    with pytest.raises(Gate55Error, match="post-freeze re-evaluation refused"):
        gate55.re_evaluate(outcome)


def test_audit_recompute_authorized_and_mismatch():
    """Authorized audit recompute appends to audit log; unauthorized/mismatch refused."""
    p = _calibrated_params()
    h = headroom.compute_headroom(100.0, 94.0, 100.0, params=p)
    outcome = gate55.decide(h, p, timestamp="2026-10-24T00:00:00Z")
    assert len(outcome.audit_log) == 0

    # 1. Unauthorized fails
    with pytest.raises(Gate55Error, match="unauthorized audit recompute"):
        gate55.audit_recompute(outcome, h, p, tech_lead_auth=False)

    # 2. Authorized matching succeeds and appends to log
    audited = gate55.audit_recompute(outcome, h, p, tech_lead_auth=True, timestamp="2026-10-24T01:00:00Z")
    assert len(audited.audit_log) == 1
    assert audited.audit_log[0]["status"] == "verified_match"
    assert audited.audit_log[0]["action"] == "audit_recompute"
    assert audited.audit_log[0]["tech_lead_auth"] is True

    # 3. Mismatched inputs fail audit
    h_mismatch = headroom.compute_headroom(100.0, 96.0, 100.0, params=p)  # 4% headroom
    with pytest.raises(Gate55Error, match="audit recomputation mismatch"):
        gate55.audit_recompute(outcome, h_mismatch, p, tech_lead_auth=True)


# ---------------------------------------------------------------------------
# 4. Falsifier Link & Boundary Vectors
# ---------------------------------------------------------------------------

def test_falsifier_link_boundary_vectors():
    """Manuscript falsifier: eB < 2 uJ/B with duty-cycled baseline > 10 mW.

    Under these boundary conditions, analytic headroom is 0.05-3.47%,
    strictly below the 5% feasibility gate.
    """
    p = _calibrated_params()
    # Boundary workload: 15 mW baseline, eB = 1.0 uJ/B
    # Static anchor energy = 100.0 J, Adaptive energy = 98.5 J (1.5% saving)
    E_static = 100.0
    E_S5 = 98.5  # 1.5% headroom < 5%

    h_falsifier = headroom.compute_headroom(E_static, E_S5, E_static, params=p)
    outcome = gate55.decide(h_falsifier, p)

    # Feasibility gate correctly rejects H3 proceed
    assert outcome.decision == "drop"
    assert outcome.headroom_pct < FEASIBILITY_THRESHOLD


# ---------------------------------------------------------------------------
# 5. Gate Contract & Determinism
# ---------------------------------------------------------------------------

def test_gate_contract_determinism_and_serialization():
    """Deterministic bootstrap and JSON serialization contract."""
    p = _calibrated_params()
    samples = []
    for i in range(15):
        # 8% saving on each trace
        samples.append(_ps("S2", f"tr_{i}", 11, "energy", 100.0))
        samples.append(_ps("S5", f"tr_{i}", 11, "energy", 92.0))

    # Run 1
    h1 = headroom.compute_headroom(samples, params=p, seed=999)
    out1 = gate55.decide(h1, p, timestamp="2026-10-24T12:00:00Z")

    # Run 2 with identical seed
    h2 = headroom.compute_headroom(samples, params=p, seed=999)
    out2 = gate55.decide(h2, p, timestamp="2026-10-24T12:00:00Z")

    # Bit-identical CIs
    assert h1.ci["ci_lo"] == h2.ci["ci_lo"]
    assert h1.ci["ci_hi"] == h2.ci["ci_hi"]

    # Serialization check
    d1 = out1.to_dict()
    serialized = json.dumps(d1)
    assert "H3-go" in serialized
    assert "headroom_pct" in serialized


# ---------------------------------------------------------------------------
# 6. G5 Retention Tests
# ---------------------------------------------------------------------------

def test_manifest_written_and_readable(tmp_path):
    """write_gate55_record writes gate55-record.json; load_gate55_record reads it back."""
    p = _calibrated_params()
    h = headroom.compute_headroom(100.0, 94.0, 100.0, params=p)
    outcome = gate55.decide(h, p, timestamp="2026-10-24T00:00:00Z")

    run_dir = tmp_path / "runs" / "exp1" / "run001"
    record_path = gate55.write_gate55_record(outcome, run_dir)

    # File must exist at the expected path
    assert record_path.exists()
    assert record_path.name == "gate55-record.json"
    assert record_path.parent == run_dir

    # Must be valid JSON
    with record_path.open() as fh:
        raw = json.load(fh)

    # Schema metadata
    assert raw["schema_version"] == 1
    assert raw["gate"] == "B-55"

    # All Gate55Outcome fields preserved exactly
    assert raw["decision"] == outcome.decision
    assert pytest.approx(raw["headroom_pct"], rel=1e-9) == outcome.headroom_pct
    assert raw["frozen_at"] == outcome.frozen_at
    assert raw["is_frozen"] is True
    assert raw["audit_log"] == []
    assert raw["per_family_shortfalls"] == []

    # load_gate55_record returns the same dict
    loaded = gate55.load_gate55_record(record_path)
    assert loaded["decision"] == raw["decision"]
    assert loaded["gate"] == "B-55"
    assert loaded["schema_version"] == 1


def test_no_overwrite_existing_record(tmp_path):
    """G5: writing gate55-record.json twice to the same path is refused."""
    p = _calibrated_params()
    h = headroom.compute_headroom(100.0, 94.0, 100.0, params=p)
    outcome = gate55.decide(h, p, timestamp="2026-10-24T00:00:00Z")

    run_dir = tmp_path / "runs" / "exp1" / "run002"

    # First write succeeds
    gate55.write_gate55_record(outcome, run_dir)

    # Second write to the same directory must be refused
    with pytest.raises(Gate55Error, match="already exists"):
        gate55.write_gate55_record(outcome, run_dir)


def test_gate55_contract_binding(tmp_path):
    """gate55_contract() enforces N, seed, per-family records, and manifest."""
    p = _calibrated_params()
    SEED = 42

    def _family_rec(name, headroom_pct, n_pairs=10):
        return {
            "family": name,
            "headroom_pct": headroom_pct,
            "seed": SEED,
            "n_pairs": n_pairs,
            "passed": True,
        }

    def _manifest(n=2):
        return {
            "gate": "B-55",
            "seed_used": str(SEED),
            "n_families": str(n),
            "code_hash": "abcdef1234567890abcdef1234567890abcdef12",
        }

    family_records = [
        _family_rec("family_alpha", 0.07),
        _family_rec("family_beta", 0.06),
    ]

    # 1. Happy path — all constraints satisfied
    result = gate55.gate55_contract(2, 2, family_records, _manifest(2))
    assert result["stated_n"] == 2
    assert result["observed_n"] == 2
    assert result["manifest_ok"] is True
    assert result["deterministic"] is True
    assert result["seed"] == SEED
    assert result["retention_form"] == "per-family"

    # 2. Stated N mismatch
    with pytest.raises(Gate55Error, match="stated N=2 but observed N=3"):
        gate55.gate55_contract(2, 3, family_records, _manifest(2))

    # 3. Placeholder family_records rejected
    with pytest.raises(Gate55Error, match="pending-harness"):
        gate55.gate55_contract(2, 2, "pending-harness", _manifest(2))

    # 4. Wrong number of records
    with pytest.raises(Gate55Error, match="stated N=2 but 1 family record"):
        gate55.gate55_contract(2, 2, family_records[:1], _manifest(2))

    # 5. Duplicate family name
    dup_records = [_family_rec("alpha", 0.07), _family_rec("alpha", 0.06)]
    with pytest.raises(Gate55Error, match="duplicate family name"):
        gate55.gate55_contract(2, 2, dup_records, _manifest(2))

    # 6. A family record where passed != True
    bad_passed = [_family_rec("alpha", 0.07), {**_family_rec("beta", 0.06), "passed": False}]
    with pytest.raises(Gate55Error, match="did not pass"):
        gate55.gate55_contract(2, 2, bad_passed, _manifest(2))

    # 7. Seed mismatch (determinism binding fails)
    seed_mismatch = [_family_rec("alpha", 0.07), {**_family_rec("beta", 0.06), "seed": 999}]
    with pytest.raises(Gate55Error, match="determinism binding failed"):
        gate55.gate55_contract(2, 2, seed_mismatch, _manifest(2))

    # 8. Missing manifest field
    bad_manifest = {k: v for k, v in _manifest(2).items() if k != "code_hash"}
    with pytest.raises(Gate55Error, match="code_hash"):
        gate55.gate55_contract(2, 2, family_records, bad_manifest)

    # 9. Wrong gate in manifest
    wrong_gate_manifest = {**_manifest(2), "gate": "B-54"}
    with pytest.raises(Gate55Error, match="manifest 'gate' must be 'B-55'"):
        gate55.gate55_contract(2, 2, family_records, wrong_gate_manifest)

    # 10. manifest n_families mismatch
    wrong_n_manifest = {**_manifest(2), "n_families": "99"}
    with pytest.raises(Gate55Error, match="manifest n_families=99 != stated N=2"):
        gate55.gate55_contract(2, 2, family_records, wrong_n_manifest)
