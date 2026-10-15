"""E1 driver tests (plan B-51.4).

The driver owns the parts of E1 that can silently lie: the gate check, the
no-joule schema rule, coverage completeness, and the transfer bound. Each
is tested by driving the production function with a hostile input, not by
asserting that a constant equals itself.
"""
import importlib.util
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def _load():
    spec = importlib.util.spec_from_file_location(
        "e1_run", REPO / "tools" / "e1_run.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["e1_run"] = mod
    spec.loader.exec_module(mod)
    return mod


e1 = _load()


def _row(op="sha256", level="host", payload=16, n=200):
    return {"op": op, "level": level, "payload": payload, "n": n,
            "ns_mean": 1, "ns_p50": 1, "ns_p95": 1, "ns_p99": 1,
            "ns_max": 2, "cycles_p50": 3,
            "heap_live_bytes": 0, "cycle_source": "rdtsc-fenced",
            "stack_metric": "pending-verification",
            "energy_field": "absent-by-design"}


def _full_matrix():
    rows = []
    for lvl in ("512", "768", "1024"):
        for op in ("ml-kem-keygen", "ml-kem-encaps", "ml-kem-decaps"):
            rows.append(_row(op, lvl))
    for lvl in ("44", "65", "87"):
        for op in ("ml-dsa-keygen", "ml-dsa-sign", "ml-dsa-verify"):
            rows.append(_row(op, lvl, n=500 if op == "ml-dsa-sign" else 200))
    for op in ("sha256", "hmac-sha256", "aes-256-gcm-encrypt"):
        rows.append(_row(op))
    rows.append(_row("hkdf-expand-64"))
    return rows


# ---- the no-joule rule (B-51.3) -----------------------------------------

def test_energy_field_is_absent_by_construction():
    """Asserted against the DRIVER's production constant, not against the
    test helper: an earlier version of this test asserted properties of
    `_row()`, a literal defined in this file, so it would still have passed
    if the benchmark emitted a real joules field."""
    assert "energy_field" not in e1.REQUIRED_ROW_KEYS
    for banned in ("joules", "energy_j", "power_w"):
        assert banned not in e1.REQUIRED_ROW_KEYS


def test_stack_metric_is_marked_pending_not_zero():
    """The removed stack instrument must be VISIBLY absent from the schema,
    never a zero that reads as 'measured, and the stack was shallow'.
    Asserted on the production key list, so a bench that started emitting
    stack_hwm_bytes could not slip past."""
    assert "stack_metric" in e1.REQUIRED_ROW_KEYS
    assert "stack_hwm_bytes" not in e1.REQUIRED_ROW_KEYS


def test_row_carrying_a_real_energy_field_is_rejected():
    """If the bench ever starts emitting joules, the driver refuses the row
    rather than retaining it as an E1 number."""
    bad = dict(_row(), joules=12.5)
    try:
        e1.parse_rows(json.dumps(bad))
    except AssertionError:
        pass
    else:
        raise AssertionError("an energy field must be refused")


def test_missing_required_key_is_refused():
    bad = _row()
    del bad["ns_p99"]
    try:
        e1.parse_rows(json.dumps(bad))
    except RuntimeError as exc:
        assert "ns_p99" in str(exc)
    else:
        raise AssertionError("incomplete row must be refused")


# ---- coverage (B-51.5) ---------------------------------------------------

def test_full_matrix_has_no_coverage_problems():
    assert e1.validate_rows(_full_matrix(), None) == []


def test_missing_level_is_reported():
    rows = [r for r in _full_matrix()
            if not (r["op"] == "ml-kem-keygen" and r["level"] == "1024")]
    problems = e1.validate_rows(rows, None)
    assert any("1024" in p for p in problems)


def test_wrong_sample_count_is_reported():
    rows = _full_matrix()
    for r in rows:
        if r["op"] == "ml-dsa-sign":
            r["n"] = 200          # sign must carry N=500
    problems = e1.validate_rows(rows, None)
    assert any("500" in p for p in problems)


def test_missing_op_family_is_reported():
    rows = [r for r in _full_matrix() if not r["op"].startswith("ml-dsa")]
    problems = e1.validate_rows(rows, None)
    assert any("ml-dsa" in p for p in problems)


def test_override_disables_the_n_assertion_but_not_coverage():
    rows = _full_matrix()
    for r in rows:
        r["n"] = 3
    assert e1.validate_rows(rows, 3) == []
    rows = [r for r in rows if r["op"] != "aes-256-gcm-encrypt"]
    assert e1.validate_rows(rows, 3) != []


# ---- gate binding (B-51.4) ---------------------------------------------

def test_run_refuses_without_a_gate(tmp_path, monkeypatch):
    """With no gate record, the campaign must refuse AND write nothing."""
    monkeypatch.setattr(e1, "BENCH", tmp_path / "bench")
    monkeypatch.setattr(e1, "RUNS", tmp_path / "runs")
    rc = e1.run()
    assert rc == e1.EXIT_GATE
    assert not (tmp_path / "runs").exists(), \
        "a refused campaign must not leave a dataset behind"


def test_run_refuses_when_the_bench_is_missing(tmp_path, monkeypatch):
    record = {"gate_id": "e0-test", "verdict": "pass", "commit": "x",
              "timestamp": "T"}
    monkeypatch.setattr(e1, "require_gate", lambda build: (record, None))
    monkeypatch.setattr(e1, "BENCH", tmp_path / "absent")
    assert e1.run() == e1.EXIT_INFRA


# ---- dataset versioning --------------------------------------------------

def test_versions_increment_and_never_collide(tmp_path, monkeypatch):
    monkeypatch.setattr(e1, "RUNS", tmp_path)
    assert e1.next_version() == "E1-0001"
    (tmp_path / "E1-0001").mkdir()
    assert e1.next_version() == "E1-0002"
    (tmp_path / "E1-0002").mkdir()
    (tmp_path / "E1-0009").mkdir()
    assert e1.next_version() == "E1-0010"


def test_versioning_ignores_unrelated_entries(tmp_path, monkeypatch):
    monkeypatch.setattr(e1, "RUNS", tmp_path)
    (tmp_path / "notes.txt").write_text("x")
    (tmp_path / "E1-0003").mkdir()
    assert e1.next_version() == "E1-0004"


def test_host_spec_reports_the_platform():
    spec = e1.host_spec()
    assert spec["platform"]
    assert spec["machine"]
