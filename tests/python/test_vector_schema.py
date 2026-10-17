"""B-54 vector/per-test retention contract + real-shaped acceptance.

Two shapes modelled so B-10.6/B-11.6 conform rather than reinvent.
The per-test shape is built from CTest JUnit cases -- the signal that
ALREADY exists non-invasively (tools/e0_gate.py parses the same XML),
so no test loop body is touched.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import pytest

from analysis.vector_schema import (FORMS, SCHEMA_VERSION, PER_TEST_FIELDS,
                                    PER_VECTOR_FIELDS, SchemaError,
                                    fields_for, monotonic_run_id,
                                    per_test_from_junit, validate,
                                    validate_set)


# ---------------- per-vector shape (what the four gates require) ------
def _pv(i=0, passed=True, gate_id=None, gate_commit=None):
    return {"schema_version": SCHEMA_VERSION, "vector_id": "kat-%06d" % i,
            "level": "ml-kem-768", "passed": passed,
            "input_sha256": None, "output_sha256": None,
            "gate_commit": gate_commit, "gate_id": gate_id}


def test_per_vector_record_validates():
    assert validate(_pv(), "per-vector") is True


def test_per_vector_set_validates_and_counts():
    assert validate_set([_pv(i) for i in range(5)], "per-vector") == 5


def test_unknown_key_is_refused_not_ignored():
    r = _pv()
    r["surprise"] = 1
    with pytest.raises(SchemaError) as e:
        validate(r, "per-vector")
    assert "surprise" in str(e.value)


def test_missing_key_is_refused():
    r = _pv()
    del r["vector_id"]
    with pytest.raises(SchemaError) as e:
        validate(r, "per-vector")
    assert "vector_id" in str(e.value)


def test_wrong_schema_version_is_refused():
    r = _pv()
    r["schema_version"] = 99
    with pytest.raises(SchemaError) as e:
        validate(r, "per-vector")
    assert "schema_version" in str(e.value)


def test_wrong_type_is_refused():
    r = _pv()
    r["passed"] = "yes"
    with pytest.raises(SchemaError):
        validate(r, "per-vector")


def test_empty_vector_id_is_refused():
    r = _pv()
    r["vector_id"] = ""
    with pytest.raises(SchemaError):
        validate(r, "per-vector")


def test_empty_set_is_refused():
    with pytest.raises(SchemaError):
        validate_set([], "per-vector")


def test_unknown_form_is_refused():
    with pytest.raises(SchemaError):
        fields_for("per-session")


# ---------------- per-test shape (G5 floor) -------------------------
def _ptcase(name="c_kem", ran=True, failed=False, skipped=False, time="0.42"):
    """A case in the shape tools/e0_gate.parse_junit_cases produces.

    PER-TEST semantics: the testcase IS the unit. Ctest's <testsuite>
    counts are run-level aggregates, so they are not attributed to an
    individual case.
    """
    return {"name": name, "classname": name, "time": time,
            "status": "run" if ran else "notrun", "ran": ran,
            "skipped": skipped, "failed": failed}


def test_per_test_from_junit_counts_pass_and_fail():
    r = per_test_from_junit(_ptcase(time=0.42))
    assert validate(r, "per-test") is True
    assert r["pass_count"] == 1 and r["fail_count"] == 0
    assert r["vector_count"] == 1 and r["test_name"] == "c_kem"

    bad = per_test_from_junit(_ptcase(failed=True))
    assert bad["pass_count"] == 0 and bad["fail_count"] == 1


def test_per_test_junit_errors_count_as_failures():
    r = per_test_from_junit(_ptcase(name="c_x", failed=True))
    assert r["fail_count"] == 1


def test_per_test_nameless_case_is_refused():
    with pytest.raises(SchemaError):
        per_test_from_junit({"ran": True, "failed": False})


def test_per_test_inconsistent_counts_are_refused():
    """pass+fail must equal vector_count -- catches a bad emitter."""
    r = per_test_from_junit(_ptcase(name="c_y"))
    r["pass_count"] = 7
    with pytest.raises(SchemaError) as e:
        validate(r, "per-test")
    assert "vector_count" in str(e.value)


def test_per_test_and_per_vector_shapes_are_distinct():
    assert set(PER_TEST_FIELDS) != set(PER_VECTOR_FIELDS)
    assert "vector_id" not in PER_TEST_FIELDS
    assert "test_name" not in PER_VECTOR_FIELDS


def test_forms_constant_names_the_two_record_forms():
    """FORMS lists the shapes that HAVE a field table.

    "pending-harness" is a manifest MARKER, not a record form; listing it
    invited `fields_for("pending-harness")`, which raises.
    """
    assert set(FORMS) == {"per-test", "per-vector"}
    for f in FORMS:
        assert fields_for(f)


# ---------------- G5 monotonic run ids -----------------------------
def test_run_id_is_normalised_to_monotonic_form():
    assert monotonic_run_id("E5", "7") == "E5-00000007"


def test_run_id_zero_is_refused():
    with pytest.raises(SchemaError):
        monotonic_run_id("E5", "0")


def test_non_numeric_run_id_is_refused():
    with pytest.raises(SchemaError):
        monotonic_run_id("E5", "latest")


def test_run_id_path_traversal_refused():
    for bad in ("../x", "a/b", "..", ""):
        with pytest.raises(SchemaError):
            monotonic_run_id("E5", bad)
        with pytest.raises(SchemaError):
            monotonic_run_id(bad, "1")


def test_run_ids_increase_never_overwrite():
    a = monotonic_run_id("E5", "1")
    b = monotonic_run_id("E5", "2")
    assert a != b and a < b


# ---------------- gate contract acceptance path ---------------------
def _manifest():
    m = {"gate_preflight": "e0-0123456789abcdef", "model_pin": "m1",
         "code_hash": "c" * 16, "assumption_log_version": "b43-device-2"}
    return m, "e0-0123456789abcdef"


def _bound_pv(i=0, passed=True, gate_id="e0-0123456789abcdef", gate_commit="c" * 40):
    return _pv(i, passed, gate_id=gate_id, gate_commit=gate_commit)


def test_gate_accepts_real_shaped_per_vector_records():
    from analysis.stats import gate_contract
    recs = [_bound_pv(i) for i in range(6)]
    for r in recs:
        validate(r, "per-vector")
    m, _ = _manifest()
    g = gate_contract(6, 6, recs, manifest=m)
    assert g["retention_form"] == "per-vector"
    assert g["vector_records"] == 6
    assert g["deterministic"] is True and g["manifest_ok"] is True


def test_gate_refuses_per_test_form_explicitly():
    """per-test satisfies G5 but not the four flat accept boxes."""
    from analysis.stats import gate_contract
    m, _ = _manifest()
    with pytest.raises(Exception) as e:
        gate_contract(6, 6, "per-test", manifest=m)
    assert "G5" in str(e.value)


def test_gate_refuses_unknown_form():
    from analysis.stats import gate_contract
    m, _ = _manifest()
    with pytest.raises(Exception):
        gate_contract(6, 6, "per-session", manifest=m)