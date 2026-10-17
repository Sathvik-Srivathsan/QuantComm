"""Regression tests for every defect the blind audit found.

Each test names the defect it locks down. These are the tests that
were MISSING: the original suite was green against all six criticals.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import pytest

from analysis.vector_schema import (SCHEMA_VERSION, SchemaError,
                                    monotonic_run_id, per_test_from_junit,
                                    sha256_hex, validate, validate_set)


def _pv(i=0, passed=True):
    return {"schema_version": SCHEMA_VERSION, "vector_id": "kat-%06d" % i,
            "level": None, "passed": passed, "input_sha256": None,
            "output_sha256": None, "gate_commit": None, "gate_id": None}


# ---- C1: real JUnit attributes are STRINGS ----
def _case(name="c_kem", ran=True, failed=False, skipped=False, time="0.42"):
    """A case in the shape parse_junit_cases actually produces.

    PER-TEST semantics: the testcase IS the unit, so the record carries
    the test's own outcome (vector_count 1). Ctest's <testsuite> counts
    are RUN-level aggregates and are deliberately not attributed to an
    individual case -- doing so invents numbers ctest never reported.
    """
    return {"name": name, "classname": name, "time": time,
            "status": "run" if ran else "notrun", "ran": ran,
            "skipped": skipped, "failed": failed}


# ---- C1: string attributes must never concatenate into a count ----
def test_c1_suite_string_counts_never_reach_a_per_test_record():
    """'1'+'0' used to yield 10 failures and -6 passes. Suite strings
    cannot reach per-test counts now that the record is test-scoped."""
    r = per_test_from_junit(_case(time="0.42"))
    assert (r["vector_count"], r["pass_count"], r["fail_count"]) == (1, 1, 0)
    assert r["duration_s"] == pytest.approx(0.42)
    validate(r, "per-test")


def test_c1_real_string_shape_validates_end_to_end():
    validate(per_test_from_junit(_case(name="c_dsa", time="1.5")), "per-test")


def test_failed_case_records_exactly_one_failure():
    r = per_test_from_junit(_case(failed=True))
    assert (r["vector_count"], r["pass_count"], r["fail_count"]) == (1, 0, 1)
    validate(r, "per-test")


# ---- C2/H6: a skipped case is NOT a pass (B-50.5 fail-closed) ----
def test_c2_skipped_case_is_refused_not_recorded_as_pass():
    """A <skipped/> child refuses the case even when the status says it ran.

    The case must carry ran=True, because a `ran=False` fixture is refused by
    the status check first -- so the skipped guard could be deleted and this
    test stayed green (verified by mutation).
    """
    with pytest.raises(SchemaError) as e:
        per_test_from_junit(_case(ran=True, skipped=True))
    assert "SKIP" in str(e.value)
    # the not-run case is a SEPARATE refusal, on status
    with pytest.raises(SchemaError, match="status"):
        per_test_from_junit(_case(ran=False, skipped=True))


def test_c2_missing_counts_are_refused_not_defaulted_to_pass():
    with pytest.raises(SchemaError):
        per_test_from_junit({"name": "c_x"})


def test_c2_case_never_ran_is_refused():
    with pytest.raises(SchemaError, match="status"):
        per_test_from_junit(_case(ran=False))


def test_c2_skipped_attribute_present_even_when_absent_is_ignored():
    """skipped=False is not a skip and must record normally."""
    assert per_test_from_junit(_case(skipped=False))["pass_count"] == 1


# ---- H: a duration ctest never reported is never a number ----
def test_fractional_duration_is_accepted():
    """0.5 s is a real ctest duration; only non-finite/negative are junk."""
    assert per_test_from_junit(dict(_case(), time="0.5"))["duration_s"] == 0.5


def test_failed_case_does_not_claim_exceeding_counts():
    """A single failing case is 1 of 1, not 'failures exceed tests'."""
    r = per_test_from_junit(_case(failed=True))
    assert r["fail_count"] <= r["vector_count"]


def test_non_numeric_duration_is_refused():
    with pytest.raises(SchemaError):
        per_test_from_junit(dict(_case(), time="abc"))


def test_negative_duration_is_refused():
    with pytest.raises(SchemaError):
        per_test_from_junit(dict(_case(), time="-1"))


def test_nonnumeric_time_is_refused():
    with pytest.raises(SchemaError):
        per_test_from_junit({"name": "c", "tests": "1", "time": "fast"})


def test_nan_time_is_refused():
    with pytest.raises(SchemaError):
        per_test_from_junit({"name": "c", "tests": "1", "time": "nan"})


# ---- every refusal leaves through SchemaError ----
@pytest.mark.parametrize("bad", [None, [], 5, "case", {}])
def test_all_bad_inputs_raise_schema_error_not_builtin(bad):
    with pytest.raises(SchemaError):
        per_test_from_junit(bad)


# ---- H5: bool is a subclass of int ----
def test_bool_rejected_for_int_fields():
    r = _pv()
    r["schema_version"] = True
    with pytest.raises(SchemaError) as e:
        validate(r, "per-vector")
    assert "bool" in str(e.value)


def test_bool_rejected_for_counts():
    r = {"schema_version": SCHEMA_VERSION, "test_name": "t", "level": None,
         "vector_count": True, "pass_count": True, "fail_count": False,
         "duration_s": None, "gate_commit": None, "gate_id": None}
    with pytest.raises(SchemaError):
        validate(r, "per-test")


# ---- H9: negative / zero counts, sum invariant ----
def test_negative_counts_refused():
    r = {"schema_version": SCHEMA_VERSION, "test_name": "t", "level": None,
         "vector_count": -10, "pass_count": -5, "fail_count": -5,
         "duration_s": None, "gate_commit": None, "gate_id": None}
    with pytest.raises(SchemaError) as e:
        validate(r, "per-test")
    assert "negative" in str(e.value)


def test_zero_count_is_refused_as_malformed():
    """vector_count 0 with pass 0 fail 0 sums, but claims nothing ran."""
    r = {"schema_version": SCHEMA_VERSION, "test_name": "t", "level": None,
         "vector_count": 0, "pass_count": 0, "fail_count": 0,
         "duration_s": None, "gate_commit": None, "gate_id": None}
    with pytest.raises(SchemaError):
        validate(r, "per-test")


# ---- H13: uniqueness + sized collection ----
def test_duplicate_vector_ids_refused():
    with pytest.raises(SchemaError) as e:
        validate_set([_pv(1), _pv(1)], "per-vector")
    assert "duplicate" in str(e.value)


def test_generator_input_refused_cleanly():
    with pytest.raises(SchemaError):
        validate_set((_pv(i) for i in range(2)), "per-vector")


def test_set_input_refused_cleanly():
    with pytest.raises(SchemaError):
        validate_set({1, 2, 3}, "per-vector")


def test_string_input_refused_cleanly():
    with pytest.raises(SchemaError):
        validate_set("not records", "per-vector")


# ---- M14: semantic fields ----
def test_sha256_fields_must_look_like_sha256():
    r = _pv()
    r["input_sha256"] = "x"
    with pytest.raises(SchemaError) as e:
        validate(r, "per-vector")
    assert "sha256" in str(e.value)


def test_uppercase_sha256_refused():
    r = _pv()
    r["output_sha256"] = sha256_hex(b"x").upper()
    with pytest.raises(SchemaError):
        validate(r, "per-vector")


def test_whitespace_vector_id_refused():
    r = _pv()
    r["vector_id"] = "   "
    with pytest.raises(SchemaError):
        validate(r, "per-vector")


def test_int_duration_accepted():
    r = {"schema_version": SCHEMA_VERSION, "test_name": "t", "level": None,
         "vector_count": 2, "pass_count": 2, "fail_count": 0,
         "duration_s": 1, "gate_commit": None, "gate_id": None}
    assert validate(r, "per-test") is True


def test_non_mapping_record_refused():
    with pytest.raises(SchemaError):
        validate(None, "per-vector")
    with pytest.raises(SchemaError):
        validate([_pv()], "per-vector")


# ---- C3: cross-experiment run-id collision ----
def test_c3_run_id_from_another_experiment_is_refused():
    """A run id that carries a DIFFERENT experiment prefix is refused.

    The message no longer distinguishes "belongs to another experiment" from
    "malformed": the matcher is now built for THIS experiment, so a foreign
    prefix simply does not match. What matters is the refusal.
    """
    with pytest.raises(SchemaError) as e:
        monotonic_run_id("E5", "E6-0007")
    assert "not monotonic" in str(e.value)


def test_c3_same_experiment_prefix_is_accepted():
    assert monotonic_run_id("E5", "E5-0007") == "E5-00000007"


def test_c3_arbitrary_prefix_is_refused():
    with pytest.raises(SchemaError):
        monotonic_run_id("E5", "whatever-7")


# ---- C4: win32 traversal ----
def test_c4_backslash_traversal_refused():
    for bad in ("..\\evil", "E5\\sub", "C:", "E5\x00"):
        with pytest.raises(SchemaError):
            monotonic_run_id(bad, "1")


def test_c4_posix_traversal_still_refused():
    for bad in ("../x", "a/b", "..", ""):
        with pytest.raises(SchemaError):
            monotonic_run_id(bad, "1")
        with pytest.raises(SchemaError):
            monotonic_run_id("E5", bad)


# ---- H11: monotonic width ----
def test_run_id_width_limit_refuses_lexicographic_break():
    assert monotonic_run_id("E5", "99999999") == "E5-99999999"
    # width is now 8 digits, so lexicographic order matches numeric order
    with pytest.raises(SchemaError):
        monotonic_run_id("E5", "999999999")


def test_ordered_run_ids_sort_correctly():
    ids = [monotonic_run_id("E5", str(n)) for n in (1, 2, 10, 100, 1000)]
    assert ids == sorted(ids)