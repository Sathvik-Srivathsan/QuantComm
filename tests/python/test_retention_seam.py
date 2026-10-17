"""END-TO-END against CTEST'S REAL JUnit shape.

The previous version of this file fabricated a fixture: it put
tests=/failures=/errors= attributes on <testcase> and called it "a real
ctest --output-junit fragment". CMake does not write those attributes
anywhere near a testcase. From Source/CTest/cmCTestTestHandler.cxx
(2758-2806) the actual shape is:

  <testsuite tests=N failures=F errors=E skipped=S disabled=D time=T>
    <testcase name=... classname=... time=t status=run|notrun|disabled>
      [<failure>|<error>|<skipped>] <properties/> <system-out/>

counts live ONLY on <testsuite>; a testcase carries exactly four
attributes. A producer that reads counts off the case sees None for every
real test, which is how the whole seam stayed dead through three greens.

The older tests/python/test_e0_junit.py has the correct shape; this file
used to contradict it.
"""
import pytest

from analysis import vector_schema as vs
from tools.e0_gate import parse_junit, parse_junit_cases, verdict_from

REAL = ('<?xml version="1.0" encoding="UTF-8"?>'
        '<testsuite name="ctest" tests="3" failures="1" errors="0" '
        'skipped="1" disabled="0" time="1.2">'
        '<testcase name="c_sha256" classname="c_sha256" time="0.110000" '
        'status="run"><properties/><system-out>ok</system-out></testcase>'
        '<testcase name="c_kem" classname="c_kem" time="0.440000" '
        'status="run"><failure message="Failed"/>'
        '<system-out>bad</system-out></testcase>'
        '<testcase name="c_dsa" classname="c_dsa" time="0" status="notrun">'
        '<skipped message="SKIP_RETURN_CODE"/></testcase>'
        '</testsuite>')

DISABLED = ('<?xml version="1.0" encoding="UTF-8"?>'
            '<testsuite name="ctest" tests="1" failures="0" errors="0" '
            'skipped="0" disabled="1" time="0">'
            '<testcase name="c_sha256" classname="c_sha256" time="0" '
            'status="disabled"><properties/></testcase></testsuite>')

DUPLICATE = ('<?xml version="1.0" encoding="UTF-8"?>'
             '<testsuite name="ctest" tests="2" failures="1" errors="0" '
             'time="1">'
             '<testcase name="c_x" classname="a" time="0.1" status="run">'
             '<failure message="boom"/></testcase>'
             '<testcase name="c_x" classname="b" time="0.1" status="run"/>'
             '</testsuite>')

NOCOUNTS = ('<?xml version="1.0" encoding="UTF-8"?>'
            '<testsuite name="ctest" time="1">'
            '<testcase name="c_nocount" classname="c" time="0.2" '
            'status="run"/></testsuite>')

NOSTATUS = ('<?xml version="1.0" encoding="UTF-8"?>'
            '<testsuite name="ctest" tests="1" failures="0" errors="0" '
            'time="1">'
            '<testcase name="c_sha256" classname="a" time="0.1"/>'
            '</testsuite>')

SUITEFAIL = ('<?xml version="1.0" encoding="UTF-8"?>'
             '<testsuite name="ctest" tests="2" failures="1" errors="1" '
             'time="1">'
             '<testcase name="c_x" classname="a" time="0.1" status="run"/>'
             '<testcase name="c_y" classname="b" time="0.1" status="run"/>'
             '</testsuite>')


def w(tmp_path, text, n="j.xml"):
    p = tmp_path / n
    p.write_text(text, encoding="utf-8")
    return p


def test_real_ctest_shape_yields_validating_records(tmp_path):
    """THE integration test, now against the shape ctest actually emits."""
    cases = parse_junit_cases(w(tmp_path, REAL))
    assert set(cases) == {"c_sha256", "c_kem", "c_dsa"}

    good = vs.per_test_from_junit(cases["c_sha256"])
    bad = vs.per_test_from_junit(cases["c_kem"])
    # PER-TEST semantics: the testcase IS the unit. ctest's <testsuite>
    # counts are run-level aggregates and are deliberately NOT attributed
    # to an individual case -- doing so would invent numbers ctest never
    # reported.
    assert good["vector_count"] == 1 and good["fail_count"] == 0
    assert good["pass_count"] == 1
    assert bad["vector_count"] == 1 and bad["fail_count"] == 1
    assert bad["pass_count"] == 0
    assert good["pass_count"] + good["fail_count"] == good["vector_count"]
    # classname is the natural level source and is no longer discarded
    assert good["level"] == "c_sha256"
    assert good["duration_s"] == pytest.approx(0.11)


def test_notrun_case_is_refused_not_a_pass(tmp_path):
    cases = parse_junit_cases(w(tmp_path, REAL))
    with pytest.raises(vs.SchemaError):
        vs.per_test_from_junit(cases["c_dsa"])


def test_disabled_case_is_refused(tmp_path):
    """ctest emits status=disabled with NO child element at all."""
    cases = parse_junit_cases(w(tmp_path, DISABLED))
    with pytest.raises(vs.SchemaError, match="status"):
        vs.per_test_from_junit(cases["c_sha256"])


def test_disabled_case_is_not_a_pass_in_the_gate(tmp_path):
    """F4: the E0 gate must not score a disabled test as green."""
    res = parse_junit(w(tmp_path, DISABLED), names=("c_sha256",))
    assert res == {"c_sha256": False}
    assert verdict_from(res)[0] == "fail"


def test_duplicate_testcase_names_are_refused(tmp_path):
    """F5: last-wins would let document order decide a gate verdict."""
    with pytest.raises(RuntimeError, match="duplicate"):
        parse_junit_cases(w(tmp_path, DUPLICATE))


def test_absent_counts_are_refused_not_invented(tmp_path):
    """F3: absence is not zero. A case that asserts no outcome is refused.

    The missing status is now caught by the status check; a case that DOES
    carry status="run" but omits `failed` is refused by the outcome check.
    """
    with pytest.raises(vs.SchemaError, match="not 'run'"):
        vs.per_test_from_junit({"name": "c", "skipped": False})
    with pytest.raises(vs.SchemaError, match="no 'failed' outcome"):
        vs.per_test_from_junit({"name": "c", "skipped": False,
                                "status": "run", "ran": True})


def test_case_without_suite_counts_is_still_valid_per_test(tmp_path):
    """Per-test records do not read suite counts at all."""
    cases = parse_junit_cases(w(tmp_path, NOCOUNTS))
    r = vs.per_test_from_junit(cases["c_nocount"])
    assert r["vector_count"] == 1 and r["fail_count"] == 0


def test_parse_junit_gate_contract_unchanged(tmp_path):
    res = parse_junit(w(tmp_path, REAL), names=("c_sha256", "c_kem"))
    assert res == {"c_sha256": True, "c_kem": False}
    assert verdict_from(res) == ("fail", 1, 2)


# ---- REGRESSION: the audit's CRITICAL/HIGH, in the GATING function ----
# These were previously absent, which is why 84 tests stayed green while
# the E0 gate could be fooled. Each asserts the GATE path, not the
# sibling.
def test_gate_path_refuses_duplicate_names(tmp_path):
    """F1: parse_junit was last-wins; a passing duplicate after a failing
    case made ('fail') read as ('pass'). This is the verdict path."""
    with pytest.raises(RuntimeError, match="duplicate"):
        parse_junit(w(tmp_path, DUPLICATE), names=("c_x",))


def test_gate_path_missing_status_is_not_a_pass(tmp_path):
    """F2/M3: a status-less testcase must not be an explicit pass.

    Under strict suite reconciliation the missing status is a MALFORMED
    report, not merely a failure: the case reads as not-passed while the
    suite declares failures="0", and that contradiction is refused before
    a verdict is ever computed. Either way the gate cannot go green --
    this test pins which refusal fires, not merely that one does.
    """
    with pytest.raises(RuntimeError, match="refusing to let the counts"):
        parse_junit(w(tmp_path, NOSTATUS), names=("c_sha256",))


def test_gate_path_suite_counts_must_reconcile(tmp_path):
    """F3: suite says failures=1 errors=1 but no case reads as failing."""
    with pytest.raises(RuntimeError, match="refusing to let the counts"):
        parse_junit(w(tmp_path, SUITEFAIL), names=("c_x", "c_y"))


def test_gate_path_reconciles_against_all_cases_not_filtered(tmp_path):
    """The counts belong to the WHOLE suite; a names= filter must not
    make a genuinely failing case look unreconciled."""
    res = parse_junit(w(tmp_path, REAL), names=("c_sha256",))
    assert res == {"c_sha256": True}


# ---- T4: the old test asserted a HARDCODED constant, so it passed even
# if string concatenation were reintroduced. This one varies the input.
def test_string_attributes_never_reach_per_test_counts():
    """C1: '"1"+"0"' once yielded 10 failures and -6 passes. Vary the
    inputs so a concatenation bug would have to reproduce by accident."""
    for suite, tc_time in ((("3", "1", "0"), "0.42"), (("10", "2", "5"), "9.9")):
        case = {"name": "c_kem", "classname": "c_kem", "time": tc_time,
                "status": "run", "ran": True, "skipped": False,
                "failed": False,
                "suite": {"tests": suite[0], "failures": suite[1],
                          "errors": suite[2], "skipped": "0",
                          "disabled": "0"}}
        r = vs.per_test_from_junit(case)
        # per-test counts are the CASE's own outcome, never the suite's
        assert (r["vector_count"], r["pass_count"], r["fail_count"]) \
            == (1, 1, 0)
        assert r["duration_s"] == pytest.approx(float(tc_time))


# ---- T5/T3 contradiction: one claimed absent counts were refused, the
# other asserted the same input yields a VALID PASS. Both were green.
# The truth: per-test records do not read suite counts at all.
def test_per_test_ignores_suite_counts_entirely(tmp_path):
    """A suite with NO counts still yields a valid per-test record --
    because per-test counts are the case's own outcome, not the suite's.
    This replaces the two tests that asserted the opposite of each
    other."""
    r = vs.per_test_from_junit(parse_junit_cases(w(tmp_path, NOCOUNTS))["c_nocount"])
    assert (r["vector_count"], r["pass_count"], r["fail_count"]) == (1, 1, 0)


def test_case_never_ran_is_refused_not_a_pass():
    """T3's real intent: a case that does not assert it ran is refused.

    Both halves are exercised: a case whose status is not "run" fails the
    status check, and a case that claims status="run" but does not assert
    `ran` fails the belt-and-braces check after it.
    """
    with pytest.raises(vs.SchemaError, match="not 'run'"):
        vs.per_test_from_junit({"name": "c", "skipped": False,
                                "failed": False, "status": "notrun"})
    with pytest.raises(vs.SchemaError, match="does not assert that it ran"):
        vs.per_test_from_junit({"name": "c", "skipped": False,
                                "failed": False, "status": "run",
                                "ran": False})


def test_absent_status_is_refused_not_treated_as_ran():
    """Fail-open closed: `status is not None and status != "run"` let a case
    with NO status reach the pass path, so a harness that omitted the
    attribute scored a pass for a test whose execution was never reported."""
    with pytest.raises(vs.SchemaError, match="not 'run'"):
        vs.per_test_from_junit({"name": "c", "skipped": False,
                                "failed": False, "ran": True})


def test_absent_failed_outcome_is_refused_not_a_pass():
    """`bool(case.get("failed"))` scored a MISSING outcome as False = pass."""
    with pytest.raises(vs.SchemaError, match="no 'failed' outcome"):
        vs.per_test_from_junit({"name": "c", "status": "run", "ran": True})
    with pytest.raises(vs.SchemaError, match="must be bool"):
        vs.per_test_from_junit({"name": "c", "status": "run", "ran": True,
                                "failed": "yes"})


# ---- `ran` is a TWO-clause expression and neither clause was pinned --------
# tools/e0_gate.py computes:
#     ran = (status in ("run", "fail")) and not skipped
# Mutation testing (tools/mutate_check.py) showed that reverting EITHER half
# left the whole suite green: no test drove a real status="fail" case, and the
# only <skipped/> test asserted `skipped`, never `ran`. A `<skipped/>` child
# counting as "executed" is a vacuous pass -- the thing the spec bans.
FAIL_STATE = ('<?xml version="1.0" encoding="UTF-8"?>'
              '<testsuite name="ctest" tests="1" failures="1" errors="0" '
              'skipped="0" disabled="0" time="0.44">'
              '<testcase name="c_kem" classname="c_kem" time="0.440000" '
              'status="fail"><failure message="Failed"/>'
              '<system-out>bad</system-out></testcase>'
              '</testsuite>')

SKIPPED_CHILD = ('<?xml version="1.0" encoding="UTF-8"?>'
                 '<testsuite name="ctest" tests="1" failures="0" errors="1" '
                 'skipped="0" disabled="0" time="0">'
                 '<testcase name="c_kem" classname="c_kem" time="0.1" '
                 'status="run"><skipped message="SKIP_RETURN_CODE"/>'
                 '</testcase></testsuite>')


def test_status_fail_means_the_test_executed(tmp_path):
    """CMake emits status="fail" for a FAILED test, not status="run".

    Treating only status=="run" as executed sent every real failure down the
    minimal-fallback path, so the JUnit-derived retained row (with its real
    duration) existed only for green runs -- the artifact degraded for exactly
    the runs that matter. Pinned end-to-end from JUnit text to the case dict.
    """
    cases = parse_junit_cases(w(tmp_path, FAIL_STATE))
    assert cases["c_kem"]["ran"] is True, "a failed test DID execute"
    assert cases["c_kem"]["failed"] is True
    assert cases["c_kem"]["skipped"] is False


def test_a_skipped_child_is_not_executed(tmp_path):
    """`and not skipped` is load-bearing: a <skipped/> child did not complete.

    Counting it as executed is a vacuous pass. This assertion is what makes
    the second half of the `ran` expression mutation-detectable.
    """
    cases = parse_junit_cases(w(tmp_path, SKIPPED_CHILD))
    assert cases["c_kem"]["skipped"] is True
    assert cases["c_kem"]["ran"] is False


# ---- T6: _count had ZERO production callers (and has since been deleted);
# its tests could not fail for a regression in the live path. These drive the
# real caller, and name the field they actually exercise: duration.
def test_duration_non_finite_is_refused_via_a_real_caller():
    for bad in (float("inf"), float("-inf"), float("nan")):
        with pytest.raises(vs.SchemaError, match="time must be finite"):
            vs.per_test_from_junit(_case(time=bad))


def test_duration_huge_digits_is_refused_via_a_real_caller():
    with pytest.raises(vs.SchemaError):
        vs.per_test_from_junit(_case(time="9" * 5000))


def _case(name="c_kem", ran=True, failed=False, skipped=False, time="0.42"):
    return {"name": name, "classname": name, "time": time,
            "status": "run" if ran else "notrun", "ran": ran,
            "skipped": skipped, "failed": failed}


def test_duration_infinity_is_refused():
    """F8: +inf passed the original d<0 / d!=d test."""
    rec = {"schema_version": vs.SCHEMA_VERSION, "test_name": "t",
           "level": "l", "vector_count": 1, "pass_count": 1,
           "fail_count": 0, "duration_s": float("inf"),
           "gate_commit": None, "gate_id": None}
    with pytest.raises(vs.SchemaError):
        vs.validate(rec, "per-test")


def test_duration_bool_is_refused():
    rec = {"schema_version": vs.SCHEMA_VERSION, "test_name": "t",
           "level": "l", "vector_count": 1, "pass_count": 1,
           "fail_count": 0, "duration_s": True,
           "gate_commit": None, "gate_id": None}
    with pytest.raises(vs.SchemaError):
        vs.validate(rec, "per-test")


def test_monotonic_run_id_refuses_non_increasing():
    """F10: it was a pure formatter; G5's no-overwrite was unenforced."""
    assert vs.monotonic_run_id("E5", "5", previous="4") == "E5-00000005"
    with pytest.raises(vs.SchemaError, match="not monotonic"):
        vs.monotonic_run_id("E5", "5", previous="5")
    with pytest.raises(vs.SchemaError, match="not monotonic"):
        vs.monotonic_run_id("E5", "3", previous="5")


def test_monotonic_run_id_refuses_non_string_exp():
    """F11: None was silently stringified to 'None-00000001'."""
    with pytest.raises(vs.SchemaError, match="must be strings"):
        vs.monotonic_run_id(None, "1")


def test_vector_id_dot_segments_refused():
    """vector_id now matches monotonic_run_id's screening."""
    for vid in (".", "..", "C:x"):
        rec = {"schema_version": vs.SCHEMA_VERSION, "vector_id": vid,
               "level": "l", "passed": True, "input_sha256": None,
               "output_sha256": None, "gate_commit": None, "gate_id": None}
        with pytest.raises(vs.SchemaError, match="unsafe vector_id"):
            vs.validate(rec, "per-vector")
