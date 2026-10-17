"""JUnit-XML result parsing tests.

The gate reads ctest's machine-readable verdicts instead of its console
output because console layout broke the parser twice. These tests pin the
fail-closed rule that matters most: only an explicit absence of
failure/error/skipped is a pass, and a missing element is an error rather
than an assumption.
"""
import importlib.util
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def _load_gate():
    spec = importlib.util.spec_from_file_location(
        "e0_gate_junit", REPO / "tools" / "e0_gate.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["e0_gate_junit"] = mod
    spec.loader.exec_module(mod)
    return mod


gate = _load_gate()

HEAD = ('<?xml version="1.0" encoding="UTF-8"?>\n<testsuite name="all" '
        'tests="4" failures="1">\n')


def _write(tmp_path, cases):
    p = tmp_path / "r.xml"
    p.write_text(HEAD + "".join(cases) + "</testsuite>\n", encoding="utf-8")
    return p


def test_pass_and_fail_elements(tmp_path):
    p = _write(tmp_path, [
        '<testcase name="c_sha256" classname="c" time="0.01" status="run"/>\n',
        '<testcase name="c_kem" classname="c" time="0.02" status="run">'
        '<failure message="boom">detail</failure></testcase>\n',
    ])
    assert gate.parse_junit(p, ("c_sha256", "c_kem")) == {
        "c_sha256": True, "c_kem": False}


def test_skipped_is_not_a_pass(tmp_path):
    """A skipped gated test must read as NOT passing. Counting it as a pass
    is precisely the vacuous pass B-50.5 forbids.

    The case must carry status="run" so the <skipped/> CHILD is the only
    thing that can make it not-a-pass. With status="notrun" the status test
    refuses it first and this test would stay green even if skip detection
    were deleted entirely (verified by mutation).
    """
    p = _write(tmp_path, [
        '<testcase name="c_dsa" classname="c" time="0" status="run"><skipped/></testcase>\n',
    ])
    assert gate.parse_junit(p, ("c_dsa",)) == {"c_dsa": False}
    # and the case view keeps the flag that caused the refusal
    assert gate.parse_junit_cases(p)["c_dsa"]["skipped"] is True


def test_error_element_is_not_a_pass(tmp_path):
    p = _write(tmp_path, [
        '<testcase name="c_rng" classname="c" time="0" status="run">'
        '<error message="crash"/></testcase>\n',
    ])
    assert gate.parse_junit(p, ("c_rng",)) == {"c_rng": False}


def test_missing_element_raises_rather_than_assuming_pass(tmp_path):
    p = _write(tmp_path, [
        '<testcase name="c_sha256" classname="c" time="0.01" status="run"/>\n',
    ])
    try:
        gate.parse_junit(p, ("c_sha256", "c_absent"))
    except RuntimeError as exc:
        assert "c_absent" in str(exc)
    else:
        raise AssertionError("missing element must raise, never assume")


def test_unreadable_report_raises(tmp_path):
    bad = tmp_path / "broken.xml"
    bad.write_text("<testsuite><testcase", encoding="utf-8")
    try:
        gate.parse_junit(bad, ("c_sha256",))
    except RuntimeError:
        pass
    else:
        raise AssertionError("malformed XML must raise")


def test_results_are_filtered_to_the_requested_names(tmp_path):
    # Own document: both cases pass, so the suite must declare
    # failures="0". Reusing HEAD (which declares failures="1") would be
    # an inconsistent fixture -- the gate now refuses those.
    p = tmp_path / "r.xml"
    p.write_text(
        '<testsuite name="ctest" tests="2" failures="0" errors="0" '
        'skipped="0" disabled="0" time="0">'
        '<testcase name="c_sha256" classname="c" time="0" status="run"/>'
        '<testcase name="c_extra" classname="c" time="0" status="run"/>'
        '</testsuite>\n', encoding="utf-8")
    out = gate.parse_junit(p, ("c_sha256",))
    assert out == {"c_sha256": True}
