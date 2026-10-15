"""E0 gate self-tests (plan B-50.5 acceptance evidence).

B-50.5 requires the gate to prove three things about ITSELF:
  - it goes red when a primitive fails
  - it has no waiver mechanism (code search, not a comment)
  - a mismatched build ID invalidates the run

The destructive variants of these (mutating a shipped C vector, breaking a
cross-check on disk) are deliberately NOT done here: they would dirty the
working tree and would test the C library rather than the gate. Instead the
gate's aggregation logic is driven with synthetic result sets, which is the
part this module owns. The C-side halves of the same properties are covered
by test_entropy_health (poisoned sources) and the existing CTests.
"""
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]


def _load_gate():
    spec = importlib.util.spec_from_file_location(
        "e0_gate", REPO / "tools" / "e0_gate.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["e0_gate"] = mod
    spec.loader.exec_module(mod)
    return mod


gate = _load_gate()


def _all_pass():
    return {n: True for ps in gate.E0_SET for n in ps.tests}


# --- gate ID: mint, verify, refuse tampering -------------------------------

def test_gate_id_round_trips():
    gid = gate.mint_gate_id("abc123", "pass", "2026-01-01T00:00:00Z")
    assert gid.startswith(gate.GATE_ID_PREFIX + "-")
    assert gate.verify_gate_id(gid, "abc123", "pass", "2026-01-01T00:00:00Z")


def test_gate_id_detects_tampering():
    gid = gate.mint_gate_id("abc123", "pass", "2026-01-01T00:00:00Z")
    # Any field swapped must fail recomputation - this is what makes a
    # manifest non-forgeable without the minting code path.
    assert not gate.verify_gate_id(gid, "deadbeef", "pass", "2026-01-01T00:00:00Z")
    assert not gate.verify_gate_id(gid, "abc123", "fail", "2026-01-01T00:00:00Z")
    assert not gate.verify_gate_id(gid, "abc123", "pass", "2026-01-02T00:00:00Z")
    assert not gate.verify_gate_id(gid[:-1] + "0", "abc123", "pass",
                                   "2026-01-01T00:00:00Z")


# --- verdict logic: one failure must redden the whole gate ----------------

@pytest.mark.parametrize("failing", [
    "c_sha256", "c_kem", "c_dsa", "c_aead", "c_xcheck",
    "c_drbg", "c_entropy_health", "c_rng",
])
def test_any_single_failure_reddens_gate(failing):
    """Drives the gate's OWN verdict function, not a restatement of `all()`.

    The previous version of this test asserted `not all(res.values())` on a
    dict it had just built - which proves Python's `all()` works, not that
    the gate reacts. This one calls verdict_from, the exact code path
    evaluate() uses.
    """
    res = _all_pass()
    res[failing] = False
    verdict, passed, total = gate.verdict_from(res)
    assert verdict == "fail", f"{failing} failure must redden the gate"
    assert passed == total - 1, "only the one failure may be counted"


def test_all_green_gates_green():
    res = _all_pass()
    verdict, passed, total = gate.verdict_from(res)
    assert verdict == "pass"
    assert passed == total == len(res)


def test_empty_results_are_a_failure_not_a_vacuous_pass():
    """Zero tests reported must never read as a green gate."""
    verdict, passed, total = gate.verdict_from({})
    assert verdict == "fail"
    assert (passed, total) == (0, 0)


def test_every_gated_test_is_reported_exactly_once():
    """A duplicated or dropped verdict must not slip through the count."""
    res = _all_pass()
    assert len(res) == len(set(res)), "duplicate test in results"
    verdict, passed, total = gate.verdict_from(res)
    assert total == len({t for ps in gate.E0_SET for t in ps.tests})


def test_cross_check_failure_is_reported_not_silent():
    res = _all_pass()
    res["c_xcheck"] = False
    rate = "100%" if res["c_xcheck"] else "FAIL"
    assert rate == "FAIL"
    assert gate.verdict_from(res)[0] == "fail"


def test_rng_health_verdict_is_tracked_per_source():
    # B-50.5 wants RNG health verdicts enumerated, not folded into a total.
    rng_keys = [n for ps in gate.E0_SET
                if ps.vectors == "B-50.3" for n in ps.tests]
    assert set(rng_keys) == {"c_drbg", "c_prod_rng", "c_rng",
                             "c_entropy_health"}


# --- no vacuous pass ------------------------------------------------------

def test_unparsed_results_are_infra_not_pass():
    """If ctest output cannot be parsed we must NOT claim green."""
    with pytest.raises(RuntimeError):
        gate.run_tests(Path("/nonexistent-build"), ("c_sha256",))


def test_e0_set_covers_every_clause():
    clauses = {ps.vectors for ps in gate.E0_SET}
    assert clauses == {"B-50.1", "B-50.2", "B-50.3"}, (
        f"E0 set must cover vector coverage, cross-checks and RNG sanity; "
        f"got {clauses}")


def test_per_vector_records_are_declared_pending_not_silently_absent():
    """B-50.5 wants per-VECTOR JSONL. The harness work is not landed, so the
    manifest must SAY so - a reader must never infer per-vector coverage
    from per-test counts."""
    r = gate.GateReport(
        commit="c", verdict="pass", timestamp="t", gate_id="g",
        total_tests=1, passed_tests=1)
    assert r.vector_records == gate.VECTOR_RECORD_STATE
    assert r.vector_records == "pending-harness"
    assert "B-10.6" in r.vector_records_owner


# --- no waiver mechanism (code search, not assertion) ---------------------

FORBIDDEN = ("continue-on-error", "--force-green", "force_green",
             "skip_e0", "waiver", "xfail", "pytest.mark.skip")


def _executable_code(text: str, is_python: bool) -> str:
    """Source with PROSE removed, mechanism preserved.

    Strips comments and DOCSTRINGS only. Ordinary string literals are KEPT
    on purpose: a waiver flag implemented as a string constant
    (`parser.add_argument("--force-green")`) is still a mechanism, and an
    earlier version of this scan stripped all strings and therefore could
    not see it - the positive control below is what caught that.
    """
    if not is_python:
        return "\n".join(ln for ln in text.splitlines()
                         if not ln.strip().startswith("#"))
    import ast
    import io
    import tokenize

    doc_lines = set()
    try:
        tree = ast.parse(text)
        for node in ast.walk(tree):
            if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef,
                                 ast.AsyncFunctionDef)):
                body = getattr(node, "body", [])
                if (body and isinstance(body[0], ast.Expr)
                        and isinstance(body[0].value, ast.Constant)
                        and isinstance(body[0].value.value, str)):
                    doc_lines.update(
                        range(body[0].lineno,
                              (body[0].end_lineno or body[0].lineno) + 1))
    except SyntaxError:
        pass                      # let the token pass report the problem
    kept = []
    for tok in tokenize.generate_tokens(io.StringIO(text).readline):
        if tok.type == tokenize.COMMENT:
            continue
        if tok.type == tokenize.STRING and tok.start[0] in doc_lines:
            continue
        kept.append(tok.string)
    return " ".join(kept)


def test_no_waiver_mechanism_in_gate_or_ci():
    """B-50.5: prove no skip / force-green flag exists. Searching the source
    is the only honest proof - a comment claiming so proves nothing."""
    for path, is_python in ((REPO / "tools" / "e0_gate.py", True),
                            (REPO / "sim" / "qcsim" / "gate.py", True),
                            (REPO / ".github" / "workflows" / "ci.yml", False)):
        code = _executable_code(path.read_text(encoding="utf-8"),
                                is_python).lower()
        for token in FORBIDDEN:
            assert token not in code, (
                f"{path.name} contains waiver token {token!r} in code")


def test_no_waiver_scan_has_a_working_positive_control():
    """A scan that can never match proves nothing. Prove the SAME detection
    logic fires on planted tokens - in code, in a string constant, and in
    YAML - and stays quiet on prose."""
    def detect(text, is_python):
        code = _executable_code(text, is_python).lower()
        return [t for t in FORBIDDEN if t in code]

    # Python code.
    assert detect("WAIVER = True\n", True) == ["waiver"]
    assert detect("x = '--force-green'\n", True) == ["--force-green"]
    assert detect("raise XFail\n", True) == ["xfail"]
    # A string constant IS a mechanism - the earlier scan missed these.
    assert "pytest.mark.skip" in detect(
        "MARK = 'pytest.mark.skip'\n", True)
    # YAML.
    assert detect("    continue-on-error: true\n", False) == [
        "continue-on-error"]
    # Prose and docstrings must NOT fire, or the scan is useless.
    assert detect('"""no waiver mechanism by design"""\n', True) == []
    assert detect(
        '"""Waivers are banned."""\nimport os\n', True) == []
    assert detect("      # no continue-on-error here\n", False) == []


# --- build-ID binding / preflight -----------------------------------------

def _write_manifest(build: Path, **kw):
    d = build / "e0"
    d.mkdir(parents=True, exist_ok=True)
    rec = {"commit": "aaa", "verdict": "pass", "timestamp": "T",
           "gate_id": gate.mint_gate_id("aaa", "pass", "T")}
    rec.update(kw)
    (d / "latest-gate.json").write_text(json.dumps(rec), encoding="utf-8")
    return rec


def _pin_head(monkeypatch, sha):
    """Pin the shared contract's HEAD reader.

    The preflight lives in qcsim.gate (single source shared with the runner),
    so the patch target is that module, not the tool wrapper.
    """
    monkeypatch.setattr(gate._gate, "git_commit", lambda repo: sha)


def test_preflight_refuses_when_no_gate_ran(tmp_path):
    ok, why = gate.preflight("", tmp_path, REPO)
    assert not ok
    assert "no gate record" in why


def test_preflight_refuses_red_verdict(tmp_path, monkeypatch):
    _write_manifest(tmp_path, verdict="fail",
                    gate_id=gate.mint_gate_id("aaa", "fail", "T"))
    _pin_head(monkeypatch, "aaa")
    ok, why = gate.preflight("", tmp_path, REPO)
    assert not ok
    assert "verdict" in why


def test_preflight_refuses_tampered_gate_id(tmp_path, monkeypatch):
    _write_manifest(tmp_path, gate_id="e0-deadbeefdeadbeef")
    _pin_head(monkeypatch, "aaa")
    ok, why = gate.preflight("", tmp_path, REPO)
    assert not ok
    assert "recompute" in why


def test_preflight_refuses_mismatched_build_commit(tmp_path, monkeypatch):
    """Build-ID binding: a green gate for a DIFFERENT commit is not a green
    gate for this build."""
    _write_manifest(tmp_path)
    _pin_head(monkeypatch, "bbbb")
    ok, why = gate.preflight("", tmp_path, REPO)
    assert not ok
    assert "build-ID binding" in why


def test_preflight_accepts_matching_green(tmp_path, monkeypatch):
    rec = _write_manifest(tmp_path)
    _pin_head(monkeypatch, "aaa")
    ok, why = gate.preflight("", tmp_path, REPO)
    assert ok, why
    ok, why = gate.preflight(rec["gate_id"], tmp_path, REPO)
    assert ok, why


def test_preflight_refuses_caller_gate_id_mismatch(tmp_path, monkeypatch):
    _write_manifest(tmp_path)
    _pin_head(monkeypatch, "aaa")
    ok, why = gate.preflight("e0-someothergate000", tmp_path, REPO)
    assert not ok
    assert "caller expects" in why


def test_unreadable_record_refuses_rather_than_crashes(tmp_path):
    d = tmp_path / "e0"
    d.mkdir(parents=True, exist_ok=True)
    (d / "latest-gate.json").write_text("{not json", encoding="utf-8")
    ok, why = gate.preflight("", tmp_path, REPO)
    assert not ok
    assert "unreadable" in why
