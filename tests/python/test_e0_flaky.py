"""B-50.4 flaky-failure policy tests.

The rerun policy is the easiest part of a gate to get quietly wrong: a
flaky pass must still be VISIBLE, and a persistent failure must stay red
across every attempt. Both are asserted here against the real retry loop,
not against a re-implementation of it.
"""
import importlib.util
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def _load_gate():
    spec = importlib.util.spec_from_file_location(
        "e0_gate_flaky", REPO / "tools" / "e0_gate.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["e0_gate_flaky"] = mod
    spec.loader.exec_module(mod)
    return mod


gate = _load_gate()


class _FakeReport:
    def __init__(self, verdict):
        self.verdict = verdict
        self.flaky_reruns = 0
        # _evaluate_with_rerun mints the gate id ONCE here, over the FINAL
        # verdict, so the double must carry the fields minting reads.
        self.commit = "f" * 40
        self.timestamp = "2026-01-01T00:00:00Z"
        self.gate_id = ""


def test_persistent_failure_stays_red(monkeypatch):
    """Three red attempts must not become a pass on the third."""
    calls = []

    def always_fail(build, repo):
        calls.append(1)
        return _FakeReport("fail"), {"c_sha256": False}

    monkeypatch.setattr(gate, "evaluate", always_fail)
    report, _, _cases = gate._evaluate_with_rerun(Path("."), REPO)
    assert report.verdict == "fail"
    assert len(calls) == gate.FLAKY_RERUNS, "must exhaust the rerun budget"
    assert report.flaky_reruns == gate.FLAKY_RERUNS - 1


def test_flaky_pass_is_recorded_not_laundered(monkeypatch):
    """H1: a rerun must NEVER promote a red gate to green. A test red with
    probability p reported green with probability 1-p**N under the old
    policy (0.875 at p=0.5). The verdict stays red as ``flaky-red`` and the
    rerun count is still recorded -- kept as flake EVIDENCE, not a waiver."""
    seq = ["fail", "fail", "pass"]
    calls = []

    def flaky(build, repo):
        calls.append(1)
        return _FakeReport(seq[min(len(calls) - 1, len(seq) - 1)]), {}

    monkeypatch.setattr(gate, "evaluate", flaky)
    report, _, _cases = gate._evaluate_with_rerun(Path("."), REPO)
    assert report.verdict == "flaky-red", (
        "a rerun must never launder a red gate into green")
    assert report.flaky_reruns == 2, "the flake must be counted, not hidden"


def test_immediate_pass_does_not_rerun(monkeypatch):
    calls = []

    def once(build, repo):
        calls.append(1)
        return _FakeReport("pass"), {}

    monkeypatch.setattr(gate, "evaluate", once)
    report, _, _cases = gate._evaluate_with_rerun(Path("."), REPO)
    assert report.verdict == "pass"
    assert len(calls) == 1, "a green first run must not be re-executed"
    assert report.flaky_reruns == 0


def test_rerun_budget_is_bounded():
    """Fail-closed means the budget is finite and > 1; a single attempt
    cannot distinguish flake from failure, and an unbounded loop would
    hang a CI job forever."""
    assert 1 < gate.FLAKY_RERUNS <= 10
