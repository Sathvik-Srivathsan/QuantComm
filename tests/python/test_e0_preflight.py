"""Runner E0-gate preflight tests (plan B-50.4 interface requirement).

B-50.4 requires experiment harnesses to preflight the gate ID and refuse on
red or missing, with a logged refusal. These tests prove the refusal is
real (a gate-less run cannot silently succeed), that it is typed (never a
silent empty result set), and that every manifest discloses whether the
preflight ran - so a run that skipped it is visible in its own output.
"""
import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "sim"))

from qcsim import GateRefusal, ExperimentRunner, generate_traces  # noqa: E402
from qcsim import gate as gate_mod                 # noqa: E402

SEED = "abcdef0123456789abcdef0123456789"
SYS = [
    {"system_id": "S2", "controller": False, "floor_bypass": False,
     "backend": "mlkem-native-2.0.0"},
    {"system_id": "S5", "controller": True, "floor_bypass": False,
     "backend": "mlkem-native-2.0.0"},
]


def _traces():
    return generate_traces("E7gen", SEED, n=10)


def _green_gate(build: Path, monkeypatch, head="head-sha"):
    d = build / "e0"
    d.mkdir(parents=True, exist_ok=True)
    rec = {"commit": head, "verdict": "pass", "timestamp": "T",
           "gate_id": gate_mod.mint_gate_id(head, "pass", "T"),
           "total_tests": 1, "passed_tests": 1}
    (d / "latest-gate.json").write_text(json.dumps(rec), encoding="utf-8")
    monkeypatch.setattr(gate_mod, "git_commit", lambda repo: head)
    return rec["gate_id"]


@pytest.fixture
def fake_build(tmp_path, monkeypatch):
    """Point the runner's build-dir lookup at a temp tree."""
    monkeypatch.setattr("qcsim.runner._build_dir", lambda: tmp_path)
    monkeypatch.setattr("qcsim.runner._repo_root", lambda: REPO)
    return tmp_path


def test_require_gate_refuses_when_no_record(fake_build):
    r = ExperimentRunner(SEED, output_tag="SIM-preflight")
    with pytest.raises(GateRefusal) as exc:
        r.run(SYS, _traces(), runs=10, require_gate=True)
    assert "no gate record" in str(exc.value)


def test_require_gate_refuses_on_red(fake_build, monkeypatch):
    d = fake_build / "e0"
    d.mkdir(parents=True, exist_ok=True)
    (d / "latest-gate.json").write_text(json.dumps({
        "commit": "head-sha", "verdict": "fail", "timestamp": "T",
        "gate_id": gate_mod.mint_gate_id("head-sha", "fail", "T"),
    }), encoding="utf-8")
    monkeypatch.setattr(gate_mod, "git_commit", lambda repo: "head-sha")
    r = ExperimentRunner(SEED, output_tag="SIM-preflight")
    with pytest.raises(GateRefusal) as exc:
        r.run(SYS, _traces(), runs=10, require_gate=True)
    assert "verdict" in str(exc.value)


def test_require_gate_refuses_on_build_mismatch(fake_build, monkeypatch):
    # Record minted for one commit, HEAD pinned to a DIFFERENT one: a green
    # gate for another build is not a green gate for this build.
    _green_gate(fake_build, monkeypatch, head="gate-sha")
    monkeypatch.setattr(gate_mod, "git_commit", lambda repo: "head-sha")
    r = ExperimentRunner(SEED, output_tag="SIM-preflight")
    with pytest.raises(GateRefusal) as exc:
        r.run(SYS, _traces(), runs=10, require_gate=True)
    assert "build-ID binding" in str(exc.value)


def test_require_gate_passes_and_records_id(fake_build, monkeypatch):
    gid = _green_gate(fake_build, monkeypatch)
    r = ExperimentRunner(SEED, output_tag="SIM-preflight")
    manifests, _ = r.run(SYS, _traces(), runs=10, require_gate=True)
    assert manifests
    for m in manifests:
        assert m["gate_preflight"] == "verified"
        assert m["e0_gate_id"] == gid


def test_named_gate_id_mismatch_refuses(fake_build, monkeypatch):
    _green_gate(fake_build, monkeypatch)
    r = ExperimentRunner(SEED, output_tag="SIM-preflight")
    with pytest.raises(GateRefusal) as exc:
        r.run(SYS, _traces(), runs=10, gate_id="e0-somethingelse000")
    assert "caller expects" in str(exc.value)


def test_manifest_discloses_skipped_preflight(fake_build, monkeypatch):
    """Without a gate, the run still works (the runner is also the sim's own
    unit-test subject) but every manifest says so explicitly."""
    monkeypatch.setattr(gate_mod, "git_commit", lambda repo: "head-sha")
    r = ExperimentRunner(SEED, output_tag="SIM-preflight")
    manifests, _ = r.run(SYS, _traces(), runs=10)
    for m in manifests:
        assert m["gate_preflight"] == "not-required"
        assert m["e0_gate_id"] is None
