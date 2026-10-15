"""The producer/consumer contract gate itself (tools/e1_smoke_check.py).

The gate exists because the bench and the driver were authored together
and nothing outside that author ever checked they agree. These tests pin
the gate's OWN behaviour, because a gate that cannot fail is the exact
false positive this whole mechanism was built to prevent.

The real end-to-end check runs in CI's `E1 producer/consumer contract
check` step, where the binary exists. On a host without it, the tests
below verify the gate refuses rather than passing vacuously.
"""
import importlib.util
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def _load():
    spec = importlib.util.spec_from_file_location(
        "e1_smoke_check", REPO / "tools" / "e1_smoke_check.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["e1_smoke_check"] = mod
    spec.loader.exec_module(mod)
    return mod


chk = _load()


def _load_driver():
    spec = importlib.util.spec_from_file_location(
        "e1_run_contract", REPO / "tools" / "e1_run.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["e1_run_contract"] = mod
    spec.loader.exec_module(mod)
    return mod


def _valid_row(**over):
    row = {"op": "sha256", "level": "host", "payload": 16, "n": 2,
           "ns_mean": 1, "ns_p50": 1, "ns_p95": 1, "ns_p99": 1,
           "ns_max": 2, "cycles_p50": 3, "heap_live_bytes": 0,
           "cycle_source": "rdtsc-fenced",
           "stack_metric": "pending-verification",
           "energy_field": "absent-by-design"}
    row.update(over)
    return row


def _fake_bench(tmp_path, monkeypatch):
    """A bench that exists and exits 0 with the given stdout."""
    fake = tmp_path / "bench"
    fake.write_text("x")
    monkeypatch.setattr(chk, "BENCH", fake)
    return fake


def test_gate_refuses_when_the_binary_is_absent(tmp_path, monkeypatch):
    """A missing bench must be INFRA (non-zero), never a silent pass."""
    monkeypatch.setattr(chk, "BENCH", tmp_path / "nope")
    assert chk.main() == 3


def test_gate_refuses_when_the_bench_exits_nonzero(tmp_path, monkeypatch):
    _fake_bench(tmp_path, monkeypatch)
    monkeypatch.setattr(chk.subprocess, "run",
                        lambda *a, **k: subprocess.CompletedProcess(
                            a[0], 3, "", "op failed"))
    assert chk.main() == 1


def test_gate_refuses_rows_the_driver_cannot_parse(tmp_path, monkeypatch):
    """Output violating the driver's schema must fail the gate. This is the
    failure the gate exists to catch: a bench/driver key drift."""
    _fake_bench(tmp_path, monkeypatch)
    monkeypatch.setattr(chk.subprocess, "run",
                        lambda *a, **k: subprocess.CompletedProcess(
                            a[0], 0, '{"op":"sha256"}\n', ""))
    assert chk.main() == 1, "a row missing every required key must be caught"


def test_gate_refuses_empty_output(tmp_path, monkeypatch):
    _fake_bench(tmp_path, monkeypatch)
    monkeypatch.setattr(chk.subprocess, "run",
                        lambda *a, **k: subprocess.CompletedProcess(
                            a[0], 0, "", ""))
    assert chk.main() == 1, "zero rows is not a pass"


def test_gate_refuses_when_rows_disagree_on_their_key_set(
        tmp_path, monkeypatch):
    """Two ops emitting different key sets is a producer defect the driver
    alone would not flag, since each row is individually schema-valid."""
    _fake_bench(tmp_path, monkeypatch)
    driver = _load_driver()
    monkeypatch.setattr(chk.subprocess, "run",
                        lambda *a, **k: subprocess.CompletedProcess(
                            a[0], 0, "rows", ""))
    monkeypatch.setattr(chk, "_load_driver", lambda: driver)
    monkeypatch.setitem(driver.__dict__, "parse_rows",
                        lambda out: [_valid_row(),
                                     _valid_row(surprise_field=1)])
    monkeypatch.setitem(driver.__dict__, "validate_rows",
                        lambda r, n: [])
    assert chk.main() == 1


def test_gate_accepts_a_conforming_matrix(tmp_path, monkeypatch):
    """Positive control: the gate must PASS on good input. A gate that
    always fails is as useless as one that always passes."""
    _fake_bench(tmp_path, monkeypatch)
    driver = _load_driver()
    monkeypatch.setattr(chk.subprocess, "run",
                        lambda *a, **k: subprocess.CompletedProcess(
                            a[0], 0, "rows", ""))
    monkeypatch.setattr(chk, "_load_driver", lambda: driver)
    monkeypatch.setitem(driver.__dict__, "parse_rows",
                        lambda out: [_valid_row(), _valid_row()])
    monkeypatch.setitem(driver.__dict__, "validate_rows",
                        lambda r, n: [])
    assert chk.main() == 0
