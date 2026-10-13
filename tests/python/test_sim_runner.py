"""Runner tests (B-43.6): count, discard, pairing, SIM refusal, manifests."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "sim"))

from qcsim import ExperimentRunner, check_sim_tag, generate_traces  # noqa: E402
from qcsim.runner import check_pairing  # noqa: E402

SEED = "abcdef0123456789abcdef0123456789"
SYS = [
    {"system_id": "S2", "controller": False, "floor_bypass": False,
     "backend": "mlkem-native-2.0.0"},
    {"system_id": "S5", "controller": True, "floor_bypass": False,
     "backend": "mlkem-native-2.0.0"},
]


def _traces():
    return generate_traces("E7gen", SEED, n=10)


def test_run_count_discard_and_manifests():
    runner = ExperimentRunner(SEED, mode="E7", output_tag="SIM-e7")
    manifests, stats = runner.run(SYS, _traces(), runs=10)
    # 10 retained manifests per system (first trial discarded).
    assert len(manifests) == 10 * len(SYS)
    assert len(stats) == 10 * len(SYS)
    assert runner.counters["discarded"] == len(SYS)
    assert all("warmup" not in s["metrics"] for s in stats)
    manifest = manifests[0]
    for key in ("manifest_id", "code_hash", "seed_hex", "trace_ids",
                "mode", "systems", "backend", "assumption_version",
                "output_tag"):
        assert key in manifest
    assert manifest["seed_hex"] == SEED
    assert manifest["output_tag"] == "SIM-e7"
    assert check_pairing(manifests) is True
    # Stats rows carry the manifest/system/trace/metrics contract.
    row = stats[0]
    assert set(row) == {"manifest_id", "system_id", "trace_id", "metrics"}
    # Deterministic: a second runner with the same seed repeats bit-identically.
    runner2 = ExperimentRunner(SEED, mode="E7", output_tag="SIM-e7")
    manifests2, stats2 = runner2.run(SYS, _traces(), runs=10)
    assert manifests2 == manifests and stats2 == stats


def test_refusals():
    runner = ExperimentRunner(SEED, output_tag="SIM-x")
    # Fewer than 10 runs refused.
    try:
        runner.run(SYS, _traces(), runs=9)
        assert False
    except ValueError:
        pass
    # Mixed backends refused (validity rule).
    mixed = [dict(SYS[0]),
             {"system_id": "SX", "controller": True,
              "floor_bypass": False, "backend": "other"}]
    try:
        runner.run(mixed, _traces(), runs=10)
        assert False
    except ValueError:
        pass
    # Non-SIM output refused at construction.
    try:
        ExperimentRunner(SEED, output_tag="hardware-run")
        assert False
    except ValueError:
        pass
    assert check_sim_tag("plot SIM caption") is True
    assert check_sim_tag("bare caption") is False
    # Unpaired manifests refused.
    manifests, _ = runner.run(SYS, _traces(), runs=10)
    bad = dict(manifests[0])
    bad["seed_hex"] = "00" * 16
    try:
        check_pairing([manifests[1], bad])
        assert False
    except ValueError:
        pass
