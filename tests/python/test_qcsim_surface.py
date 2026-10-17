"""qcsim surface gate: exactly the sixteen B-43/B-44/B-50 names (lean
service). Growth is deliberate per change, never silent."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "sim"))

import qcsim  # noqa: E402

THIRTY_THREE = {
    "AttackError",
    "CampaignError",
    "EpsilonRegistration",
    "TOwncome",
    "CampaignManifest",
    "Cell",
    "ControlLoop",
    "DeviceModel",
    "ExperimentRunner",
    "GateRefusal",
    "ModelPinChanged",
    "Registration",
    "NetworkModel",
    "RNGStreams",
    "SimClock",
    "baseline_systems",
    "epsilon",
    "excess_energy",
    "excess_rate_J_per_h",
    "h4_input",
    "check_comparison",
    "check_split",
    "check_oracle_bound",
    "check_sim_tag",
    "e5_cells",
    "generate_traces",
    "h3_comparator",
    "h3_input_record",
    "parse_scenario",
    "play_scenario",
    "register_e6",
    "run_count",
    "select_anchor",
}

SUBMODULES = {"attacks", "campaign", "clock", "control", "device", "gate", "network", "runner",
              "scenarios", "simtag", "streams", "systems", "traces",
              "validity"}


def test_qcsim_surface_exact():
    assert set(qcsim.__all__) == THIRTY_THREE
    for name in qcsim.__all__:
        assert callable(getattr(qcsim, name)), name
    public = {n for n in dir(qcsim) if not n.startswith("_")}
    assert public - SUBMODULES == set(qcsim.__all__), public
