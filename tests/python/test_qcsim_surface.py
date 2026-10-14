"""qcsim surface gate: exactly the fifteen B-43/B-44 names (lean service).
Growth is deliberate per change, never silent."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "sim"))

import qcsim  # noqa: E402

FIFTEEN = {
    "ControlLoop",
    "DeviceModel",
    "ExperimentRunner",
    "ExperimentRunner",
    "NetworkModel",
    "RNGStreams",
    "SimClock",
    "baseline_systems",
    "check_comparison",
    "check_oracle_bound",
    "check_sim_tag",
    "generate_traces",
    "h3_input_record",
    "parse_scenario",
    "play_scenario",
    "select_anchor",
}


def test_qcsim_surface_exact():
    assert set(qcsim.__all__) == FIFTEEN
    for name in qcsim.__all__:
        assert callable(getattr(qcsim, name)), name
    public = {n for n in dir(qcsim) if not n.startswith("_")}
    assert public - {"clock", "control", "device", "network", "runner",
                      "scenarios", "simtag", "streams", "systems", "traces",
                      "validity"} == set(qcsim.__all__), public
