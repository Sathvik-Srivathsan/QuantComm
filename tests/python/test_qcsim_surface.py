"""qcsim surface gate: exactly the five B-43 foundation names."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "sim"))

import qcsim  # noqa: E402

FIVE = {
    "ExperimentRunner",
    "RNGStreams",
    "SimClock",
    "check_sim_tag",
    "generate_traces",
}


def test_qcsim_surface_exact():
    assert set(qcsim.__all__) == FIVE
    for name in qcsim.__all__:
        assert callable(getattr(qcsim, name)), name
    public = {n for n in dir(qcsim) if not n.startswith("_")}
    assert public - {"clock", "runner", "simtag", "streams", "traces"} == \
        set(qcsim.__all__), public
