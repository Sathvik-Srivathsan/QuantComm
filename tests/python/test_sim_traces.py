"""Trace-generator tests (B-43.5): 30 traces, IDs, schema, priors."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "sim"))

from qcsim import generate_traces  # noqa: E402
from qcsim.traces import validate_trace  # noqa: E402

SEED = "0123456789abcdef0123456789abcdef"


def test_thirty_traces_validate():
    traces = generate_traces("E7gen", SEED)
    assert len(traces) == 30
    ids = [t["trace_id"] for t in traces]
    assert len(set(ids)) == 30  # unique by construction
    for i, trace in enumerate(traces):
        assert trace["serial"] == i
        assert trace["trace_id"].startswith(f"E7gen-{i:08d}-")
        assert trace["trace_id"].endswith(SEED)
        assert trace["schema_version"] == [1, 0]
        assert trace["meta"]["synthetic"] is True
        assert trace["priors"]["topology"] == "calm/attack"
        assert validate_trace(trace) is True
        assert len(trace["vectors"]) == 64
        for vec in trace["vectors"]:
            assert vec["ver"] == [1, 0]
            assert 0 <= vec["soc"] <= 100
            assert vec["S"] in (0, 1)
    # No global default: unknown family refuses.
    try:
        generate_traces("E7gen", SEED, family="nope")
        assert False
    except ValueError:
        pass
