"""qcgw surface gate: exactly the eight B-42 names (lean service).
Growth is deliberate per change, never silent. The qcsrv six-verb
freeze is a separate package and untouched by this file.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "server"))

import qcgw  # noqa: E402

EIGHT = {
    "E2ERelay",
    "GatewayRegistry",
    "Reassembler",
    "TrustedRelay",
    "check_gateway",
    "loopback_pair",
    "split_frame",
    "tcp_pair",
}


def test_qcgw_surface_exact():
    assert set(qcgw.__all__) == EIGHT
    for name in qcgw.__all__:
        assert callable(getattr(qcgw, name)), name
    public = {n for n in dir(qcgw) if not n.startswith("_")}
    assert public - {"frag", "relay", "transports"} == set(
        qcgw.__all__), public
