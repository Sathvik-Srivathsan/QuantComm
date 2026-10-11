"""API-surface gate: exactly the six B-40 verbs (B-40.6 lean-ness).
Growth beyond six fails CI deliberately — a seventh public entry
point means the service stopped being lean.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "server"))

import qcsrv  # noqa: E402

SIX = {
    "AuditStore",
    "Registry",
    "srv_handshake",
    "srv_ingest",
    "srv_policy",
    "srv_verify",
}


def test_surface_exact():
    assert set(qcsrv.__all__) == SIX
    for name in qcsrv.__all__:
        assert callable(getattr(qcsrv, name)), name
    # Submodules are import-system attributes, not API: allow exactly
    # the six implementation modules, nothing else public.
    public = {n for n in dir(qcsrv) if not n.startswith("_")}
    assert public - {"audit", "registry", "handshake", "ingress",
                     "policy", "verifier"} == set(qcsrv.__all__), public
