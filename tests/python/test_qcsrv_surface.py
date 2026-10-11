"""API-surface gate: the package exposes exactly the verbs that have
landed (two now, six at B-40 completion). Growth is deliberate: adding
a verb updates this allowlist in the same commit, never silently.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "server"))

import qcsrv  # noqa: E402


def test_surface_exact():
    assert qcsrv.__all__ == ["AuditStore", "Registry"]
    for name in qcsrv.__all__:
        assert callable(getattr(qcsrv, name)), name
    # Submodules are import-system attributes, not API: allow exactly
    # the two implementation modules, nothing else public.
    public = {n for n in dir(qcsrv) if not n.startswith("_")}
    assert public - {"audit", "registry"} == set(qcsrv.__all__), public
