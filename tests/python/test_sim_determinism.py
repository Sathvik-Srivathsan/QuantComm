"""Determinism tests (B-43.1): streams, clock, banned calls, double-run.

Deterministic (fixed seeds throughout). The banned-call scan is the
CI grep gate's in-suite twin: wall-clock reads, os.urandom outside
the seeder, threads, and unseeded random must never enter sim/.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "sim"))

from qcsim import RNGStreams, SimClock, generate_traces  # noqa: E402

SEED = "00" * 15 + "01"


def test_streams_domain_separated_and_reproducible():
    a = RNGStreams(SEED)
    b = RNGStreams(SEED)
    # Same seed: bit-identical draws per label.
    assert a.next_bytes("device", 64) == b.next_bytes("device", 64)
    assert a.next_u64("network") == b.next_u64("network")
    # Labels never share draws: device bytes != network bytes.
    c = RNGStreams(SEED)
    assert c.next_bytes("device", 32) != c.next_bytes("network", 32)
    # Uniform in [0, 1), reproducible.
    d = RNGStreams(SEED)
    u = d.next_uniform("attacker")
    assert 0.0 <= u < 1.0
    assert RNGStreams(SEED).next_uniform("attacker") == u
    # Guards: bad seeds refuse.
    for bad in ("", "zz" * 16, "00" * 15, "00" * 17):
        try:
            RNGStreams(bad)
            assert False, bad
        except ValueError:
            pass


def test_clock_monotonic_no_wall_clock():
    c = SimClock()
    assert c.now() == 0
    assert c.advance() is None
    c.schedule(30, "b")
    c.schedule(10, "a")
    assert c.advance() == (10, "a")
    assert c.now() == 10
    assert c.advance() == (30, "b")
    assert c.now() == 30
    assert c.pending() == 0
    try:
        SimClock(start_us=-1)
        assert False
    except ValueError:
        pass
    try:
        c.schedule(-5)
        assert False
    except ValueError:
        pass
    # No wall-clock surface anywhere in the package.
    import qcsim.clock as ck
    import qcsim.streams as st
    assert not hasattr(ck, "time") and "time" not in dir(ck)
    assert "time" not in dir(st)


def test_banned_calls_absent():
    repo = Path(__file__).resolve().parents[2] / "sim" / "qcsim"
    text = "\n".join(p.read_text() for p in repo.glob("*.py"))
    assert "import time" not in text
    assert "from time" not in text
    assert "import datetime" not in text
    assert "from datetime" not in text
    assert "import threading" not in text
    assert "from threading" not in text
    assert "import random" not in text
    assert "from random" not in text
    # The seeder is the sole os.urandom call site (streams.py from_os only;
    # docstrings may name it, so count call syntax, not prose mentions).
    assert text.count("os.urandom(") == 1
    assert "from_os" in text


def test_double_run_bit_identical():
    t1 = generate_traces("E7gen", SEED)
    t2 = generate_traces("E7gen", SEED)
    assert t1 == t2
    assert generate_traces("E7gen", "ff" * 16) != t1
