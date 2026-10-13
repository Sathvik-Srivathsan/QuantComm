"""SIM-tag enforcement (B-43.1/B-43.6): sim results never read as hardware.

Every output path, table caption, and plot watermark must carry the
SIM marker (case-sensitive substring "SIM"); the runner validates
with hard-error refusal on violation (ValueError, never silent).
Filenames, plot labels, tables: same predicate, one choke point.
"""

MARKER = "SIM"


def check_sim_tag(text):
    """True iff text carries the SIM marker (non-string -> False)."""
    return isinstance(text, str) and MARKER in text


def require_sim_tag(text, what="output"):
    """Raise ValueError unless text carries the SIM marker."""
    if not check_sim_tag(text):
        raise ValueError(f"{what} must carry the SIM marker (refused)")
    return True
