"""The mutation harness must be able to fail.

A checker that always exits 0 is decoration. `tools/mutate_check.py` claims
to detect guarantees with no test behind them, so it must (a) exit non-zero
when a mutation survives, and (b) exit non-zero when a listed pattern no
longer exists -- a renamed guarantee otherwise disappears from the report
while the step stays green.
"""
import os
import pathlib
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parents[2]
SRC = REPO / "tools" / "mutate_check.py"


def _run_with(extra_entry):
    """Run the harness with one scratch entry prepended; always restore."""
    base = SRC.read_text(encoding="utf-8")
    try:
        SRC.write_text(base.replace("MUTATIONS = [", "MUTATIONS = [\n" +
                                    extra_entry, 1),
                       encoding="utf-8", newline="\n")
        env = dict(os.environ, QC_REPO=str(REPO), QC_MUTATE_FAST="1")
        p = subprocess.run([sys.executable, str(SRC)], capture_output=True,
                           text=True, cwd=str(REPO), env=env)
        return p.returncode, p.stdout + p.stderr
    finally:
        SRC.write_text(base, encoding="utf-8", newline="\n")


def test_harness_reports_a_surviving_mutation():
    """A docstring-only edit cannot break behaviour, so it MUST survive."""
    rc, out = _run_with(
        '    ("control: docstring-only edit must survive",\n'
        '     "analysis/stats.py",\n'
        '     "Supplies NUMBERS",\n'
        '     "Supplies NUMBERS at all"),')
    assert rc == 1, "a survivor must exit 1, got %d\n%s" % (rc, out[-2000:])
    assert "control: docstring-only edit must survive" in out


def test_harness_reports_a_drifted_pattern():
    """A pattern that is not in the file must be reported, not ignored."""
    rc, out = _run_with(
        '    ("control: pattern that does not exist",\n'
        '     "analysis/stats.py",\n'
        '     "this literal is definitely not in stats.py",\n'
        '     "nor is this"),')
    assert rc == 2, "a skip must exit 2, got %d\n%s" % (rc, out[-2000:])
    assert "SKIPPED" in out or "control: pattern that does not exist" in out


def test_harness_restores_every_file_it_touches():
    """The harness patches files in place; it must leave the tree as it found
    it. A killed run once left a mutation behind, and nothing noticed."""
    before = subprocess.run(["git", "status", "--porcelain"],
                            capture_output=True, text=True,
                            cwd=str(REPO)).stdout
    env = dict(os.environ, QC_REPO=str(REPO))
    subprocess.run([sys.executable, str(SRC)], capture_output=True,
                   text=True, cwd=str(REPO), env=env)
    after = subprocess.run(["git", "status", "--porcelain"],
                           capture_output=True, text=True,
                           cwd=str(REPO)).stdout
    assert before == after, "the harness left the tree modified"
