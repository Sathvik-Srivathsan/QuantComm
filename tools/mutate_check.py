"""Mutation harness: does the suite actually pin what it claims?

For each mutation, patch ONE line of production code to a wrong-but-plausible
form, run the named test files, and record whether the suite went RED.

A mutation that leaves the suite GREEN is the definition of a weak test:
the guarantee is named but not enforced.

Exit codes (a skipped mutation is NOT a pass):
  0  every mutation was caught
  1  at least one mutation SURVIVED (a guarantee with no test behind it)
  2  at least one mutation was SKIPPED (the pattern drifted or was a no-op,
     so the harness is not measuring what it lists)

This is wired into CI as the `mutation adequacy` step precisely because the
defects that reached this branch were all invisible to a green suite.
"""
import os
import subprocess
import sys
from pathlib import Path

# Repo root: honour an explicit override (CI checks out anywhere), else the
# directory this file lives in. A hard-coded Windows path would make the
# step fail on the Linux runner.
REPO = Path(os.environ.get("QC_REPO",
                           Path(__file__).resolve().parents[1]))

# A hung suite must not be scored as a detection (false positive) nor as a
# survivor (false red); it is reported as SKIP and fails the run.
TIMEOUT_S = int(os.environ.get("QC_MUTATE_TIMEOUT", "900"))
TIMEOUT_RC = 124

TESTS = [
    "tests/python/test_e0_contract.py",
    "tests/python/test_e0_gate.py",
    "tests/python/test_e0_selftests.py",
    "tests/python/test_schema_regressions.py",
    "tests/python/test_retention_seam.py",
    "tests/python/test_stats.py",
    "tests/python/test_vector_schema.py",
    "tests/python/test_e0_junit.py",
    "tests/python/test_e0_flaky.py",
    "tests/python/test_e0_preflight.py",
    "tests/python/test_h5.py",
]

# (label, file, literal-to-find, replacement)
MUTATIONS = [
    ("driver: pass_count drops provenance",
     "analysis/vector_schema.py",
     '"gate_commit": gate_commit,',
     '"gate_commit": None,'),
    # PER_TEST and PER_VECTOR carry the same field literal, so each form needs
    # its OWN mutation: a shared pattern would patch only the first occurrence
    # and the "CAUGHT" result would say nothing about the second form.
    ("schema: stop requiring gate_id (per-test)",
     "analysis/vector_schema.py",
     '    "gate_id": (str, type(None)),\n}\n\nPER_VECTOR_FIELDS = {',
     '}\n\nPER_VECTOR_FIELDS = {'),
    ("schema: stop requiring gate_id (per-vector)",
     "analysis/vector_schema.py",
     '    "gate_id": (str, type(None)),\n}\n\n_SHA256_RE = re.compile',
     '}\n\n_SHA256_RE = re.compile'),
    ("writer: on-disk rows lose provenance",
     "tools/e0_gate.py",
     '"gate_id": report.gate_id}',
     '"gate_id": None}'),
    ("gate: preflight ignores row count (the CRITICAL)",
     "sim/qcsim/gate.py",
     'if len(retained) != total:',
     'if False:'),
    ("junit: a real failure reads as not-executed",
     "tools/e0_gate.py",
     'ran = (status in ("run", "fail")) and not skipped',
     'ran = status == "run"'),
    ("junit: skipped child counted as executed",
     "tools/e0_gate.py",
     'ran = (status in ("run", "fail")) and not skipped',
     'ran = status in ("run", "fail")'),
    ("stats: unequal seed sets intersected silently",
     "analysis/stats.py",
     'raise StatsError("UNPAIRED seeds: " + "; ".join(seed_problems))',
     'pass'),
    ("stats: any non-empty gate_preflight accepted",
     "analysis/stats.py",
     'claimed = manifest["gate_preflight"]',
     'claimed = manifest["gate_preflight"]\n        return {"ok": True}'),
    ("scan: fires on docstrings (current behaviour)",
     "analysis/reproduce.py",
     'return sorted(set(found))',
     'return sorted(set(found)) or ["decision"]'),
    ("scan: blind to a planted decision branch",
     "analysis/reproduce.py",
     'low = code.lower()',
     'low = ""'),
    ("scan: strips string literals (the B-50.5 regression)",
     "analysis/reproduce.py",
     "        if isinstance(first, ast.Expr) and isinstance(first.value,\n"
     "                                                      ast.Constant) \\\n"
     "                and isinstance(first.value.value, str):",
     "        if True:"),
    ("scan: strips ALL string literals, not just docstrings",
     "analysis/reproduce.py",
     "            if tok.type == tokenize.STRING:\n"
     "                string_spans.append((tok.start[0], tok.end[0]))",
     "            if False:\n"
     "                string_spans.append((tok.start[0], tok.end[0]))\n"
     "            elif tok.type == tokenize.STRING:\n"
     "                drop_at[(tok.start[0], tok.start[1])] = (\n"
     "                    tok.end[0], tok.end[1])"),
    ("producer/consumer: skipped case read as executed",
     "tools/e0_gate.py",
     '"skipped": skipped,',
     '"skipped": False,'),
]


def run_tests() -> int:
    try:
        p = subprocess.run(
            [sys.executable, "-m", "pytest", *TESTS,
             "-p", "no:cacheprovider", "-p", "no:warnings", "-q", "--tb=no"],
            cwd=str(REPO), capture_output=True, text=True, timeout=TIMEOUT_S)
    except subprocess.TimeoutExpired:
        # A hung suite must not be read as "caught": reporting a timeout as a
        # detection would be a false positive of the harness itself.
        return TIMEOUT_RC
    return p.returncode


def main():
    base = run_tests()
    print("baseline rc = %d %s" % (base, "(GREEN)" if base == 0 else "(RED)"))
    if base != 0:
        print("baseline is not green; abort")
        return 1

    survivors, caught, skipped = [], [], []
    for label, rel, find, repl in MUTATIONS:
        path = REPO / rel
        orig = path.read_text(encoding="utf-8")
        if find not in orig:
            skipped.append((label, rel))
            print("  SKIP  %-52s (pattern not found in %s)" % (label, rel))
            continue
        if find == repl:
            skipped.append((label, rel))
            print("  SKIP  %-52s (no-op mutation)" % label)
            continue
        try:
            # newline="" keeps the file's existing line endings: the default
            # would rewrite LF as CRLF on Windows and dirty every target.
            path.write_text(orig.replace(find, repl, 1), encoding="utf-8",
                            newline="")
            rc = run_tests()
        finally:
            path.write_text(orig, encoding="utf-8", newline="")
        if rc == TIMEOUT_RC:
            skipped.append((label, rel))
            print("  SKIP  %-52s (suite timed out - not a detection)" % label)
            continue
        if rc != 0:
            caught.append(label)
            print("  CAUGHT  %s" % label)
        else:
            survivors.append((label, rel))
            print("  SURVIVED %-50s <-- WEAK TEST" % label)

    print()
    print("caught=%d survived=%d skipped=%d"
          % (len(caught), len(survivors), len(skipped)))
    if survivors:
        print("\nSURVIVING MUTATIONS (the suite does not enforce these):")
        for label, rel in survivors:
            print("  - %s  [%s]" % (label, rel))
    if skipped:
        # A skipped mutation is not a pass. Either the pattern drifted (the
        # guarantee was renamed, so nothing pins it) or it was a no-op (it
        # never tested anything). Both mean the harness is not measuring what
        # it claims, so this must fail rather than quietly under-report.
        print("\nSKIPPED MUTATIONS (harness is not measuring these):")
        for label, rel in skipped:
            print("  - %s  [%s]" % (label, rel))
        return 2
    return 1 if survivors else 0


if __name__ == "__main__":
    raise SystemExit(main())
