"""Producer/consumer contract check for the E1 runner (plan B-51.5).

Why this exists: `c_e1_smoke` proves the benchmark binary runs, but ctest
discards its stdout, so nothing verified that the rows it emits actually
satisfy the driver's schema. Producer and consumer were written in the
same chunk by the same author, so nothing outside that author had ever
checked they agree - and the stack-metric key was renamed twice during
that chunk, which is exactly how such a drift happens silently. The smoke
test would have stayed green through a rename that makes every real
campaign run fail.

This closes it: run the real binary, parse its real output through the
real driver's parser, and fail the build on any disagreement.
"""
from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
BENCH = REPO / "build" / "tools" / "e1_bench"


def _load_driver():
    spec = importlib.util.spec_from_file_location(
        "e1_run_contract", REPO / "tools" / "e1_run.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["e1_run_contract"] = mod
    spec.loader.exec_module(mod)
    return mod


def main() -> int:
    if not BENCH.exists():
        print(f"contract check: bench not built at {BENCH}", file=sys.stderr)
        return 3

    driver = _load_driver()
    proc = subprocess.run([str(BENCH), "contract-check", "2"],
                          capture_output=True, text=True)
    if proc.returncode != 0:
        print(f"contract check: bench exited {proc.returncode}\n"
              f"{proc.stderr[-800:]}", file=sys.stderr)
        return 1

    # The driver's OWN parser - not a re-implementation of it. It raises
    # on bad input; a gate must REFUSE CLEANLY (message + exit code), not
    # crash with a traceback. An exception here still fails the build, but
    # it buries the reason under a stack trace and trains people to ignore
    # red.
    try:
        rows = driver.parse_rows(proc.stdout)
        problems = driver.validate_rows(rows, 2)
    except Exception as exc:                    # noqa: BLE001 - gate edge
        print(f"contract check: driver refused the bench output: {exc}",
              file=sys.stderr)
        return 1
    if problems:
        print("contract check: coverage problems against the real output:",
              file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        return 1

    # Extra guarantee the driver does not itself enforce: every row must
    # carry the same key set, so one op gaining or losing a field is
    # caught even if both sides agree it is "valid".
    keysets = {frozenset(r) for r in rows}
    if len(keysets) != 1:
        print(f"contract check: rows disagree on their key set "
              f"({len(keysets)} distinct sets)", file=sys.stderr)
        return 1

    print(f"contract check: OK - {len(rows)} rows, one key set, "
          f"schema and coverage agree with the driver")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
