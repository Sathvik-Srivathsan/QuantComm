"""E0 gate ID contract (plan B-50.4).

Single source of truth for the gate ID format and the preflight rule, shared
by the two sides that must agree:

  - `tools/e0_gate.py` MINTS ids (the producer; runs in CI)
  - `sim/qcsim` CONSUMES them via `preflight()` (the experiment harnesses)

They cannot drift because there is only one implementation. Layering is
deliberate: the producer depends on the consumer library, never the reverse.

Gate ID = {git commit of code+vectors, verdict, timestamp}, SHA-256 over
`commit|verdict|timestamp`, verifiable by recomputation from the stored raw
fields. A record whose id does not recompute is rejected as tampered or
stale rather than trusted.

Preflight refuses on red OR MISSING, with the reason returned (never raised
from here) so the caller decides how to log it. B-50.4: no waiver exists -
there is no parameter that turns a refusal into a pass.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

GATE_ID_PREFIX = "e0"
GATE_DIRNAME = "e0"
GATE_MANIFEST = "latest-gate.json"


def mint_gate_id(commit: str, verdict: str, timestamp: str) -> str:
    """Mint the gate id. Deterministic in its three inputs."""
    blob = f"{commit}|{verdict}|{timestamp}".encode()
    return f"{GATE_ID_PREFIX}-{hashlib.sha256(blob).hexdigest()[:16]}"


def verify_gate_id(gate_id: str, commit: str, verdict: str,
                   timestamp: str) -> bool:
    """Recomputation check. False means forged, truncated or stale."""
    return gate_id == mint_gate_id(commit, verdict, timestamp)


def git_commit(repo: Path) -> str:
    """Commit hash of code+vectors. Read-only; never mutates the repo."""
    try:
        p = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"],
                           capture_output=True, text=True)
    except (FileNotFoundError, NotADirectoryError,
            PermissionError) as exc:
        raise RuntimeError(f"cannot execute git: {exc}") from exc
    if p.returncode != 0:
        # Carry git's own words forward: "not a repo", "dubious ownership",
        # and a shallow/empty checkout all look identical otherwise, and
        # this is the single message that explains a red gate.
        raise RuntimeError(
            f"git rev-parse HEAD failed in {repo}: "
            f"{(p.stderr or p.stdout).strip()[:200]}")
    return p.stdout.strip()


def preflight(gate_id: str, build: Path, repo: Path) -> tuple:
    """Experiment-harness entry check. Returns (ok, reason).

    Refusal conditions, all fail-closed:
      - no record at all (gate never ran for this build tree)
      - unreadable / malformed record
      - verdict not "pass"
      - id does not recompute (tampered or hand-edited)
      - record's commit != current build HEAD (build-ID binding)
      - caller named an expected gate id and the record holds a different one
    """
    mpath = build / GATE_DIRNAME / GATE_MANIFEST
    if not mpath.exists():
        return False, f"no gate record at {mpath} (gate never ran)"
    try:
        m = json.loads(mpath.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return False, f"gate record unreadable: {exc}"
    if m.get("verdict") != "pass":
        return False, f"gate verdict is {m.get('verdict')!r}"
    if not verify_gate_id(m.get("gate_id", ""), m.get("commit", ""),
                          m.get("verdict", ""), m.get("timestamp", "")):
        return False, "gate ID does not recompute (tampered or stale)"
    head = git_commit(repo)
    if m.get("commit") != head:
        return False, (f"gate commit {str(m.get('commit',''))[:12]} != build "
                       f"HEAD {head[:12]} (build-ID binding)")
    if gate_id and m.get("gate_id") != gate_id:
        return False, (f"caller expects gate {gate_id}, record holds "
                       f"{m.get('gate_id')}")
    return True, "gate green and bound to this build"
