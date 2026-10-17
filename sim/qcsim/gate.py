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
GATE_RECORDS = "e0-gate.jsonl"


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


def _records_sha256(jsonl: Path) -> str:
    """Digest of a retained JSONL artifact's BYTES.

    Public-by-underscore convention, like the rest of this module's helpers:
    tests and the writer tool both need to compute the same digest, and the
    manifest carries it so preflight can bind the artifact to the record.
    """
    h = hashlib.sha256()
    with open(jsonl, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def preflight(gate_id: str, build: Path, repo: Path) -> tuple:
    """Experiment-harness entry check. Returns (ok, reason).

    Refusal conditions, all fail-closed:
      - no record at all (gate never ran for this build tree)
      - unreadable / malformed record, or a record that is not a JSON object
      - verdict not "pass"
      - id does not recompute (tampered or hand-edited)
      - a "pass" whose counts are internally inconsistent (green means every
        gated test passed, so passed_tests must equal a non-zero total_tests)
      - the JSONL artifact this manifest names is missing, or its bytes do
        not match the digest the manifest carries (provenance, not shape)
      - record's commit != current build HEAD (build-ID binding)
      - caller named an expected gate id and the record holds a different one

    Everything here RETURNS a refusal; nothing is raised out of this
    function, including a git failure.
    """
    mpath = build / GATE_DIRNAME / GATE_MANIFEST
    if not mpath.exists():
        return False, f"no gate record at {mpath} (gate never ran)"
    try:
        m = json.loads(mpath.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return False, f"gate record unreadable: {exc}"
    # json.loads happily returns a list/str/int for other valid JSON, and
    # `m.get` then raised AttributeError out of a function whose contract
    # says refusals are returned, never raised.
    if not isinstance(m, dict):
        return False, ("gate record is not a JSON object (got %s)"
                       % type(m).__name__)
    if m.get("verdict") != "pass":
        return False, f"gate verdict is {m.get('verdict')!r}"
    if not verify_gate_id(m.get("gate_id", ""), m.get("commit", ""),
                          m.get("verdict", ""), m.get("timestamp", "")):
        return False, "gate ID does not recompute (tampered or stale)"
    # Internal consistency: a hand-written manifest with the right shape and
    # a recomputable id (the id is over public inputs) used to be accepted
    # even with passed_tests=0 beside verdict="pass".
    passed, total = m.get("passed_tests"), m.get("total_tests")
    if not isinstance(passed, int) or isinstance(passed, bool) \
            or not isinstance(total, int) or isinstance(total, bool):
        return False, "gate record has no usable test counts"
    if total <= 0 or passed != total:
        return False, ("gate says pass but %r/%r tests passed; green means "
                       "every gated test passed" % (passed, total))
    # Provenance: bind the manifest to the artifact it claims to describe.
    digest = m.get("records_sha256")
    if not isinstance(digest, str) or not digest:
        return False, "gate record carries no records_sha256 (not produced "\
                      "by the gate writer)"
    # The manifest records WHERE its artifact lives, because the pointer at
    # build/e0/latest-gate.json is a COPY of a manifest whose JSONL sits in the
    # per-run directory. A hard-coded "e0-gate.jsonl" beside the pointer made
    # the binding unverifiable for every run-dir layout (the pointer's neighbour
    # is never the artifact), so the check silently refused real records.
    records = m.get("records_file")
    name = Path(records).name if isinstance(records, str) and records \
        else GATE_RECORDS                      # basename: no traversal follows
    # The pointer is a copy that lives in build/e0/, so a bare sibling lookup
    # finds nothing. records_dir names the run directory.
    #
    # It may be either a single relative component (the normal build/e0/<gid>
    # layout) or an absolute path that RESOLVES INSIDE the build tree (a
    # caller that wrote its run dir somewhere else, e.g. a test tmp_path).
    # What must never be accepted is a value that names a location OUTSIDE
    # the tree: Path.__truediv__ discards the left operand when the right is
    # absolute, so screening only for ".." let records_dir="C:/Windows/Temp"
    # make preflight hash and accept an attacker-chosen file whose digest the
    # attacker also controls. Resolve and confine instead.
    sub = m.get("records_dir")
    if isinstance(sub, str) and sub:
        if sub != sub.strip() or ".." in sub.replace("\\", "/").split("/"):
            return False, ("records_dir %r is not a usable run directory; "
                           "refusing a value that could name a location "
                           "outside the build tree" % sub)
        resolved = Path(sub)
        if resolved.is_absolute():
            try:
                resolved.resolve().relative_to(build.resolve())
            except ValueError:
                return False, ("records_dir %r resolves outside the build "
                               "tree (%s); refusing" % (sub, build))
            jsonl = resolved / name
            candidates = [jsonl]
        else:
            # `sub` is recorded RELATIVE TO THE BUILD TREE by the writer, so
            # resolve it against build/ first (that covers build/e0/<gid> and
            # build/exp/runX alike). The build/e0/ candidate is kept for
            # records written before the pointer recorded a build-relative
            # path, where only the gate-id component was stored.
            candidates = [build / sub / name,
                          mpath.parent / sub / name,
                          build / GATE_DIRNAME / sub / name]
    else:
        candidates = [mpath.parent / name, build / GATE_DIRNAME / name]
    jsonl, actual = None, None
    for c in candidates:
        if not c.exists():
            continue
        try:
            actual = _records_sha256(c)
        except OSError as exc:
            return False, f"retained records unreadable: {exc}"
        if actual == digest:
            jsonl = c
            break
    if jsonl is None:
        # Either the artifact is absent or its bytes are not the ones this
        # manifest was written from. Both are refusals, but they are different
        # faults and a reader needs to know which.
        if not any(c.exists() for c in candidates):
            return False, ("retained records missing (looked for %s)"
                           % ", ".join(str(c) for c in candidates))
        return False, ("retained records do not match the manifest digest "
                       "(records_sha256); the artifact is not the one this "
                       "record was written from")
    # The digest only proves the artifact is the one the manifest was written
    # from; it says nothing about how many rows that artifact holds. Both the
    # id and the commit are over PUBLIC inputs, so an attacker (or a broken
    # harness) who can write build/e0/ can publish total_tests=12, passed=12
    # over a one-line {"junk": true} file and preflight returned green. Bind
    # the row count to the claim: N stated must be N retained.
    try:
        with jsonl.open("r", encoding="utf-8") as fh:
            retained = [ln for ln in fh.read().splitlines() if ln.strip()]
    except (OSError, UnicodeDecodeError) as exc:
        return False, f"retained records unreadable: {exc}"
    if len(retained) != total:
        return False, ("gate claims %r gated test(s) but the artifact retains "
                       "%r row(s); the evidence does not support the count"
                       % (total, len(retained)))
    try:
        head = git_commit(repo)
    except RuntimeError as exc:
        return False, f"cannot resolve build commit: {exc}"
    if m.get("commit") != head:
        return False, (f"gate commit {str(m.get('commit',''))[:12]} != build "
                       f"HEAD {head[:12]} (build-ID binding)")
    if gate_id and m.get("gate_id") != gate_id:
        return False, (f"caller expects gate {gate_id}, record holds "
                       f"{m.get('gate_id')}")
    return True, "gate green and bound to this build"
