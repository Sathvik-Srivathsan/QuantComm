"""B-55: 5% Hardware-Feasibility Headroom Gate.

Normative spec: plan-rigorous.md §B-55, phase5-detailed.md §B-55.
Decision rule:
    Aggregate headroom >= 5.0% -> "H3-go" (boundary: exactly 5% goes).
    Aggregate headroom < 5.0%  -> "drop" (rescope to measurement study).
    Per-family shortfalls reported without family veto.
    CI spanning 5% recorded as elevated uncertainty note (does not flip decision).
Timing & Immutability:
    Pre-calibration evaluation refused.
    Evaluated ONCE, frozen immutable thereafter.
    Post-freeze re-evaluation refused.
    Re-computation permitted ONLY for audit with identical inputs (append-only log).
Retention (G5):
    write_gate55_record() persists the frozen outcome to runs/<exp>/<id>/gate55-record.json.
    No overwrite: once written the record is immutable on-disk.
    gate55_contract() binds N, seed, family records, and manifest before any gate can pass.
"""
from __future__ import annotations

import json
import math
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from analysis.headroom import Headroom, scan_assumed_flags

FEASIBILITY_THRESHOLD = 0.05


class Gate55Error(Exception):
    """Refusal for gate violations, timing violations, or unauthorized access."""


@dataclass
class Gate55Outcome:
    decision: str  # "H3-go" | "drop"
    headroom_pct: float
    ci_span_note: Optional[str]
    frozen_at: str
    audit_log: List[Dict[str, Any]] = field(default_factory=list)
    is_frozen: bool = True
    per_family_shortfalls: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def decide(
    headroom: Headroom,
    calibrated_params: Dict[str, Any],
    timestamp: Optional[str] = None,
    allow_unfrozen: bool = False,
) -> Gate55Outcome:
    """Evaluate the 5% headroom feasibility gate and freeze the outcome.

    Refuses pre-calibration evaluation (calibrated_params must be complete).
    Refuses any input carrying ASSUMED flags.
    """
    if calibrated_params is None:
        raise Gate55Error("calibrated_params required")

    # 1. Calibrated-only parameter enforcement
    scan_assumed_flags(calibrated_params)

    # 2. Timing gate: Pre-calibration evaluation is refused
    if calibrated_params.get("calibration_complete") is not True:
        raise Gate55Error(
            "pre-calibration evaluation refused: calibration must be complete "
            "with all flags cleared before B-55 gate evaluation"
        )

    # 3. Decision rule on aggregate headroom
    agg_headroom = headroom.aggregate.get("headroom_pct")
    if agg_headroom is None:
        raise Gate55Error("headroom aggregate missing 'headroom_pct'")

    # Exactly 5% (0.05) goes to H3-go (at-or-above rule)
    if agg_headroom >= FEASIBILITY_THRESHOLD:
        decision = "H3-go"
    else:
        decision = "drop"

    # 4. Per-family shortfall detection (reported without family veto)
    shortfalls = []
    for fam_name, fam_data in headroom.per_family.items():
        if fam_data.get("headroom_pct", 0.0) < FEASIBILITY_THRESHOLD:
            shortfalls.append(fam_name)

    # 5. CI span check: elevated uncertainty recorded if CI spans 5%
    ci_note = None
    if headroom.ci and "ci_lo" in headroom.ci and "ci_hi" in headroom.ci:
        ci_lo = headroom.ci["ci_lo"]
        ci_hi = headroom.ci["ci_hi"]
        if ci_lo < FEASIBILITY_THRESHOLD < ci_hi:
            ci_note = (
                f"elevated uncertainty: 95% CI [{ci_lo:.4f}, {ci_hi:.4f}] "
                f"spans {FEASIBILITY_THRESHOLD * 100:.1f}% threshold; "
                f"point-estimate ({agg_headroom * 100:.2f}%) decides"
            )

    # 6. Freeze timestamp and immutability
    ts = timestamp or datetime.now(timezone.utc).isoformat()
    return Gate55Outcome(
        decision=decision,
        headroom_pct=agg_headroom,
        ci_span_note=ci_note,
        frozen_at=ts,
        audit_log=[],
        is_frozen=not allow_unfrozen,
        per_family_shortfalls=sorted(shortfalls),
    )


def re_evaluate(frozen_outcome: Gate55Outcome) -> None:
    """Post-freeze re-evaluation is refused by design."""
    if frozen_outcome.is_frozen:
        raise Gate55Error("post-freeze re-evaluation refused: outcome is frozen immutable")


def audit_recompute(
    frozen_outcome: Gate55Outcome,
    headroom: Headroom,
    calibrated_params: Dict[str, Any],
    tech_lead_auth: bool = False,
    timestamp: Optional[str] = None,
) -> Gate55Outcome:
    """Recompute the gate decision for audit purposes only.

    Requires tech lead authorization and identical inputs.
    Appends audit record append-only to audit_log.
    """
    if not tech_lead_auth:
        raise Gate55Error(
            "unauthorized audit recompute: tech lead authorization required"
        )

    if not frozen_outcome.is_frozen:
        raise Gate55Error("cannot audit an unfrozen outcome")

    # Recompute
    recomputed = decide(
        headroom=headroom,
        calibrated_params=calibrated_params,
        timestamp=timestamp,
        allow_unfrozen=True,
    )

    # Verify identical outcome
    if recomputed.decision != frozen_outcome.decision:
        raise Gate55Error(
            f"audit recomputation mismatch: decision changed from "
            f"{frozen_outcome.decision} to {recomputed.decision}"
        )
    if not math.isclose(recomputed.headroom_pct, frozen_outcome.headroom_pct, rel_tol=1e-7):
        raise Gate55Error(
            f"audit recomputation mismatch: headroom changed from "
            f"{frozen_outcome.headroom_pct} to {recomputed.headroom_pct}"
        )

    # Append to audit log (append-only)
    ts = timestamp or datetime.now(timezone.utc).isoformat()
    audit_entry = {
        "action": "audit_recompute",
        "timestamp": ts,
        "tech_lead_auth": True,
        "status": "verified_match",
        "headroom_pct": recomputed.headroom_pct,
        "decision": recomputed.decision,
    }
    frozen_outcome.audit_log.append(audit_entry)
    return frozen_outcome


# ---------------------------------------------------------------------------
# G5 Retention: manifest writing & contract enforcement
# ---------------------------------------------------------------------------

_RECORD_SCHEMA_VERSION = 1
_RECORD_FILENAME = "gate55-record.json"

# Required manifest fields for B-55 gate contract
_MANIFEST_REQUIRED_FIELDS = ("gate", "seed_used", "n_families", "code_hash")


def write_gate55_record(
    outcome: Gate55Outcome,
    run_dir: Union[str, Path],
) -> Path:
    """Write a frozen Gate55Outcome to ``<run_dir>/gate55-record.json``.

    Implements G5 retention:
    - Creates ``run_dir`` if it does not exist.
    - Refuses to overwrite an existing record (immutable once written).
    - Writes a JSON document with all outcome fields plus schema metadata.

    Returns the path of the written file.
    """
    if not outcome.is_frozen:
        raise Gate55Error("cannot persist an unfrozen outcome; freeze first")

    run_dir = Path(run_dir)
    run_dir.mkdir(parents=True, exist_ok=True)

    record_path = run_dir / _RECORD_FILENAME
    if record_path.exists():
        raise Gate55Error(
            f"gate55-record.json already exists at {record_path}; "
            "G5 forbids overwriting an immutable record"
        )

    record = {
        "schema_version": _RECORD_SCHEMA_VERSION,
        "gate": "B-55",
        **outcome.to_dict(),
    }

    with record_path.open("w", encoding="utf-8") as fh:
        json.dump(record, fh, indent=2)

    return record_path


def load_gate55_record(record_path: Union[str, Path]) -> Dict[str, Any]:
    """Load and return a gate55-record.json from disk (read-only helper).

    Validates schema_version and required top-level fields.
    Raises Gate55Error if the file is malformed.
    """
    record_path = Path(record_path)
    if not record_path.exists():
        raise Gate55Error(f"gate55-record.json not found at {record_path}")

    with record_path.open("r", encoding="utf-8") as fh:
        try:
            record = json.load(fh)
        except json.JSONDecodeError as exc:
            raise Gate55Error(f"gate55-record.json is not valid JSON: {exc}") from exc

    if not isinstance(record, dict):
        raise Gate55Error("gate55-record.json root must be a JSON object")
    if record.get("schema_version") != _RECORD_SCHEMA_VERSION:
        raise Gate55Error(
            f"gate55-record.json schema_version mismatch: "
            f"expected {_RECORD_SCHEMA_VERSION}, got {record.get('schema_version')!r}"
        )
    if record.get("gate") != "B-55":
        raise Gate55Error(
            f"gate55-record.json gate field mismatch: expected 'B-55', got {record.get('gate')!r}"
        )
    for req in ("decision", "headroom_pct", "frozen_at", "is_frozen"):
        if req not in record:
            raise Gate55Error(f"gate55-record.json missing required field {req!r}")

    return record


def gate55_contract(
    n_declared: int,
    n_observed: int,
    family_records: List[Dict[str, Any]],
    manifest: Dict[str, Any],
) -> Dict[str, Any]:
    """B-55.6 gate contract: stated N, 100% deterministic, per-family records, manifest.

    All four must be concrete and non-placeholder. Raises Gate55Error on any violation.

    Args:
        n_declared:     Number of trace families declared in the study design.
        n_observed:     Number of trace families actually evaluated.
        family_records: List of per-family dicts, each with at minimum:
                        ``family``, ``headroom_pct``, ``seed``, ``n_pairs``, ``passed``.
        manifest:       Dict with at minimum ``gate``, ``seed_used``, ``n_families``,
                        ``code_hash``.

    Returns:
        Summary dict on success.
    """
    # --- N binding ---
    if isinstance(n_declared, bool) or not isinstance(n_declared, int) or n_declared <= 0:
        raise Gate55Error(
            f"stated N must be a positive int, got {n_declared!r}"
        )
    if isinstance(n_observed, bool) or not isinstance(n_observed, int):
        raise Gate55Error(
            f"observed N must be an int, got {n_observed!r}"
        )
    if n_observed != n_declared:
        raise Gate55Error(
            f"stated N={n_declared} but observed N={n_observed}; cannot pass gate"
        )

    # --- Family records: no placeholder ---
    if family_records == "pending-harness":
        raise Gate55Error(
            "family_records is 'pending-harness'; the B-55 gate cannot pass on a placeholder"
        )
    if not isinstance(family_records, list):
        raise Gate55Error(
            f"family_records must be a list of per-family dicts, got {type(family_records).__name__}"
        )
    if not family_records:
        raise Gate55Error("family_records is empty; at least one family required")
    if len(family_records) != n_declared:
        raise Gate55Error(
            f"stated N={n_declared} but {len(family_records)} family record(s)"
        )

    required_family_fields = ("family", "headroom_pct", "seed", "n_pairs", "passed")
    seen_families: set = set()
    for i, rec in enumerate(family_records):
        if not isinstance(rec, dict):
            raise Gate55Error(f"family_records[{i}] must be a dict, got {type(rec).__name__}")
        for fld in required_family_fields:
            if fld not in rec:
                raise Gate55Error(f"family_records[{i}] missing required field {fld!r}")
        fam_name = rec["family"]
        if not isinstance(fam_name, str) or not fam_name.strip():
            raise Gate55Error(f"family_records[{i}] has empty/invalid 'family' name")
        if fam_name in seen_families:
            raise Gate55Error(f"duplicate family name {fam_name!r} in family_records")
        seen_families.add(fam_name)
        if rec["passed"] is not True:
            raise Gate55Error(
                f"family_records[{i}] ({fam_name!r}) did not pass: passed={rec['passed']!r}"
            )
        if not isinstance(rec["seed"], int) or isinstance(rec["seed"], bool):
            raise Gate55Error(
                f"family_records[{i}] ({fam_name!r}) seed must be an int, got {rec['seed']!r}"
            )
        if not isinstance(rec["n_pairs"], int) or isinstance(rec["n_pairs"], bool) or rec["n_pairs"] < 1:
            raise Gate55Error(
                f"family_records[{i}] ({fam_name!r}) n_pairs must be a positive int"
            )

    # --- Manifest binding ---
    if manifest is None or not isinstance(manifest, dict) or not manifest:
        raise Gate55Error("manifest must be a non-empty dict")
    for fld in _MANIFEST_REQUIRED_FIELDS:
        v = manifest.get(fld)
        if not isinstance(v, str) or not v.strip():
            raise Gate55Error(
                f"manifest field {fld!r} must be a non-empty string, got {v!r}"
            )
    if manifest.get("gate") != "B-55":
        raise Gate55Error(
            f"manifest 'gate' must be 'B-55', got {manifest.get('gate')!r}"
        )
    # seed_used in manifest must match seed used in every family record
    try:
        manifest_seed = int(manifest["seed_used"])
    except (ValueError, TypeError) as exc:
        raise Gate55Error(
            f"manifest 'seed_used' must be an integer string, got {manifest.get('seed_used')!r}"
        ) from exc
    for i, rec in enumerate(family_records):
        if rec["seed"] != manifest_seed:
            raise Gate55Error(
                f"family_records[{i}] ({rec['family']!r}) seed={rec['seed']} "
                f"!= manifest seed_used={manifest_seed}; determinism binding failed"
            )
    # n_families in manifest must match n_declared
    try:
        manifest_n = int(manifest["n_families"])
    except (ValueError, TypeError) as exc:
        raise Gate55Error(
            f"manifest 'n_families' must be an integer string, got {manifest.get('n_families')!r}"
        ) from exc
    if manifest_n != n_declared:
        raise Gate55Error(
            f"manifest n_families={manifest_n} != stated N={n_declared}"
        )

    return {
        "stated_n": n_declared,
        "observed_n": n_observed,
        "retention_form": "per-family",
        "family_records": len(family_records),
        "manifest_ok": True,
        "deterministic": True,
        "seed": manifest_seed,
    }
