"""Baseline system definitions S0-S6 (B-44.1/.2): data, not machinery.

Each definition implements the B-43 S-definition interface owned by
the runner (system ID; fixed-profile or controller flag; floor-bypass
flag for S0/S1/S4 experiment-only; crypto backend selector held
identical across compared systems; trace-set binding) — this module
owns the DEFINITIONS (B-44's job), never the runner (forward use).

Semantics (B-44.1, cited never re-valued): S0 symmetric-only
(AES-256-GCM under a static 32-B campaign PSK — sim-only credential,
never a device key, outside Kdev machinery); S1 classical SL0
(ECDH-P256 + ECDSA-P256 + AES-GCM via host OpenSSL bindings pinned in
the manifest); S2 static PQC trio (SL1/SL2/SL3 fixed profiles);
S3 static high (SL3 everywhere); S4 naive battery rule (starts SL3,
steps down one SL at SoC below 50 then 25 — PAPER-PARAM provisionals
— floor SL1); S5 adaptive controller (full B-30-B-35 stack, floors
enforced, zero-violation mandate); S6 offline oracle (B-34 argmin per
window with perfect future knowledge, analysis-only, compute excluded
from energy columns, verdict-blind via separate run dirs).

Floor bypass (B-44.2): S0/S1/S4 ONLY, through the experiment-config
flag (no firmware path — the B-31.5 sim mechanism, cited). Bypassed
runs skip the bucket gate and never call shed; every violation is
counted as {system, trace, window, constraint, magnitude} with
per-constraint units (C1 SL steps below floor; C2/C3 applied-over-
bound ratios; C4 bytes over; C5 ms over). Bypass outside experiment
configs is refused (factory gate, loud).
"""

from .streams import RNGStreams

S2_IDS = ("S2-SL1", "S2-SL2", "S2-SL3")
S3_ID = "S3"
BYPASSED = ("S0", "S1", "S4")

# S4 naive-rule provisionals (PAPER-PARAM, confirmed at build).
S4_THRESHOLDS = (50, 25)
S4_START = "SL3"
S4_FLOOR = "SL1"
_SL_ORDER = ("SL1", "SL2", "SL3")


def s4_profile(soc):
    """Naive-rule profile at a battery SoC (B-44.1 S4 semantics)."""
    if not isinstance(soc, (int, float)):
        raise ValueError("soc must be numeric")
    steps = sum(1 for t in S4_THRESHOLDS if soc < t)
    return _SL_ORDER[max(0, _SL_ORDER.index(S4_START) - steps)]


def violation_record(system_id, trace_id, window, constraint, magnitude):
    """One counted floor violation (B-44.2 shape + units contract)."""
    if constraint not in ("C1", "C2", "C3", "C4", "C5"):
        raise ValueError("constraint must be C1-C5")
    if not isinstance(magnitude, (int, float)) or magnitude < 0:
        raise ValueError("magnitude must be non-negative")
    return {"system": system_id, "trace": trace_id, "window": window,
            "constraint": constraint, "magnitude": magnitude}


def baseline_systems(backend, experiment=True, seed_hex=None,
                     psk_hex=None):
    """Build the S0-S6 definitions. Returns (systems, psk_hex).

    backend: shared build ID held identical across the comparison
    (B-44.3 same-backend rule; the runner enforces it). experiment:
    bypass flags are only issued under experiment configs (refused
    otherwise). seed_hex mints the campaign PSK deterministically;
    psk_hex pins it explicitly (tests). The PSK is recorded by the
    caller in the run manifest/scenario (runner scenario slot) —
    never inside device machinery.
    """
    if not isinstance(backend, str) or not backend:
        raise ValueError("backend must be a nonempty build ID")
    if psk_hex is None:
        if seed_hex is None:
            raise ValueError("seed_hex or psk_hex required (PSK source)")
        psk_hex = RNGStreams(seed_hex).next_bytes("generator", 32).hex()
    if not isinstance(psk_hex, str) or len(psk_hex) != 64:
        raise ValueError("psk_hex must be 32 bytes hex (S0 campaign PSK)")
    try:
        bytes.fromhex(psk_hex)
    except ValueError:
        raise ValueError("psk_hex must be hex")

    def mk(system_id, controller, bypass, kind, profile):
        if bypass and system_id not in BYPASSED:
            raise ValueError(
                f"floor bypass refused for {system_id} (S0/S1/S4 only)")
        if bypass and not experiment:
            raise ValueError(
                "floor bypass outside experiment configs refused")
        return {"system_id": system_id, "controller": controller,
                "floor_bypass": bypass, "backend": backend,
                "kind": kind, "profile": profile}

    systems = [
        mk("S0", False, True, "psk-static",
           {"cipher": "AES-256-GCM", "psk_role": "campaign-sim-only"}),
        mk("S1", False, True, "classical",
           {"kem": "ECDH-P256", "sig": "ECDSA-P256",
            "crypto": "OpenSSL-pinned"}),
        mk("S2-SL1", False, False, "pqc-static", {"sl": "SL1"}),
        mk("S2-SL2", False, False, "pqc-static", {"sl": "SL2"}),
        mk("S2-SL3", False, False, "pqc-static", {"sl": "SL3"}),
        mk("S3", False, False, "pqc-static-high", {"sl": "SL3"}),
        mk("S4", False, True, "naive-rule",
           {"start": S4_START, "thresholds": list(S4_THRESHOLDS),
            "floor": S4_FLOOR}),
        mk("S5", True, False, "adaptive",
           {"stack": "B-30-B-35", "violations": "zero-mandate"}),
        mk("S6", False, False, "oracle",
           {"future": True, "verdict_blind": "separate-run-dirs",
            "compute": "excluded-from-energy"}),
    ]
    return systems, psk_hex.lower()
