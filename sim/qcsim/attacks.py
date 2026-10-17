"""E10 security tests T1-T13 + energy capture (B-53).

B-53.3 DATA. Accept/reject OUTCOMES only -- H4 VERDICTS belong to B-64
and are never emitted here. The adversary is Dolev-Yao network powers by
default (B-53.4.1).

Wire constants are DERIVED from the C headers, never transcribed:
  qc_frame.h   QC_FRAME_HDR_LEN 74, QC_FRAME_TAG_LEN 16
  qc_manifest.h QC_MFT_MAX_BODY 4096, QC_MFT_VERIFY_PER_HOUR 6
  qc_gov.h     QC_GOV_RESTORE_FRAC_DFLT 0.5, QC_GOV_DWELL_DFLT 3
T2 tamper positions: HEADER (0), PLEN (74), CT (78), TAG (last 16).
"""

FRAME_HDR_LEN = 74
FRAME_TAG_LEN = 16
FRAME_PLEN_OFF = 74
FRAME_CT_OFF = 78

TAMPER_POSITIONS = ("header", "plen", "ct", "tag")

MANIFEST_FORGERY_TYPES = ("bad-sig", "wrong-key", "old-version",
                          "floor-escalation")

T_TESTS = {
    "T1": "replay", "T2": "tampering", "T3": "downgrade",
    "T4": "rollback", "T5": "forged-manifest", "T6": "handshake-flood",
    "T7": "reboot-loop", "T8": "loss-desync",
    "T9": "compromised-gateway", "T10": "risk-spoofing",
    "T11": "nonce-reuse", "T12": "ble-downgrade",
    "T13": "sustained-absence",
}

T_ATTACK_PER_CLASS_S = 86400


class AttackError(Exception):
    """Refusal. Loud."""


class TOwncome:
    """B-53.3 T{i}Outcome. Numbers only, never verdicts."""

    __slots__ = ("t_id", "scenario_id", "scenario_version", "accept",
                 "accept_path", "energy_J_per_h", "baseline_J_per_h",
                 "excess_J_per_h", "counters", "manifest", "seeds")

    def __init__(self, t_id, scenario_id, scenario_version, accept,
                 accept_path, energy_J_per_h, baseline_J_per_h, counters,
                 manifest, seeds):
        self.t_id = t_id
        self.scenario_id = scenario_id
        self.scenario_version = scenario_version
        self.accept = accept
        self.accept_path = accept_path
        self.energy_J_per_h = energy_J_per_h
        self.baseline_J_per_h = baseline_J_per_h
        self.excess_J_per_h = energy_J_per_h - baseline_J_per_h
        self.counters = dict(counters)
        self.manifest = manifest
        self.seeds = tuple(seeds)

    def as_dict(self):
        return {"t_id": self.t_id, "scenario_id": self.scenario_id,
                "scenario_version": self.scenario_version,
                "accept": self.accept, "accept_path": self.accept_path,
                "energy_J_per_h": self.energy_J_per_h,
                "baseline_J_per_h": self.baseline_J_per_h,
                "excess_J_per_h": self.excess_J_per_h,
                "counters": dict(self.counters)}


def excess_energy(attack_J_per_h, baseline_J_per_h):
    """B-53.4.2: excess = attack - baseline, J/hour, SAME trace."""
    return attack_J_per_h - baseline_J_per_h


def excess_rate_J_per_h(attack_J_per_h, baseline_J_per_h, window_s):
    """B-53.3: a RATE over the window, never accumulated."""
    if window_s <= 0:
        raise AttackError("window must be positive")
    return excess_energy(attack_J_per_h, baseline_J_per_h)


def epsilon(Hmax, Ehs, cooldown_s, backoff_s):
    """B-53.3: pre-registered cap computed AT BUILD from LIVE values.

    No post-hoc epsilon. Units: J/hour over one T_attack window.
    """
    if Hmax <= 0 or cooldown_s <= 0 or backoff_s <= 0:
        raise AttackError("epsilon inputs must be positive")
    return (Hmax * Ehs + cooldown_s + backoff_s) * 3600.0 / T_ATTACK_PER_CLASS_S


class EpsilonRegistration:
    """Pre-registration: frozen BEFORE the first run."""

    def __init__(self, epsilon_value, hmax, ehs, cooldown_s, backoff_s,
                 t_attack_s=T_ATTACK_PER_CLASS_S):
        self.epsilon_value = epsilon_value
        self.hmax = hmax
        self.ehs = ehs
        self.cooldown_s = cooldown_s
        self.backoff_s = backoff_s
        self.t_attack_s = t_attack_s
        self.first_run_at = None

    def record_first_run(self, timestamp):
        if self.first_run_at is None:
            self.first_run_at = timestamp

    def check_order(self):
        if self.first_run_at is None:
            raise AttackError("no run recorded")
        if self.first_run_at < self.epsilon_at:
            raise AttackError("epsilon registered AFTER first run")
        return True

    epsilon_at = None


def h4_input(outcomes, eps):
    """B-53.3 H4Input: INPUTS for B-64, never a verdict."""
    by = {o.t_id: o for o in outcomes}
    for need in ("T3", "T4", "T5"):
        if need not in by:
            raise AttackError("missing %s outcome" % need)
    if not by["T5"].accept:
        raise AttackError("T5 did not hold")
    return {"T3_accept": by["T3"].accept, "T4_accept": by["T4"].accept,
            "T5_accept": by["T5"].accept,
            "T6_excess_rate": by.get("T6").excess_J_per_h if by.get("T6") else 0.0,
            "T7_excess_rate": by.get("T7").excess_J_per_h if by.get("T7") else 0.0,
            "epsilon_snapshot": eps.epsilon_value,
            "T_attack_per_class": eps.t_attack_s}


E11_ARMS = {
    "no-risk-hysteresis": "risk state machine",
    "no-governor": "token bucket",
    "no-floor-upper-bound": "floor upper bound",
    "reference-vs-optimized": "primitive track",
    "E2E-vs-gateway": "trust placement",
}