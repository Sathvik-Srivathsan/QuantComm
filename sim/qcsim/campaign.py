"""E5/E6/E7 sim campaigns (B-52).

B-52.1 REQUIRES: B-32 (risk DOE), B-33 (model + ASSUMED priors),
B-34 (lambda grid range, B-34-owned), B-43 (runner/device/network/
scenarios), B-44 (S-definitions + validity + H3 records), B-51 (E1).

B-52.3 DATA: Cell matrix; Registration (design + alias_table +
resolution + prereg_hash) with the analysis-script hash participating;
CampaignManifest carrying gate_preflight, model pin, seeds, SIM tags,
H3 comparator id, per-cell/per-system rows, assumption-log version,
DOE registration hash and code hash.

H3 VERDICTS belong to B-64 and are never emitted here (B-52.7).
"""

import hashlib

E5_RATES_HZ = (0.2, 1.0, 5.0)
E5_ATTESTATION = ("none", "600s", "60s", "per-event", "per-message")

E6_FACTORS = ("level", "Tpq", "Ta", "Nb", "connection_interval", "rate")
E6_RESOLUTION_FLOOR = 4
E6_ANALYSIS_SCRIPT = "analysis/anova_e6.py"

H3_COMPARATOR = "S1"
H3_NEVER_COMPARATOR = "S0"


class CampaignError(Exception):
    """Refusal. Loud, never a silent filter."""


class ModelPinChanged(CampaignError):
    """Mid-campaign model-pin change: the campaign is INVALID (B-52.3)."""


class Cell:
    __slots__ = ("cell_id", "rate_hz", "attestation", "system_ids",
                 "anchor_id")

    def __init__(self, cell_id, rate_hz, attestation, system_ids,
                 anchor_id):
        self.cell_id = cell_id
        self.rate_hz = rate_hz
        self.attestation = attestation
        self.system_ids = tuple(system_ids)
        self.anchor_id = anchor_id

    def as_dict(self):
        return {"cell_id": self.cell_id, "rate_hz": self.rate_hz,
                "attestation": self.attestation,
                "system_ids": list(self.system_ids),
                "anchor_id": self.anchor_id}


def e5_cells():
    """B-52.4 item 1: full factorial in fixed stated order."""
    systems = ("S1", "S2L2", "S2L3", "S5", "S0")
    cells = []
    for rate in E5_RATES_HZ:
        for att in E5_ATTESTATION:
            cid = "e5-r%s-a%s" % (str(rate).replace(".", "_"), att)
            cells.append(Cell(cid, rate, att, systems, "S0"))
    return tuple(cells)


def run_count(resolution, levels, include_center_points=True):
    """B-52.3: 2^(6-p) + CENTER POINTS, minimal p."""
    p = resolution - 1
    if p < E6_RESOLUTION_FLOOR - 1:
        raise CampaignError(
            "resolution %r below floor %r" % (resolution,
                                              E6_RESOLUTION_FLOOR))
    if p > len(levels):
        raise CampaignError("resolution %r exceeds factor count" % (resolution,))
    base = 2 ** (len(levels) - p)
    if not include_center_points:
        return base
    return base + len(levels)


class Registration:
    """B-52.4 item 2: freeze() hashes design+alias+resolution+script."""

    def __init__(self, factors, levels, resolution, alias_table):
        self.factors = tuple(factors)
        self.levels = tuple(levels)
        self.resolution = resolution
        self.alias_table = tuple(alias_table)
        self.run_count = run_count(resolution, levels)
        self.analysis_script_sha256 = None
        self._frozen = None

    def _design(self):
        return {"factors": list(self.factors), "levels": list(self.levels),
                "resolution": self.resolution,
                "alias_table": list(self.alias_table),
                "run_count": self.run_count,
                "analysis_script_sha256": self.analysis_script_sha256}

    def freeze(self, analysis_script_sha256=None):
        if self.analysis_script_sha256 is None:
            self.analysis_script_sha256 = analysis_script_sha256
        if self.analysis_script_sha256 is None:
            raise CampaignError("analysis-script hash required at freeze")
        self._frozen = hashlib.sha256(
            repr(self._design()).encode()).hexdigest()
        return self._frozen

    def verify(self):
        if self._frozen is None:
            raise CampaignError("unfrozen registration")
        return hashlib.sha256(
            repr(self._design()).encode()).hexdigest() == self._frozen

    @property
    def prereg_hash(self):
        return self._frozen


def register_e6(factors, levels, resolution, alias_table,
                analysis_script_sha256=None):
    return Registration(factors, levels, resolution, alias_table).freeze(
        analysis_script_sha256)


def check_split(traces, mode):
    """B-52.4 item 3: refuse unrecorded splits; refuse tuning on hold-out
    LOUDLY. A calibration-only set must be admitted (positive control)."""
    if not traces:
        raise CampaignError("empty admission")
    unrecorded = [t for t in traces if not getattr(t, "split", None)]
    if unrecorded:
        raise CampaignError(
            "unrecorded split on %d trace(s); never assumed calibration"
            % len(unrecorded))
    if mode == "tuning":
        holdout = [t for t in traces if t.split == "holdout"]
        if holdout:
            raise CampaignError(
                "tuning on hold-out refused naming trace(s) %s"
                % ",".join(str(getattr(t, "serial", "?")) for t in holdout))
    return True


def h3_comparator(system_ids):
    """B-52.4 item 4: return S1; refuse a campaign without S1."""
    ids = set(system_ids)
    if H3_COMPARATOR not in ids:
        raise CampaignError(
            "no %s in campaign; %s is never the comparator"
            % (H3_COMPARATOR, H3_NEVER_COMPARATOR))
    if H3_NEVER_COMPARATOR in ids and H3_COMPARATOR in ids:
        pass
    return H3_COMPARATOR


class CampaignManifest:
    """B-52.3 CampaignManifest. Records NUMBERS only; never verdicts."""

    def __init__(self, model_pin, assumption_log_version, code_hash,
                 gate_preflight, doe_registration_hash=None,
                 h3_comparator_id=None, seeds=()):
        self.model_pin = model_pin
        self.assumption_log_version = assumption_log_version
        self.code_hash = code_hash
        self.gate_preflight = gate_preflight
        self.doe_registration_hash = doe_registration_hash
        self.h3_comparator_id = h3_comparator_id
        self.seeds = tuple(seeds)
        self.rows = []
        self.sim_tags = ()

    def set_model_pin(self, pin):
        """Mid-campaign pin change INVALIDATES: restart, never mutate."""
        if self.rows and pin != self.model_pin:
            raise ModelPinChanged(
                "model pin %r -> %r after %d row(s); campaign INVALID, "
                "restart with the new pin" % (self.model_pin, pin,
                                               len(self.rows)))
        self.model_pin = pin

    def add_row(self, row):
        self.rows.append(dict(row))

    def as_dict(self):
        return {"model_pin": self.model_pin,
                "assumption_log_version": self.assumption_log_version,
                "code_hash": self.code_hash,
                "gate_preflight": self.gate_preflight,
                "doe_registration_hash": self.doe_registration_hash,
                "h3_comparator_id": self.h3_comparator_id,
                "seeds": list(self.seeds),
                "sim_tags": list(self.sim_tags),
                "rows": [dict(r) for r in self.rows]}