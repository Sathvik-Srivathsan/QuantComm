"""B-54 H5 gate: MAPE/MAE/RMSE on BOTH denominators + overhead floor.

B-54.3 rules:
  * overhead floor in J/hour is PAPER-PARAM, PRE-REGISTERED BEFORE H5
    runs, at/above 3x rig resolution, deliberately set (no provisional).
  * MAPE on BOTH denominators (session energy AND security overhead)
    vs 10%.
  * Below floor -> MAPE SUPPRESSED, MAE/RMSE still reported
    (additive, unconditional).
  * Tail p99/max preserved through the pipeline, never averaged.

Supplies NUMBERS, never verdicts (B-54.7).
"""

MAPE_THRESHOLD = 0.10
RESOLUTION_MULTIPLE = 3


class H5Error(Exception):
    """Hard refusal. Never a silent suppression."""


class FloorRegistration:
    """Pre-registered before H5 runs; ordering enforced fail-closed."""

    def __init__(self, floor_J_per_h, rig_resolution_J_per_h,
                 registered_at=None):
        if floor_J_per_h <= 0:
            raise H5Error("floor must be positive")
        if rig_resolution_J_per_h <= 0:
            raise H5Error("rig resolution must be positive")
        # 3*res is computed on floats, so the boundary needs a relative
        # tolerance or a floor set EXACTLY at 3x rig resolution is
        # refused by 1 ULP.
        minimum = RESOLUTION_MULTIPLE * rig_resolution_J_per_h
        tol = minimum * 1e-9
        if floor_J_per_h < minimum - tol:
            raise H5Error(
                "floor %r below %dx rig resolution %r: a floor below "
                "measurement resolution cannot gate"
                % (floor_J_per_h, RESOLUTION_MULTIPLE, rig_resolution_J_per_h))
        self.floor_J_per_h = floor_J_per_h
        self.rig_resolution_J_per_h = rig_resolution_J_per_h
        self.registered_at = registered_at
        self.first_run_at = None

    def record_first_run(self, timestamp):
        if self.first_run_at is None:
            self.first_run_at = timestamp

    def check_order(self):
        if self.registered_at is None or self.first_run_at is None:
            raise H5Error("floor/run not recorded: order unverifiable")
        if self.first_run_at < self.registered_at:
            raise H5Error("floor registered AFTER first run")
        return True


def _errors(pred, actual):
    return [(a - p, p, a) for p, a in zip(pred, actual)]


def _mape(errs):
    out = []
    for e, p, _a in errs:
        if p == 0:
            raise H5Error("MAPE undefined at a zero predicted value")
        out.append(abs(e) / abs(p))
    return sum(out) / len(out)


def _mae(errs):
    return sum(abs(e) for e, _p, _a in errs) / len(errs)


def _rmse(errs):
    return (sum(e * e for e, _p, _a in errs) / len(errs)) ** 0.5


def h5_gate(pred_total, act_total, pred_overhead, act_overhead, floor,
            threshold=MAPE_THRESHOLD):
    """B-54.4.5: suppress MAPE below floor; ALWAYS report MAE/RMSE on both.

    Returns the H5Gate fields: mape_total, mape_overhead (or None when
    suppressed), mae_total, mae_overhead, rmse_total, rmse_overhead,
    floor_J_per_h, suppressed. Never a verdict.
    """
    if len(pred_total) != len(act_total):
        raise H5Error("total arrays differ in length")
    if len(pred_overhead) != len(act_overhead):
        raise H5Error("overhead arrays differ in length")
    if not pred_total:
        raise H5Error("empty input")
    et = _errors(pred_total, act_total)
    eo = _errors(pred_overhead, act_overhead)

    overhead_excess = max(abs(a - p) for e, p, a in eo)
    suppressed = overhead_excess < floor.floor_J_per_h

    out = {
        "floor_J_per_h": floor.floor_J_per_h,
        "suppressed": suppressed,
        "mae_total": _mae(et),
        "mae_overhead": _mae(eo),
        "rmse_total": _rmse(et),
        "rmse_overhead": _rmse(eo),
        "mape_total": None,
        "mape_overhead": None,
    }
    if suppressed:
        # MAE/RMSE stay; MAPE is withheld because it would be dominated
        # by an overhead smaller than the floor.
        return out
    out["mape_total"] = _mape(et)
    out["mape_overhead"] = _mape(eo)
    out["mape_passes"] = (out["mape_total"] <= threshold
                          and out["mape_overhead"] <= threshold)
    return out


def tail_preserved(values):
    """p99/max preserved, never averaged away by the pipeline."""
    if not values:
        raise H5Error("empty tail input")
    s = sorted(values)
    return {"p99": s[min(len(s) - 1, int(0.99 * (len(s) - 1)))],
            "max": s[-1], "n": len(s)}