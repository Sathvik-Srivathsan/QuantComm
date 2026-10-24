"""B-55: Adaptive Headroom Computation + Calibrated-Only Enforcement.

Normative spec: plan-rigorous.md §B-55, phase5-detailed.md §B-55.
Formula:
    headroom = (E_static_at_highest_floor - E_S5) / E_total
    where E_total = E_static_at_highest_floor on the identical trace.
Calibrated parameters ONLY: ASSUMED priors are strictly refused by flag scan.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional, Union

from analysis import stats


class HeadroomError(Exception):
    """Hard refusal on invalid inputs or uncalibrated parameters."""


@dataclass
class HeadroomInput:
    E_static_anchor: Union[Dict[str, float], float]
    E_S5: Union[Dict[str, float], float]
    E_total: Optional[Union[Dict[str, float], float]] = None
    calibrated_params: Optional[Dict[str, Any]] = None
    families: Optional[List[str]] = None


@dataclass
class Headroom:
    per_family: Dict[str, Dict[str, Any]]
    aggregate: Dict[str, Any]
    ci: Dict[str, Any]
    families: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def scan_assumed_flags(params: Any) -> None:
    """Scan parameter structures for ASSUMED flags. Fail-closed.

    Any uncalibrated prior or ASSUMED marker raises HeadroomError.
    """
    if params is None:
        raise HeadroomError("calibrated-only violation: params cannot be None")

    if isinstance(params, dict):
        # Direct flag checks
        if params.get("assumed") is True or params.get("is_assumed") is True:
            raise HeadroomError("calibrated-only violation: input carries ASSUMED flag")
        if params.get("is_calibrated") is False:
            raise HeadroomError("calibrated-only violation: parameter is not calibrated")
        for k, v in params.items():
            if isinstance(k, str) and "assumed" in k.lower() and v is True:
                raise HeadroomError(f"calibrated-only violation: key {k!r} indicates assumed prior")
            if isinstance(v, str) and "ASSUMED" in v.upper():
                raise HeadroomError(f"calibrated-only violation: field {k!r} has ASSUMED value {v!r}")
            if isinstance(v, (dict, list, tuple)):
                scan_assumed_flags(v)
    elif isinstance(params, (list, tuple)):
        for item in params:
            if isinstance(item, str) and "ASSUMED" in item.upper():
                raise HeadroomError(f"calibrated-only violation: item has ASSUMED value {item!r}")
            if isinstance(item, (dict, list, tuple)):
                scan_assumed_flags(item)


def compute_headroom(
    E_static: Union[Dict[str, float], float, List[Dict[str, Any]]],
    E_S5: Optional[Union[Dict[str, float], float]] = None,
    E_total: Optional[Union[Dict[str, float], float]] = None,
    params: Optional[Dict[str, Any]] = None,
    target: float = 0.05,
    families: Optional[List[str]] = None,
    seed: int = 12345,
    n_resamples: int = 10000,
) -> Headroom:
    """Compute adaptive headroom per trace family and aggregate.

    Enforces calibrated-only parameters and E_total == E_static.
    Supports either:
      - (E_static, E_S5, E_total, params) as numbers/dicts
      - (HeadroomInput) as a single dataclass argument
      - (paired_samples, target, ...) list of B-54 paired sample dictionaries
    """
    # Form 1: HeadroomInput dataclass passed as first argument
    if isinstance(E_static, HeadroomInput):
        inp = E_static
        return compute_headroom(
            E_static=inp.E_static_anchor,
            E_S5=inp.E_S5,
            E_total=inp.E_total,
            params=inp.calibrated_params,
            target=target,
            families=inp.families,
            seed=seed,
            n_resamples=n_resamples,
        )

    # Form 2: Paired samples list (B-54 PairedSample format)
    if isinstance(E_static, list) and E_static and isinstance(E_static[0], dict) and "system" in E_static[0]:
        paired_samples = E_static
        # When params is passed in E_S5 or params kwarg
        cal_params = params if params is not None else (E_S5 if isinstance(E_S5, dict) and "system" not in E_S5 else None)
        scan_assumed_flags(cal_params if cal_params is not None else {"calibrated": True})

        grouped = stats.pair(paired_samples)
        sys_keys = sorted(grouped.keys())
        # Expect at least two systems (e.g. S2 and S5)
        if "S5" not in grouped:
            raise HeadroomError("paired samples must contain system 'S5'")
        anchor_cand = [k for k in sys_keys if k != "S5"]
        if not anchor_cand:
            raise HeadroomError("paired samples must contain a static anchor system in addition to S5")
        anchor_sys = anchor_cand[0]

        diffs = stats.paired_diffs(grouped, anchor_sys, "S5")
        # diffs are (anchor - S5)
        # Headroom fraction: diff / anchor
        # Retrieve anchor values
        a_traces = grouped[anchor_sys]
        s5_traces = grouped["S5"]
        ratios = []
        family_records: Dict[str, List[float]] = {}
        for tr in sorted(set(a_traces) & set(s5_traces)):
            for sd in sorted(set(a_traces[tr]) & set(s5_traces[tr])):
                e_anc = a_traces[tr][sd]
                e_s5 = s5_traces[tr][sd]
                if e_anc <= 0:
                    raise HeadroomError(f"non-positive anchor energy {e_anc} on trace {tr}")
                hr = (e_anc - e_s5) / e_anc
                ratios.append(hr)
                fam = tr.split("_")[0] if "_" in tr else "default"
                family_records.setdefault(fam, []).append(hr)

        if not ratios:
            raise HeadroomError("no paired observations found")

        ci_lo, ci_hi, ci_seed = stats.bootstrap_ci(ratios, n=n_resamples, seed=seed)
        agg_mean = sum(ratios) / len(ratios)
        ci_dict = {"ci_lo": ci_lo, "ci_hi": ci_hi, "seed": ci_seed, "n_resamples": n_resamples}

        per_family = {}
        fam_list = sorted(family_records.keys())
        for f in fam_list:
            fr = family_records[f]
            f_mean = sum(fr) / len(fr)
            f_ci = stats.bootstrap_ci(fr, n=n_resamples, seed=seed) if len(fr) >= 2 else (f_mean, f_mean, seed)
            per_family[f] = {
                "headroom_pct": f_mean,
                "n": len(fr),
                "ci_lo": f_ci[0],
                "ci_hi": f_ci[1],
            }

        aggregate = {
            "headroom_pct": agg_mean,
            "n_pairs": len(ratios),
            "target": target,
        }
        return Headroom(per_family=per_family, aggregate=aggregate, ci=ci_dict, families=fam_list)

    # Form 3: Explicit numeric or per-family dict values
    scan_assumed_flags(params)

    if E_S5 is None:
        raise HeadroomError("E_S5 must be provided")

    # If E_total is omitted, by specification E_total = E_static_at_highest_floor
    if E_total is None:
        E_total = E_static

    # Case A: Scalar numeric values
    if isinstance(E_static, (int, float)) and isinstance(E_S5, (int, float)):
        if E_static <= 0:
            raise HeadroomError(f"E_static must be strictly positive, got {E_static}")
        if not math.isclose(float(E_total), float(E_static), rel_tol=1e-7):
            raise HeadroomError("E_total must equal E_static anchor energy by design")

        diff = float(E_static) - float(E_S5)
        hr_pct = diff / float(E_total)
        fam_list = families or ["aggregate"]
        per_fam = {
            fam_list[0]: {
                "headroom_pct": hr_pct,
                "E_static": float(E_static),
                "E_S5": float(E_S5),
                "E_total": float(E_total),
            }
        }
        aggregate = {
            "headroom_pct": hr_pct,
            "E_static": float(E_static),
            "E_S5": float(E_S5),
            "E_total": float(E_total),
            "target": target,
        }
        ci_dict = {"ci_lo": hr_pct, "ci_hi": hr_pct, "seed": seed, "n_resamples": 0}
        return Headroom(per_family=per_fam, aggregate=aggregate, ci=ci_dict, families=fam_list)

    # Case B: Dictionaries per family
    if isinstance(E_static, dict) and isinstance(E_S5, dict):
        if not E_static:
            raise HeadroomError("E_static dictionary cannot be empty")
        if set(E_static.keys()) != set(E_S5.keys()):
            raise HeadroomError(
                f"key mismatch between E_static {sorted(E_static)} and E_S5 {sorted(E_S5)}"
            )

        e_tot_dict = E_total if isinstance(E_total, dict) else {k: E_static[k] for k in E_static}
        fam_list = sorted(families if families is not None else E_static.keys())

        per_family = {}
        diff_ratios = []
        tot_static = 0.0
        tot_s5 = 0.0
        tot_total = 0.0

        for f in fam_list:
            if f not in E_static:
                raise HeadroomError(f"family {f!r} not in E_static")
            s_val = float(E_static[f])
            s5_val = float(E_S5[f])
            t_val = float(e_tot_dict[f])

            if s_val <= 0:
                raise HeadroomError(f"family {f!r} has non-positive E_static {s_val}")
            if not math.isclose(t_val, s_val, rel_tol=1e-7):
                raise HeadroomError(f"family {f!r} E_total ({t_val}) != E_static ({s_val})")

            ratio = (s_val - s5_val) / t_val
            per_family[f] = {
                "headroom_pct": ratio,
                "E_static": s_val,
                "E_S5": s5_val,
                "E_total": t_val,
            }
            diff_ratios.append(ratio)
            tot_static += s_val
            tot_s5 += s5_val
            tot_total += t_val

        agg_headroom = (tot_static - tot_s5) / tot_total

        if len(diff_ratios) >= 2:
            ci_lo, ci_hi, ci_seed = stats.bootstrap_ci(diff_ratios, n=n_resamples, seed=seed)
        else:
            ci_lo, ci_hi, ci_seed = agg_headroom, agg_headroom, seed

        ci_dict = {
            "ci_lo": ci_lo,
            "ci_hi": ci_hi,
            "seed": ci_seed,
            "n_resamples": n_resamples if len(diff_ratios) >= 2 else 0,
        }

        aggregate = {
            "headroom_pct": agg_headroom,
            "E_static": tot_static,
            "E_S5": tot_s5,
            "E_total": tot_total,
            "target": target,
        }
        return Headroom(per_family=per_family, aggregate=aggregate, ci=ci_dict, families=fam_list)

    raise HeadroomError(f"unsupported input types: E_static={type(E_static)}, E_S5={type(E_S5)}")
