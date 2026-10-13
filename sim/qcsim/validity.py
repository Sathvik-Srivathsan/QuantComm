"""Comparison validity + H3 inputs (B-44.3/.4): gates, never decisions.

check_comparison: identical traces/seeds (B-43 pairing, cited) plus
identical backend builds across compared systems (never
optimized-vs-reference; cross-implementation comparison invalidates
H3 — refused here with hard errors naming the offender).

select_anchor: H3 static anchor (B-44.3) — minimum-energy static over
{S2-SL1, S2-SL2, S2-SL3, S3} restricted to the eligible set passed by
the caller (eligibility = every-window floor satisfaction evaluated
by the caller under B-31 predicates, cited); tie broken toward lower
SL then S2 over S3; else-S3 retained as campaign-scope fallback when
no S2 variant is present in the campaign (not floor logic). Returns
(anchor_id, rationale) — the rationale is recorded, never silent.

check_oracle_bound: S5 saving above S6 saving alarms as model bug
(oracle bounds from above) — loud ValueError, never a quiet flag.

h3_input_record: H3-input numbers {trace ID, anchor ID + rationale,
S5 mean, anchor mean, violations, oracle bound, seeds, code hash}
with the S5 zero-violation gate enforced (nonzero refused). The 15
percent threshold and 5 percent headroom gate are applied by B-55
(forward; this module supplies numbers, never decides).
"""

from .runner import check_pairing
from .systems import S2_IDS, S3_ID


def check_comparison(systems, manifests):
    """Gate a comparison: shared backend + paired traces/seeds."""
    if not systems:
        raise ValueError("no systems to compare")
    backends = {s["backend"] for s in systems}
    if len(backends) != 1:
        raise ValueError(
            f"cross-implementation comparison refused: {backends}")
    check_pairing(manifests)
    return True


def select_anchor(means, eligible, campaign_ids=None):
    """Pick the H3 static anchor. Returns (anchor_id, rationale)."""
    candidates = [s for s in (list(S2_IDS) + [S3_ID])
                  if s in eligible and s in means]
    if not candidates:
        raise ValueError("no eligible anchor candidate")
    if campaign_ids is not None and \
            not any(s in campaign_ids for s in S2_IDS):
        if S3_ID in candidates:
            return S3_ID, "else-S3 campaign fallback (no S2 in campaign)"
    order = {s: i for i, s in enumerate(list(S2_IDS) + [S3_ID])}
    best = min(candidates, key=lambda s: (means[s], order[s]))
    if best == S3_ID and any(s in candidates for s in S2_IDS):
        return best, "S3 min-energy among eligible (S2 eligible but costlier)"
    if best in S2_IDS:
        return best, "min-energy static among eligible (ties to lower SL)"
    return best, "min-energy static among eligible"


def check_oracle_bound(s5_mean, s6_mean):
    """Oracle-sanity gate: S5 must not beat the S6 bound."""
    if s5_mean < s6_mean:
        raise ValueError(
            "oracle bound violated (S5 beats S6: model bug)")
    return True


def h3_input_record(trace_id, anchor_id, rationale, s5_mean,
                    anchor_mean, violations, oracle_bound, seeds,
                    code_hash):
    """Build one H3-input record (numbers only; B-55 decides)."""
    if not isinstance(trace_id, str) or not trace_id:
        raise ValueError("trace_id must be a nonempty str")
    if violations != 0:
        raise ValueError("S5 violations must be zero (gate)")
    record = {"trace_id": trace_id, "anchor_id": anchor_id,
              "rationale": rationale, "s5_mean": s5_mean,
              "anchor_mean": anchor_mean, "violations": violations,
              "oracle_bound": oracle_bound, "seeds": seeds,
              "code_hash": code_hash}
    import json as _json
    _json.dumps(record)  # retention contract: JSON-serializable
    return record
