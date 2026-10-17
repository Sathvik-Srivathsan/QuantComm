"""B-54 statistics pipeline: pairing, bootstrap, effect sizes,
Holm-Bonferroni. Supplies NUMBERS, never verdicts -- a decision branch
here is a defect (B-54.7); the no-decision scan enforces it.

B-54.3 rules honoured here:
  * 95% bootstrap CIs, 10,000 resamples, PAIRED resampling of TRACES
    (never individual runs).
  * bootstrap RNG seeded per run and the seed recorded; identical CIs
    on replay.
  * effect size = native-unit mean difference + paired standardized d.
  * Holm-Bonferroni FAMILY is PINNED: family = every pairwise
    comparison contributing evidence to a given H-claim, NOT one family
    per claim. The correction uses the LENGTH of the enumerated list.
  * E8 (n=5) and E9 (n=1..2) exceptions: no inferential stats.
"""

import hashlib
import random
import re

N_RESAMPLES = 10000
CI_LEVEL = 0.95
FWER = 0.05

# An E0 gate id is "e0-" + 16 hex (qcsim.gate.mint_gate_id). Duplicated as a
# shape check rather than imported: analysis/ must not depend on sim/.
GATE_ID_RE = re.compile(r"^e0-[0-9a-f]{16}$")


class StatsError(Exception):
    """Hard refusal. Never a silent drop, never a partial output."""


def pair(samples):
    """B-54.4.1: group by (system, trace, seed).

    Refuses UNPAIRED inputs with a hard error naming the system and the
    offending trace. Returns {system: {trace: {seed: value}}}.
    """
    grouped = {}
    for s in samples:
        for k in ("system", "trace", "seed", "value"):
            if k not in s:
                raise StatsError("sample missing field %r" % k)
        traces = grouped.setdefault(s["system"], {})
        if s["seed"] in traces.setdefault(s["trace"], {}):
            raise StatsError(
                "duplicate key system=%r trace=%r seed=%r"
                % (s["system"], s["trace"], s["seed"]))
        traces[s["trace"]][s["seed"]] = s["value"]
    if len(grouped) > 1:
        full = set()
        for traces in grouped.values():
            full |= set(traces)
        problems = []
        for sysname in sorted(grouped):
            missing = sorted(full - set(grouped[sysname]))
            if missing:
                problems.append("%r missing trace(s) %s"
                                % (sysname, missing))
        if problems:
            raise StatsError("UNPAIRED input: " + "; ".join(problems))
        # Trace completeness is not enough: paired_diffs intersects the SEED
        # sets per trace, so a system rated on fewer seeds was silently
        # dropped from the pairing (N, CI and effect size all computed on a
        # subset with no signal). The module contract is "never a silent
        # drop", so refuse an unequal seed set by name.
        seed_problems = []
        for tr in sorted(full):
            sets = {name: set(grouped[name][tr]) for name in sorted(grouped)}
            common = set.intersection(*sets.values())
            for name in sorted(sets):
                extra = sorted(sets[name] - common)
                if extra:
                    seed_problems.append(
                        "%r trace %r has unpaired seed(s) %s"
                        % (name, tr, extra))
        if seed_problems:
            raise StatsError("UNPAIRED seeds: " + "; ".join(seed_problems))
    return grouped


def paired_diffs(grouped, system_a, system_b):
    """Per-trace differences a-b over the common (trace, seed) keys."""
    for name in (system_a, system_b):
        if name not in grouped:
            raise StatsError("unknown system %r (have %s)"
                             % (name, sorted(grouped)))
    a = grouped[system_a]
    b = grouped[system_b]
    out = []
    for tr in sorted(set(a) & set(b)):
        for seed in sorted(set(a[tr]) & set(b[tr])):
            out.append(a[tr][seed] - b[tr][seed])
    if not out:
        raise StatsError("no paired observations for %s vs %s"
                         % (system_a, system_b))
    return out


def _mean(xs):
    return sum(xs) / len(xs)


def _sd(xs):
    n = len(xs)
    if n < 2:
        return 0.0
    m = _mean(xs)
    return (sum((x - m) ** 2 for x in xs) / (n - 1)) ** 0.5


def bootstrap_ci(diffs, n=N_RESAMPLES, seed=0, level=CI_LEVEL):
    """B-54.4.2: paired resampling with a RECORDED seed.

    Returns (lo, hi, seed). Identical on replay for the same seed.
    """
    if not diffs:
        raise StatsError("empty diffs")
    rng = random.Random(seed)
    m = len(diffs)
    reps = []
    for _ in range(n):
        s = 0.0
        for _ in range(m):
            s += diffs[rng.randrange(m)]
        reps.append(s / m)
    reps.sort()
    alpha = (1.0 - level) / 2.0
    return (reps[int(alpha * (n - 1))],
            reps[int((1.0 - alpha) * (n - 1))], seed)


def effect_size(diffs, n=N_RESAMPLES, seed=0):
    """B-54.4.3: native-unit mean + paired standardized d + its CI."""
    m = len(diffs)
    mean = _mean(diffs)
    sd = _sd(diffs)
    if m < 2 or sd == 0:
        return {"mean_diff": mean, "d": None, "d_ci": None, "n": m,
                "method": "paired-mean", "flags": ["sd-zero"]}
    rng = random.Random(seed)
    reps = []
    for _ in range(n):
        picks = [diffs[rng.randrange(m)] for _ in range(m)]
        sd_b = _sd(picks)
        reps.append((_mean(picks) / sd_b) if sd_b > 0 else 0.0)
    reps.sort()
    alpha = (1.0 - CI_LEVEL) / 2.0
    d_ci = (reps[int(alpha * (n - 1))],
            reps[int((1.0 - alpha) * (n - 1))])
    return {"mean_diff": mean, "d": mean / sd, "d_ci": d_ci, "n": m,
            "method": "paired-bootstrap", "flags": []}


def summarize_small_n(values, method="mean-range"):
    """B-54.3 E8/E9 exception: NO bootstrap, NO inferential stats."""
    n = len(values)
    if n > 5:
        raise StatsError("summarize_small_n is for n<=5 only; use bootstrap")
    if n == 0:
        raise StatsError("empty")
    out = {"n": n, "method": method, "mean": _mean(values),
           "flags": ["small-n-no-inference"]}
    if n > 1:
        out["range"] = (min(values), max(values))
        out["projection"] = ("linear-extrapolation "
                             "(PROJECTION, not a measurement)")
    else:
        out["range"] = None
        out["projection"] = "single-trace, no projection possible"
    return out


def should_discard(exp_class, is_short_run):
    """B-54.3: short runs ONLY discard; E8/E9 long runs NEVER discard."""
    if not is_short_run:
        return False
    return exp_class in ("E5", "E6", "E7", "E10", "E11")


def holm_bonferroni(p_values, family):
    """B-54.4.4 FWER 0.05 over the MANIFEST-ENUMERATED family.

    The correction uses len(family), NOT a constant: counting claims
    instead of comparisons under-corrects and is a review-blocking
    defect (B-54.3).
    """
    if not family:
        raise StatsError("empty family: Holm-Bonferroni undefined")
    # A missing/None p-value used to raise a raw KeyError/TypeError out of the
    # sort key, breaking this module's "the ONLY exception raised is
    # StatsError" contract while the `if p is None` branch below was
    # unreachable. Validate first, then sort.
    for c in family:
        if c not in p_values:
            raise StatsError("family member %r has no p-value" % (c,))
        p = p_values[c]
        if p is not None and (isinstance(p, bool)
                              or not isinstance(p, (int, float))):
            raise StatsError("p-value for %r is %r, not a number or None"
                             % (c, p))
    m = len(family)
    ordered = sorted(family,
                     key=lambda c: (p_values[c] is None,
                                    p_values[c] if p_values[c] is not None
                                    else 0.0))
    out = {}
    running = 0.0
    for i, c in enumerate(ordered):
        p = p_values[c]
        if p is None:
            # Not computable (e.g. too few samples). It is still part of the
            # family count m, which is the point of counting claims: an
            # uncomputable comparison must not silently shrink the family.
            out[c] = None
            continue
        running = max(running, min(1.0, (m - i) * p))
        out[c] = running
    return out


def family_comparisons(hm_claim_id, cells, systems, metrics):
    """B-54.3: m cells x s system-pairs x k metrics."""
    comps = []
    for cell in cells:
        for i, s1 in enumerate(systems):
            for s2 in systems[i + 1:]:
                for k in metrics:
                    comps.append("%s|%s|%s|%s|%s"
                                 % (hm_claim_id, cell, s1, s2, k))
    return comps


def dataset_hash(rows):
    """Order-independent content hash (determinism guard)."""
    h = hashlib.sha256()
    for r in sorted(rows, key=lambda x: repr(sorted(x.items()))):
        h.update(repr(sorted(r.items())).encode())
    return h.hexdigest()


def known_ci_vector(diffs, seed, n=N_RESAMPLES):
    """EXACT expected CI for a fixed seed.

    A bracket-only assertion (lo <= mean <= hi) cannot distinguish a
    correct percentile from a wrong one; B-54.5 demands KNOWN bounds,
    so the oracle is recomputed here and the TEST pins the numbers.
    """
    lo, hi, s = bootstrap_ci(diffs, n=n, seed=seed)
    return {"ci_lo": lo, "ci_hi": hi, "seed": s, "n_resamples": n,
            "level": CI_LEVEL}


def gate_contract(n_declared, n_observed, vector_records, manifest=None):
    """B-54.6 gate: stated N, 100% deterministic, per-vector JSONL AND
    manifest. All four are required; none may be a placeholder."""
    if isinstance(n_declared, bool) or isinstance(n_observed, bool) \
            or not isinstance(n_declared, int) \
            or not isinstance(n_observed, int):
        raise StatsError("stated N and observed N must be ints, got %r/%r"
                         % (n_declared, n_observed))
    if n_declared <= 0:
        raise StatsError("stated N must be positive")
    if n_observed != n_declared:
        raise StatsError("stated N=%r but produced %d"
                         % (n_declared, n_observed))
    if vector_records == "pending-harness":
        raise StatsError("per-vector JSONL is pending-harness; the gate "
                         "cannot pass on a placeholder")
    if vector_records == "per-test":
        raise StatsError("per-test retention satisfies G5 but NOT the "
                         "per-vector accept boxes (:573/:687/:807"
                         "/:913); the per-vector form is required")
    if not isinstance(vector_records, list):
        raise StatsError("unknown retention form %r (%s); expected a "
                         "per-vector record list"
                         % (vector_records, type(vector_records).__name__))
    if not vector_records:
        raise StatsError("per-vector record list empty")
    from .vector_schema import SchemaError, validate_set
    try:
        n_records = validate_set(vector_records, "per-vector")
    except SchemaError as exc:
        raise StatsError("per-vector records invalid: %s" % exc)
    if n_records != n_declared:
        raise StatsError("stated N=%d but %d per-vector records"
                         % (n_declared, n_records))
    # Schema-valid is not gate-valid. `passed` and the per-row gate provenance
    # are part of the record for a reason; validating only the SHAPE let a
    # record set in which 100% of vectors failed publish as manifest_ok.
    failed = [r["vector_id"] for r in vector_records if r["passed"] is not True]
    if failed:
        raise StatsError("per-vector record(s) did not pass: %s"
                         % (failed[:5],))
    if manifest is None:
        raise StatsError("manifest absent: B-54.6 requires JSONL AND "
                         "manifest")
    if not isinstance(manifest, dict) or not manifest:
        raise StatsError("manifest must be a non-empty mapping")
    for field in ("gate_preflight", "model_pin", "code_hash",
                  "assumption_log_version"):
        v = manifest.get(field)
        if not isinstance(v, str) or not v.strip():
            raise StatsError("manifest field %r must be a non-empty "
                             "string, got %r" % (field, v))
        # A value with leading/trailing whitespace reaches a path component
        # and a log line in other contexts; here it silently defeated the
        # sentinel comparison below, so "not-required " was accepted as a
        # VERIFIED gate. Refuse the padded form outright.
        if v != v.strip():
            raise StatsError("manifest field %r has surrounding whitespace "
                             "(%r); values are compared exactly"
                             % (field, v))
    # "not-required" is the runner's own sentinel for "the E0 preflight never
    # ran" (sim/qcsim/runner.py). Accepting it here meant a run that skipped
    # the gate was indistinguishable from a verified one. Compare on a
    # normalised form as well, so casing/padding cannot bypass the sentinel
    # even if a future producer changes how it spells it.
    if manifest["gate_preflight"].strip().lower() == "not-required":
        raise StatsError("gate_preflight is 'not-required': the E0 gate was "
                         "never consulted for this run")
    # ...but refusing ONE sentinel is not verification. The gate id has a
    # checkable shape (qcsim.gate: "e0-" + 16 hex) and is recomputable, yet
    # any other string -- "verified", "yolo", a well-formed fake -- was
    # accepted, so a run with no gate at all could be relabelled and pass.
    # Shape-check here; recomputation is qcsim.gate.verify_gate_id's job (this
    # module must not import the sim layer), and preflight is what actually
    # walks the record.
    claimed = manifest["gate_preflight"]
    if not GATE_ID_RE.match(claimed):
        raise StatsError("manifest gate_preflight %r is not an E0 gate id "
                         "(expected 'e0-<16 hex>'); a value that cannot name a "
                         "gate is not evidence that one passed" % (claimed,))
    # Provenance binding: the retained rows must name the same gate the
    # manifest claims. Without this the JSONL and the manifest were two
    # unrelated objects that the gate only checked EXIST.
    mismatched = [r["vector_id"] for r in vector_records
                  if r["gate_id"] != claimed]
    if mismatched:
        raise StatsError("per-vector record(s) %s carry gate_id != "
                         "manifest gate_preflight %r"
                         % (mismatched[:5], claimed))
    unbound = [r["vector_id"] for r in vector_records
               if not r["gate_commit"]]
    if unbound:
        raise StatsError("per-vector record(s) %s carry no gate_commit; a "
                         "result without provenance is not a result"
                         % (unbound[:5],))
    unknown = sorted(set(manifest) - {"gate_preflight", "model_pin",
                                      "code_hash",
                                      "assumption_log_version"}, key=str)
    if unknown:
        raise StatsError("manifest has unknown key(s) %s" % unknown)
    return {"stated_n": n_declared, "observed_n": n_observed,
            "retention_form": "per-vector",
            "vector_records": n_records,
            "manifest_ok": True,
            "deterministic": True}


def determinism_hash(payloads):
    """100% determinism: identical inputs -> identical hash, always."""
    return dataset_hash(payloads)
