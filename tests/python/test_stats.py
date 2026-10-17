"""B-54 stats core, proven against HAND-COMPUTABLE synthetic rows.

This is the Section-X de-risking override: statistics correctness is
proven independently of whether B-52/B-53 datasets exist yet.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import pytest

from analysis.stats import (CI_LEVEL, FWER, N_RESAMPLES, StatsError,
                            bootstrap_ci, dataset_hash, effect_size,
                            family_comparisons, holm_bonferroni, pair,
                            paired_diffs, should_discard,
                            summarize_small_n)


def _s(system, trace, seed, value):
    return {"system": system, "trace": trace, "seed": seed, "value": value}


def _paired(n=6):
    a, b = [], []
    for i in range(n):
        a.append(_s("S5", "t%d" % i, 7, 10.0 + i))
        b.append(_s("S1", "t%d" % i, 7, 8.0 + i))
    return a + b


# ---- pairing ----
def test_pair_groups_by_system_trace_seed():
    g = pair(_paired())
    assert set(g) == {"S5", "S1"}
    assert sorted(g["S5"]) == ["t%d" % i for i in range(6)]


def test_pair_refuses_unpaired_naming_the_key():
    rows = _paired()
    rows = [r for r in rows if not (r["system"] == "S5" and r["trace"] == "t3")]
    with pytest.raises(StatsError) as e:
        pair(rows)
    msg = str(e.value)
    assert "UNPAIRED" in msg and "'S5'" in msg and "t3" in msg


def test_pair_refuses_duplicate_key():
    rows = _paired() + [_s("S5", "t0", 7, 999.0)]
    with pytest.raises(StatsError) as e:
        pair(rows)
    assert "duplicate" in str(e.value)


def test_paired_diffs_are_a_minus_b():
    g = pair(_paired())
    d = paired_diffs(g, "S5", "S1")
    assert len(d) == 6
    assert all(x == 2.0 for x in d)


def test_paired_diffs_refuse_disjoint_systems():
    g = pair(_paired())
    with pytest.raises(StatsError):
        paired_diffs(g, "S5", "NOPE")


# ---- bootstrap ----
def test_bootstrap_ci_brackets_the_mean():
    d = paired_diffs(pair(_paired()), "S5", "S1")
    lo, hi, seed = bootstrap_ci(d, n=2000, seed=11)
    assert lo <= 2.0 <= hi
    assert seed == 11


def test_bootstrap_is_identical_on_replay():
    """Same seed -> same CI. The seed is recorded, not incidental."""
    d = paired_diffs(pair(_paired()), "S5", "S1")
    a = bootstrap_ci(d, n=1000, seed=5)
    b = bootstrap_ci(d, n=1000, seed=5)
    assert a == b


def test_different_seeds_differ_or_are_close_but_not_forced():
    d = paired_diffs(pair(_paired()), "S5", "S1")
    a = bootstrap_ci(d, n=1000, seed=1)
    b = bootstrap_ci(d, n=1000, seed=2)
    assert a[2] != b[2], "seed must be recorded per run"


def test_bootstrap_uses_10000_and_95_by_default():
    assert N_RESAMPLES == 10000
    assert CI_LEVEL == 0.95


def test_bootstrap_refuses_empty():
    with pytest.raises(StatsError):
        bootstrap_ci([], seed=1)


def test_bootstrap_on_a_constant_sample_is_a_degenerate_ci():
    lo, hi, _ = bootstrap_ci([2.0] * 8, n=200, seed=3)
    assert lo == hi == 2.0


# ---- effect size ----
def test_effect_size_mean_and_d_on_hand_data():
    d = [-2.0, -1.0, 0.0, 1.0, 2.0, 3.0]
    r = effect_size(d, n=500, seed=9)
    assert r["mean_diff"] == pytest.approx(0.5)
    assert r["n"] == 6
    mean = 0.5
    sd = (sum((x - mean) ** 2 for x in d) / 5) ** 0.5
    assert r["d"] == pytest.approx(mean / sd, rel=1e-9)


def test_effect_size_flags_zero_sd_instead_of_dividing():
    r = effect_size([1.0, 1.0, 1.0], n=100, seed=1)
    assert r["d"] is None and "sd-zero" in r["flags"]


def test_effect_size_records_method():
    r = effect_size([1.0, 2.0, 3.0], n=200, seed=1)
    assert r["method"] == "paired-bootstrap"


# ---- E8 / E9 ----
def test_e8_n5_gets_flags_not_cis():
    r = summarize_small_n([1.0, 2.0, 3.0, 4.0, 5.0])
    assert r["n"] == 5 and "small-n-no-inference" in r["flags"]
    assert "ci" not in r and "ci_lo" not in r


def test_e9_single_trace_gets_projection_not_stats():
    r = summarize_small_n([4.0])
    assert r["n"] == 1 and r["range"] is None
    assert "no projection possible" in r["projection"]


def test_small_n_refuses_n_above_five():
    with pytest.raises(StatsError):
        summarize_small_n([1.0] * 6)


# ---- discard rule ----
def test_short_runs_discard_only_in_short_classes():
    for c in ("E5", "E6", "E7", "E10", "E11"):
        assert should_discard(c, True) is True
        assert should_discard(c, False) is False, c


def test_long_runs_never_discard():
    for c in ("E8", "E9"):
        assert should_discard(c, True) is False, c


# ---- Holm-Bonferroni ----
def test_holm_uses_family_length_not_a_constant():
    fam = ["a", "b", "c", "d", "e", "f", "g", "h"]
    pv = {c: 0.01 for c in fam}
    adj = holm_bonferroni(pv, fam)
    assert adj["a"] == pytest.approx(0.08)   # 8 * 0.01
    assert adj["h"] == pytest.approx(0.08)


def test_holm_is_monotone_non_decreasing_by_p():
    fam = ["a", "b", "c"]
    pv = {"a": 0.001, "b": 0.02, "c": 0.04}
    adj = holm_bonferroni(pv, fam)
    assert adj["a"] <= adj["b"] <= adj["c"]


def test_holm_clamps_at_one():
    fam = ["a", "b"]
    adj = holm_bonferroni({"a": 0.6, "b": 0.7}, fam)
    assert all(v <= 1.0 for v in adj.values())


def test_holm_refuses_empty_family():
    with pytest.raises(StatsError):
        holm_bonferroni({}, [])


def test_family_enumeration_is_the_product():
    comps = family_comparisons("H1", ["c1", "c2"], ["S1", "S2", "S3"],
                               ["energy", "latency"])
    assert len(comps) == 2 * 3 * 2   # cells * pairs * metrics


def test_family_enumeration_pairs_are_systems_not_cells():
    comps = family_comparisons("H1", ["c1"], ["S1", "S2"], ["m"])
    assert comps == ["H1|c1|S1|S2|m"]


# ---- determinism ----
def test_dataset_hash_is_order_independent():
    r = _paired()
    assert dataset_hash(r) == dataset_hash(list(reversed(r)))


def test_dataset_hash_changes_with_content():
    r = _paired()
    r2 = list(r)
    r2[0] = dict(r2[0], value=999.0)
    assert dataset_hash(r) != dataset_hash(r2)


def test_fwer_constant_is_five_percent():
    assert FWER == 0.05


# ---- KNOWN CI bounds (B-54.5: exact, not a bracket) ----
KNOWN_LO = 2.5833333333333335
KNOWN_HI = 3.9166666666666665


def test_bootstrap_matches_known_exact_bounds():
    """Exact bounds for a fixed seed. A bracket check cannot catch a
    wrong percentile; these numbers can. (CPython's Mersenne Twister
    is stable, so this oracle is reproducible on any CPython.)"""
    from analysis.stats import known_ci_vector
    d = [2.0, 2.5, 3.0, 3.5, 4.0, 4.5]
    v = known_ci_vector(d, seed=11, n=10000)
    assert v["ci_lo"] == KNOWN_LO
    assert v["ci_hi"] == KNOWN_HI
    assert v["n_resamples"] == 10000 and v["level"] == 0.95


def test_known_bounds_are_wider_than_a_single_observation_spread():
    """A bootstrap CI on this sample must be NARROWER than the raw
    range (4.5-2.0=2.5) but wider than zero -- a wrong percentile
    (e.g. 99.9%) would blow past the raw range."""
    assert KNOWN_LO > 2.0
    assert KNOWN_HI < 4.5
    assert (KNOWN_HI - KNOWN_LO) < (4.5 - 2.0)


def test_known_bounds_fail_if_percentile_is_shifted():
    """Positive control: the oracle must be able to fail."""
    from analysis.stats import bootstrap_ci
    d = [2.0, 2.5, 3.0, 3.5, 4.0, 4.5]
    lo, _hi, _s = bootstrap_ci(d, n=10000, seed=11, level=0.80)
    assert lo != KNOWN_LO, "an 80% CI must not equal the 95% oracle"


# ---- B-54.6 gate contract ----
def _manifest():
    return {"gate_preflight": "e0-abc123", "model_pin": "m1",
            "code_hash": "c" * 16, "assumption_log_version": "b43-device-2"}


def test_gate_accepts_matching_n_with_real_vector_records():
    from analysis.stats import gate_contract
    g = gate_contract(6, 6, [{"v": 1}, {"v": 2}], manifest=_manifest())
    assert g["stated_n"] == 6 and g["vector_records"] == 2
    assert g["manifest_ok"] is True and g["deterministic"] is True


def test_gate_refuses_absent_manifest():
    """B-54.6 requires JSONL AND manifest."""
    from analysis.stats import gate_contract
    with pytest.raises(StatsError) as e:
        gate_contract(6, 6, [{"v": 1}])
    assert "manifest" in str(e.value)


def test_gate_refuses_empty_or_non_mapping_manifest():
    from analysis.stats import gate_contract
    for bad in ({}, "not-a-dict", []):
        with pytest.raises(StatsError):
            gate_contract(6, 6, [{"v": 1}], manifest=bad)


def test_gate_refuses_manifest_missing_a_required_field():
    from analysis.stats import gate_contract
    for field in ("gate_preflight", "model_pin", "code_hash",
                  "assumption_log_version"):
        m = _manifest()
        del m[field]
        with pytest.raises(StatsError) as e:
            gate_contract(6, 6, [{"v": 1}], manifest=m)
        assert field in str(e.value), field


def test_gate_refuses_n_mismatch():
    from analysis.stats import gate_contract
    with pytest.raises(StatsError) as e:
        gate_contract(6, 5, [{"v": 1}], manifest=_manifest())
    assert "N=" in str(e.value)


def test_gate_refuses_the_pending_harness_placeholder():
    """A gate must not pass on a placeholder."""
    from analysis.stats import gate_contract
    with pytest.raises(StatsError) as e:
        gate_contract(6, 6, "pending-harness", manifest=_manifest())
    assert "pending-harness" in str(e.value)


def test_gate_refuses_missing_or_empty_n():
    from analysis.stats import gate_contract
    for n in (None, 0, -1):
        with pytest.raises(StatsError):
            gate_contract(n, 1, [{"v": 1}], manifest=_manifest())


def test_gate_refuses_empty_vector_records():
    from analysis.stats import gate_contract
    with pytest.raises(StatsError):
        gate_contract(6, 6, [], manifest=_manifest())


def test_determinism_hash_is_stable_across_calls():
    from analysis.stats import determinism_hash
    payloads = [{"a": 1, "b": "x"}, {"c": 2}]
    assert determinism_hash(payloads) == determinism_hash(payloads)