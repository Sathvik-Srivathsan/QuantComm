"""B-52 items 1-4 + manifest/model-pin surface. Every test drives a
production function; each gate has a POSITIVE CONTROL so it cannot pass
by refusing everything (B-52.5)."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "sim"))

import pytest

from qcsim import (CampaignError, CampaignManifest, ModelPinChanged, check_split,
                   e5_cells, h3_comparator, register_e6, run_count)


class T:
    def __init__(self, serial, split):
        self.serial = serial
        self.split = split


def _traces(n=4, split="calibration"):
    return [T(i, split) for i in range(n)]


# ---- B-52.4 item 1: matrix ----
def test_matrix_is_a_product_not_a_list():
    """Asserted as a PRODUCT so a dropped axis is caught."""
    cells = e5_cells()
    assert len(cells) == 15
    assert len(cells) == len({c.rate_hz for c in cells}) * len(
        {c.attestation for c in cells})


def test_matrix_ids_unique_and_deterministic():
    a, b = e5_cells(), e5_cells()
    assert [c.cell_id for c in a] == [c.cell_id for c in b]
    assert len({c.cell_id for c in a}) == 15


def test_every_cell_carries_systems_and_anchor():
    for c in e5_cells():
        assert c.system_ids, c.cell_id
        assert c.anchor_id == "S0", c.cell_id
        assert "S5" in c.system_ids, c.cell_id


# ---- B-52.4 item 2: pre-registration ----
def _design():
    return (("level", "Tpq", "Ta", "Nb", "conn", "rate"), (2, 2, 2, 2, 2, 2), 4, (("level*Tpq",),))


def test_freeze_yields_hex_hash_and_verifies():
    f, lv, res, alias = _design()
    r = register_e6(f, lv, res, alias, "a" * 64)
    assert len(r) == 64 and int(r, 16) >= 0


def test_identical_designs_hash_identically():
    f, lv, res, alias = _design()
    a = register_e6(f, lv, res, alias, "b" * 64)
    b = register_e6(f, lv, res, alias, "b" * 64)
    assert a == b


def test_editing_the_design_breaks_verification():
    f, lv, res, alias = _design()
    r = register_e6(f, lv, res, alias, "c" * 64)
    from qcsim import Registration
    live = Registration(f, lv, res, alias)
    live.analysis_script_sha256 = "c" * 64
    live._frozen = r
    assert live.verify()
    live.resolution = 5
    assert not live.verify(), "silent re-freeze is the defect"


def test_analysis_script_hash_participates():
    f, lv, res, alias = _design()
    a = register_e6(f, lv, res, alias, "d" * 64)
    b = register_e6(f, lv, res, alias, "e" * 64)
    assert a != b, "script hash must change the registration"


def test_unfrozen_registration_refused():
    from qcsim import Registration
    f, lv, res, alias = _design()
    with pytest.raises(CampaignError):
        Registration(f, lv, res, alias).verify()


def test_underpowered_design_refused_naming_the_floor():
    with pytest.raises(CampaignError) as e:
        register_e6(("level",), (2,), 3, (), "f" * 64)
    assert "floor" in str(e.value)


def test_center_points_are_in_the_run_count():
    """B-52.3: 2^(6-p) + CENTER POINTS."""
    six = (2, 2, 2, 2, 2, 2)
    assert run_count(4, six) == 2 ** 3 + 6
    assert run_count(4, six, include_center_points=False) == 2 ** 3


# ---- B-52.4 item 3: discipline ----
def test_calibration_only_admitted_positive_control():
    """The gate must not pass by refusing everything."""
    assert check_split(_traces(split="calibration"), "tuning") is True


def test_tuning_on_holdout_refused_naming_the_trace():
    ts = _traces(2, "holdout")
    with pytest.raises(CampaignError) as e:
        check_split(ts, "tuning")
    assert "0" in str(e.value) and "hold-out" in str(e.value)


def test_unrecorded_split_refused_never_assumed():
    ts = [T(0, None)]
    with pytest.raises(CampaignError):
        check_split(ts, "tuning")


def test_holdout_mode_sees_both():
    ts = _traces(2, "calibration") + _traces(2, "holdout")
    assert check_split(ts, "holdout") is True


def test_empty_admission_refused():
    with pytest.raises(CampaignError):
        check_split([], "tuning")


# ---- B-52.4 item 4: H3 ----
def test_h3_comparator_is_s1():
    assert h3_comparator(["S0", "S1", "S5"]) == "S1"


def test_campaign_without_s1_refused_naming_s0():
    with pytest.raises(CampaignError) as e:
        h3_comparator(["S0", "S5"])
    assert "S0" in str(e.value) and "never the comparator" in str(e.value)


def test_s0_is_not_the_comparator_constant():
    from qcsim import campaign
    assert campaign.H3_NEVER_COMPARATOR != campaign.H3_COMPARATOR


# ---- manifest + model pin ----
def _manifest():
    return CampaignManifest(model_pin="m1", assumption_log_version="v1",
                            code_hash="c" * 8, gate_preflight="g-1")


def test_manifest_records_fields():
    m = _manifest()
    d = m.as_dict()
    for k in ("model_pin", "assumption_log_version", "code_hash",
              "gate_preflight", "rows"):
        assert k in d, k


def test_mid_campaign_pin_change_invalidates():
    """B-52.3: restart with a new pin, never change mid-campaign."""
    m = _manifest()
    m.add_row({"cell_id": "e5-x"})
    with pytest.raises(ModelPinChanged):
        m.set_model_pin("m2")


def test_pin_change_before_rows_is_allowed():
    m = _manifest()
    m.set_model_pin("m2")
    assert m.model_pin == "m2"