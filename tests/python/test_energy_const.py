"""KEM size cross-check: core/qc_energy.c hardcodes FIPS 203 |ek|+2|ct|
rows for Ehs (linking the backend lib into the energy test just for
constants would drag PQC codegen into a pure-arithmetic TU). This test
fails the suite if the two sources diverge — the duplication is guarded,
not silent. Deterministic, no vectors needed.
"""
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def _kem_h(name):
    text = (REPO / "crypto" / "qc_kem.h").read_text()
    m = re.search(r"#define\s+" + name + r"\s+(\d+)", text)
    assert m, f"define {name} missing in qc_kem.h"
    return int(m.group(1))


def test_energy_kem_sizes_match_adapter():
    src = (REPO / "core" / "qc_energy.c").read_text()
    rows = re.findall(
        r"\{\s*(\d+),\s*(\d+)\s*\},?\s*/\*", src
    )
    assert len(rows) == 3, f"expected 3 KEM_SIZES rows, found {len(rows)}"
    for (pk, ct), lvl in zip(rows, (512, 768, 1024)):
        assert int(pk) == _kem_h(f"QC_KEM{lvl}_PK_BYTES"), lvl
        assert int(ct) == _kem_h(f"QC_KEM{lvl}_CT_BYTES"), lvl
    # And the air-term identity the model relies on.
    assert int(rows[0][0]) + 2 * int(rows[0][1]) == 2336
    assert int(rows[1][0]) + 2 * int(rows[1][1]) == 3360
    assert int(rows[2][0]) + 2 * int(rows[2][1]) == 4704
