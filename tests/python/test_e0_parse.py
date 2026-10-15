"""ctest output-parsing tests.

These exist because the gate's inventory parser silently dropped test names
on some ctest builds and the failure surfaced three layers away (the gate
reporting missing tests it had never actually parsed). The parser is a pure
function precisely so it can be pinned here without ctest installed.

Fixtures are shaped from real `ctest -N` output, including the variants
that broke the previous implementation: ANSI colourisation, leading
whitespace, and padded/dotted names.
"""
import importlib.util
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def _load_gate():
    spec = importlib.util.spec_from_file_location(
        "e0_gate_parse", REPO / "tools" / "e0_gate.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["e0_gate_parse"] = mod
    spec.loader.exec_module(mod)
    return mod


gate = _load_gate()

PLAIN = """Test project /home/runner/work/QuantComm
  Test #1: c_smoke
  Test #2: c_sha256
  Test #3: c_rng
  Test #4: c_hmac
  Test #5: c_hkdf

Total Tests: 5
"""

PADDED = """Test project /x
  Test  #1: c_smoke ................
  Test  #2: c_sha256

Total Tests: 2
"""

COLORISED = (
    "Test project /x\n"
    "  \x1b[1mTest #1\x1b[0m: c_smoke\n"
    "  \x1b[1mTest #2\x1b[0m: c_sha256\n"
    "\nTotal Tests: 2\n"
)


def test_plain_output_parses():
    assert gate.parse_inventory(PLAIN) == [
        "c_smoke", "c_sha256", "c_rng", "c_hmac", "c_hkdf"]


def test_padded_dotted_names_parse():
    """The old parser took split()[0] after ':' and was fragile to padding;
    the regex takes the token itself."""
    assert gate.parse_inventory(PADDED) == ["c_smoke", "c_sha256"]


def test_colourised_output_parses():
    assert gate.parse_inventory(COLORISED) == ["c_smoke", "c_sha256"]


def test_empty_output_is_empty_not_an_error():
    assert gate.parse_inventory("") == []
    assert gate.parse_inventory("no tests here") == []


def test_total_line_is_not_mistaken_for_a_test():
    out = "  Test #1: c_smoke\n\nTotal Tests: 1\n"
    assert gate.parse_inventory(out) == ["c_smoke"]


def test_every_gated_name_survives_a_realistic_inventory():
    """End-to-end shape check: build a synthetic inventory containing every
    gated test (in the order CMakeLists registers them) and confirm the
    E0 set resolves against it with nothing missing."""
    gated = [n for ps in gate.E0_SET for n in ps.tests]
    out = "Test project /x\n" + "".join(
        f"  Test #{i + 1}: {name}\n" for i, name in enumerate(gated))
    parsed = gate.parse_inventory(out)
    assert parsed == gated
    missing = [n for n in gated if n not in parsed]
    assert missing == []
