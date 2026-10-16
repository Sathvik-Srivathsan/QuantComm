"""B-50.5 gate self-tests: prove the gate actually goes RED.

These are the three self-tests B-50.5 mandates. Each plants EXACTLY ONE
failure and asserts the WHOLE gate is red, not merely that the failure was
"reported".

WHAT IS COVERED HERE (runs anywhere, no toolchain needed):
the gate's DECISION LOGIC. Each test drives the production `verdict_from`
rule over a results mapping built from the production `E0_SET` constant,
with one entry flipped to False (the fourth test below instead drives the
empty set). If the rule stopped failing on a red, or started passing on an
empty set, these fail - verified in BOTH directions by the positive
control.

WHAT IS NOT COVERED ANYWHERE YET (named, not papered over):
B-50.5's negative half - that a corrupted VECTOR actually makes the
gating ctest red, that a broken CROSS-CHECK actually disagrees, and that a
poisoned entropy source actually trips the health primitive in a CI run -
and the BOOT-HALT leg (a poisoned source must halt the run before any
experiment is admitted, not merely redden a unit test).
Those need fault injection into the C suite or a mutated fixture tree.
There is NO fault-injection step in .github/workflows/ci.yml: the `c` job
runs the pristine vectors. (The entropy-health PRIMITIVE's own poison
cases ARE covered by tests/c/test_entropy_health.c, which asserts a
specific rc per poisoned shape - though two shapes deliberately share the
ones-skew rc, since all-zero trips the ones test first. What is missing
is the end-to-end vector-corruption and boot-halt legs.) This is an open
B-50.5 gap, tracked as such.

No repo vector, KAT, or fixture is touched by these tests: the planted
failure lives entirely in the mapping handed to the verdict rule, so a red
here can never poison a future real run.
"""

import importlib.util
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def _load_gate():
    spec = importlib.util.spec_from_file_location(
        "e0_gate_selftests", REPO / "tools" / "e0_gate.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["e0_gate_selftests"] = mod
    spec.loader.exec_module(mod)
    return mod


gate = _load_gate()


def _all_pass():
    """The real gated set, all passing, from the production constant."""
    return {n: True for ps in gate.E0_SET for n in ps.tests}


def _plant(results, name):
    """Flip one gated test to False, refusing anything not actually gated.

    Without the membership check, naming a test that is no longer in
    E0_SET would ADD a phantom key. `verdict_from` counts a False key but
    never inspects names, so the phantom would be counted and the test
    would pass while proving nothing about any real gated test. That
    vacuity is exactly what this check exists to close.
    """
    assert name in results, (
        f"{name!r} is not in E0_SET; planting it would add a phantom entry "
        f"and the test would pass vacuously. Gated: {sorted(results)}")
    results[name] = False
    return name


def _assert_exactly_one_red(results, planted):
    """Red, short by exactly one, and the shortfall IS the planted failure.

    Note which assertion does the catching: `verdict` and `passed` come
    from verdict_from's return, so they are what detect a rule that stopped
    failing on a red, or that dropped/double-counted an entry. The `falsy`
    check is a test-side PRECONDITION - it confirms this test planted what
    it thinks it planted - and detects nothing about the gate itself.
    """
    verdict, passed, total = gate.verdict_from(results)
    falsy = [k for k, v in results.items() if not v]
    assert falsy == [planted], (
        f"expected exactly one falsy entry ({planted!r}), got {falsy}")
    assert verdict == "fail", f"gate read {verdict!r}, expected fail"
    assert passed == total - 1, (
        f"expected exactly the planted failure to be lost ({total - 1}/"
        f"{total}), got {passed}/{total}")


def _control_is_green():
    """Positive control: the untouched gate is green.

    Without this, a rule hardcoded to always return "fail" would satisfy
    every mutation assertion below.
    """
    results = _all_pass()
    verdict, passed, total = gate.verdict_from(results)
    assert verdict == "pass", f"control read {verdict!r}, expected pass"
    assert passed == total and total > 0
    return results


# --- 1. mutate-one-vector -> red ------------------------------------------

def test_mutate_one_vector_reddens_gate():
    """One red vector test must redden the whole gate.

    No single gated test is privileged: the gate is a conjunction, so any
    member going red fails it. The cross-check and entropy cases below use
    different planted names, so together the three pin that NONE OF THOSE
    THREE names is special-cased in the verdict rule. (The other eight
    gated names are covered by the wider parameterisation in
    test_e0_gate.py, not by this file.)
    """
    results = _control_is_green()
    _assert_exactly_one_red(results, _plant(results, "c_sha256"))


# --- 2. break-one-cross-check -> red --------------------------------------

def test_break_one_cross_check_reddens_gate():
    """A red independent-implementation cross-check must redden the gate.

    Same conjunction as above, planted on the cross-check name. This is
    deliberately NOT claiming a separate, stricter code path exists for it:
    `verdict_from` treats every gated name identically, and that uniformity
    is itself part of what these tests pin.
    """
    results = _control_is_green()
    _assert_exactly_one_red(results, _plant(results, "c_xcheck"))


# --- 3. poison-RNG-health -> red -----------------------------------------

def test_poison_rng_health_reddens_gate():
    """A red entropy-health test must redden the gate.

    Poor entropy health is a stop condition in substance (the KATs are
    meaningless on a starved RNG), but mechanically it reaches the verdict
    through the same conjunction as everything else. Planted on its own
    name so a name-special-cased verdict rule cannot pass all three.
    """
    results = _control_is_green()
    _assert_exactly_one_red(results, _plant(results, "c_entropy_health"))


# --- 4. empty is not green -----------------------------------------------

def test_empty_result_set_is_not_green():
    """Zero tests must never read as a pass.

    The vacuous-pass hole: `all()` over nothing is True, so an emptied or
    mis-scoped E0_SET would otherwise report green and let campaigns run
    against nothing. (Kept here alongside the planted-failure tests rather
    than only in test_e0_gate.py so the four decision-logic rules live in
    one place.)
    """
    verdict, passed, total = gate.verdict_from({})
    assert verdict == "fail", f"empty set read {verdict!r}; must be fail"
    assert passed == 0 and total == 0