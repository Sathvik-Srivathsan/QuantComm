"""Import-time determinism guard (B-43.1): banned-call enforcement in code.

The grep CI gate runs per-push; THIS runs per-import, so a violation
fails at the earliest possible moment (test collection, sim startup)
instead of waiting for CI. Same banned set as ci.yml, kept in sync by
the guard's own unit test (which asserts the pattern lists match the
documented CI patterns — update both together or the test fails).

Mechanism: line scan over the package's own *.py files. Per file,
strip quoted spans whole-text (so docstrings and string literals
never trip it), cut # comments, then match statement prefixes. The
seeder call is counted (not prefix-matched) and must appear exactly
once package-wide (the streams seeder); anything else is a violation.
"""
from pathlib import Path

_MODULES = ("time", "datetime", "threading", "random")
# Patterns are COMPOSED (never literal) so this guard's own source
# cannot trip either this scan or the CI grep, which are plain text.
BANNED_PREFIXES = tuple([f"import {m}" for m in _MODULES] +
                        [f"from {m} import" for m in _MODULES])

# CI grep patterns this mirrors (ci.yml sim banned-call scan): keep in
# sync — test_guard_matches_ci_documents this pairing.
CI_PATTERNS = (f"import {m}" for m in _MODULES)

_URAND = "os." + "urandom" + "("
URANDOM_TOKEN = _URAND


def _strip_source(text):
    """Drop quoted spans over the whole text (triple quotes span lines).

    Single-line stripping cannot cover multi-line docstrings (this
    module's own docstring is the regression case): strip first,
    then cut # comments per line in scan_source.
    """
    out = []
    i, n = 0, len(text)
    while i < n:
        if text.startswith('"""', i) or text.startswith("'''", i):
            q = text[i:i + 3]
            j = text.find(q, i + 3)
            i = n if j < 0 else j + 3
        elif text[i] in ("'", '"'):
            c = text[i]
            i += 1
            while i < n and text[i] != c and text[i] != "\n":
                if text[i] == "\\":
                    i += 1
                i += 1
            if i < n and text[i] == c:
                i += 1
        else:
            out.append(text[i])
            i += 1
    return "".join(out)


def scan_source(text):
    """Returns (banned_hits, seeder_count) for one source text."""
    code = _strip_source(text)
    banned, ur = 0, 0
    for line in code.splitlines():
        bare = line.split("#", 1)[0].strip()
        if any(bare.startswith(p) for p in BANNED_PREFIXES):
            banned += 1
        ur += bare.count(URANDOM_TOKEN)
    return banned, ur


def check_package(pkg_dir):
    """Scan every *.py under pkg_dir. Raises ImportError on violation."""
    banned, ur = 0, 0
    for path in sorted(Path(pkg_dir).glob("*.py")):
        b, u = scan_source(path.read_text(encoding="utf-8"))
        banned += b
        ur += u
    if banned:
        raise ImportError(
            f"qcsim determinism guard: {banned} banned import(s)")
    if ur != 1:
        raise ImportError(
            f"qcsim determinism guard: seeder x{ur}, want exactly 1")
    return True
