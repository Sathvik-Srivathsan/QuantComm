"""B-54 retention record contract: two shapes, one validator.

Spec basis:
  * G5 (:174-177) -- retention is "per-vector (where the harness
    provides it) OR per-test JSONL + run manifest + DOE registration +
    assumption log", all JSON under runs/<exp>/<id>/, kept for project
    lifetime, and a re-run NEVER overwrites a prior version.
  * :240 -- vector_records is a two-valued enum:
    "pending-harness" | "per-vector".

CRITICAL (read from the four accept boxes at :573/:687/:807/:913, all
stated FLAT with no "or" and no cross-reference): the per-vector form
is required for those four gates specifically. It is NOT satisfied by
per-test retention. gate_contract() enforces this by refusing the
placeholder; :973 authorises RECORDING the pending state honestly, not
substituting another form.

Both shapes are modelled so B-10.6/B-11.6 conform instead of
reinventing a schema when they land.

HARDENING NOTES (from a blind audit; each is enforced, not documented):
  * bool is a subclass of int in Python, so every int field excludes
    bool explicitly.
  * CTest/JUnit attributes arrive as STRINGS; they are coerced and
    validated before any arithmetic, never concatenated.
  * a skipped case is NOT a pass (B-50.5 fail-closed).
  * counts must be non-negative and sum to vector_count.
  * run ids reject cross-experiment prefixes and BOTH path separators
    (this project runs on win32).
  * every refusal leaves through SchemaError, never TypeError/ValueError.
"""

import hashlib
import re

SCHEMA_VERSION = 1

FORMS = ("pending-harness", "per-test", "per-vector")

PER_TEST_FIELDS = {
    "schema_version": int,
    "test_name": str,
    "level": (str, type(None)),
    "vector_count": int,
    "pass_count": int,
    "fail_count": int,
    "duration_s": (int, float, type(None)),
}

PER_VECTOR_FIELDS = {
    "schema_version": int,
    "vector_id": str,
    "level": (str, type(None)),
    "passed": bool,
    "input_sha256": (str, type(None)),
    "output_sha256": (str, type(None)),
}

_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_RUNNUM_RE = re.compile(r"^[A-Za-z0-9]+-(\d{1,8})$")


class SchemaError(Exception):
    """Hard refusal. The ONLY exception this module raises."""


def fields_for(form):
    if form == "per-test":
        return PER_TEST_FIELDS
    if form == "per-vector":
        return PER_VECTOR_FIELDS
    raise SchemaError("unknown form %r (have %s)" % (form, FORMS))


def _check_type(name, value, spec):
    """isinstance, but bool is never accepted for an int field."""
    flat = spec if isinstance(spec, tuple) else (spec,)
    if isinstance(value, bool) and int in flat and float not in flat:
        raise SchemaError("field %r expected int, got bool" % name)
    if not isinstance(value, spec):
        raise SchemaError("field %r expected %s, got %s"
                          % (name, spec, type(value).__name__))


def validate(record, form):
    """Validate one record against its form. Unknown keys REFUSED."""
    if not isinstance(record, dict):
        raise SchemaError("record must be a mapping, got %s"
                          % type(record).__name__)
    spec = fields_for(form)
    keys = set(record)
    unknown = sorted(keys - set(spec))
    if unknown:
        raise SchemaError("unknown key(s) %s for form %r"
                          % (unknown, form))
    missing = sorted(k for k in spec if k not in keys)
    if missing:
        raise SchemaError("missing key(s) %s for form %r" % (missing, form))
    for k, t in spec.items():
        _check_type(k, record[k], t)
    if record["schema_version"] != SCHEMA_VERSION \
            or isinstance(record["schema_version"], bool):
        raise SchemaError("schema_version %r != %r"
                          % (record["schema_version"], SCHEMA_VERSION))
    if form == "per-test":
        vc, pc, fc = (record["vector_count"], record["pass_count"],
                      record["fail_count"])
        for n in (vc, pc, fc):
            if n < 0:
                raise SchemaError("negative count in %r" % record["test_name"])
        if vc < 1:
            raise SchemaError("vector_count must be >= 1 in %r"
                              % record["test_name"])
        if pc + fc != vc:
            raise SchemaError("pass+fail != vector_count in %r"
                              % record["test_name"])
        d = record["duration_s"]
        if d is not None and (d < 0 or d != d):
            raise SchemaError("duration_s must be finite and >= 0")
    else:
        vid = record["vector_id"]
        if not vid.strip():
            raise SchemaError("empty vector_id")
        if (len(vid) > 128 or any(ord(c) < 32 for c in vid)
                or "/" in vid or "\\" in vid or vid != vid.strip()):
            raise SchemaError("unsafe vector_id %r" % vid)
        for h in ("input_sha256", "output_sha256"):
            v = record[h]
            if v is not None and not _SHA256_RE.match(v):
                raise SchemaError("%s is not a lowercase hex sha256: %r"
                                  % (h, v))
    return True


def validate_set(records, form):
    """Validate a whole record set; returns the count.

    Requires a concrete sized collection and unique ids -- a set that
    repeats one vector can otherwise pad itself to N.
    """
    if isinstance(records, (str, bytes, dict, set, frozenset)) or not hasattr(records, "__len__"):
        raise SchemaError("record set must be a sized collection, got %s"
                          % type(records).__name__)
    if len(records) == 0:
        raise SchemaError("empty record set for form %r" % form)
    seen = set()
    for r in records:
        validate(r, form)
        key = (r["test_name"] if form == "per-test" else r["vector_id"])
        if key in seen or key.lower() in seen:
            raise SchemaError("duplicate record id %r in %r set"
                              % (key, form))
        seen.add(key)
        seen.add(key.lower())
    return len(records)


def _count(value, field, case_name):
    """JUnit attributes are STRINGS; coerce strictly, never concatenate."""
    if value is None:
        return 0
    if isinstance(value, bool):
        raise SchemaError("%s bool for %r" % (field, case_name))
    if isinstance(value, int):
        n = value
    elif isinstance(value, str):
        s = value.strip()
        if not s:
            return 0
        if not re.match(r"^\d+$", s):
            raise SchemaError("%s %r is not a non-negative integer (%r)"
                              % (field, case_name, value))
        n = int(s)
    elif isinstance(value, float):
        if value != int(value):
            raise SchemaError("%s %r is fractional" % (field, value))
        n = int(value)
    else:
        raise SchemaError("%s has unsupported type %s"
                          % (field, type(value).__name__))
    if n < 0:
        raise SchemaError("%s negative for %r" % (field, case_name))
    return n


def per_test_from_junit(case):
    """Build a per-test record from ONE CTest JUnit <testcase>.

    The signal already exists in CTest's machine-readable output and is
    parsed by tools/e0_gate.py, so no test loop body is touched.

    Fail-closed (B-50.5): a SKIPPED case is NOT a pass, and a case with
    no counts at all is refused rather than defaulted to a pass.
    """
    if not isinstance(case, dict):
        raise SchemaError("junit case must be a mapping")
    name = case.get("name")
    if not isinstance(name, str) or not name.strip():
        raise SchemaError("junit case has no usable name")
    skipped = case.get("skipped")
    if isinstance(skipped, str) and skipped.strip() in ("", "0", "false", "False"):
        skipped = 0
    if skipped:
        raise SchemaError("junit case %r is SKIPPED; a skip is not a pass"
                          % name)
    if "tests" not in case and "failures" not in case \
            and "errors" not in case:
        raise SchemaError("junit case %r carries no counts" % name)
    failures = _count(case.get("failures"), "failures", name)
    errors = _count(case.get("errors"), "errors", name)
    total = _count(case.get("tests"), "tests", name)
    bad = failures + errors
    if total < 1:
        raise SchemaError("junit case %r executed zero vectors" % name)
    if bad > total:
        raise SchemaError("junit case %r: failures+errors (%d) exceed "
                          "tests (%d)" % (name, bad, total))
    t = case.get("time")
    duration = None
    if t is not None:
        if isinstance(t, bool):
            raise SchemaError("time bool for %r" % name)
        try:
            duration = float(t)
        except (TypeError, ValueError):
            raise SchemaError("time %r is not numeric for %r" % (t, name))
        if duration != duration or duration < 0:
            raise SchemaError("time must be finite and >= 0 for %r" % name)
    rec = {"schema_version": SCHEMA_VERSION, "test_name": name,
           "level": None, "vector_count": total, "pass_count": total - bad,
           "fail_count": bad, "duration_s": duration}
    validate(rec, "per-test")
    return rec


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def monotonic_run_id(exp, run_id):
    """G5: re-runs NEVER overwrite; IDs are monotonic per experiment.

    A run id that already carries a DIFFERENT experiment prefix is
    refused rather than relabelled, and BOTH path separators are
    rejected because this project runs on win32.
    """
    for v in (exp, run_id):
        s = str(v)
        if not s or s in (".", "..") or "/" in s or "\\" in s \
                or "\x00" in s or ":" in s:
            raise SchemaError("unsafe path component %r" % v)
    exp = str(exp)
    raw = str(run_id)
    m = _RUNNUM_RE.match(raw)
    if m:
        prefix, num = raw.rsplit("-", 1)
        if prefix != exp:
            raise SchemaError("run id %r belongs to experiment %r, not %r"
                              % (raw, prefix, exp))
        n = int(num)
    elif re.match(r"^\d{1,8}$", raw):
        n = int(raw)
    else:
        raise SchemaError("run id %r is not monotonic "
                          "(expected NNNN or <exp>-NNNN)" % raw)
    if n < 1:
        raise SchemaError("run id %r must be >= 1" % raw)
    if n > 99999999:
        raise SchemaError("run id %r exceeds the monotonic width" % raw)
    return "%s-%08d" % (exp, n)