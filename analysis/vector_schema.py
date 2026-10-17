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

# "pending-harness" is a MARKER the manifest carries while the per-vector
# harness does not exist yet -- it is not a record shape. Listing it in FORMS
# invited a caller to iterate FORMS and call fields_for("pending-harness"),
# which raises. Forms are the things that HAVE a field table.
FORMS = ("per-test", "per-vector")

PER_TEST_FIELDS = {
    "schema_version": int,
    "test_name": str,
    "level": (str, type(None)),
    "vector_count": int,
    "pass_count": int,
    "fail_count": int,
    "duration_s": (int, float, type(None)),
    # Provenance stamped by the E0 gate on each retained record. The writer
    # emits these; without them here validate() rejects every row it writes.
    "gate_commit": (str, type(None)),
    "gate_id": (str, type(None)),
}

PER_VECTOR_FIELDS = {
    "schema_version": int,
    "vector_id": str,
    "level": (str, type(None)),
    "passed": bool,
    "input_sha256": (str, type(None)),
    "output_sha256": (str, type(None)),
    # Provenance stamped by the E0 gate on each retained record.
    "gate_commit": (str, type(None)),
    "gate_id": (str, type(None)),
}

_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")


def _runnum_re(exp):
    """Matches `<exp>-NNNN` for THIS experiment.

    The previous fixed pattern (`^[A-Za-z0-9]+-(\\d{1,8})$`) could not
    re-parse this function's own output for any experiment whose name
    contains '-' or '.', so 'B-54-00000001' was refused as malformed and
    round-tripping the emitted id through `previous=` was impossible.
    `\\Z` (not `$`) so a trailing newline cannot slip through.
    """
    return re.compile(re.escape(exp) + r"-(\d{1,8})\Z")


class SchemaError(Exception):
    """Hard refusal. The ONLY exception this module raises."""


def fields_for(form):
    """Field table for a form. Returns a COPY: handing out the live table let
    any caller add or delete a field and silently change validate() for the
    whole process, poisoning a published contract."""
    if form == "per-test":
        return dict(PER_TEST_FIELDS)
    if form == "per-vector":
        return dict(PER_VECTOR_FIELDS)
    raise SchemaError("unknown form %r (have %s)" % (form, FORMS))


def _safe(v):
    """repr() that cannot itself raise.

    Refusal messages format the offending value, and formatting an int with
    more than ~4300 digits raises ValueError under CPython's int->str limit --
    so a malformed huge integer escaped the module's SchemaError contract as a
    ValueError. Message paths use this instead of bare repr().
    """
    try:
        out = repr(v)
    except Exception:                                   # noqa: BLE001
        try:
            return "<%s with %d bits>" % (type(v).__name__, v.bit_length())
        except Exception:                               # noqa: BLE001
            return "<unrepresentable %s>" % type(v).__name__
    return out if len(out) <= 200 else out[:200] + "...<%d chars>" % len(out)


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
    # key=_safe: unknown keys of MIXED types (5 and "zzz") made the bare sort
    # raise TypeError, which escaped this module's SchemaError-only contract
    # AND the consumer's `except SchemaError`. str() alone was not enough --
    # str() on a >4300-digit int raises ValueError, so the sort key itself
    # must be the non-raising formatter.
    unknown = sorted(keys - set(spec), key=_safe)
    if unknown:
        raise SchemaError("unknown key(s) %s for form %s"
                          % ([_safe(u) for u in unknown], form))
    missing = sorted(k for k in spec if k not in keys)
    if missing:
        raise SchemaError("missing key(s) %s for form %s" % (missing, form))
    for k, t in spec.items():
        _check_type(k, record[k], t)
    if record["schema_version"] != SCHEMA_VERSION \
            or isinstance(record["schema_version"], bool):
        raise SchemaError("schema_version %s != %s"
                          % (_safe(record["schema_version"]),
                             _safe(SCHEMA_VERSION)))
    if form == "per-test":
        tn = record["test_name"]
        if not isinstance(tn, str) or not tn.strip():
            raise SchemaError("empty test_name")
        if (len(tn) > 128 or any(ord(c) < 32 for c in tn)
                or "/" in tn or "\\" in tn or tn != tn.strip()
                or tn in (".", "..") or ":" in tn):
            raise SchemaError("unsafe test_name %r" % tn)
        lvl = record["level"]
        if lvl is not None:
            if not isinstance(lvl, str) or not lvl.strip() or len(lvl) > 64:
                raise SchemaError("unsafe level %r" % lvl)
            if any(ord(c) < 32 for c in lvl) or "/" in lvl or "\\" in lvl \
                    or ":" in lvl or lvl != lvl.strip() \
                    or lvl in (".", ".."):
                raise SchemaError("unsafe level %s" % _safe(lvl))
        vc, pc, fc = (record["vector_count"], record["pass_count"],
                      record["fail_count"])
        for n in (vc, pc, fc):
            if n < 0:
                raise SchemaError("negative count in %s"
                                  % _safe(record["test_name"]))
        if vc < 1:
            raise SchemaError("vector_count must be >= 1 in %s"
                              % _safe(record["test_name"]))
        if pc + fc != vc:
            raise SchemaError("pass+fail != vector_count in %s"
                              % _safe(record["test_name"]))
        d = record["duration_s"]
        # bool is a subclass of int, so True would otherwise read as 1.0s.
        if isinstance(d, bool):
            raise SchemaError("duration_s must not be bool")
        # NaN check (d != d), then both infinities: +inf passes d < 0 and
        # d != d, so the original test silently accepted it.
        if d is not None and (d != d or d in (float("inf"), float("-inf"))
                               or d < 0):
            raise SchemaError("duration_s must be finite and >= 0")
    else:
        vid = record["vector_id"]
        if not vid.strip():
            raise SchemaError("empty vector_id")
        if (len(vid) > 128 or any(ord(c) < 32 for c in vid)
                or "/" in vid or "\\" in vid or vid != vid.strip()
                or vid in (".", "..") or ":" in vid):
            raise SchemaError("unsafe vector_id %s" % _safe(vid))
        for h in ("input_sha256", "output_sha256"):
            v = record[h]
            if v is not None and not _SHA256_RE.match(v):
                raise SchemaError("%s is not a lowercase hex sha256: %s"
                                  % (h, _safe(v)))
        # level: the per-test branch screens this because a level can reach a
        # path or a log line. The per-vector branch did not read it at all, so
        # "../../evil" and control characters were accepted here.
        lvl = record["level"]
        if lvl is not None:
            if not isinstance(lvl, str) or not lvl.strip() or len(lvl) > 64:
                raise SchemaError("unsafe level %s" % _safe(lvl))
            if any(ord(c) < 32 for c in lvl) or "/" in lvl or "\\" in lvl \
                    or ":" in lvl or lvl != lvl.strip() \
                    or lvl in (".", ".."):
                raise SchemaError("unsafe level %s" % _safe(lvl))
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


def per_test_from_junit(case, gate_commit=None, gate_id=None):
    """Build a per-test record from ONE CTest JUnit <testcase> mapping.

    The producer is tools/e0_gate.parse_junit_cases. CTest writes counts
    ONLY on <testsuite> (never on <testcase>), so the counts arrive under
    case["suite"]. Reading case["tests"] directly -- as an earlier version
    of this function did -- sees None for every real case, because CMake
    writes exactly four attributes on a testcase: name, classname, time,
    status (Source/CTest/cmCTestTestHandler.cxx:2758-2806).

    Fail-closed (B-50.5), on three separate axes:
      * a case that never RAN (status != "run" -- INCLUDING a missing
        status, or a <skipped> child) is not a pass -- ctest emits
        status="disabled" with NO child element, so a child-element check
        alone scores a disabled test as passed;
      * a case with no 'failed' outcome is refused, never defaulted to a
        pass -- absence of an outcome is not a pass;
      * a non-bool 'failed' is refused rather than coerced by truthiness.
    """
    if not isinstance(case, dict):
        raise SchemaError("junit case must be a mapping")
    name = case.get("name")
    if not isinstance(name, str) or not name.strip():
        raise SchemaError("junit case has no usable name")

    # require, not accept: an ABSENT status is not an explicit "it ran", and
    # `status is not None and status != "run"` let a case with no status at
    # all reach the pass path below (verified by hand-built case dicts).
    status = case.get("status")
    # The status and skipped checks are NOT nested inside a `ran` guard.
    # A caller that sets ran=True before examining the children would
    # otherwise skip the entire fail-closed path -- verified exploitable
    # by hand-built case dicts, which is how every test constructs one.
    #
    # "run" and "fail" both mean the test EXECUTED (CMake emits status="fail"
    # for a failed test); the outcome is carried by `failed` below. Accepting
    # only "run" made every real ctest failure unrepresentable here, so all
    # red runs fell back to the minimal row and this shape was never used.
    if status not in ("run", "fail"):
        raise SchemaError(
            "junit case %s has status=%s, not 'run'; a test that did not "
            "run is not a pass" % (_safe(name), _safe(status)))
    if case.get("skipped"):
        raise SchemaError("junit case %r is SKIPPED; a skip is not a pass"
                          % name)
    if case.get("ran") is not True:
        raise SchemaError("junit case %r does not assert that it ran" % name)

    # PER-TEST semantics: the unit of this record IS the testcase, so the
    # counts are the test's own outcome. CTest's <testsuite> counts are
    # RUN-level aggregates (tests=N failures=F over the whole suite) and
    # are NOT per-testcase -- attributing them to an individual case
    # would invent per-test numbers that ctest never reported.
    #
    # `failed` must be PRESENT and a real bool. Defaulting a missing key to
    # False scored "no evidence" as a pass, so a case dict that omitted it
    # published a full pass for a test whose outcome was never reported.
    if "failed" not in case:
        raise SchemaError("junit case %s has no 'failed' outcome; absence "
                          "of an outcome is not a pass" % _safe(name))
    raw_failed = case["failed"]
    if not isinstance(raw_failed, bool):
        raise SchemaError("junit case %s: 'failed' must be bool, got %s"
                          % (_safe(name), type(raw_failed).__name__))
    failed = raw_failed
    total, bad = 1, (1 if failed else 0)
    t = case.get("time")
    duration = None
    if t is not None:
        if isinstance(t, bool):
            raise SchemaError("time bool for %s" % _safe(name))
        try:
            duration = float(t)
        except (TypeError, ValueError, OverflowError) as exc:
            # OverflowError: float() on a huge int raises it, and it is
            # neither TypeError nor ValueError.
            raise SchemaError("time %s is not numeric for %s"
                              % (_safe(t), _safe(name))) from exc
        if duration != duration or duration in (float("inf"),
                                                float("-inf")) or duration < 0:
            raise SchemaError("time must be finite and >= 0 for %r" % name)
    rec = {"schema_version": SCHEMA_VERSION, "test_name": name,
           "level": case.get("classname"), "vector_count": total,
           "pass_count": total - bad, "fail_count": bad,
           "duration_s": duration,
           "gate_commit": gate_commit, "gate_id": gate_id}
    validate(rec, "per-test")
    return rec


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def sha256_file(path):
    """Digest of a file's BYTES, read in chunks (retained JSONL can be large).

    Used to bind a manifest to the artifact it describes: the rows'
    schema-validity says nothing about whether the numbers in them are the
    numbers the gate actually produced.
    """
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def monotonic_run_id(exp, run_id, previous=None):
    """G5: re-runs NEVER overwrite; IDs are monotonic per experiment.

    A run id that already carries a DIFFERENT experiment prefix is
    refused rather than relabelled, and BOTH path separators are
    rejected because this project runs on win32.

    `previous` is the id last issued for this experiment. When supplied,
    the new number MUST be strictly greater -- otherwise this function
    was a pure formatter that could re-issue an existing id, which is
    the overwrite G5 forbids. With no `previous` there is nothing to
    compare against, so the monotonicity half cannot be checked and the
    caller must say so at the call site.
    """
    if not isinstance(exp, str) or not isinstance(run_id, str):
        raise SchemaError("exp and run_id must be strings, got %r/%r"
                          % (type(exp).__name__, type(run_id).__name__))
    for v in (exp, run_id):
        s = str(v)
        # Control characters are screened too: this value is emitted straight
        # into a filesystem path component and a log line, so a newline/tab
        # injected an unscreened byte sequence into both. The docstring claims
        # both separators are rejected because this project runs on win32 --
        # which is exactly why a bare CR is unacceptable in a path.
        if not s or s in (".", "..") or "/" in s or "\\" in s \
                or "\x00" in s or ":" in s \
                or any(ord(c) < 32 for c in s):
            raise SchemaError("unsafe path component %s" % _safe(v))
    exp = str(exp)
    raw = str(run_id)
    m = _runnum_re(exp).match(raw)
    if m:
        n = int(m.group(1))
    elif re.match(r"^\d{1,8}\Z", raw):
        n = int(raw)
    else:
        raise SchemaError("run id %r is not monotonic "
                          "(expected NNNN or <exp>-NNNN)" % raw)
    if n < 1:
        raise SchemaError("run id %r must be >= 1" % raw)
    if previous is not None:
        prior = monotonic_run_id(exp, previous)
        pri_n = int(prior.rsplit("-", 1)[1])
        if n <= pri_n:
            raise SchemaError(
                "run id %r is not monotonic: %r was already issued for %r"
                % (raw, previous, exp))
    return "%s-%08d" % (exp, n)
