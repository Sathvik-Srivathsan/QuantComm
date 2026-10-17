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

Both shapes are modelled now so B-10.6/B-11.6 conform instead of
reinventing a schema when they land.
"""

SCHEMA_VERSION = 1

FORMS = ("pending-harness", "per-test", "per-vector")

PER_TEST_FIELDS = {
    "schema_version": int,
    "test_name": str,
    "level": (str, type(None)),
    "vector_count": int,
    "pass_count": int,
    "fail_count": int,
    "duration_s": (float, type(None)),
}

PER_VECTOR_FIELDS = {
    "schema_version": int,
    "vector_id": str,
    "level": (str, type(None)),
    "passed": bool,
    "input_sha256": (str, type(None)),
    "output_sha256": (str, type(None)),
}

REQUIRED = ("per-test", "per-vector")


class SchemaError(Exception):
    """Hard refusal. Unknown keys are refused, never ignored."""


def fields_for(form):
    if form == "per-test":
        return PER_TEST_FIELDS
    if form == "per-vector":
        return PER_VECTOR_FIELDS
    raise SchemaError("unknown form %r (have %s)" % (form, FORMS))


def validate(record, form):
    """Validate one record against its form. Unknown keys REFUSED."""
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
        if not isinstance(record[k], t):
            raise SchemaError("field %r expected %s, got %s"
                              % (k, t, type(record[k]).__name__))
    if record["schema_version"] != SCHEMA_VERSION:
        raise SchemaError("schema_version %r != %r"
                          % (record["schema_version"], SCHEMA_VERSION))
    if form == "per-test":
        if record["pass_count"] + record["fail_count"] != \
                record["vector_count"]:
            raise SchemaError("pass+fail != vector_count in %r"
                              % record["test_name"])
    else:
        if not record["vector_id"]:
            raise SchemaError("empty vector_id")
    return True


def validate_set(records, form):
    """Validate a whole record set; returns the count."""
    if not records:
        raise SchemaError("empty record set for form %r" % form)
    for r in records:
        validate(r, form)
    return len(records)


def per_test_from_junit(case):
    """Build a per-test record from ONE CTest JUnit <testcase>.

    This is the non-invasive signal: it already exists in CTest's
    machine-readable output and is parsed by tools/e0_gate.py, so no
    test loop body is touched.
    """
    name = case.get("name")
    if not name:
        raise SchemaError("junit case has no name")
    failures = case.get("failures") or 0
    errors = case.get("errors") or 0
    bad = failures + errors
    tc = case.get("tests") or 1
    return {"schema_version": SCHEMA_VERSION, "test_name": name,
            "level": None, "vector_count": int(tc),
            "pass_count": int(tc) - int(bad), "fail_count": int(bad),
            "duration_s": case.get("time")}


def monotonic_run_id(exp, run_id):
    """G5: re-runs NEVER overwrite; IDs are monotonic per experiment."""
    for v in (exp, run_id):
        if "/" in str(v) or str(v) in ("", ".", ".."):
            raise SchemaError("unsafe component %r" % v)
    try:
        n = int(str(run_id).split("-")[-1])
    except (ValueError, IndexError):
        raise SchemaError("run id %r is not monotonic (expected "
                          "<exp>-NNNN)" % run_id)
    if n < 1:
        raise SchemaError("run id %r must be >= 1" % run_id)
    return "%s-%04d" % (exp, n)