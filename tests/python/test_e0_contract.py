"""G10: end-to-end contract tests for the retention artifact.

Every other test in this tree builds its inputs by hand. These drive the
REAL writer (tools/e0_gate.write_records), read the bytes it puts on disk,
and hand them to the REAL consumer (qcsim.gate.preflight). That is the
check whose absence let three CI reds through: write_records was the only
function in its chunk with no executing test, so a change on one side of
the producer/consumer contract could never fail locally.
"""
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tools"))

import e0_gate  # noqa: E402
from analysis import stats as stats  # noqa: E402
from analysis import vector_schema as vs  # noqa: E402
from qcsim import gate as qgate  # noqa: E402

COMMIT = "a" * 40
TS = "2026-10-20T00:00:00Z"


def _report(gate_id, commit=COMMIT, verdict="pass", total=2, passed=2):
    return e0_gate.GateReport(
        commit=commit, verdict=verdict, timestamp=TS, gate_id=gate_id,
        total_tests=total, passed_tests=passed)


def _case(name, failed=False, time="0.42"):
    return {"name": name, "classname": "c", "time": time,
            "status": "run", "ran": True, "failed": failed}


def _read_rows(path):
    return [json.loads(line) for line in
            path.read_text(encoding="utf-8").splitlines() if line.strip()]


# ---- the artifact the writer actually produces -------------------------

def test_written_rows_carry_provenance_and_validate(tmp_path):
    run_dir = tmp_path / "e0"
    gid = qgate.mint_gate_id(COMMIT, "pass", TS)
    jsonl, _ = e0_gate.write_records(
        run_dir, _report(gid, total=2, passed=1), {"c_a": True, "c_b": False})

    rows = _read_rows(jsonl)
    assert len(rows) == 2
    for row in rows:
        assert row["gate_commit"] == COMMIT
        assert row["gate_id"] == gid
        assert vs.validate(row, "per-test") is True


def test_written_rows_from_real_junit_cases_carry_provenance(tmp_path):
    run_dir = tmp_path / "e0"
    gid = qgate.mint_gate_id(COMMIT, "pass", TS)
    cases = {"c_a": _case("c_a"), "c_b": _case("c_b", failed=True, time="0.1")}
    jsonl, _ = e0_gate.write_records(
        run_dir, _report(gid, total=2, passed=1), {"c_a": True, "c_b": False},
        cases)

    rows = {r["test_name"]: r for r in _read_rows(jsonl)}
    assert rows["c_a"]["pass_count"] == 1
    assert rows["c_b"]["fail_count"] == 1
    for row in rows.values():
        assert row["gate_commit"] == COMMIT and row["gate_id"] == gid
        assert vs.validate(row, "per-test") is True


def test_manifest_gate_id_verifies_with_the_consumer(tmp_path):
    """The producer and the consumer must agree on the id's inputs.

    This is the check that would have caught the evidence-folded id: the
    producer minted over commit|verdict:evidence|ts while preflight
    recomputed over commit|verdict|ts, so every real record failed.
    """
    run_dir = tmp_path / "e0"
    gid = qgate.mint_gate_id(COMMIT, "pass", TS)
    _, manifest = e0_gate.write_records(run_dir, _report(gid, total=1, passed=1), {"c_a": True})

    m = json.loads(manifest.read_text(encoding="utf-8"))
    assert m["gate_id"] == gid
    assert qgate.verify_gate_id(m["gate_id"], m["commit"], m["verdict"],
                                m["timestamp"]) is True


def test_second_write_to_same_run_dir_is_refused(tmp_path):
    """G5: a re-run never overwrites a prior gate record."""
    run_dir = tmp_path / "e0"
    gid = qgate.mint_gate_id(COMMIT, "pass", TS)
    e0_gate.write_records(run_dir, _report(gid, total=1, passed=1), {"c_a": True})
    with pytest.raises(RuntimeError, match="refusing to overwrite"):
        e0_gate.write_records(run_dir, _report(gid, total=1, passed=1), {"c_a": True})


# ---- positive control: the assertions above can fail -------------------

def test_stripping_provenance_makes_the_same_row_invalid(tmp_path):
    run_dir = tmp_path / "e0"
    gid = qgate.mint_gate_id(COMMIT, "pass", TS)
    jsonl, _ = e0_gate.write_records(run_dir, _report(gid, total=1, passed=1), {"c_a": True})

    row = _read_rows(jsonl)[0]
    del row["gate_commit"]
    with pytest.raises(vs.SchemaError, match="missing key"):
        vs.validate(row, "per-test")


# ---- the whole seam, writer -> preflight ------------------------------

def _git_repo(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    run = lambda *a: subprocess.run(["git", "-C", str(repo)] + list(a),
                                    capture_output=True, text=True, check=True)
    run("init", "-q")
    run("config", "user.email", "t@example.invalid")
    run("config", "user.name", "t")
    (repo / "f.txt").write_text("x", encoding="utf-8")
    run("add", "f.txt")
    run("commit", "-q", "-m", "init")
    return repo, run("rev-parse", "HEAD").stdout.strip()


def test_preflight_accepts_a_record_the_writer_just_published(tmp_path):
    repo, commit = _git_repo(tmp_path)
    build = tmp_path / "build"
    gid = qgate.mint_gate_id(commit, "pass", TS)

    _, manifest = e0_gate.write_records(
        build / "e0", _report(gid, commit=commit), {"c_a": True, "c_b": True})
    e0_gate._latest_pointer(build, manifest)

    ok, reason = e0_gate.preflight(gid, build, repo)
    assert ok, reason


# ---- a case that never ran must not become an INFRA failure ------------

def test_disabled_case_is_retained_not_fatal(tmp_path):
    """ctest status="disabled" is refused by the schema's fail-closed rule.

    That refusal must not abort the whole write: without a fallback, a run
    containing ONE disabled case wrote NO record at all, so the gate job
    reported INFRA FAILURE instead of the red verdict the run actually had.
    The disabled case is retained as the honest minimal row (failed, no
    duration) and every other case keeps its real per-test record.
    """
    run_dir = tmp_path / "e0"
    gid = qgate.mint_gate_id(COMMIT, "fail", TS)
    disabled = {"name": "c_off", "classname": "c", "time": "0.0",
                "status": "disabled", "ran": False, "failed": True}
    cases = {"c_a": _case("c_a"), "c_off": disabled}
    jsonl, _ = e0_gate.write_records(
        run_dir, _report(gid, verdict="fail", total=2, passed=1), {"c_a": True, "c_off": False},
        cases)

    rows = {r["test_name"]: r for r in _read_rows(jsonl)}
    assert set(rows) == {"c_a", "c_off"}
    # c_a keeps its real per-test record from the JUnit shape
    assert rows["c_a"]["pass_count"] == 1
    # c_off falls back to the minimal row: red, no invented duration
    assert rows["c_off"]["fail_count"] == 1
    assert rows["c_off"]["duration_s"] is None
    for row in rows.values():
        assert vs.validate(row, "per-test") is True
        assert row["gate_id"] == gid


# ---- the manifest binds the artifact it describes ---------------------

def test_manifest_digest_binds_the_retained_jsonl(tmp_path):
    """A shape-valid manifest is not provenance.

    `passed_tests=0` beside `verdict="pass"` used to be accepted, and a
    hand-written record with a recomputable id (the id is over public
    inputs) passed too. The manifest now carries records_sha256 and preflight
    requires the artifact beside it to match.
    """
    run_dir = tmp_path / "e0"
    gid = qgate.mint_gate_id(COMMIT, "pass", TS)
    jsonl, manifest = e0_gate.write_records(
        run_dir, _report(gid, total=2), {"c_a": True, "c_b": True})

    m = json.loads(manifest.read_text(encoding="utf-8"))
    assert m["records_sha256"] == qgate._records_sha256(jsonl)

    # Positive control: touching the artifact breaks the binding.
    with jsonl.open("a", encoding="utf-8") as fh:
        fh.write('{"tampered": true}\n')
    assert qgate._records_sha256(jsonl) != m["records_sha256"]

def test_flaky_record_still_verifies_with_the_consumer(tmp_path, monkeypatch):
    """CRITICAL regression: _evaluate_with_rerun rewrites verdict -> flaky-red.

    The id used to be minted inside evaluate() over verdict="pass" and then
    the stored verdict became "flaky-red", so preflight recomputed over the
    STORED verdict, got a different digest, and refused every flaky record as
    tampered. Bind the id to the verdict that is actually stored.
    """
    repo, commit = _git_repo(tmp_path)
    build = tmp_path / "build"
    calls = []

    class _R:
        pass

    def fake_eval(b, r):
        calls.append(1)
        # Mirror the real evaluate(): it mints over THIS pass's verdict, so
        # the double must too, or the test would not exercise the re-mint.
        v = "fail" if len(calls) == 1 else "pass"
        rep = e0_gate.GateReport(
            commit=commit, verdict=v,
            timestamp=TS, gate_id=qgate.mint_gate_id(commit, v, TS),
            total_tests=1, passed_tests=1 if len(calls) > 1 else 0)
        return rep, {"c_a": len(calls) > 1}, {}

    monkeypatch.setattr(e0_gate, "evaluate", fake_eval)
    report, results, cases = e0_gate._evaluate_with_rerun(build, repo)
    assert report.verdict == "flaky-red"

    _, manifest = e0_gate.write_records(build / "e0", report, results, cases)
    e0_gate._latest_pointer(build, manifest)
    m = json.loads(manifest.read_text(encoding="utf-8"))
    assert qgate.verify_gate_id(m["gate_id"], m["commit"], m["verdict"],
                                m["timestamp"]) is True
    # Positive control: minting over the PRE-rerun verdict reproduces the
    # original defect, so this test can actually fail for its stated reason.
    wrong = qgate.mint_gate_id(m["commit"], "pass", m["timestamp"])
    assert qgate.verify_gate_id(wrong, m["commit"], m["verdict"],
                                m["timestamp"]) is False


def test_evaluate_mints_an_id_its_own_consumer_accepts(tmp_path, monkeypatch):
    """C1: evaluate() must return a record preflight can verify.

    Moving the mint into _evaluate_with_rerun left evaluate() returning an
    empty gate_id, so every direct caller (the documented entry point)
    published a manifest whose id did not recompute -- refused as tampered.
    An empty id also collapsed the run dir onto build/e0/, so a second run
    could not publish at all. This drives the REAL evaluate() and the REAL
    writer, then the REAL consumer: the whole chain, which no test did before.
    """
    repo, commit = _git_repo(tmp_path)
    build = tmp_path / "build"

    class _R:
        pass

    gated = tuple(n for ps in e0_gate.E0_SET for n in ps.tests)
    monkeypatch.setattr(e0_gate, "git_commit", lambda r: commit)
    monkeypatch.setattr(e0_gate, "ctest_inventory", lambda b: list(gated))
    monkeypatch.setattr(e0_gate, "run_tests",
                        lambda b, names: ({n: True for n in names}, {}))

    report, results, cases = e0_gate.evaluate(build, repo)

    assert report.gate_id, "evaluate() returned an empty gate id"
    assert results, "the fake run produced no gated tests"
    run_dir = build / "e0" / report.gate_id
    _, manifest = e0_gate.write_records(run_dir, report, results, cases)
    # preflight reads build/e0/latest-gate.json and e0-gate.jsonl beside it,
    # while write_records writes into the per-run dir. main() publishes the
    # pointer after writing; this test drives the same chain. Note the digest
    # check then reads build/e0/e0-gate.jsonl, which does not exist here --
    # that is the L1 duplicated-filename hazard, tracked separately.
    e0_gate._latest_pointer(build, manifest)
    ok, why = qgate.preflight(report.gate_id, build, repo)
    assert ok is True, why


def test_report_counts_must_agree_with_the_rows_written(tmp_path):
    """H1: a manifest claiming 500/500 beside a one-row artifact.

    preflight's consistency check compares the manifest's own two integers, so
    a mismatch between report counts and the records actually written was
    invisible: the artifact could not support the claim. Refuse at the writer.
    """
    run_dir = tmp_path / "e0"
    gid = qgate.mint_gate_id(COMMIT, "pass", TS)
    with pytest.raises(RuntimeError, match="disagree with the records written"):
        e0_gate.write_records(run_dir, _report(gid, total=500, passed=500),
                              {"c_a": True})


def test_huge_int_refusal_stays_inside_the_schema_error_contract():
    """HIGH-1: refusal messages must not raise while formatting the value.

    repr() of an int over CPython's 4300-digit limit raises ValueError, so a
    malformed huge integer escaped both this module's SchemaError contract and
    the consumer's `except SchemaError`.
    """
    big = 1 << 20000
    for call in (lambda: vs.validate({big: "x"}, "per-vector"),
                 lambda: vs.validate_set([{big: "v"}], "per-vector"),
                 lambda: vs.per_test_from_junit(
                     {"name": "c", "status": "run", "ran": True,
                      "failed": False, "time": big})):
        with pytest.raises(vs.SchemaError):
            call()


def test_bare_dotdot_level_is_refused_like_a_dotdot_vector_id():
    """LOW-7: the level screen rejected '../../evil' but accepted bare '..'."""
    rec = {"schema_version": vs.SCHEMA_VERSION, "vector_id": "v",
           "level": "..", "passed": True, "input_sha256": None,
           "output_sha256": None, "gate_commit": COMMIT, "gate_id": "e0-x"}
    with pytest.raises(vs.SchemaError, match="unsafe level"):
        vs.validate(rec, "per-vector")


def test_control_characters_are_refused_in_a_run_id_path_component():
    """LOW-6: exp/newline reached a filesystem path unscreened."""
    for bad in ("E5\n", "E5\t", "E5\r"):
        with pytest.raises(vs.SchemaError, match="unsafe path component"):
            vs.monotonic_run_id(bad, "1")


def test_pointer_publishes_an_artifact_the_consumer_can_locate(tmp_path,
                                                              monkeypatch):
    """L1: the pointer is a COPY of a manifest whose JSONL lives elsewhere.

    preflight read a hard-coded "e0-gate.jsonl" beside the pointer, but the
    pointer's neighbour is never the artifact (the JSONL sits in the per-run
    directory), so the digest binding was unverifiable for every run-dir
    layout. The manifest now carries records_file.
    """
    repo, commit = _git_repo(tmp_path)
    build = tmp_path / "build"
    gid = qgate.mint_gate_id(commit, "pass", TS)
    run_dir = build / "e0" / gid
    _, manifest = e0_gate.write_records(
        run_dir, _report(gid, commit=commit, total=1, passed=1), {"c_a": True})
    e0_gate._latest_pointer(build, manifest)

    ok, why = qgate.preflight(gid, build, repo)
    assert ok is True, why


def test_artifact_digest_binding_refuses_a_rewritten_jsonl(tmp_path):
    """The digest is the point: a rewritten artifact must not verify."""
    repo, commit = _git_repo(tmp_path)
    build = tmp_path / "build"
    gid = qgate.mint_gate_id(commit, "pass", TS)
    run_dir = build / "e0" / gid
    jsonl, manifest = e0_gate.write_records(
        run_dir, _report(gid, commit=commit, total=1, passed=1), {"c_a": True})
    e0_gate._latest_pointer(build, manifest)
    assert qgate.preflight(gid, build, repo)[0] is True

    jsonl.write_text(jsonl.read_text(encoding="utf-8") + "\n",
                     encoding="utf-8")
    ok, why = qgate.preflight(gid, build, repo)
    assert ok is False and "digest" in why, why


def test_writer_refuses_an_empty_gate_id(tmp_path):
    """A record with no id is unverifiable BY CONSTRUCTION.

    main() guarded this by deriving the run dir from the id, but the writer is
    the shared contract: any direct caller could publish rows with gate_id=""
    and a manifest no consumer can verify.
    """
    gid = qgate.mint_gate_id(COMMIT, "pass", TS)
    rep = _report(gid, total=1, passed=1)
    rep.gate_id = ""
    with pytest.raises(RuntimeError, match="empty gate id"):
        e0_gate.write_records(tmp_path / "e0", rep, {"c_a": True})


def test_preflight_refuses_a_records_dir_outside_the_build_tree(tmp_path):
    """HIGH: an absolute records_dir defeated the artifact binding.

    Path.__truediv__ discards the left operand when the right is absolute, so
    screening records_dir only for ".." let a manifest name ANY file on disk:
    preflight hashed it, compared it to the digest the manifest itself
    carried, and reported the gate green. Resolve-and-confine instead.
    """
    repo, commit = _git_repo(tmp_path)
    build = tmp_path / "build"
    gid = qgate.mint_gate_id(commit, "pass", TS)
    run_dir = build / "e0" / gid
    _, manifest = e0_gate.write_records(
        run_dir, _report(gid, commit=commit, total=1, passed=1), {"c_a": True})
    e0_gate._latest_pointer(build, manifest)
    assert qgate.preflight(gid, build, repo)[0] is True

    outside = tmp_path / "outside"
    outside.mkdir()
    shutil.copy(run_dir / e0_gate.GATE_RECORDS, outside / "anything.jsonl")

    pointer = build / "e0" / "latest-gate.json"
    for value in (str(outside), str(outside).replace("\\", "/"),
                  "../outside", "..", "a/b", "C:/Windows/Temp"):
        body = json.loads(manifest.read_text(encoding="utf-8"))
        body["records_dir"] = value
        body["records_file"] = "anything.jsonl"
        pointer.write_text(json.dumps(body), encoding="utf-8")
        ok, why = qgate.preflight(gid, build, repo)
        assert ok is False, "%r was accepted: %s" % (value, why)


def test_gate_contract_refuses_a_padded_not_required_sentinel():
    """HIGH: "not-required " (trailing space) passed as a VERIFIED gate.

    The sentinel was compared with exact equality while every other manifest
    field is whitespace-normalised, so the one value that means "the gate
    never ran" was the one value a space could smuggle past.
    """
    for sentinel in ("not-required", "not-required ", " not-required",
                     "NOT-REQUIRED", "Not-Required", "\tnot-required"):
        rec = {"schema_version": vs.SCHEMA_VERSION, "vector_id": "v",
               "level": None, "passed": True, "input_sha256": None,
               "output_sha256": None, "gate_commit": COMMIT,
               "gate_id": sentinel.strip().lower()}
        man = {"gate_preflight": sentinel, "model_pin": "m",
               "code_hash": "h", "assumption_log_version": "v1"}
        with pytest.raises(stats.StatsError):
            stats.gate_contract(1, 1, [rec], manifest=man)


def test_real_ctest_failure_shape_is_recorded_as_a_per_test_row(tmp_path):
    """MEDIUM: status="fail" made every real red run use the fallback row.

    CMake emits status="fail" for a failed test. Accepting only status="run"
    as "executed" sent every failure through the minimal fallback, so the
    JUnit-derived shape was produced only for green runs -- the retention
    artifact was degraded for exactly the runs that matter.
    """
    case = {"name": "c_kem", "classname": "c", "time": "0.44",
            "status": "fail", "ran": True, "failed": True, "skipped": False}
    row = vs.per_test_from_junit(case, COMMIT, "e0-x")
    assert row["fail_count"] == 1
    assert row["pass_count"] == 0
    assert row["duration_s"] == 0.44, "real duration must survive"


# ---- the count the manifest claims must be the count the artifact holds ---

def test_preflight_refuses_a_count_the_artifact_cannot_support(tmp_path):
    """CRITICAL: total=12/passed=12 backed by a one-line {"junk": true}.

    The id is over public inputs (commit|verdict|timestamp) and commit must
    equal HEAD, so both are reproducible. The digest only proved the artifact
    was the one the manifest was written from; it never counted rows, so a
    hand-written manifest over a junk file reported the gate green.
    """
    repo, commit = _git_repo(tmp_path)
    build = tmp_path / "build"
    gid = qgate.mint_gate_id(commit, "pass", TS)
    run_dir = build / "e0" / gid
    run_dir.mkdir(parents=True)
    jsonl = run_dir / e0_gate.GATE_RECORDS
    jsonl.write_text('{"junk": true}\n', encoding="utf-8")
    forged = {"commit": commit, "verdict": "pass", "timestamp": TS,
              "gate_id": gid, "total_tests": 12, "passed_tests": 12,
              "gate_preflight": gid,
              "records_sha256": qgate._records_sha256(jsonl),
              "records_file": e0_gate.GATE_RECORDS, "records_dir": gid}
    pointer = build / "e0" / "latest-gate.json"
    pointer.parent.mkdir(parents=True, exist_ok=True)
    pointer.write_text(json.dumps(forged), encoding="utf-8")

    ok, why = qgate.preflight(gid, build, repo)
    assert ok is False and "retains" in why, why

    # Positive control: the SAME manifest verifies once the artifact really
    # holds 12 rows, so the refusal is the count binding and not the digest.
    jsonl.write_text(
        "".join('{"i": %d}\n' % i for i in range(12)), encoding="utf-8")
    forged["records_sha256"] = qgate._records_sha256(jsonl)
    pointer.write_text(json.dumps(forged), encoding="utf-8")
    assert qgate.preflight(gid, build, repo) == (
        True, "gate green and bound to this build")


def test_gate_contract_refuses_a_gate_id_that_cannot_name_a_gate():
    """HIGH: refusing ONE sentinel was not verification.

    gate_preflight was accepted as any string but "not-required" -- "yolo",
    "verified", or a well-formed fake all passed, because gate_contract never
    checked that the value could name a gate at all.
    """
    for bogus in ("yolo", "verified", "totally-not-a-gate", "e0-abc123",
                  "e0-DEADBEEFDEADBEEF", ""):
        rec = {"schema_version": vs.SCHEMA_VERSION, "vector_id": "v",
               "level": None, "passed": True, "input_sha256": None,
               "output_sha256": None, "gate_commit": COMMIT,
               "gate_id": bogus}
        man = {"gate_preflight": bogus, "model_pin": "m", "code_hash": "h",
               "assumption_log_version": "v1"}
        with pytest.raises(stats.StatsError):
            stats.gate_contract(1, 1, [rec], manifest=man)

    # Positive control: a real-shaped id still passes, so the check is the
    # shape and not a blanket refusal of everything.
    good = qgate.mint_gate_id(COMMIT, "pass", TS)
    rec = {"schema_version": vs.SCHEMA_VERSION, "vector_id": "v",
           "level": None, "passed": True, "input_sha256": None,
           "output_sha256": None, "gate_commit": COMMIT, "gate_id": good}
    man = {"gate_preflight": good, "model_pin": "m", "code_hash": "h",
           "assumption_log_version": "v1"}
    assert stats.gate_contract(1, 1, [rec], manifest=man)["manifest_ok"] is True


def test_a_red_result_cannot_be_retained_as_a_passing_row(tmp_path):
    """MEDIUM: the row was built from `cases`, the verdict from `results`.

    A caller passing a JUnit case that says "passed" beside results[name]
    False wrote pass_count=1 into the artifact under a verdict="fail", so the
    retained evidence (what a human reads) contradicted the gate. The row's
    counts now follow the verdict's own reading.
    """
    gid = qgate.mint_gate_id(COMMIT, "fail", TS)
    rep = _report(gid, verdict="fail", total=1, passed=0)
    case = {"name": "c_a", "classname": "c", "time": "0.5", "status": "run",
            "ran": True, "failed": False, "skipped": False}
    jsonl, _ = e0_gate.write_records(tmp_path / "e0", rep, {"c_a": False},
                                     {"c_a": case})
    row = json.loads(jsonl.read_text(encoding="utf-8").splitlines()[0])
    assert row["pass_count"] == 0 and row["fail_count"] == 1
    assert row["duration_s"] == 0.5, "the JUnit duration still survives"


def test_pointer_records_a_run_dir_the_consumer_can_resolve(tmp_path):
    """MEDIUM: a nested run dir lost its intermediate components.

    _latest_pointer's `except ValueError: manifest.parent.name` stored only
    "runX" for build/exp/runX, so preflight looked in build/e0/runX and
    refused a genuinely green record. The path is now build-relative.
    """
    repo, commit = _git_repo(tmp_path)
    build = tmp_path / "build"
    gid = qgate.mint_gate_id(commit, "pass", TS)
    _, manifest = e0_gate.write_records(
        build / "exp" / "runX",
        _report(gid, commit=commit, total=1, passed=1), {"c_a": True})
    e0_gate._latest_pointer(build, manifest)

    body = json.loads((build / "e0" / "latest-gate.json").read_text())
    assert Path(body["records_dir"]).parts == ("exp", "runX")
    ok, why = qgate.preflight(gid, build, repo)
    assert ok is True, why
