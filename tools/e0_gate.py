"""E0 correctness gate (plan B-50.4 gate mechanics).

The gate is the entry criterion for all downstream build and test work: a red
gate blocks every E-campaign, sim campaign, target measurement, and protocol
integration. There is no waiver mechanism by design.

What this module owns:
  - the E0 test set, enumerated per run (never sampled)
  - per-primitive pass counts, cross-check match rate, RNG health verdicts
  - the gate ID: {git commit of code+vectors, verdict, timestamp}, minted
    here and verifiable by recomputation
  - per-test JSONL + manifest retention (gate records kept for project life)
  - the preflight API that experiment harnesses call to refuse on red/missing

What this module deliberately does NOT own:
  - per-VECTOR records. Those ride the B-10.6/B-11.6 harness work (10k-vector
    volume + hang oracle restructures the per-test vector loops). The manifest
    carries `vector_records: "pending-harness"` so a reader can never mistake
    per-test granularity for per-vector coverage. See VECTOR-RECORD-OWNER.
  - protocol-level vectors (B-20/B-21/B-22/B-24/B-25/B-26 own their own).

Exit codes follow the B-02 harness convention: 0 pass, 1 crypto mismatch,
2 infrastructure failure. A flaky run is rerun up to FLAKY_RERUNS times; a
run that fails every rerun is deterministic red and fails closed.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import xml.etree.ElementTree as _ET
from dataclasses import dataclass, field, asdict
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO / "sim"))
# The retention contract lives in analysis/ at the repo root. pytest injects
# the rootdir, so this resolves in the test suite but NOT under
# `python tools/e0_gate.py` (the e0-gate CI job), where only tools/ lands.
sys.path.insert(0, str(_REPO))
from qcsim import gate as _gate          # noqa: E402  single-source contract
from analysis import vector_schema as _vs  # noqa: E402  retention contract

EXIT_PASS = 0
EXIT_CRYPTO = 1
EXIT_INFRA = 2

FLAKY_RERUNS = 3

# Gate ID prefix so a bare hash in a manifest is self-identifying.
GATE_ID_PREFIX = _gate.GATE_ID_PREFIX

# The retained artifact's filename, from the single-source contract module, so
# the writer and the consumer cannot drift apart by renaming one of two
# duplicated literals.
GATE_RECORDS = _gate.GATE_RECORDS

# Per-vector JSONL is owned by the harness work, not by this gate. Recorded
# as an explicit marker so nobody reads per-test counts as per-vector proof.
VECTOR_RECORD_OWNER = "B-10.6/B-11.6 harness (10k volume + hang oracle)"
VECTOR_RECORD_STATE = "pending-harness"


@dataclass(frozen=True)
class PrimitiveSet:
    """One primitive's gated tests. `vectors` names the spec clause."""

    primitive: str
    vectors: str          # plan clause that requires these, e.g. "B-50.1"
    tests: tuple[str, ...]


# B-50.1 vector coverage + B-50.2 cross-checks + B-50.3 RNG sanity.
# Every entry is an EXISTING ctest target; the gate adds none of its own
# coverage, it aggregates and binds. Keep this list explicit: an unlisted
# test is not gated, and the manifest records the full ctest inventory so a
# silent omission is visible rather than implicit.
E0_SET: tuple[PrimitiveSet, ...] = (
    PrimitiveSet("sha256", "B-50.1", ("c_sha256",)),
    PrimitiveSet("hmac", "B-50.1", ("c_hmac",)),
    PrimitiveSet("hkdf", "B-50.1", ("c_hkdf",)),
    PrimitiveSet("aes-gcm", "B-50.1", ("c_aead",)),
    PrimitiveSet("ml-kem", "B-50.1", ("c_kem",)),
    PrimitiveSet("ml-dsa", "B-50.1", ("c_dsa",)),
    PrimitiveSet("cross-check-pq", "B-50.2", ("c_xcheck",)),
    PrimitiveSet("rng-drbg", "B-50.3", ("c_drbg",)),
    PrimitiveSet("rng-prod", "B-50.3", ("c_prod_rng",)),
    PrimitiveSet("rng-injection", "B-50.3", ("c_rng",)),
    # B-50.3 IID/non-IID health testing over the boot entropy source.
    PrimitiveSet("entropy-health", "B-50.3", ("c_entropy_health",)),
)


@dataclass
class TestResult:
    name: str
    passed: bool
    duration_s: float


@dataclass
class GateReport:
    commit: str
    verdict: str                 # "pass" | "fail"
    timestamp: str
    gate_id: str
    total_tests: int
    passed_tests: int
    primitive_counts: dict = field(default_factory=dict)
    cross_check_match_rate: str = "n/a"
    rng_health_verdicts: dict = field(default_factory=dict)
    ctest_inventory: list = field(default_factory=list)
    unlisted_tests: list = field(default_factory=list)
    vector_records: str = VECTOR_RECORD_STATE
    vector_records_owner: str = VECTOR_RECORD_OWNER
    flaky_reruns: int = 0
    notes: list = field(default_factory=list)


def _repo_root() -> Path:
    """Repo root = the parent of tools/ (this file's parents[1]).

    parents[2] would be the PARENT OF THE REPO - a bug that made every
    `git -C` resolve outside the worktree and fail on CI, while the unit
    tests still passed because they computed their own correct REPO.
    """
    return Path(__file__).resolve().parents[1]


def _build_dir() -> Path:
    return _repo_root() / "build"


def git_commit(repo: Path) -> str:
    """Commit hash of code+vectors. Delegates to the shared contract."""
    return _gate.git_commit(repo)


def _run(cmd: list) -> subprocess.CompletedProcess:
    """Subprocess with the two failure modes folded into RuntimeError.

    A missing binary (no ctest on PATH, wrong host) is an INFRASTRUCTURE
    failure and must read as one - never as an empty pass and never as a
    raw OSError escaping to a traceback.
    """
    try:
        return subprocess.run(cmd, capture_output=True, text=True)
    except (FileNotFoundError, NotADirectoryError, PermissionError) as exc:
        raise RuntimeError(f"cannot execute {cmd[0]}: {exc}") from exc


_ANSI = __import__("re").compile(r"\x1b\[[0-9;]*[A-Za-z]")
_TEST_LINE = __import__("re").compile(r"Test\s+#\d+\s*:\s*(\S+)")


def parse_inventory(stdout: str) -> list:
    """Extract test names from `ctest -N` output.

    A pure function so it can be unit-tested without ctest - the previous
    string-splitting version silently dropped names on any ctest build
    that colorises or pads its output, and the gate could not tell that
    from a missing test.
    """
    names = []
    for line in stdout.splitlines():
        line = _ANSI.sub("", line)
        m = _TEST_LINE.search(line)
        if m:
            names.append(m.group(1))
    return names


def ctest_inventory(build: Path) -> list:
    """Full enumerated test list. B-50.5: N equals the full suite count,
    enumerated per run, never sampled."""
    p = _run(["ctest", "--test-dir", str(build), "-N"])
    if p.returncode != 0:
        raise RuntimeError(f"ctest -N failed: {p.stderr[:200]}")
    names = parse_inventory(p.stdout)
    if not names:
        raise RuntimeError(
            f"ctest -N produced no test names (build not configured?); "
            f"first 300 chars: {p.stdout[:300]!r}")
    return names


def parse_junit(path: Path, names: tuple) -> dict:
    """Parse ctest's JUnit XML into {name: passed}.

    JUnit XML is ctest's machine-readable contract; the human-readable
    console output is a display format and has broken this parser twice
    (padding, colour, and "Passed" never being the last token on the line).
    A correctness gate must not depend on layout.

    Fail-closed: only an explicit absence of failure/error/skipped counts
    as a pass. A skipped gated test is NOT a pass - that would be exactly
    the vacuous pass B-50.5 forbids.
    """
    try:
        tree = _ET.parse(path)
    except (OSError, _ET.ParseError) as exc:
        raise RuntimeError(f"ctest JUnit output unreadable: {exc}") from exc
    results = {}
    all_results = {}
    for tc in tree.iter("testcase"):
        name = tc.get("name")
        if not name:
            continue
        if name in results:
            # CMake stores tests in PER-DIRECTORY maps, so the same name in
            # two subdirectories is legal and ctest emits it twice.
            # Last-wins would make the gate verdict a function of XML
            # document order: a failing case followed by a passing one
            # reads green. Refuse instead of choosing.
            raise RuntimeError(
                f"duplicate <testcase name={name!r}> in ctest JUnit output; "
                "refusing to let ordering pick the verdict")
        status = tc.get("status")
        # Fail-closed on ABSENCE of status too: a missing attribute is not
        # an explicit "it ran". Only status="run" with no failure/error/
        # skipped child is a pass.
        bad = (status != "run"
               or any(ch.tag in ("failure", "error", "skipped")
                      for ch in tc))
        results[name] = not bad
        all_results[name] = results[name]
    missing = [n for n in names if n not in results]
    if missing:
        raise RuntimeError(
            f"ctest reported no result element for: {missing} "
            f"(got {sorted(results)})")
    _reconcile_suite(tree, all_results)
    return {n: results[n] for n in names}


def _reconcile_suite(tree, all_results):
    """Refuse a <testsuite> whose declared failures no case accounts for.

    CTest writes run-level counts on <testsuite> only. If the suite says
    failures="1" but every <testcase> reads as a pass, either a case was
    dropped or the counts disagree with the elements. Either way the
    counts must not be silently discarded: without this check a suite
    declaring failures=1 errors=1 with two passing-looking cases yields
    ('pass', 2, 2).
    """
    root = tree.getroot()
    suite = root if root.tag == "testsuite" else tree.find(".//testsuite")
    if suite is None:
        return
    try:
        declared_bad = (int(suite.get("failures") or 0)
                        + int(suite.get("errors") or 0)
                        + int(suite.get("skipped") or 0)
                        + int(suite.get("disabled") or 0))
    except (TypeError, ValueError):
        raise RuntimeError(
            "ctest suite declares an unparseable failure/error count")
    # A case that did not run (status=notrun / disabled / skipped child)
    # reads as not-passed here, and the suite counts it under skipped or
    # disabled -- so all four count toward the total, not just failures.
    seen_bad = sum(1 for v in all_results.values() if not v)
    # M3: the guard was short-circuited by `declared_bad and ...`, so a suite
    # declaring failures="0" (or omitting the attribute) alongside a
    # <failure> case was ACCEPTED -- decorative in exactly the case the
    # docstring names. Reconcile unconditionally.
    if declared_bad != seen_bad:
        raise RuntimeError(
            "ctest suite declares %d failure(s)+error(s) but %d testcase(s) "
            "read as failing; refusing to let the counts be discarded"
            % (declared_bad, seen_bad))


def parse_junit_cases(path) -> dict:
    """{name: case-mapping} for every <testcase>, counts + time preserved.

    SIBLING of parse_junit, not a replacement. parse_junit collapses each
    case to a pass/fail bool because that is all a verdict needs; the
    per-test retention schema (analysis/vector_schema.py,
    per_test_from_junit) needs counts and duration that parse_junit
    deliberately discards.

    CTEST'S REAL SHAPE (verified against CMake's own source,
    Source/CTest/cmCTestTestHandler.cxx:2758-2806). An earlier version of
    this function was WRONG about this and read attributes that do not
    exist on a testcase:

      <testsuite tests=N failures=F errors=E skipped=S disabled=D time=T>
        <testcase name=... classname=... time=t status=run|notrun|disabled>
          [<failure>|<error>|<skipped>] <properties/> <system-out/>

    The counts live ONLY on <testsuite>. CMake writes exactly four
    attributes on <testcase>: name, classname, time, status.

    status is authoritative and is NOT redundant with the child elements:
    a DISABLED test is emitted with status="disabled" and NO child at all,
    so a child-element-only check scores it as a pass. That is the vacuous
    pass B-50.5 forbids.
    """
    try:
        tree = _ET.parse(path)
    except (OSError, _ET.ParseError) as exc:
        raise RuntimeError(f"ctest JUnit output unreadable: {exc}") from exc
    suite = tree.getroot()
    if suite.tag != "testsuite":
        # ctest writes <testsuite> as the ROOT element, and ".//testsuite"
        # matches DESCENDANTS only -- so the root has to be checked first.
        suite = tree.find(".//testsuite")
    # Counts exist only here. Absent stays None -- never invented as 0,
    # because "no failure information" is not "zero failures".
    suite_counts = None
    if suite is not None:
        suite_counts = {
            k: suite.get(k)
            for k in ("tests", "failures", "errors", "skipped", "disabled")}
    cases = {}
    for tc in tree.iter("testcase"):
        name = tc.get("name")
        if not name:
            continue
        if name in cases:
            # CMake stores tests in per-directory maps, so duplicate names
            # across subdirectories are legal and ctest emits them twice.
            # Last-wins would let document order decide a gate verdict.
            raise RuntimeError(
                f"duplicate <testcase name={name!r}> in ctest JUnit output; "
                "refusing to let ordering pick the verdict")
        status = tc.get("status")
        skipped = any(ch.tag == "skipped" for ch in tc)
        failed = any(ch.tag in ("failure", "error") for ch in tc)
        # "ran" must mean THIS TEST EXECUTED, not "it passed". CMake emits
        # status="fail" for a failed test (cmCTestTestHandler.cxx:2789-2801),
        # so treating only status=="run" as executed sent EVERY real failure
        # down the minimal-fallback path in write_records and the JUnit-derived
        # per-test shape was produced only for green runs -- the retention
        # artifact was degraded for exactly the runs that matter.
        # notrun/disabled did not execute; a <skipped/> child did not complete.
        ran = (status in ("run", "fail")) and not skipped
        cases[name] = {
            "name": name,
            "classname": tc.get("classname"),
            "time": tc.get("time"),
            "status": status,
            "ran": ran,
            "skipped": skipped,
            "failed": failed,
            "suite": suite_counts,
        }
    return cases


def verdict_from(results: dict) -> tuple:
    """(verdict, passed, total) from a {name: passed} mapping.

    Pure and extracted so the one rule that decides whether the whole gate
    is red can be tested directly with synthetic verdicts - a test that
    only asserts `not all(mydict.values())` proves nothing about the gate.
    """
    # M5: truthiness counted "fail", -1, 1.0 and [0] as passes. Require a
    # real bool so only a genuine True can ever be a pass.
    passed = sum(1 for v in results.values() if v is True)
    verdict = "pass" if passed == len(results) and results else "fail"
    return verdict, passed, len(results)


def run_tests(build: Path, names: tuple) -> dict:
    """Run the named tests. Returns {name: passed}.

    -R is an anchored alternation so `c_aead` cannot match a future
    `c_aead_extra`; --output-on-failure keeps a red's evidence inline;
    --output-junit gives the machine-readable verdicts.
    """
    pattern = "^(" + "|".join(names) + ")$"
    junit = build / "e0-ctest.xml"
    if junit.exists():
        junit.unlink()          # never read a previous run's verdicts
    p = _run(["ctest", "--test-dir", str(build), "-R", pattern,
              "--output-on-failure", "--timeout", "300",
              "--output-junit", str(junit)])
    if not junit.exists():
        raise RuntimeError(
            f"ctest produced no JUnit report (rc={p.returncode}); "
            f"last output: {(p.stdout or p.stderr)[-300:]}")
    # M2: ctest's exit status is INDEPENDENT corroboration of the XML. It was
    # used only for an error message, so rc=8 ("some tests failed") with a
    # green-looking report read as pass. Disagreement is refused, not chosen.
    if p.returncode != 0:
        failing = [n for n, ok in parse_junit(junit, names).items() if not ok]
        if not failing:
            raise RuntimeError(
                "ctest exited rc=%d but the JUnit report shows every test "
                "as passing; report and exit status disagree" % p.returncode)
    return parse_junit(junit, names), parse_junit_cases(junit)


def mint_gate_id(commit: str, verdict: str, timestamp: str) -> str:
    """Delegates to the shared contract so producer and consumer cannot
    drift (see sim/qcsim/gate.py for the single implementation)."""
    return _gate.mint_gate_id(commit, verdict, timestamp)


def verify_gate_id(gate_id: str, commit: str, verdict: str,
                   timestamp: str) -> bool:
    """Recomputation check. A forged or mismatched ID fails here."""
    return _gate.verify_gate_id(gate_id, commit, verdict, timestamp)


def records_sha256(jsonl) -> str:
    """Digest of a retained JSONL artifact, for the manifest to bind it."""
    return _vs.sha256_file(jsonl)


def write_records(run_dir: Path, report: GateReport,
                  results: dict, cases: dict = None) -> tuple:
    """Per-test JSONL + manifest. Retention: caller owns the directory; we
    never prune, never overwrite a prior gate record (neither the JSONL nor
    the manifest -- the manifest used to be rewritten unconditionally).

    The JSONL rows are SCHEMA-VALID per-test records from
    analysis/vector_schema.per_test_from_junit -- the shared retention
    contract -- carrying the gate provenance (commit, gate_id) on each row.
    An earlier version wrote an ad-hoc {"test","passed",...} shape that
    validate() rejects as unknown keys, so the retention artifact and the
    schema were two different objects and only tests ever exercised the
    seam.

    When `cases` is unavailable (no JUnit retained), OR the case cannot be
    represented as a retained record (a ctest status="disabled"/"notrun"
    case is refused by the schema's fail-closed rule -- and that refusal
    must not turn a RED gate into an INFRA failure that writes no record at
    all), a minimal schema-valid row is built from the boolean result.
    Absence of duration is recorded as absent, never invented as 0.0.

    The manifest additionally carries `records_sha256`, a digest of the
    exact JSONL bytes, so a consumer can distinguish a record this writer
    produced from a hand-written manifest of plausible shape.
    """
    run_dir.mkdir(parents=True, exist_ok=True)
    # A record with no gate id cannot be verified by any consumer (preflight
    # recomputes the id and refuses a mismatch), so publishing one writes an
    # artifact that is unverifiable BY CONSTRUCTION. main() guarded this by
    # deriving the run dir from the id; the writer is the shared contract and
    # must refuse it itself, for every caller.
    if not report.gate_id:
        raise RuntimeError(
            "refusing to write a record with an empty gate id: no consumer "
            "can verify it (the id is over commit|verdict|timestamp)")
    jsonl = run_dir / GATE_RECORDS
    manifest = run_dir / "e0-gate-manifest.json"
    schema_version = _vs.SCHEMA_VERSION
    for path in (jsonl, manifest):
        # G5: a re-run never overwrites. The manifest was previously written
        # unconditionally, so a re-run with --run-dir replaced a prior gate
        # record's manifest while its JSONL stayed put -- two different
        # records sharing one directory. "x" also makes each refusal atomic
        # if two writers race; the explicit check gives a clear message.
        if path.exists():
            raise RuntimeError(f"refusing to overwrite {path} (G5: a re-run "
                               f"never overwrites a prior gate record)")
    with jsonl.open("x", encoding="utf-8") as fh:
        for name in sorted(results):
            row = None
            if cases and name in cases:
                try:
                    row = _vs.per_test_from_junit(cases[name], report.commit,
                                                  report.gate_id)
                except _vs.SchemaError:
                    # Not representable as a retained per-test record (the
                    # one real case being status != "run"). Fall through to
                    # the honest minimal row below rather than aborting the
                    # whole write and losing the red verdict.
                    row = None
            if row is None:
                # Same identity rule as verdict_from: only an explicit bool
                # True is a pass. Truthiness here counted "fail", -1 and 1.0
                # as passes, so a manifest could read verdict="pass" beside a
                # row whose own counts say otherwise.
                passed = results[name] is True
                row = {"schema_version": schema_version, "test_name": name,
                       "level": None, "vector_count": 1,
                       "pass_count": 1 if passed else 0,
                       "fail_count": 0 if passed else 1,
                       "duration_s": None,
                       "gate_commit": report.commit,
                       "gate_id": report.gate_id}
            # The JUnit-derived row is preferred for its duration, but it is
            # built from `cases` while the verdict and the H1 count come from
            # `results`. If those two disagree the artifact would record a
            # PASSING row beside a failing result -- the retained evidence
            # (what a human or audit reads) contradicting the verdict. Force
            # the verdict's own reading into the row's counts; a red result
            # can never be stored as green.
            v_passed = results[name] is True
            if (row["pass_count"] == 1) != v_passed:
                row["pass_count"] = 1 if v_passed else 0
                row["fail_count"] = 0 if v_passed else 1
            _vs.validate(row, "per-test")
            fh.write(json.dumps(row, sort_keys=True) + "\n")
    # H1: report.total_tests/passed_tests come from the report, while the rows
    # come from results/cases. A caller passing a mismatched `cases` could
    # publish a manifest claiming 500/500 green beside a one-row artifact, and
    # preflight's consistency check only compares the manifest to itself.
    written_pass = sum(1 for n in results if results[n] is True)
    if report.total_tests != len(results) \
            or report.passed_tests != written_pass:
        raise RuntimeError(
            "report counts (%d/%d) disagree with the records written "
            "(%d/%d); refusing to publish a manifest the artifact does not "
            "support" % (report.passed_tests, report.total_tests,
                         written_pass, len(results)))
    # Provenance of the ARTIFACT, not just the shape: the manifest carries a
    # digest of the exact JSONL bytes beside it, so a consumer can tell a
    # record the gate wrote from a hand-written one with a plausible shape.
    body = json.loads(json.dumps(asdict(report), sort_keys=True))
    body["records_sha256"] = _vs.sha256_file(jsonl)
    # The artifact's location travels WITH the manifest. The pointer at
    # build/e0/latest-gate.json is a copy of this file placed beside a
    # directory that does not hold the JSONL, so a consumer that assumed a
    # fixed sibling name could never verify a run-dir layout.
    body["records_file"] = jsonl.name
    manifest.write_text(json.dumps(body, indent=2, sort_keys=True),
                        encoding="utf-8")
    return jsonl, manifest


def evaluate(build: Path, repo: Path) -> tuple:
    """Returns (report, results, cases) so the caller writes records from the
    same pass that produced the verdict. No second run, no re-derivation.

    The id IS minted here, over this pass's verdict. Two rules hold together:
    every record that leaves this function is verifiable on its own, and a
    caller that later REWRITES the verdict (the rerun path) must re-mint --
    which `_evaluate_with_rerun` does, in one place, when it finalises.
    """
    commit = git_commit(repo)
    inventory = ctest_inventory(build)
    gated = tuple(n for ps in E0_SET for n in ps.tests)
    unlisted = sorted(set(inventory) - set(gated))

    missing = [n for n in gated if n not in inventory]
    if missing:
        raise RuntimeError(
            f"E0 set names tests that do not exist: {missing}. "
            f"Parsed {len(inventory)} tests from ctest -N: {inventory}")

    results, cases = run_tests(build, gated)

    counts = {}
    for ps in E0_SET:
        p = sum(1 for t in ps.tests if results[t])
        counts[ps.primitive] = {"passed": p, "total": len(ps.tests),
                                "clause": ps.vectors}
    verdict, passed_n, total_n = verdict_from(results)
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    xc = results["c_xcheck"]
    rng = {k: v for k, v in results.items() if k.startswith("c_drbg")
           or k.startswith("c_prod_rng") or k.startswith("c_entropy_health")
           or k == "c_rng"}

    report = GateReport(
        commit=commit,
        verdict=verdict,
        timestamp=ts,
        gate_id=mint_gate_id(commit, verdict, ts),
        total_tests=total_n,
        passed_tests=passed_n,
        primitive_counts=counts,
        cross_check_match_rate=("100%" if xc else "FAIL"),
        rng_health_verdicts=rng,
        ctest_inventory=inventory,
        unlisted_tests=unlisted,
    )
    return report, results, cases


def preflight(gate_id: str, build: Path, repo: Path) -> tuple:
    """Experiment-harness entry check. Delegates to the shared contract."""
    return _gate.preflight(gate_id, build, repo)


def _latest_clear(build: Path) -> None:
    """H3: invalidate the published pointer BEFORE a run.

    A stale green latest-gate.json survived every later failure -- a
    crashed ctest, a disabled test, an escaping SchemaError -- so a
    downstream preflight reading it accepted the PREVIOUS commit's green.
    """
    dest = build / "e0" / "latest-gate.json"
    try:
        dest.unlink()
    except OSError:
        pass


def _latest_pointer(build: Path, manifest: Path) -> None:
    """Publish the record under build/e0/latest-gate.json for preflight.

    The pointer is a COPY of the manifest, and it is deliberately placed in
    build/e0/ while its JSONL artifact lives in build/e0/<gate_id>/. Both the
    artifact's name and its directory therefore have to travel with the copy,
    or the consumer cannot locate the bytes the digest describes.
    """
    dest = build / "e0"
    dest.mkdir(parents=True, exist_ok=True)
    body = json.loads(manifest.read_text(encoding="utf-8"))
    # The run dir may sit anywhere. Prefer a path RELATIVE to the build tree
    # so the consumer resolves it against build/ (the flat build/e0/<gid>
    # layout, and any nested one, both work). Only if the manifest lives
    # outside the tree entirely do we fall back to an absolute path -- the
    # old `except: manifest.parent.name` dropped intermediate components, so
    # a run dir like build/exp/runX was recorded as "runX" and preflight then
    # looked in build/e0/runX and refused a genuinely green record.
    try:
        body["records_dir"] = str(manifest.parent.relative_to(build))
    except ValueError:
        body["records_dir"] = str(manifest.parent.resolve())
    (dest / "latest-gate.json").write_text(
        json.dumps(body, indent=2, sort_keys=True), encoding="utf-8")


def _evaluate_with_rerun(build: Path, repo: Path) -> tuple:
    """B-50.4 flaky policy.

    A gate that fails and then passes on rerun with NO code or vector
    change is infrastructure nondeterminism (flaky). One that fails every
    attempt is a real red. Either way the gate verdict comes from the LAST
    attempt and a flaky pass is recorded with its rerun count, never
    laundered into a clean run. Fails closed: three red attempts stay red.
    """
    attempt = 0
    while True:
        attempt += 1
        _ev = evaluate(build, repo)
        # Tolerate a 2-tuple from a caller/test double that predates the
        # JUnit cases being threaded through; retention then falls back to
        # the schema-valid minimal row rather than an illegal one.
        if isinstance(_ev, tuple) and len(_ev) == 3:
            report, results, cases = _ev
        else:
            report, results = _ev
            cases = None
        if report.verdict == "pass" or attempt >= FLAKY_RERUNS:
            # H1: we ONLY break on a first-attempt pass. Once a rerun has
            # happened, a later green is NOT promoted -- otherwise a test
            # red with probability p reports green with probability 1-p**N
            # (0.875 at p=0.5, 0.999 at p=0.1), which is a waiver in a gate
            # whose contract says "no waiver mechanism by design". The rerun
            # is kept as FLAKE EVIDENCE: verdict stays red, flaky_reruns
            # records it. Two independent greens are weaker evidence than
            # one, not stronger.
            if report.verdict == "pass" and attempt > 1:
                report.verdict = "flaky-red"
            break
        print(f"E0 GATE: attempt {attempt}/{FLAKY_RERUNS} red; "
              f"rerunning to distinguish flake from failure",
              file=sys.stderr)
    report.flaky_reruns = attempt - 1
    # Re-mint ONLY when this function changed the verdict. The rerun path
    # rewrites "pass" -> "flaky-red", and an id minted over the pre-rewrite
    # verdict no longer recomputes from the record that is stored, so
    # preflight refused every flaky run as tampered. evaluate() already minted
    # over this pass's verdict, so the non-rerun case needs no second mint --
    # re-minting unconditionally would be harmless but this documents the
    # invariant that the id always matches the verdict actually recorded.
    expected = mint_gate_id(report.commit, report.verdict, report.timestamp)
    if report.gate_id != expected:
        report.gate_id = expected
    return report, results, cases


def main(argv: list) -> int:
    repo = _repo_root()
    build = _build_dir()
    outdir = None
    args = list(argv)
    if "--run-dir" in args:
        # A bare `--run-dir` with no value raised IndexError out of a tool
        # whose docstring promises exit codes, and CI would read the bare 1
        # as a crypto mismatch rather than an infra fault.
        idx = args.index("--run-dir") + 1
        if idx >= len(args) or args[idx].startswith("--"):
            print("E0 GATE: INFRA FAILURE: --run-dir needs a path",
                  file=sys.stderr)
            return EXIT_INFRA
        outdir = Path(args[idx])

    _latest_clear(build)
    try:
        report, results, cases = _evaluate_with_rerun(build, repo)
        # An empty id would collapse every run onto build/e0/ itself, so the
        # second run -- including a second GREEN run -- refuses to publish
        # (G5) and the retained artifact stays the previous one. Refuse
        # explicitly rather than derive a directory from an unverifiable id.
        if not report.gate_id:
            raise RuntimeError("gate id was not minted; refusing to write a "
                               "record that cannot be verified")
        run_dir = outdir or (build / "e0" / report.gate_id)
        # H3: write_records sat OUTSIDE the try, so a SchemaError escaped
        # main entirely with the pointer still green.
        _, manifest = write_records(run_dir, report, results, cases)
    except Exception as exc:              # noqa: BLE001 - infra boundary
        print(f"E0 GATE: INFRA FAILURE: {exc}", file=sys.stderr)
        return EXIT_INFRA

    _latest_pointer(build, manifest)

    if report.unlisted_tests:
        print(f"E0 GATE: note - {len(report.unlisted_tests)} ctest target(s) "
              f"not in the E0 set (manifest records them)", file=sys.stderr)
    print(f"E0 GATE: {report.verdict.upper()}  {report.gate_id}")
    print(f"  commit   {report.commit}")
    print(f"  tests    {report.passed_tests}/{report.total_tests}")
    if report.flaky_reruns:
        print(f"  flaky    {report.flaky_reruns} rerun(s) — logged for infra "
              f"triage, verdict stands")
    print(f"  xcheck   {report.cross_check_match_rate}")
    print(f"  vectors  {report.vector_records} (owner: {report.vector_records_owner})")
    for prim, c in sorted(report.primitive_counts.items()):
        print(f"  {prim:<18} {c['passed']}/{c['total']}  ({c['clause']})")
    print(f"  manifest {manifest}")
    return EXIT_PASS if report.verdict == "pass" else EXIT_CRYPTO


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
