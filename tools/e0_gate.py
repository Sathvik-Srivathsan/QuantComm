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

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "sim"))
from qcsim import gate as _gate          # noqa: E402  single-source contract

EXIT_PASS = 0
EXIT_CRYPTO = 1
EXIT_INFRA = 2

FLAKY_RERUNS = 3

# Gate ID prefix so a bare hash in a manifest is self-identifying.
GATE_ID_PREFIX = _gate.GATE_ID_PREFIX

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
    for tc in tree.iter("testcase"):
        name = tc.get("name")
        if not name:
            continue
        bad = any(ch.tag in ("failure", "error", "skipped")
                  for ch in tc)
        results[name] = not bad
    missing = [n for n in names if n not in results]
    if missing:
        raise RuntimeError(
            f"ctest reported no result element for: {missing} "
            f"(got {sorted(results)})")
    return {n: results[n] for n in names}


def verdict_from(results: dict) -> tuple:
    """(verdict, passed, total) from a {name: passed} mapping.

    Pure and extracted so the one rule that decides whether the whole gate
    is red can be tested directly with synthetic verdicts - a test that
    only asserts `not all(mydict.values())` proves nothing about the gate.
    """
    passed = sum(1 for v in results.values() if v)
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
    return parse_junit(junit, names)


def mint_gate_id(commit: str, verdict: str, timestamp: str) -> str:
    """Delegates to the shared contract so producer and consumer cannot
    drift (see sim/qcsim/gate.py for the single implementation)."""
    return _gate.mint_gate_id(commit, verdict, timestamp)


def verify_gate_id(gate_id: str, commit: str, verdict: str,
                   timestamp: str) -> bool:
    """Recomputation check. A forged or mismatched ID fails here."""
    return _gate.verify_gate_id(gate_id, commit, verdict, timestamp)


def write_records(run_dir: Path, report: GateReport,
                  results: dict) -> tuple:
    """Per-test JSONL + manifest. Retention: caller owns the directory;
    we never prune, never overwrite a prior gate record."""
    run_dir.mkdir(parents=True, exist_ok=True)
    jsonl = run_dir / "e0-gate.jsonl"
    manifest = run_dir / "e0-gate-manifest.json"
    with jsonl.open("w", encoding="utf-8") as fh:
        for name in sorted(results):
            fh.write(json.dumps({
                "test": name,
                "passed": results[name],
                "commit": report.commit,
                "gate_id": report.gate_id,
                "granularity": "per-test",
            }, sort_keys=True) + "\n")
    manifest.write_text(json.dumps(asdict(report), indent=2, sort_keys=True),
                        encoding="utf-8")
    return jsonl, manifest


def evaluate(build: Path, repo: Path) -> tuple:
    """Returns (report, results) so the caller writes records from the same
    pass that produced the verdict. No second run, no re-derivation."""
    commit = git_commit(repo)
    inventory = ctest_inventory(build)
    gated = tuple(n for ps in E0_SET for n in ps.tests)
    unlisted = sorted(set(inventory) - set(gated))

    missing = [n for n in gated if n not in inventory]
    if missing:
        raise RuntimeError(
            f"E0 set names tests that do not exist: {missing}. "
            f"Parsed {len(inventory)} tests from ctest -N: {inventory}")

    results = run_tests(build, gated)

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
    return report, results


def preflight(gate_id: str, build: Path, repo: Path) -> tuple:
    """Experiment-harness entry check. Delegates to the shared contract."""
    return _gate.preflight(gate_id, build, repo)


def _latest_pointer(build: Path, manifest: Path) -> None:
    """Publish the record under build/e0/latest-gate.json for preflight."""
    dest = build / "e0"
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "latest-gate.json").write_text(
        manifest.read_text(encoding="utf-8"), encoding="utf-8")


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
        report, results = evaluate(build, repo)
        if report.verdict == "pass" or attempt >= FLAKY_RERUNS:
            break
        print(f"E0 GATE: attempt {attempt}/{FLAKY_RERUNS} red; "
              f"rerunning to distinguish flake from failure",
              file=sys.stderr)
    report.flaky_reruns = attempt - 1
    return report, results


def main(argv: list) -> int:
    repo = _repo_root()
    build = _build_dir()
    outdir = None
    args = list(argv)
    if "--run-dir" in args:
        outdir = Path(args[args.index("--run-dir") + 1])

    try:
        report, results = _evaluate_with_rerun(build, repo)
    except Exception as exc:              # noqa: BLE001 - infra boundary
        print(f"E0 GATE: INFRA FAILURE: {exc}", file=sys.stderr)
        return EXIT_INFRA

    run_dir = outdir or (build / "e0" / (report.gate_id))
    _, manifest = write_records(run_dir, report, results)
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
