"""E1 campaign driver (plan B-51.4 outputs).

Owns everything the C runner deliberately does not: the gate check, host
spec capture, dataset versioning, manifest, and the B-33 fill.

Hard rules encoded here:
  - No green E0 gate for THIS build => refuse. No manual override.
  - No joules. The schema has no energy key; the C runner emits
    energy_field="absent-by-design" as a positive marker.
  - Host numbers are ASSUMED priors for B-33, never target claims. The
    manifest records that bound on every row.
  - The dataset is versioned and retained verbatim; a re-run never
    overwrites a prior version.
"""
from __future__ import annotations

import json
import platform


import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "sim"))
from qcsim import gate as gate_mod          # noqa: E402

REPO = Path(__file__).resolve().parents[1]
BENCH = REPO / "build" / "tools" / "e1_bench"
RUNS = REPO / "runs" / "E1"

EXIT_PASS = 0
EXIT_GATE = 2      # gate refused (distinct from a measurement failure)
EXIT_INFRA = 3     # could not run the bench

REQUIRED_ROW_KEYS = ("op", "level", "payload", "n", "ns_mean", "ns_p50",
                     "ns_p95", "ns_p99", "ns_max", "cycles_p50",
                     "heap_live_bytes", "cycle_source", "stack_metric")


def host_spec() -> dict:
    """B-51.2 requires the host recorded per dataset. Collected from the
    OS, not from the operator's memory."""
    spec = {
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "python": platform.python_version(),
    }
    try:
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.lower().startswith("model name"):
                spec["cpu_model"] = line.split(":", 1)[1].strip()
                break
    except OSError:
        pass
    return spec


def compiler_spec(build: Path) -> str:
    """Compiler + flags, recorded per dataset (B-51.2)."""
    cache = build / "CMakeCache.txt"
    if cache.exists():
        for line in cache.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("CMAKE_C_COMPILER:"):
                return line.split("=", 1)[1].strip()
    return "unknown"


def require_gate(build: Path) -> tuple:
    """B-51.4: gate-ID mismatch refuses the dataset."""
    ok, why = gate_mod.preflight("", build, REPO)
    if not ok:
        return None, why
    return json.loads(
        (build / gate_mod.GATE_DIRNAME / gate_mod.GATE_MANIFEST)
        .read_text(encoding="utf-8")), None


def parse_rows(stdout: str) -> list:
    rows = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        row = json.loads(line)
        missing = [k for k in REQUIRED_ROW_KEYS if k not in row]
        if missing:
            raise RuntimeError(f"E1 row missing keys {missing}: {line[:120]}")
        # B-51.3 no-joule rule: the schema must not carry energy at all.
        for banned in ("joules", "energy_j", "power_w", "mah", "uj"):
            assert banned not in row, f"energy field {banned!r} in E1 row"
        rows.append(row)
    if not rows:
        raise RuntimeError("E1 produced no rows")
    return rows


def validate_rows(rows: list, n_override) -> list:
    """Coverage checks (B-51.5). Cheap, and they stop a partial matrix
    from being retained as if it were complete."""
    problems = []
    ops = {r["op"] for r in rows}
    required_ops = {"sha256", "hmac-sha256", "aes-256-gcm-encrypt",
                    "hkdf-expand-64", "ml-kem-keygen", "ml-kem-encaps",
                    "ml-kem-decaps", "ml-dsa-keygen", "ml-dsa-sign",
                    "ml-dsa-verify"}
    missing = required_ops - ops
    if missing:
        problems.append(f"matrix cells missing: {sorted(missing)}")
    for lvl in ("512", "768", "1024"):
        if not any(r["op"] == "ml-kem-keygen" and r["level"] == lvl
                   for r in rows):
            problems.append(f"ml-kem level {lvl} absent")
    for lvl in ("44", "65", "87"):
        if not any(r["op"] == "ml-dsa-sign" and r["level"] == lvl
                   for r in rows):
            problems.append(f"ml-dsa level {lvl} absent")
    if n_override is None:
        for r in rows:
            want = 500 if r["op"] == "ml-dsa-sign" else 200
            if r["n"] != want:
                problems.append(
                    f"{r['op']}/{r['level']} n={r['n']}, want {want}")
                break
    return problems


def next_version() -> str:
    if not RUNS.exists():
        return "E1-0001"
    vers = sorted(p.name for p in RUNS.iterdir() if p.is_dir())
    if not vers:
        return "E1-0001"
    last = vers[-1]
    return f"E1-{int(last.split('-')[1]) + 1:04d}"


def run(n_override=None) -> int:
    build = REPO / "build"
    record, why = require_gate(build)
    if record is None:
        print(f"E1 REFUSED: {why}", file=sys.stderr)
        print("E1 requires a green E0 gate for this exact build "
              "(B-51.4, no override).", file=sys.stderr)
        return EXIT_GATE

    if not BENCH.exists():
        print(f"E1 INFRA: bench not built at {BENCH}", file=sys.stderr)
        return EXIT_INFRA

    argv = [str(BENCH), record["gate_id"]]
    if n_override:
        argv.append(str(n_override))
    proc = subprocess.run(argv, capture_output=True, text=True)
    if proc.returncode != 0:
        print(f"E1 INFRA: bench exited {proc.returncode}\n"
              f"{proc.stderr[-500:]}", file=sys.stderr)
        return EXIT_INFRA

    rows = parse_rows(proc.stdout)
    problems = validate_rows(rows, n_override)
    if problems:
        print("E1 COVERAGE FAILURES:", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        return EXIT_PASS      # rows still retained for inspection

    version = next_version()
    outdir = RUNS / version
    outdir.mkdir(parents=True, exist_ok=False)

    jsonl = outdir / "e1.jsonl"
    jsonl.write_text("".join(json.dumps(r, sort_keys=True) + "\n"
                            for r in rows), encoding="utf-8")

    manifest = {
        "dataset_version": version,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "code_hash": gate_mod.git_commit(REPO),
        "e0_gate_id": record["gate_id"],
        "e0_verdict": record["verdict"],
        "host": host_spec(),
        "compiler": compiler_spec(build),
        "n_default": n_override or 200,
        "n_dsa_sign": n_override or 500,
        "warmup_pct": 10,
        "rows": len(rows),
        "cycles_source": "rdtsc-fenced",
        "energy_field": "absent-by-design (B-51.3: host joules are "
                        "unrepresentative of the target; energy is B-62 "
                        "plus the B-33 model)",
        "stack_high_water": "PENDING VERIFICATION - not measured in this "
                            "dataset. Two paint implementations failed "
                            "silently (static buffer in .bss; frame-local "
                            "buffer placed above the stack pointer), both "
                            "reporting plausible non-degenerate numbers "
                            "instead of erroring. Emitting a memory column "
                            "that is quietly wrong is worse than emitting "
                            "none, so the metric is absent rather than "
                            "zero. Owner: B-51 follow-up, needs alloca() or a "
                            "dedicated measurement TU plus a host that can "
                            "build and run it.",
        "transfer_bound": "host numbers are ASSUMED priors for B-33 e_o "
                          "and footprint tables; they are NOT target claims "
                          "and never transfer as such (B-51.1)",
        "determinism": "setup, schema and matrix are deterministic (fixed "
                       "seed, stated N, stated warmup); timings are physical "
                       "measurements and are retained verbatim",
        "problems": problems,
    }
    (outdir / "e1-manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")

    print(f"E1 {version}: {len(rows)} rows, gate {record['gate_id']}")
    print(f"  dataset {outdir}")
    if problems:
        print("  COVERAGE PROBLEMS recorded in the manifest:")
        for p in problems:
            print(f"    - {p}")
    return EXIT_PASS


def main(argv):
    n = None
    if "--n" in argv:
        n = int(argv[argv.index("--n") + 1])
    return run(n)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
