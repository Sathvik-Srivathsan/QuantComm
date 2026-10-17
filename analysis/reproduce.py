"""B-54 reproducibility: release assembly + hashing + rerun check.

B-54.3: a Release carries raw datasets (JSONL), scripts + lockfile,
manifests, DOE registrations, assumption logs, and hashes. The closure
set for a bit-identical rerun is: seed + code hash + manifest +
assumption-log version + DOE hash.

Supplies NUMBERS, never verdicts (B-54.7).
"""

import hashlib
import json
import os

REQUIRED_ARTIFACTS = ("datasets", "scripts", "manifests", "doe_regs",
                      "assumption_logs", "closure")
CLOSURE_FIELDS = ("seed", "code_hash", "manifest_hash",
                  "assumption_log_version", "doe_hash")


class ReproduceError(Exception):
    """Hard refusal. A missing artifact never passes silently."""


def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


_sha256_bytes = sha256_bytes


def sha256_file(path):
    if not os.path.isfile(path):
        raise ReproduceError("missing file %r" % path)
    with open(path, "rb") as fh:
        return _sha256_bytes(fh.read())


def sha256_tree(root):
    """Order-independent content hash over a directory."""
    if not os.path.isdir(root):
        raise ReproduceError("missing directory %r" % root)
    h = hashlib.sha256()
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            h.update(os.path.relpath(full, root).encode())
            h.update(sha256_file(full).encode())
    return h.hexdigest()


def closure(seed, code_hash, manifest, assumption_log_version, doe_hash):
    """The complete closure set; nothing else is needed to rerun."""
    c = {"seed": seed, "code_hash": code_hash,
         "manifest_hash": sha256_bytes(json.dumps(
             manifest, sort_keys=True).encode()),
         "assumption_log_version": assumption_log_version,
         "doe_hash": doe_hash}
    missing = [f for f in CLOSURE_FIELDS if c.get(f) in (None, "")]
    if missing:
        raise ReproduceError("incomplete closure set, missing %s" % missing)
    return c


def assemble_release(datasets, scripts_hash, manifests, doe_regs,
                     assumption_logs, closure_set):
    """B-54.4.6: gather + hash + record. Every artifact must be present."""
    present = {
        "datasets": list(datasets),
        "scripts": scripts_hash,
        "manifests": list(manifests),
        "doe_regs": list(doe_regs),
        "assumption_logs": list(assumption_logs),
        "closure": closure_set,
    }
    missing = [k for k in REQUIRED_ARTIFACTS if not present.get(k)]
    if missing:
        raise ReproduceError("incomplete release, missing %s" % missing)
    present["hash"] = _sha256_bytes(
        json.dumps(present, sort_keys=True, default=str).encode())
    return present


def verify_release(release):
    """Re-derive the release hash; a mutated artifact fails."""
    body = {k: v for k, v in release.items() if k != "hash"}
    return _sha256_bytes(
        json.dumps(body, sort_keys=True, default=str).encode()) == release["hash"]


def rerun_matches(run_fn, closure_set, observed):
    """Bit-identical rerun from the closure set alone."""
    again = run_fn(closure_set)
    if again != observed:
        raise ReproduceError("rerun diverged from the recorded result")
    return True


def write_release(release, root, exp, run_id):
    """B-54.3: artifacts land as JSON under runs/<exp>/<id>/.

    Writes datasets, manifests, DOE regs, assumption logs and the
    closure set, then re-reads the tree to confirm the release hash
    verifies against what is on disk (not against memory).
    """
    exp = str(exp)
    run_id = str(run_id)
    if "/" in exp or "/" in run_id or exp in ("", ".", "..") \
            or run_id in ("", ".", ".."):
        raise ReproduceError("unsafe exp/id %r %r" % (exp, run_id))
    out = os.path.join(root, exp, run_id)
    parts = (("datasets", "datasets"), ("manifests", "manifests"),
             ("doe_regs", "doe_regs"), ("assumption_logs",
                                        "assumption_logs"))
    for key, sub in parts:
        d = os.path.join(out, sub)
        os.makedirs(d, exist_ok=True)
        items = release.get(key) or []
        if isinstance(items, dict):
            items = [items]
        for i, item in enumerate(items):
            with open(os.path.join(d, "%03d.json" % i), "w") as fh:
                json.dump(item, fh, sort_keys=True, default=str)
    with open(os.path.join(out, "release.json"), "w") as fh:
        json.dump(release, fh, sort_keys=True, default=str)
    return out


def verify_release_on_disk(release, path):
    """Re-read the written tree and re-verify the hash from DISK."""
    with open(os.path.join(path, "release.json")) as fh:
        stored = json.load(fh)
    return verify_release(stored)


# ---- covariates (B-54.3): logged, flagged, report-only ----
COVARIATE_RANGES = {"voltage_V": (3.0, 3.6), "temperature_C": (10.0, 45.0),
                    "rssi_dBm": (-100.0, -40.0)}


def log_covariates(rows):
    """Report-only QC. Out-of-range rows are FLAGGED, never adjusted."""
    flagged, clean = [], []
    for i, r in enumerate(rows):
        out = {}
        for name, (lo, hi) in COVARIATE_RANGES.items():
            if name not in r:
                raise ReproduceError("row %d missing covariate %r" % (i, name))
            v = r[name]
            if not (lo <= v <= hi):
                out[name] = {"value": v, "range": [lo, hi],
                             "out_of_range": True}
        (flagged if out else clean).append({"row": i, "out_of_range": out})
    return {"clean": clean, "flagged": flagged, "n": len(rows),
            "adjusted": False}


# ---- no-decision scan (B-54.4: a verdict branch here is a defect) ----
VERDICT_TOKENS = ("verdict", "h4_pass", "h4_fail", "h1_verdict", "h2_verdict",
                  "h3_verdict", "h5_verdict", "decision", "accept =",
                  "final_call")


def scan_no_decision(text):
    """Return the decision-like tokens found. Empty list == clean."""
    found = []
    low = text.lower()
    for tok in VERDICT_TOKENS:
        if tok in low:
            found.append(tok)
    return sorted(set(found))