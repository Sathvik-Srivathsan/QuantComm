"""Audit store (B-40.5): unified append-only event sink.

Record schema (EXACT keys — the no-secret rule by construction: no key
or plaintext field exists, only IDs/hashes/codes): timestamp (caller
clock; wall-clock UTC in prod with untrusted-timestamp flagging owned
by the orchestrator, never gating here), source, code, id_hex,
hash_hex, dev_seq (per-device monotonic from the registry entry),
idx (server-global export index assigned on append).

Export writes JSONL (idx order) plus a manifest record {records, sha256
of the file, sig} signed by a caller-supplied signer (server manifest
key custody is B-41; tests sign via the srv_crypto servant). Rotation
opens a fresh file; retain(n) prunes oldest files (experiment-defined
retention policy, enforced here). Timestamps never gate security
decisions (records only).
"""
import hashlib
import json
from pathlib import Path

_RECORD_KEYS = frozenset(
    {"ts", "source", "code", "id_hex", "hash_hex", "dev_seq", "idx"}
)


def _check_hex(name, value):
    if not isinstance(value, str):
        raise ValueError(f"{name} must be hex str")
    try:
        bytes.fromhex(value)
    except ValueError:
        raise ValueError(f"{name} must be hex str") from None
    if len(value) % 2 != 0:
        raise ValueError(f"{name} must be even-length hex")


class AuditStore:
    """Append-only JSONL audit sink (see module docstring)."""

    def __init__(self, path):
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._idx = 0
        self._files = [str(self._path)]

    def append(self, ts, source, code, id_hex="", hash_hex="",
               dev_seq=0):
        if not isinstance(source, str) or not source:
            raise ValueError("source must be nonempty str")
        if not isinstance(code, str) or not code:
            raise ValueError("code must be nonempty str")
        if not isinstance(dev_seq, int) or dev_seq < 0:
            raise ValueError("dev_seq must be nonneg int")
        _check_hex("id_hex", id_hex)
        _check_hex("hash_hex", hash_hex)
        rec = {
            "ts": ts,
            "source": source,
            "code": code,
            "id_hex": id_hex,
            "hash_hex": hash_hex,
            "dev_seq": dev_seq,
            "idx": self._idx,
        }
        assert set(rec) == _RECORD_KEYS, "schema drift"
        with open(self._path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, sort_keys=True) + "\n")
        self._idx += 1
        return rec["idx"]

    def query(self, source=None, code=None, device=None):
        """Filter appended records (copies; device matches id_hex)."""
        out = []
        with open(self._path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                rec = json.loads(line)
                if source is not None and rec["source"] != source:
                    continue
                if code is not None and rec["code"] != code:
                    continue
                if device is not None and rec["id_hex"] != device:
                    continue
                out.append(rec)
        return out

    def export(self, manifest_path, signer):
        """JSONL is already on disk; write + sign the manifest record.

        signer(digest_hex) -> sig_hex (caller/B-41 custody). Returns
        the manifest dict.
        """
        digest = hashlib.sha256(
            self._path.read_bytes()
        ).hexdigest()
        sig = signer(digest)
        if not isinstance(sig, str):
            raise ValueError("signer must return hex str")
        manifest = {
            "records": self._idx,
            "sha256": digest,
            "sig": sig,
        }
        Path(manifest_path).write_text(
            json.dumps(manifest, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return manifest

    def rotate(self, new_path):
        """Close current file, open fresh (retention via retain())."""
        self._path = Path(new_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._files.append(str(self._path))
        return str(self._path)

    def retain(self, n):
        """Prune oldest rotated files beyond the newest n."""
        if n < 1:
            raise ValueError("retain at least 1")
        while len(self._files) > n:
            old = self._files.pop(0)
            try:
                Path(old).unlink()
            except FileNotFoundError:
                pass
        return list(self._files)

    @property
    def record_keys(self):
        """The exact schema (no-plaintext test asserts against this)."""
        return set(_RECORD_KEYS)
