"""Private servant bridge (used by the verbs, never public API).

Single choke point between Python and the C adapters: hex in/out,
subprocess isolation, exit-code discipline. stdout NEVER carries
anything the caller didn't ask to print — the no-plaintext test
audits the stores, not this pipe (pipe bytes are the caller's
responsibility the moment they return).

Binary location: $QC_SRV_CRYPTO override, else build/server/srv_crypto
relative to this file's repo root (cwd-independent). Missing binary
raises loudly (tests fail, never skip).
"""
import os
import subprocess
from pathlib import Path


class BridgeError(Exception):
    """Servant-level failure (usage, not protocol)."""


def _binary():
    override = os.environ.get("QC_SRV_CRYPTO")
    if override:
        return Path(override)
    return Path(__file__).resolve().parents[2] / "build" / "server" \
        / "srv_crypto"


def run(*args):
    """Run one servant call. Returns (rc, [stdout lines], stderr).

    Raises BridgeError if the binary is absent (loud, not silent).
    Protocol failures surface as nonzero rc (adapter codes) — callers
    branch on rc, never on exceptions, for expected outcomes.
    """
    exe = _binary()
    if not exe.exists():
        raise BridgeError(f"servant missing: {exe} (build it)")
    p = subprocess.run(
        [str(exe), *[str(a) for a in args]],
        capture_output=True, text=True, timeout=180,
    )
    return p.returncode, p.stdout.split(), p.stderr


def hx(b: bytes) -> str:
    return b.hex()


def unhx(s: str) -> bytes:
    return bytes.fromhex(s)


def sizes(kind, level):
    """Live level sizes from the adapters: (pk, sk, ct_or_sig)."""
    rc, out, _ = run("sizes", kind, str(level))
    if rc != 0 or len(out) != 3:
        raise BridgeError(f"sizes failed: {kind} {level}")
    return int(out[0]), int(out[1]), int(out[2])


def sha256(data: bytes) -> bytes:
    rc, out, _ = run("sha256", hx(data))
    if rc != 0:
        raise BridgeError("sha256 failed")
    return unhx(out[0])


def hmac(key: bytes, msg: bytes) -> bytes:
    rc, out, _ = run("hmac", hx(key), hx(msg))
    if rc != 0:
        raise BridgeError("hmac failed")
    return unhx(out[0])


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    rc, out, _ = run("hkdf-extract", hx(salt), hx(ikm))
    if rc != 0:
        raise BridgeError("hkdf-extract failed")
    return unhx(out[0])


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    rc, out, _ = run("hkdf-expand", hx(prk), hx(info), str(length))
    if rc != 0:
        raise BridgeError("hkdf-expand failed")
    return unhx(out[0])
