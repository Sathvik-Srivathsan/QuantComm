"""Ceremony helpers (B-41 procedures as executable steps). TEST-SIDE.

Scope boundaries (deliberate, documented):
- Device NVS here is a local FILE (write/readback/verify discipline is
  under test; byte-format fidelity belongs to the C store tests, which
  own the format — this file never reimplements it).
- KdevSlots models the B-41.3 two-slot swap DISCIPLINE for host-side
  proof (single-active, staged-never-authenticates, confirm-timeout,
  erase-verify, power-loss atomicity). Device firmware ports the model
  later (B-60); the discipline, not the bytes, is what's pinned here.
- Wrap/unwrap use the servant (identical AEAD/HKDF, never reimplemented).
- Manifest issue/verify go through the policy verb + servant (the
  rotation manifest is real, signed, version-gated).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "server"))

from qcsrv.policy import srv_policy  # noqa: E402
from test_srv_crypto import hx, run  # noqa: E402

_ZERO32 = bytes(32)


class DeviceNVS:
    """File-backed NVS stand-in with fault injection."""

    def __init__(self, path):
        self.path = Path(path)
        self.fail_write = False
        self.corrupt_read = False

    def write(self, blob: bytes):
        if self.fail_write:
            return False
        self.path.write_bytes(bytes(blob))
        return True

    def read(self):
        if not self.path.exists():
            return None
        data = self.path.read_bytes()
        if self.corrupt_read and data:
            bad = bytearray(data)
            bad[0] ^= 1
            return bytes(bad)
        return data

    def wipe(self):
        """Secure erase (zeros + readback proof)."""
        if not self.path.exists():
            return True
        size = self.path.stat().st_size
        self.path.write_bytes(bytes(size))
        return self.path.read_bytes() == bytes(size)


class KdevSlots:
    """Two-slot Kdev discipline (B-41.3): exactly one active Kdev;
    staged keys never authenticate; confirm atomically swaps; timeout
    keeps the old; erase is readback-verified."""

    def __init__(self):
        self.slots = [None, None]
        self.dead = [False, False]
        self.active = 0

    def provision(self, kdev: bytes):
        assert len(kdev) == 32
        self.slots[0] = bytes(kdev)
        self.slots[1] = None
        self.dead = [False, False]
        self.active = 0

    def active_key(self):
        """The ONLY key the device authenticates with (or None)."""
        if self.dead[self.active]:
            return None
        return self.slots[self.active]

    def stage(self, kdev: bytes):
        """Write the inactive slot (never authenticates while staged)."""
        assert len(kdev) == 32
        other = 1 - self.active
        if self.dead[other]:
            return False
        self.slots[other] = bytes(kdev)
        return True

    def staged(self):
        return self.slots[1 - self.active]

    def confirm(self):
        """Atomic swap: old slot invalidated + zeroized (verified)."""
        other = 1 - self.active
        if self.slots[other] is None:
            return False
        self.slots[self.active] = None
        self.dead[self.active] = True
        # Readback proof of erasure (model: slot must read dead/empty).
        if self.slots[self.active] is not None:
            return False
        self.active = other
        return True

    def confirm_timeout(self):
        """Staged discarded, old stays live (no lockout)."""
        other = 1 - self.active
        self.slots[other] = None
        return self.active_key() is not None

    def snapshot(self):
        """Persisted image (power-loss simulation source)."""
        return {
            "slots": [bytes(s) if s else None for s in self.slots],
            "dead": list(self.dead),
            "active": self.active,
        }

    def restore(self, snap):
        self.slots = [bytes(s) if s else None for s in snap["slots"]]
        self.dead = list(snap["dead"])
        self.active = snap["active"]


def wrap_kdev(session_prk: bytes, device_id: bytes, manifest_version: int,
              new_kdev: bytes, nonce: bytes):
    """B-41.3 wrap: key = Expand(PRK, QC-ROTATE||id); AAD = id||version.
    Returns (nonce, ct, tag). Caller supplies nonce (explicit coins)."""
    rc, out, _ = run(
        "hkdf-expand", session_prk.hex(),
        hx(b"QC-ROTATE" + device_id), "32")
    assert rc == 0, "wrap key derivation failed"
    wkey = bytes.fromhex(out[0])
    aad = device_id + manifest_version.to_bytes(4, "big")
    rc, out, _ = run("aead-enc", wkey.hex(), nonce.hex(), aad.hex(),
                     new_kdev.hex())
    assert rc == 0, "wrap encrypt failed"
    return nonce, bytes.fromhex(out[0]), bytes.fromhex(out[1])


def unwrap_kdev(session_prk: bytes, device_id: bytes, manifest_version: int,
                nonce: bytes, ct: bytes, tag: bytes):
    """Inverse of wrap_kdev. Returns new Kdev or None (auth fail)."""
    rc, out, _ = run(
        "hkdf-expand", session_prk.hex(),
        hx(b"QC-ROTATE" + device_id), "32")
    assert rc == 0
    wkey = bytes.fromhex(out[0])
    aad = device_id + manifest_version.to_bytes(4, "big")
    rc, out, _ = run("aead-dec", wkey.hex(), nonce.hex(), aad.hex(),
                     ct.hex(), tag.hex())
    if rc != 0:
        return None
    return bytes.fromhex(out[0])


def version_carry(device_version, server_max):
    """B-41.2 carry rule: readable -> max(device, server); loss (None)
    -> server_max + 1. Never provisions below a known max."""
    if device_version is None:
        if server_max < 0:
            raise ValueError("server_max must be >= 0")
        return server_max + 1
    if device_version < 1:
        raise ValueError("device version must be >= 1")
    return max(device_version, server_max)
