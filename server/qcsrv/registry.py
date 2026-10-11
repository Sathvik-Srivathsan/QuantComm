"""Session registry (B-40.1): device entries keyed by 16-B ID.

Admission precedes the pipeline (unknown/blacklisted/cross-config/full
refusals here, never inside it). Eviction is idle-timeout only — a full
registry of live entries refuses (fail-closed) rather than evicting live
entries to make room. Silence is computed, never sensed: past-interval
entries flag + report with durations, zero device cost.

Concurrency shape per spec: one global asyncio.Lock for
admit/enroll/evict (check-insert-evict atomicity) plus a per-entry lock
for state mutation (lock order global-then-entry, single direction).
Timestamps are caller clocks (opaque seconds); tests use fixed values.
Session keys live in entry RAM only (never logged/exported — the
no-plaintext test enforces this at the stores, not here).
"""
import asyncio
from dataclasses import dataclass, field

from . import _bridge as _B


@dataclass
class RegistryEntry:
    device_id: bytes
    epoch_last: int = 0
    session_keys: dict = field(default_factory=dict)
    counters: dict = field(
        default_factory=lambda: {"c2s": 0, "s2c": 0}
    )
    window: set = field(default_factory=set)
    window_high: int = -1
    ratchet_r: int = 0
    manifest_ver: int = 0
    audit_seq: int = 0
    # Handshake replay bar + ratchet chain (chunk-2 additive fields,
    # defaults keep old constructions valid; epoch_last stays the
    # liveness/attestation horizon, hs_* gate handshakes only).
    hs_epoch: int = 0
    hs_counter: int = 0
    r_chain: bytes = b""
    config: str = "E2E"
    blacklisted: bool = False
    last_contact: float = 0.0
    interval: float = 0.0
    silence: bool = False
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)


class Registry:
    """In-memory device registry (see module docstring for rules)."""

    def __init__(self, capacity, idle_timeout_s):
        if capacity <= 0 or idle_timeout_s <= 0:
            raise ValueError("capacity/timeout must be positive")
        self._capacity = capacity
        self._idle_timeout = idle_timeout_s
        self._entries = {}
        self._tombstones = set()
        self._lock = asyncio.Lock()
        self.counters = {
            "unknown_drops": 0,
            "blacklist_drops": 0,
            "config_drops": 0,
            "full_refusals": 0,
            "tombstone_refusals": 0,
            "evictions": 0,
        }

    def _check_id(self, device_id):
        if not isinstance(device_id, (bytes, bytearray)) or \
                len(device_id) != 16:
            raise ValueError("device_id must be 16 bytes")

    async def enroll(self, device_id, config="E2E", now=0.0,
                     interval=0.0):
        """Provision an entry (B-41 calls this, not the pipeline)."""
        self._check_id(device_id)
        if config not in ("E2E", "trusted-gateway"):
            raise ValueError("unknown deployment config")
        key = bytes(device_id)
        async with self._lock:
            if key in self._entries:
                return "exists"
            if key in self._tombstones:
                self.counters["tombstone_refusals"] += 1
                return "refuse-tombstoned"
            if len(self._entries) >= self._capacity:
                self.counters["full_refusals"] += 1
                return "refuse-full"
            self._entries[key] = RegistryEntry(
                device_id=key, config=config, last_contact=now,
                interval=interval,
            )
            return "ok"

    async def admit(self, device_id, config_attempt="E2E"):
        """Pre-pipeline gate: entry or drop code (never raises)."""
        self._check_id(device_id)
        key = bytes(device_id)
        async with self._lock:
            ent = self._entries.get(key)
            if ent is None:
                self.counters["unknown_drops"] += 1
                return "drop-unknown", None
            if ent.blacklisted:
                self.counters["blacklist_drops"] += 1
                return "drop-blacklisted", None
            if ent.config != config_attempt:
                self.counters["config_drops"] += 1
                return "drop-config", None
            return "ok", ent

    async def blacklist(self, device_id, flag=True):
        self._check_id(device_id)
        async with self._lock:
            ent = self._entries.get(bytes(device_id))
            if ent is None:
                return False
            ent.blacklisted = bool(flag)
            return True

    async def heartbeat(self, device_id, now, epoch=None):
        """Contact tick (advances last-contact; optionally epoch)."""
        self._check_id(device_id)
        async with self._lock:
            ent = self._entries.get(bytes(device_id))
            if ent is None:
                return False
            ent.last_contact = now
            ent.silence = False
            if epoch is not None:
                ent.epoch_last = epoch
            return True

    def next_audit_seq(self, entry):
        """Per-device monotonic audit seq (persisted in the entry).

        Atomic under asyncio (no awaits inside); callers with real
        threads must hold entry.lock (audit: single-threaded use only).
        """
        entry.audit_seq += 1
        return entry.audit_seq

    async def evict_idle(self, now):
        """Evict idle-past-timeout entries; returns their IDs."""
        evicted = []
        async with self._lock:
            for key, ent in list(self._entries.items()):
                if now - ent.last_contact > self._idle_timeout:
                    del self._entries[key]
                    evicted.append(key)
            self.counters["evictions"] += len(evicted)
        return evicted

    async def silence_check(self, now):
        """Flag + report entries past their report interval."""
        late = []
        async with self._lock:
            for key, ent in self._entries.items():
                if ent.interval > 0 and \
                        now - ent.last_contact > ent.interval:
                    ent.silence = True
                    late.append((key, now - ent.last_contact))
        return late

    def __len__(self):
        return len(self._entries)

    def get(self, device_id):
        """Test/debug lookup (returns the live entry or None)."""
        self._check_id(device_id)
        return self._entries.get(bytes(device_id))

    async def rollback_enroll(self, device_id):
        """Undo a provisioning enrollment (ceremony abort path).

        Unlike decommission, this does NOT tombstone: a rolled-back ID
        may be enrolled fresh later. Returns True if an entry existed.
        """
        self._check_id(device_id)
        async with self._lock:
            return self._entries.pop(bytes(device_id), None) is not None

    async def decommission(self, device_id):
        """Retire an ID forever: delete the entry + tombstone it.

        Retired IDs are never reassigned (re-enroll of a tombstoned ID
        refuses). Returns True if an entry existed.
        """
        self._check_id(device_id)
        key = bytes(device_id)
        async with self._lock:
            existed = self._entries.pop(key, None) is not None
            self._tombstones.add(key)
            return existed


class CredentialStore:
    """Server Kdev custody (B-41.2): AES-GCM under a store master key.

    Role-separated access (PAPER-PARAM policy, enforced here):
    provisioning may read/write/delete, handshake may read, audit may
    do nothing (records carry hashes, never keys). Violations raise
    PermissionError (operator/caller bug, never a protocol outcome).
    Nonces are explicit caller coins (12 B, derand discipline — tests
    fixed, prod from servant rng). Entries bind AAD=device-ID (a blob
    copied under another ID fails closed). Master key held, never
    logged, never exported (B-41 custody boundary).
    """

    _ROLES = {
        "provisioning": frozenset({"read", "write", "delete"}),
        "handshake": frozenset({"read"}),
        "audit": frozenset(),
    }

    def __init__(self, master_key):
        if not isinstance(master_key, (bytes, bytearray)) or \
                len(master_key) != 32:
            raise ValueError("master key must be 32 bytes")
        self._master = bytes(master_key)
        self._blobs = {}

    def _need(self, role, op):
        if role not in self._ROLES or op not in self._ROLES[role]:
            raise PermissionError(f"role {role!r} may not {op}")

    @staticmethod
    def _check_id(device_id):
        if not isinstance(device_id, (bytes, bytearray)) or \
                len(device_id) != 16:
            raise ValueError("device_id must be 16 bytes")

    def put(self, device_id, kdev, role, nonce):
        """Store Kdev (encrypts). Returns True."""
        self._check_id(device_id)
        if not isinstance(kdev, (bytes, bytearray)) or len(kdev) != 32:
            raise ValueError("kdev must be 32 bytes")
        if not isinstance(nonce, (bytes, bytearray)) or \
                len(nonce) != 12:
            raise ValueError("nonce must be 12 bytes")
        self._need(role, "write")
        rc, out, _ = _B.run("aead-enc", self._master.hex(),
                            bytes(nonce).hex(), bytes(device_id).hex(),
                            bytes(kdev).hex())
        if rc != 0:
            raise ValueError("store seal failed")
        self._blobs[bytes(device_id)] = (
            bytes(nonce), bytes.fromhex(out[0]), bytes.fromhex(out[1]))
        return True

    def get(self, device_id, role="handshake"):
        """Fetch Kdev (decrypts) or None if absent."""
        self._check_id(device_id)
        self._need(role, "read")
        blob = self._blobs.get(bytes(device_id))
        if blob is None:
            return None
        nonce, ct, tag = blob
        rc, out, _ = _B.run(
            "aead-dec", self._master.hex(), nonce.hex(),
            bytes(device_id).hex(), ct.hex(), tag.hex())
        if rc != 0:
            raise ValueError("store open failed (tamper/wrong key)")
        return bytes.fromhex(out[0])

    def delete(self, device_id, role):
        """Drop an entry. Returns True if one existed."""
        self._check_id(device_id)
        self._need(role, "delete")
        return self._blobs.pop(bytes(device_id), None) is not None
