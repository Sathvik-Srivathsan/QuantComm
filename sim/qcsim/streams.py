"""Seeded RNG sub-streams (B-43.1): domain-separated, never shared.

Seed is 128-bit, recorded hex (32 lowercase hex chars). Per-model
sub-streams via domain-separated SHA-256 expansion over labels
("device", "network", "attacker", "generator" — the spec's four
domains; extra labels allowed but each gets an independent counter,
so no two models ever share draws). Counter-mode: block = SHA-256
(key || counter_u64be), key = SHA-256(seed || b"|" || label).

Same seed + same code version gives bit-identical draws (the
determinism test proves it). The ONLY os.urandom call in the sim
lives in RNGStreams.from_os (the seeder); every other draw is
counter-mode SHA-256. The banned-call scan test enforces this.
"""

import hashlib
import os

LABELS = ("device", "network", "attacker", "generator")


def _u64(b):
    return int.from_bytes(b[:8], "big")


class RNGStreams:
    """Four (or more) independent deterministic byte streams."""

    def __init__(self, seed_hex):
        if not isinstance(seed_hex, str) or len(seed_hex) != 32:
            raise ValueError("seed_hex must be 32 hex chars (128-bit)")
        try:
            seed = bytes.fromhex(seed_hex)
        except ValueError:
            raise ValueError("seed_hex must be hex")
        if len(seed) != 16:
            raise ValueError("seed must decode to 16 bytes")
        self._seed_hex = seed_hex.lower()
        self._keys = {}
        self._counters = {}
        for label in LABELS:
            self._keys[label] = hashlib.sha256(
                seed + b"|" + label.encode()).digest()
            self._counters[label] = 0

    @classmethod
    def from_os(cls):
        """Mint a fresh 128-bit seed from OS entropy (the seeder).

        The sole os.urandom call in the sim — recorded hex goes into
        the run manifest per B-43.1.
        """
        return cls(os.urandom(16).hex())

    @property
    def seed_hex(self):
        return self._seed_hex

    def _key(self, label):
        if label not in self._keys:
            seed = bytes.fromhex(self._seed_hex)
            self._keys[label] = hashlib.sha256(
                seed + b"|" + label.encode()).digest()
            self._counters[label] = 0
        return self._keys[label]

    def next_bytes(self, label, n):
        """Draw n deterministic bytes from a label's stream."""
        if not isinstance(n, int) or n <= 0:
            raise ValueError("n must be a positive int")
        key = self._key(label)
        out = bytearray()
        while len(out) < n:
            ctr = self._counters[label]
            out.extend(hashlib.sha256(
                key + ctr.to_bytes(8, "big")).digest())
            self._counters[label] = ctr + 1
        return bytes(out[:n])

    def next_u64(self, label):
        """Draw one deterministic uint64 from a label's stream."""
        return _u64(self.next_bytes(label, 8))

    def next_uniform(self, label):
        """Draw one deterministic float in [0, 1) from a label's stream."""
        return self.next_u64(label) / 2.0**64
