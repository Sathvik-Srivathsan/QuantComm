"""Fragmentation/reassembly (B-42.4): MTU-bounded split, keyed join.

Wire format (all big-endian, exact), kind-flagged (audit-mandated:
length-based first/other discrimination aliased middle fragments as
index-0 whenever their bytes 6:8 were zero — a data-dependent black
hole caught pre-commit; the flag byte makes misparse structurally
impossible for well-formed traffic, garbage still fails closed):
first fragment = kind u8 (0x00) || total u32 || count u16 || index u16
(0) || payload; other fragments = kind u8 (0x01) || index u16 ||
payload. Payloads sized so each fragment fits MTU. Fragments carry NO
auth (order: reassemble, then AEAD verify downstream; garbage dies at
verify — never here).

Reassembly keyed by (peer, epoch, counter); the counter rides inside
the FIRST fragment's embedded frame header, so out-of-order non-zero
fragments park in a bounded orphan pen until index 0 lands (documented
mechanism, not an afterthought). First payloads below 26 B (sub-35B
MTUs, e.g. BLE-20) cannot carry the counter: content-hash fallback
keys those slots (distinct frames key distinctly; see helper).
Rules: timeout drop + counter; slot
and gateway-wide bounds with oldest-incomplete-first drop; duplicate
index first-wins (counted, never overwrite-poisoned); interleaved
frames get independent slots; count/index structural mismatches drop;
total over max-frame drops pre-buffer (B-20.1 single source, passed in
— never copied here); pre-verify work is memcpy plus compare only.
"""

import hashlib

_FIRST_HDR = 9  # kind u8 + total u32 + count u16 + index u16
_OTHER_HDR = 3  # kind u8 + index u16
_KIND_FIRST = 0
_KIND_OTHER = 1
_COUNTER_FLOOR = 26  # payload bytes needed to read the [18:26] counter


def _fallback_counter(total, count, payload):
    """Slot key when the counter is unreadable (first payload < 26 B,
    i.e. MTU below ~35 B — the coming BLE-20B reality).

    Hash of (total, count, payload): distinct frames key distinctly
    (same-size pipelined traffic completes independently); identical
    interleaved frames may merge or drop via timeout (fail-safe:
    misassembly dies at AEAD verify downstream, never delivers
    silently). Collision with a parsed counter int is ~2^-64 per pair
    and equally benign. Deterministic across runs and platforms.
    """
    h = hashlib.sha256()
    h.update(total.to_bytes(4, "big"))
    h.update(count.to_bytes(2, "big"))
    h.update(payload)
    return int.from_bytes(h.digest()[:8], "big")


def split_frame(frame, mtu, max_frame):
    """Split one frame into MTU-fit fragments. Returns [bytes].

    Raises ValueError on: empty frame, mtu below first-header size,
    frame over max_frame (rejected pre-fragment, never fragmented).
    max_frame arrives from the caller (B-20.1 single source).
    """
    if not isinstance(frame, (bytes, bytearray)) or len(frame) == 0:
        raise ValueError("frame must be nonempty bytes")
    frame = bytes(frame)
    if mtu < _FIRST_HDR + 1:
        raise ValueError("mtu below first-fragment header")
    if len(frame) > max_frame:
        raise ValueError("oversize frame refused pre-fragment")
    first_cap = mtu - _FIRST_HDR
    other_cap = mtu - _OTHER_HDR
    chunks = [frame[0:first_cap]]
    rest = frame[first_cap:]
    while rest:
        chunks.append(rest[:other_cap])
        rest = rest[other_cap:]
    total = len(frame)
    count = len(chunks)
    if count > 0xFFFF:
        raise ValueError("frame needs more fragments than countable")
    out = [bytes([_KIND_FIRST]) + total.to_bytes(4, "big") +
           count.to_bytes(2, "big") + (0).to_bytes(2, "big") + chunks[0]]
    for i in range(1, count):
        out.append(bytes([_KIND_OTHER]) + i.to_bytes(2, "big") +
                   chunks[i])
    return out


class Reassembler:
    """Keyed reassembly with timeouts and bounds (see module doc)."""

    def __init__(self, max_frame, timeout_s=5.0, max_slots=16,
                 max_orphans=16):
        if max_frame <= 0 or timeout_s <= 0:
            raise ValueError("max_frame/timeout must be positive")
        if max_slots < 1 or max_orphans < 1:
            raise ValueError("bounds must be >= 1")
        self._max_frame = max_frame
        self._timeout = timeout_s
        self._max_slots = max_slots
        self._max_orphans = max_orphans
        self._slots = {}   # (peer, epoch, counter) -> slot dict
        self._orphans = {}  # (peer, epoch) -> list of (index, payload)
        # Graveyard: consumed (peer, epoch, idx, sha256) -> arrival order.
        # Kills the dup-after-complete poison vector (audit-found): an
        # orphan byte-identical to consumed data is a TRUE replay and
        # drops, instead of being adopted into the next frame's slot
        # (which delivered wrong-but-well-formed bytes). Known corner,
        # documented: byte-identical frags across DIFFERENT live frames
        # (e.g. shared zero runs) also drop here — fail-safe (timeout +
        # counters, never corruption); entries expire with sweep so the
        # window of over-matching stays one timeout wide.
        self._graveyard = {}
        self._grave_seq = 0
        self.counters = {
            "completed": 0,
            "timeout_drops": 0,
            "bound_drops": 0,
            "duplicates": 0,
            "malformed": 0,
            "oversize": 0,
        }

    def _evict_oldest(self):
        oldest, oldest_at = None, None
        for key, slot in self._slots.items():
            if oldest_at is None or slot["first_at"] < oldest_at:
                oldest, oldest_at = key, slot["first_at"]
        if oldest is not None:
            del self._slots[oldest]
            self.counters["bound_drops"] += 1

    def feed(self, peer, epoch, frag, now=0.0):
        """Feed one fragment. Returns (status, frame|None).

        Status: complete / incomplete / drop-malformed / drop-oversize
        / drop-timeout. Counter 0 frames embed peer/epoch/counter from
        their frame header (74 B layout: identity[16], cls, level,
        counter u64 at [18:26]).
        """
        if not isinstance(peer, (bytes, bytearray)) or \
                not isinstance(frag, (bytes, bytearray)):
            return "drop-malformed", None
        peer = bytes(peer)
        frag = bytes(frag)
        # Expire one overdue slot opportunistically (full sweep below).
        self.sweep(now)
        if len(frag) < 1:
            self.counters["malformed"] += 1
            return "drop-malformed", None
        kind = frag[0]
        if kind == _KIND_FIRST:
            if len(frag) < _FIRST_HDR + 1:
                self.counters["malformed"] += 1
                return "drop-malformed", None
            total = int.from_bytes(frag[1:5], "big")
            count = int.from_bytes(frag[5:7], "big")
            idx = int.from_bytes(frag[7:9], "big")
            if idx != 0:
                # Flag says first but index disagrees: corrupt.
                self.counters["malformed"] += 1
                return "drop-malformed", None
        elif kind == _KIND_OTHER:
            if len(frag) < _OTHER_HDR:
                self.counters["malformed"] += 1
                return "drop-malformed", None
            total, count = None, None
            idx = int.from_bytes(frag[1:3], "big")
        else:
            self.counters["malformed"] += 1
            return "drop-malformed", None
        if idx == 0:
            if total is None or count == 0 or count > 0xFFFF:
                self.counters["malformed"] += 1
                return "drop-malformed", None
            if total > self._max_frame:
                self.counters["oversize"] += 1
                return "drop-oversize", None
            if total == 0 or total > self._max_frame:
                self.counters["oversize" if total > self._max_frame
                              else "malformed"] += 1
                return ("drop-oversize" if total > self._max_frame
                        else "drop-malformed"), None
            payload = frag[_FIRST_HDR:]
            if len(payload) > total:
                self.counters["malformed"] += 1
                return "drop-malformed", None
            if len(payload) >= _COUNTER_FLOOR:
                counter = int.from_bytes(payload[18:26], "big")
            else:
                counter = _fallback_counter(total, count, payload)
            key = (peer, epoch, counter)
            slot = self._slots.get(key)
            if slot is None:
                while len(self._slots) >= self._max_slots:
                    self._evict_oldest()
                slot = {"total": total, "count": count, "parts": {},
                        "first_at": now, "deadline": now + self._timeout}
                self._slots[key] = slot
            else:
                if slot["total"] != total or slot["count"] != count:
                    self.counters["malformed"] += 1
                    return "drop-malformed", None
            if 0 in slot["parts"]:
                self.counters["duplicates"] += 1
            else:
                slot["parts"][0] = payload
            # Adopt parked orphans for this key. Attribution risk when
            # frames interleave under reorder (an orphan may belong to a
            # sibling frame): ACCEPTED because misassembly dies at AEAD
            # verify downstream (fail-safe), while refusing adoption
            # would break every legitimately reordered single frame.
            # Graveyard filter (dup-after-complete poison fix): a parked
            # orphan byte-identical to consumed data is a TRUE replay —
            # drop it instead of adopting it into the next frame's slot
            # (which delivered wrong-but-well-formed bytes pre-fix).
            for o_idx, o_pay, _ in self._orphans.pop((peer, epoch), []):
                o_hash = hashlib.sha256(o_pay).digest()
                if (peer, epoch, o_idx, o_hash) in self._graveyard:
                    self.counters["duplicates"] += 1
                    continue
                if o_idx < count and o_idx not in slot["parts"]:
                    slot["parts"][o_idx] = o_pay
                else:
                    self.counters["duplicates"] += 1
            return self._try_complete(key, slot, peer, epoch, now)
        # Non-zero index: need a slot (else park as orphan).
        # Counter unknown without index 0 — park first, key later.
        # Order matters (audit fix v2): live slot needing this idx wins
        # first — shared-tail siblings (identical bytes across different
        # live frames, e.g. zero runs) must deliver to the waiter, not
        # drop as replays. Only when NO live slot needs idx do the
        # duplicate/replay checks run: idx already in a live slot is
        # first-wins (pre-fix these parked and poisoned the NEXT frame),
        # byte-identical to consumed data is a TRUE replay and drops
        # (dup-after-complete tail would otherwise park then adopt into
        # the next frame). Both drop as duplicates, never park.
        found = None
        for key, slot in self._slots.items():
            if key[0] == peer and key[1] == epoch and \
                    idx < slot["count"] and idx not in slot["parts"]:
                found = (key, slot)
                break
        if found is not None:
            key, slot = found
            slot["parts"][idx] = frag[_OTHER_HDR:]
            return self._try_complete(key, slot, peer, epoch, now)
        for _key, _slot in self._slots.items():
            if _key[0] == peer and _key[1] == epoch and \
                    idx in _slot["parts"]:
                self.counters["duplicates"] += 1
                return "incomplete", None
        _pay = frag[_OTHER_HDR:]
        _h = hashlib.sha256(_pay).digest()
        if (peer, epoch, idx, _h) in self._graveyard:
            self.counters["duplicates"] += 1
            return "incomplete", None
        pen = self._orphans.setdefault((peer, epoch), [])
        for o_idx, _, _ in pen:
            if o_idx == idx:
                self.counters["duplicates"] += 1
                return "incomplete", None
        pen.append((idx, frag[_OTHER_HDR:], now))
        while len(pen) > self._max_orphans:
            pen.pop(0)
            self.counters["bound_drops"] += 1
        return "incomplete", None

    def _try_complete(self, key, slot, peer, epoch, now):
        if len(slot["parts"]) != slot["count"]:
            return "incomplete", None
        frame = b"".join(slot["parts"][i]
                          for i in range(slot["count"]))
        if len(frame) != slot["total"]:
            self.counters["malformed"] += 1
            del self._slots[key]
            return "drop-malformed", None
        del self._slots[key]
        # Record consumed fragments in the graveyard so dup-after-complete
        # tails drop as replays instead of poisoning the next frame.
        # Cap the graveyard (oldest-seq-first) to keep memory bounded.
        for _idx, _pay in slot["parts"].items():
            _h = hashlib.sha256(_pay).digest()
            self._graveyard[(peer, epoch, _idx, _h)] = \
                (self._grave_seq, now)
            self._grave_seq += 1
        while len(self._graveyard) > max(64, self._max_orphans * 8):
            _oldest, _ = min(self._graveyard.items(),
                             key=lambda kv: kv[1][0])
            del self._graveyard[_oldest]
        self.counters["completed"] += 1
        return "complete", frame

    def sweep(self, now=0.0):
        """Drop overdue slots AND stale orphans. Returns expired count."""
        expired = 0
        for key in [k for k, s in self._slots.items()
                    if now >= s["deadline"]]:
            del self._slots[key]
            expired += 1
        for penkey in list(self._orphans):
            pen = [(i, p, a) for (i, p, a) in self._orphans[penkey]
                   if now - a < self._timeout]
            dropped = len(self._orphans[penkey]) - len(pen)
            if dropped:
                expired += dropped
            if pen:
                self._orphans[penkey] = pen
            else:
                del self._orphans[penkey]
        # Graveyard entries expire silently after one timeout (window of
        # over-matching stays one timeout wide; no counter — expiry is
        # housekeeping, not a drop).
        for gkey in [k for k, (_, at) in self._graveyard.items()
                     if now - at >= self._timeout]:
            del self._graveyard[gkey]
        self.counters["timeout_drops"] += expired
        return expired
