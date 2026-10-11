"""Telemetry ingress verb (B-40.3): AEAD open + window + ratchet receive.

Per frame: parse header (74 B layout per B-24.1) -> entry lookup ->
AEAD decrypt under the directional key (servant, identical impl) ->
counter/window check (B-23.2: high-water advance, in-window duplicates
dropped, below-lowest dropped) -> ratchet advance (below) -> reading
(device, class, counter, payload) to the caller.

Ratchet mapping (advance-every-message): frame counter c decrypts
under chain index r = c+1 (generation-0 session keys seed only, never
traffic). Fast-forward on counter jumps bounded by max-skip 16
(provisional, B-26); over-skip rejects (resync orchestration is
future). r <= ratchet_r (late gap-fills past erasure) drops stale:
skipped states never persist (forward secrecy), so late frames are
unreadable by design — documented tension with reorder tolerance,
resolved per the erasure rule. Full skip-ahead from wire r awaits the
B-24.1 r field (documented gap, behavior-preserving until then).

Return (disposition, reading|None). Plaintext leaves ONLY as the
returned reading (caller's sink duty) — never logged, never stored
(no-plaintext contract). Direction selects the key (c2s/s2c).
C2 prioritization is a batch concern (single-frame API: no-op here).
"""
import asyncio
import logging
from collections import OrderedDict

from . import _bridge as B
from .registry import Registry

log = logging.getLogger(__name__)

_HDR_LEN = 74
_PLEN_OFF = 74
_TAG_LEN = 16
_WINDOW_SPAN = 128  # provisional (B-23.2 window default)
_MAX_SKIP = 16      # provisional (B-26 max-skip default)


def _be64(b):
    return int.from_bytes(b, "big")


async def srv_ingest(frame, ctx, *, direction="c2s", now=0.0):
    """Ingest one protected frame. See module docstring."""
    if not isinstance(frame, (bytes, bytearray)):
        return "drop-malformed", None
    frame = bytes(frame)
    registry = ctx.get("registry")
    if not isinstance(registry, Registry):
        raise ValueError("ctx['registry'] must be a Registry")
    if len(frame) < _HDR_LEN + 4 + _TAG_LEN:
        return "drop-malformed", None
    hdr = frame[:_HDR_LEN]
    cls, level = hdr[16], hdr[17]
    if cls not in (0, 1, 2) or level not in (1, 2, 3):
        return "drop-malformed", None
    counter = _be64(hdr[18:26])
    plen = int.from_bytes(frame[_PLEN_OFF:_PLEN_OFF + 4], "big")
    if plen > 65535 or len(frame) != _HDR_LEN + 4 + plen + _TAG_LEN:
        return "drop-malformed", None
    identity = hdr[0:16]
    code, entry = await registry.admit(identity, ctx.get("config", "E2E"))
    if code != "ok":
        return code, None
    keys = entry.session_keys
    want = "k_c2s" if direction == "c2s" else "k_s2c" if \
        direction == "s2c" else None
    if want is None or want not in keys or len(keys[want]) != 32:
        return "drop-nokey", None
    # Session liveness: no chain and no K_rat means pre-handshake.
    if not entry.r_chain and "k_rat" not in keys:
        return "drop-nokey", None
    # Ordering rationale (audited): counter-gating precedes crypto.
    # Duplicates are undecryptable post-erasure (their keys are gone by
    # forward-secrecy design), so a decrypt-first order could never
    # report drop-duplicate correctly — the B-40.3 prose order is read
    # as component listing, with replay gating first (matches B-23.2
    # intent and the C server's observable dispositions).
    async with entry.lock:
        if counter in entry.window:
            ctx.setdefault("_counters", {}).setdefault("dup", 0)
            ctx["_counters"]["dup"] += 1
            return "drop-duplicate", None
        if counter <= entry.window_high:
            ctx.setdefault("_counters", {}).setdefault("stale", 0)
            ctx["_counters"]["stale"] += 1
            return "drop-stale", None
    # Ratchet to r = counter+1 (generation-0 session keys seed only).
    # Derived into LOCALS — commit happens only after a successful
    # decrypt (failed auth must not advance chain state).
    r_target = counter + 1
    steps = r_target - entry.ratchet_r
    if steps > _MAX_SKIP:
        ctx.setdefault("_counters", {}).setdefault("overskip", 0)
        ctx["_counters"]["overskip"] += 1
        log.info("frame %s ctr=%d disposition=drop-overskip",
                 identity.hex(), counter)
        return "drop-overskip", None
    if steps <= 0:
        # Unreachable (window admitted only strictly-greater counters)
        # — defensive, never silent.
        ctx.setdefault("_counters", {}).setdefault("stale", 0)
        ctx["_counters"]["stale"] += 1
        return "drop-stale", None
    chain = entry.r_chain if entry.r_chain else keys["k_rat"]
    r_walk = entry.ratchet_r
    try:
        for _ in range(steps):
            r_walk += 1
            blob = B.hkdf_expand(
                chain, b"ratchet" + r_walk.to_bytes(8, "big"), 96)
            chain = blob[0:32]
            k_msg = (blob[32:64], blob[64:96])
            del blob
    except B.BridgeError:
        return "drop-auth", None
    # At this point k_msg is always set (steps >= 1 above).
    epoch_b = entry.epoch_last.to_bytes(4, "big")
    nonce = epoch_b + counter.to_bytes(8, "big")
    ct = frame[_HDR_LEN + 4:_HDR_LEN + 4 + plen]
    tag = frame[_HDR_LEN + 4 + plen:]
    k_use = k_msg[0] if direction == "c2s" else k_msg[1]
    rc, out, _ = B.run("aead-dec", k_use.hex(), nonce.hex(), hdr.hex(),
                    ct.hex(), tag.hex())
    if rc != 0:
        ctx.setdefault("_counters", {}).setdefault("auth-fail", 0)
        ctx["_counters"]["auth-fail"] += 1
        log.info("frame %s ctr=%d disposition=drop-auth",
                 identity.hex(), counter)
        return "drop-auth", None
    async with entry.lock:
        pt = B.unhx(out[0])
        entry.window.add(counter)
        entry.window_high = counter
        while len(entry.window) > _WINDOW_SPAN:
            entry.window.discard(min(entry.window))
        entry.r_chain = chain
        entry.ratchet_r = r_walk
        entry.last_contact = now
    reading = {
        "device": identity.hex(),
        "class": cls,
        "counter": counter,
        "payload": pt,
    }
    return "ok", reading
