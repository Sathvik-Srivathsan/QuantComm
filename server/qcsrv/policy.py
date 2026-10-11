"""Policy authority verb (B-40.2): manifest issuance + divergence.

Single dispatch verb (lean surface): op issue/check/repin.
- issue: canonical-encode fields (B-25 schema, structural validation
  here), sign via the servant under the caller-held server key, bump
  the monotonic issuance record. Never re-signs older-or-equal
  (refuse-stale); signing failure emits nothing (fail-sign).
- check: device-reported version vs issued — behind gets current
  (catch-up issuance happens via issue), ahead holds + alarm counter
  (never downgrade issuance).
- repin: replace the signing-key handle (B-41 rotation ceremony owns
  the ceremony; this stores the outcome, never generates keys).

Custody boundary: the key handle arrives per call / at repin and is
never generated, cached beyond the handle object, or logged (B-41
owns custody; the no-plaintext test covers the stores).
"""
import asyncio
import logging

from . import _bridge as B

log = logging.getLogger(__name__)

_MAX_BODY = 4096


def _u16(n):
    return n.to_bytes(2, "big")


def _u32(n):
    return n.to_bytes(4, "big")


def encode_manifest(fields):
    """Canonical body bytes or None (structural refusal).

    fields: version int, floors [(cls, min_level)], profiles [u8],
    hmax int, t_cool int, c2_threshold int, next_key bytes|None.
    """
    try:
        version = fields["version"]
        floors = fields["floors"]
        profiles = fields["profiles"]
        hmax = fields["hmax"]
        t_cool = fields["t_cool"]
        c2t = fields["c2_threshold"]
        nkey = fields.get("next_key", b"") or b""
        if not isinstance(version, int) or version <= 0:
            return None
        if not isinstance(floors, list) or not floors:
            return None
        prev = -1
        for cls, lvl in floors:
            if cls not in (0, 1, 2) or lvl not in (1, 2, 3):
                return None
            if cls <= prev:
                return None  # canonical ascending order
            prev = cls
        if not isinstance(profiles, list) or not profiles or \
                any(not isinstance(p, int) or p < 0 or p > 255
                    for p in profiles):
            return None
        for v in (hmax, t_cool, c2t):
            if not isinstance(v, int) or v < 0 or v > 0xFFFFFFFF:
                return None
        if not isinstance(nkey, (bytes, bytearray)) or \
                len(nkey) > 2592:
            return None
        body = _u32(version) + _u16(len(floors))
        for cls, lvl in floors:
            body += bytes([cls, lvl])
        body += _u16(len(profiles)) + bytes(profiles)
        body += _u32(hmax) + _u32(t_cool) + _u16(c2t)
        body += _u16(len(nkey)) + bytes(nkey)
        if len(body) > _MAX_BODY:
            return None
        return body
    except (KeyError, TypeError):
        return None


async def srv_policy(op, ctx, **kw):
    """Policy dispatch. Returns (code, payload). Codes: issued (body,
    sig hex) / refuse-stale / fail-sign / malformed / issue-current
    (version) / hold-ahead / repinned / bad-op."""
    ctx.setdefault("_lock", asyncio.Lock())
    ctx.setdefault("_issued", 0)
    ctx.setdefault("_ahead_alarms", 0)
    ctx.setdefault("_halted", False)
    if op == "halt":
        # Server-key compromise: halt signing (sessions continue).
        ctx["_halted"] = True
        log.warning("policy signing halted (compromise)")
        return "halted", None
    if op == "resume":
        # Trust restored via B-41 re-enrollment ceremony (out-of-band).
        ctx["_halted"] = False
        log.info("policy signing resumed")
        return "resumed", None
    if op == "issue":
        if ctx["_halted"]:
            return "halted", None
        fields = kw.get("fields")
        sk = kw.get("sk")
        level = kw.get("level")
        rnd = kw.get("rnd")
        if level not in (44, 65, 87) or not isinstance(sk, (
                bytes, bytearray)) or len(sk) == 0 or \
                not isinstance(rnd, (bytes, bytearray)) or \
                len(rnd) != 32:
            return "malformed", None
        body = encode_manifest(fields or {})
        if body is None:
            return "malformed", None
        async with ctx["_lock"]:
            if fields["version"] <= ctx["_issued"]:
                return "refuse-stale", None
            rc, out, _ = B.run("dsa-sign", str(level), bytes(sk).hex(),
                            body.hex(), bytes(rnd).hex())
            if rc != 0:
                log.warning("policy issue: signing failed rc=%d", rc)
                return "fail-sign", None
            ctx["_issued"] = fields["version"]
            log.info("policy issued version=%d", fields["version"])
            return "issued", (body.hex(), out[0])
    if op == "check":
        reported = kw.get("device_version", -1)
        if not isinstance(reported, int) or reported < 0:
            return "malformed", None
        if reported < ctx["_issued"]:
            return "issue-current", ctx["_issued"]
        if reported > ctx["_issued"]:
            ctx["_ahead_alarms"] += 1
            log.warning("policy device-ahead v=%d issued=%d",
                        reported, ctx["_issued"])
            return "hold-ahead", ctx["_issued"]
        return "issue-current", ctx["_issued"]
    if op == "repin":
        level = kw.get("level")
        pk = kw.get("pk")
        sk = kw.get("sk")
        if level not in (44, 65, 87) or not isinstance(pk, (
                bytes, bytearray)) or not isinstance(sk, (
                bytes, bytearray)):
            return "malformed", None
        ctx["_signing"] = {"level": level, "pk": bytes(pk),
                           "sk": bytes(sk)}
        log.info("policy signing key re-pinned (level %d)", level)
        return "repinned", None
    return "bad-op", None
