"""Attestation verifier verb (B-40.4): roots, absence, C2, retention.

Single dispatch verb. Retained frames rest as received wire bytes
(ciphertext — never plaintext at rest); recompute is transient (bytes
objects, GC-reclaimed; CPython cannot guarantee wipes — documented
limitation, identical to the ingress reading path).

Leaf/tree rules (bit-exact with B-24.3, reimplemented here over the
identical SHA-256, not forked crypto): leaf = SHA256("QC-ATTEST" ||
class u8 || counter u64-BE || frame); tree = SHA256(left||right),
odd promoted, single == leaf. Root signatures verify via the servant
(empty ctx — attestation signs roots context-free, documented choice).

Ops (all return (code, payload)):
- retain(device, frames): store wire frames (bounded per-device cap,
  oldest-drop + dropped count; cap provisional, labeled).
- submit(device, root|None, sig|None, pk|None, level): absence-ok (no
  retained, nothing submitted); alarm-stale (retained but no root, or
  root with nothing retained); verified (recompute matches + DSA ok,
  retained batch archived to the audit store when ctx carries one);
  alarm-tamper (root mismatch); verify-fail (DSA rejects).
- liveness(device, now, ta_s): ok, or alarm-stale past 2*Ta without a
  verify (verify-liveness monitor).
- c2(frame_ignored, sig|None, pk|None, level): AEAD validity is
  established by ingress BEFORE calling (precondition, documented);
  present sig verifies (c2-signed-ok / c2-bad-sig), absent sig is
  accepted unsigned (c2-unsigned-ok).
"""
import asyncio
import hashlib
import hmac as hmac_mod
import logging

from . import _bridge as B

log = logging.getLogger(__name__)

_ATTEST_LABEL = b"QC-ATTEST"
_RET_CAP_DFLT = 256  # per-device frames (provisional: ~2 Ta windows)


def _parse_header(frame):
    if len(frame) < 74 + 4 + 16:
        return None
    cls, level = frame[16], frame[17]
    if cls not in (0, 1, 2) or level not in (1, 2, 3):
        return None
    counter = int.from_bytes(frame[18:26], "big")
    plen = int.from_bytes(frame[74:78], "big")
    if plen > 65535 or len(frame) != 74 + 4 + plen + 16:
        return None
    return cls, counter


async def srv_verify(op, ctx, **kw):
    """Verifier dispatch. See module docstring for codes."""
    ctx.setdefault("_ret", {})
    ctx.setdefault("_vmeta", {})
    ctx.setdefault("_lock", asyncio.Lock())
    ctx.setdefault("_counters", {})
    cap = ctx.get("ret_cap", _RET_CAP_DFLT)

    def _inc(name):
        ctx["_counters"][name] = ctx["_counters"].get(name, 0) + 1

    if op == "retain":
        device = kw.get("device")
        frames = kw.get("frames", [])
        if not isinstance(device, str) or not isinstance(frames, list):
            return "malformed", None
        dropped = 0
        async with ctx["_lock"]:
            buf = ctx["_ret"].setdefault(device, [])
            for f in frames:
                if not isinstance(f, (bytes, bytearray)):
                    return "malformed", None
                if _parse_header(bytes(f)) is None:
                    return "malformed", None
                buf.append(bytes(f))
            while len(buf) > cap:
                buf.pop(0)
                dropped += 1
        if dropped:
            _inc("retention-drops")
            log.warning("verifier %s retention dropped %d", device,
                        dropped)
        return "ok", dropped
    if op == "submit":
        device = kw.get("device")
        root = kw.get("root")
        sig = kw.get("sig")
        pk = kw.get("pk")
        level = kw.get("level")
        if not isinstance(device, str):
            return "malformed", None
        async with ctx["_lock"]:
            retained = list(ctx["_ret"].get(device, []))
        if not retained and root is None and sig is None:
            return "absence-ok", None
        if not retained or root is None or sig is None:
            _inc("stale-alarms")
            log.warning("verifier %s alarm-stale", device)
            return "alarm-stale", None
        try:
            root_b = bytes.fromhex(root)
            sig_b = bytes.fromhex(sig)
            pk_b = bytes.fromhex(pk or "")
        except (ValueError, TypeError, AttributeError):
            return "malformed", None
        if level not in (44, 65, 87) or len(root_b) != 32:
            return "malformed", None
        leaves = []
        for f in retained:
            parsed = _parse_header(f)
            if parsed is None:
                return "malformed", None
            cls, counter = parsed
            try:
                lh = B.sha256(
                    _ATTEST_LABEL + bytes([cls]) +
                    counter.to_bytes(8, "big") + f)
            except B.BridgeError:
                return "alarm-tamper", None
            leaves.append(lh)
        # Tree locally (hashlib over servant-produced leaves: the leaf
        # binding is the security point; internal nodes are plain
        # SHA-256 either way — documented split).
        cur = list(leaves)
        while len(cur) > 1:
            nxt = []
            for i in range(0, len(cur), 2):
                if i + 1 < len(cur):
                    h = hashlib.sha256()
                    h.update(cur[i])
                    h.update(cur[i + 1])
                    nxt.append(h.digest())
                else:
                    nxt.append(cur[i])
            cur = nxt
        if not hmac_mod.compare_digest(cur[0], root_b):
            _inc("tamper-alarms")
            log.warning("verifier %s alarm-tamper", device)
            return "alarm-tamper", None
        rc, _, _ = B.run("dsa-verify", str(level), pk_b.hex(), root_b.hex(),
                      sig_b.hex())
        if rc != 0:
            _inc("sig-fails")
            return "verify-fail", None
        # Identity hex for the audit record comes from the retained
        # frames themselves (the caller passes names, not hex — the
        # record schema demands hex; audit fix: never pass names).
        dev_hex = retained[0][0:16].hex() if retained else ""
        async with ctx["_lock"]:
            ctx["_ret"][device] = []
            ctx["_vmeta"][device] = {"root": root,
                                     "at": kw.get("now", 0.0)}
        audit = ctx.get("audit")
        if audit is not None:
            audit.append(kw.get("now", 0.0), "verifier",
                         "batch-verified", dev_hex, root, 0)
        return "verified", None
    if op == "liveness":
        device = kw.get("device")
        now = kw.get("now", 0.0)
        ta_s = kw.get("ta_s", 0)
        if not isinstance(device, str):
            return "malformed", None
        meta = ctx["_vmeta"].get(device)
        if meta is None:
            return "ok", None  # nothing attested yet: absence regime
        if ta_s > 0 and now - meta["at"] > 2 * ta_s:
            _inc("stale-alarms")
            return "alarm-stale", None
        return "ok", None
    if op == "c2":
        sig = kw.get("sig")
        pk = kw.get("pk")
        level = kw.get("level")
        if sig is None:
            return "c2-unsigned-ok", None
        try:
            sig_b = bytes.fromhex(sig)
            pk_b = bytes.fromhex(pk or "")
        except (ValueError, TypeError, AttributeError):
            return "malformed", None
        if level not in (44, 65, 87):
            return "malformed", None
        # The signed payload is the alarm root/message bytes supplied
        # by the caller (AEAD validity pre-established by ingress).
        msg = kw.get("msg", "")
        try:
            msg_b = bytes.fromhex(msg)
        except (ValueError, TypeError, AttributeError):
            return "malformed", None
        rc, _, _ = B.run("dsa-verify", str(level), pk_b.hex(),
                      msg_b.hex(), sig_b.hex())
        if rc != 0:
            _inc("c2-bad-sigs")
            return "c2-bad-sig", None
        return "c2-signed-ok", None
    return "bad-op", None
