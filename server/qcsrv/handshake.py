"""Handshake service verb (B-40.1 service half).

Implements the B-22 pipeline VERBATIM in order — parse, admission,
HMAC, epoch, cache, floor, decaps, encaps, derive, M2-store — calling
the identical C primitives through the servant (no logic fork: order
re-expressed, primitives shared). Dispositions and the six counters
match B-22.3 names; per-hour failed-confirmation exists at 0 (no wire
event feeds it yet — documented, not omitted silently).

Context dict (orchestrator-owned, no new API names):
  registry  Registry instance
  kem       {512|768|1024: {"pk": bytes, "sk": bytes}} server pairs
  kdevs     {device_id: kdev} provisioned device keys
  floor     int wire codepoint (server floor, B-25 carried)
  config    str deployment ("E2E" / "trusted-gateway")
  cache_cap int (default 1024), t_hs float (default 5.0, in-flight
    resend window), cache_ttl float (default 3600.0)
Underscore keys (_cache, _counters, _lock, _sizes) are unit-managed.

Coins discipline (derand house rule): N_S (32 B) and K2 encaps coins
(32 B) arrive as explicit params — deterministic tests pass fixed
coins; prod passes servant-rng output. Returns (disposition, m2|None).
Dispositions: m2/resend/drop-parse/drop-unknown/drop-blacklisted/
drop-config/drop-auth/drop-epoch/drop-replay/drop-floor/abort-decaps/
abort-encaps/abort-internal (hosting fault, beyond B-22 taxonomy).
Retry semantics: identical M1 within t_hs resends identical M2 bytes
(no fresh KEM work); simultaneous duplicate races may mint distinct
M2s (last wins, both valid — documented benign race, single-threaded
tests never observe it).
"""
import asyncio
import hmac as hmac_mod
import logging
from collections import OrderedDict

from . import _bridge as B
from .registry import CredentialStore, Registry

log = logging.getLogger(__name__)

_WIRE_LEVEL = {1: 512, 2: 768, 3: 1024}
_COUNTERS = (
    "parse-fail", "auth-fail", "replay-drop", "handshake-attempt",
    "floor-refusal", "confirm-fail",
)


def _sat_inc(counters, name):
    counters[name] = min(counters.get(name, 0) + 1, 2**64 - 1)


def _ctx_defaults(ctx):
    ctx.setdefault("_cache", OrderedDict())
    ctx.setdefault("_counters", {k: 0 for k in _COUNTERS})
    ctx.setdefault("_lock", asyncio.Lock())
    ctx.setdefault("_sizes", {})
    ctx.setdefault("cache_cap", 1024)
    ctx.setdefault("t_hs", 5.0)
    ctx.setdefault("cache_ttl", 3600.0)


def _sizes_for(ctx, level):
    if level not in ctx["_sizes"]:
        pk, sk, ct = B.sizes("kem", level)
        ctx["_sizes"][level] = (pk, sk, ct)
    return ctx["_sizes"][level]


async def srv_handshake(m1, ctx, *, coins_ns, coins_k2, now=0.0):
    """Run one server handshake. See module docstring for contract."""
    _ctx_defaults(ctx)
    counters = ctx["_counters"]
    lock = ctx["_lock"]
    registry = ctx["registry"]
    if not isinstance(registry, Registry):
        raise ValueError("ctx['registry'] must be a Registry")
    if not isinstance(m1, (bytes, bytearray)) or len(m1) < 18:
        _sat_inc(counters, "parse-fail")
        log.info("m1 short: disposition=drop-parse")
        return "drop-parse", None
    m1 = bytes(m1)
    if m1[0] != 1:
        _sat_inc(counters, "parse-fail")
        log.info("m1 bad version: disposition=drop-parse")
        return "drop-parse", None
    wire_lvl = m1[17]
    if wire_lvl not in _WIRE_LEVEL:
        _sat_inc(counters, "parse-fail")
        log.info("m1 bad level: disposition=drop-parse")
        return "drop-parse", None
    level = _WIRE_LEVEL[wire_lvl]
    try:
        ek_len, _, ct_len = _sizes_for(ctx, level)
    except B.BridgeError:
        _sat_inc(counters, "parse-fail")
        return "drop-parse", None
    want = 1 + 16 + 1 + ek_len + ct_len + 12 + 32
    if len(m1) != want:
        _sat_inc(counters, "parse-fail")
        log.info("m1 bad length: disposition=drop-parse")
        return "drop-parse", None
    dev_id = m1[1:17]
    ek_w = m1[18:18 + ek_len]
    ct_s = m1[18 + ek_len:18 + ek_len + ct_len]
    nw = m1[18 + ek_len + ct_len:18 + ek_len + ct_len + 12]
    body, tag = m1[:-32], m1[-32:]

    # Admission precedes keyed steps (unknown has no Kdev to check).
    code, entry = await registry.admit(dev_id, ctx.get("config", "E2E"))
    if code != "ok":
        log.info("m1 %s disposition=%s", dev_id.hex(), code)
        return code, None
    # Kdev source: plain dict (tests/legacy) or CredentialStore
    # (role-enforced custody — the B-41.2 path).
    _kdevs = ctx.get("kdevs", {})
    if isinstance(_kdevs, CredentialStore):
        try:
            kdev = _kdevs.get(dev_id, "handshake")
        except PermissionError:
            kdev = None
    else:
        kdev = _kdevs.get(dev_id)
    if kdev is None or len(kdev) != 32:
        _sat_inc(counters, "auth-fail")
        log.info("m1 %s disposition=drop-auth (no credential)",
                 dev_id.hex())
        return "drop-auth", None
    try:
        mac = B.hmac(kdev, body)
    except B.BridgeError:
        _sat_inc(counters, "auth-fail")
        return "drop-auth", None
    if not hmac_mod.compare_digest(mac, tag):
        _sat_inc(counters, "auth-fail")
        log.info("m1 %s disposition=drop-auth", dev_id.hex())
        return "drop-auth", None
    _sat_inc(counters, "handshake-attempt")

    epoch = int.from_bytes(nw[0:4], "big")
    counter = int.from_bytes(nw[4:12], "big")
    last = (entry.hs_epoch, entry.hs_counter)
    if (epoch, counter) < last:
        log.info("m1 %s disposition=drop-epoch", dev_id.hex())
        return "drop-epoch", None

    # Replay cache (check-insert-evict atomicity; never held across
    # servant calls — the slow crypto below runs lock-free).
    try:
        hct = B.sha256(ct_s)
    except B.BridgeError:
        # Hosting fault, not a protocol outcome (documented extension
        # beyond the B-22 taxonomy; fail-closed, no counter spent).
        log.warning("m1 %s abort-internal (bridge)", dev_id.hex())
        return "abort-internal", None
    key = dev_id + epoch.to_bytes(4, "big") + nw + hct
    async with lock:
        hit = ctx["_cache"].get(key)
        if hit is not None:
            m2_old, stored_at = hit
            if now - stored_at <= ctx["t_hs"]:
                ctx["_cache"].move_to_end(key)
                log.info("m1 %s disposition=resend", dev_id.hex())
                return "resend", m2_old
            _sat_inc(counters, "replay-drop")
            log.info("m1 %s disposition=drop-replay", dev_id.hex())
            return "drop-replay", None
        if (epoch, counter) == last:
            # Equal pair, unknown bytes: replay-ambiguous, drop safe.
            log.info("m1 %s disposition=drop-epoch (equal-unseen)",
                     dev_id.hex())
            return "drop-epoch", None
    # Unconfigured floor defaults to 3 (most restrictive: fail-secure
    # on orchestrator omission, never fail-open).
    if wire_lvl < ctx.get("floor", 3):
        _sat_inc(counters, "floor-refusal")
        log.info("m1 %s disposition=drop-floor", dev_id.hex())
        return "drop-floor", None

    # KEM pair (servant primitives; no locks held across these calls).
    pair = ctx.get("kem", {}).get(level)
    if pair is None or len(coins_ns) != 32 or len(coins_k2) != 32:
        return "drop-auth", None
    rc, out, _ = B.run("kem-decaps", str(level), ct_s.hex(),
                    pair["sk"].hex())
    if rc != 0:
        log.info("m1 %s disposition=abort-decaps rc=%d", dev_id.hex(),
                 rc)
        return "abort-decaps", None
    k1 = B.unhx(out[0])
    rc, out, _ = B.run("kem-encaps", str(level), ek_w.hex(),
                    coins_k2.hex())
    if rc != 0:
        log.info("m1 %s disposition=abort-encaps rc=%d", dev_id.hex(),
                 rc)
        return "abort-encaps", None
    ct_w, k2 = B.unhx(out[0]), B.unhx(out[1])

    # KDF + M2 (formats per B-20.1/B-21, byte-exact).
    try:
        prk = B.hkdf_extract(nw + coins_ns, b"QC-HS" + k1 + k2 + kdev)
        m2_body = bytes([m1[0]]) + ct_w + coins_ns
        th = B.sha256(m1 + m2_body)
        okm = B.hkdf_expand(prk, b"QC-TRANSCRIPT" + b"\x00" + th, 128)
        k_c2s, k_s2c, k_rat, k_conf = (
            okm[0:32], okm[32:64], okm[64:96], okm[96:128])
        confirm = B.hmac(k_conf, m1 + m2_body)
    except B.BridgeError:
        log.warning("m1 %s abort-internal (bridge)", dev_id.hex())
        return "abort-internal", None
    m2 = m2_body + confirm

    # M2-store (atomic check-insert-evict under the lock).
    async with lock:
        ctx["_cache"][key] = (m2, now)
        ctx["_cache"].move_to_end(key)
        while len(ctx["_cache"]) > ctx["cache_cap"]:
            ctx["_cache"].popitem(last=False)
        cutoff = now - ctx["cache_ttl"]
        for k in [k for k, (_, t) in ctx["_cache"].items()
                  if t < cutoff]:
            del ctx["_cache"][k]
    async with entry.lock:
        entry.hs_epoch = epoch
        entry.hs_counter = counter
        entry.epoch_last = epoch
        entry.session_keys = {
            "k_c2s": k_c2s, "k_s2c": k_s2c, "k_rat": k_rat,
        }
        entry.counters = {"c2s": 0, "s2c": 0}
        entry.window = set()
        entry.window_high = -1
        entry.ratchet_r = 0
        entry.r_chain = k_rat
        entry.last_contact = now
    log.info("m1 %s disposition=m2 epoch=%d level=%d", dev_id.hex(),
             epoch, wire_lvl)
    return "m2", m2
