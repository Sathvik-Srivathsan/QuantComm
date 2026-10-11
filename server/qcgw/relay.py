"""Gateway relays (B-42.1/.2/.5): association routing, no keys.

E2ERelay: ciphertext-only relay keyed by BLE-link association
(link-handle to device-ID map; identity resolved from HMAC-verified
M1 by the caller, bound thereafter for the link lifetime). Byte-
transparent at frame/fragment granularity (no re-framing, never
interprets). Holds NO keys and sees plaintext never — structural: no
key fields exist on the object (key-absence scan test), logs carry
connection metadata only (link, device hex, counters — never payload
bytes). Relay latency budget counted per relay call (caller-measured
ms; over-budget counts, never drops). Gateway compromise costs
availability only (ciphertext-only relay; modification dies at AEAD
downstream).

TrustedRelay: separate deployment (constructor config flag, immutable
— no setter exists, attempted reassignment raises AttributeError by
construction). Two legs (W-G and G-S) under distinct contexts; the
gateway holds a B-41-provisioned device identity for its G-to-S leg
and runs the standard handshake there (caller-driven via the handshake
verb; no new key types). Routing exposes class/level WITHOUT decrypting
(header parse only — proven by constructing with zero keys). Configs
never intermix: unknown association/leg drops; no runtime fallback in
either direction (re-deployment only).

GatewayRegistry: server-side gateway allowlist (add/remove/check +
unknown counter). check_gateway: device-side allowlist predicate
(allowed list + gw ID -> bool). Association lifetime equals link
duration (dissociate on link close; stale bindings dropped, counted).
"""
import logging

log = logging.getLogger(__name__)


class E2ERelay:
    """Ciphertext-only relay (see module docstring)."""

    def __init__(self, relay_budget_ms=0):
        self._assoc = {}  # link-handle -> device-id hex
        self._budget = relay_budget_ms
        self.counters = {
            "relayed": 0,
            "over_budget": 0,
            "drop_unknown": 0,
            "dissociated": 0,
        }

    def associate(self, link, device_id_hex, verified=True):
        """Bind a link handle to a verified device identity.

        verified must be True (identity resolved from HMAC-verified
        M1 by the caller); False refuses (unverified bindings are how
        relays get hijacked).
        """
        if not isinstance(link, str) or not link:
            raise ValueError("link must be nonempty str")
        if not isinstance(device_id_hex, str) or not device_id_hex:
            raise ValueError("device id must be nonempty hex str")
        if verified is not True:
            raise ValueError("association requires verified identity")
        self._assoc[link] = device_id_hex
        return True

    def dissociate(self, link):
        if self._assoc.pop(link, None) is not None:
            self.counters["dissociated"] += 1
            return True
        return False

    def relay(self, frame, link, latency_ms=0):
        """Relay one frame/fragment verbatim. Returns (code, bytes|None).

        Codes: relayed (bytes identical in/out), drop-unknown
        (no association — including trusted-leg frames, which never
        associate here: no-intermix by construction).
        """
        if not isinstance(frame, (bytes, bytearray)):
            return "drop-malformed", None
        if link not in self._assoc:
            self.counters["drop_unknown"] += 1
            return "drop-unknown", None
        if self._budget > 0 and latency_ms > self._budget:
            self.counters["over_budget"] += 1
        self.counters["relayed"] += 1
        log.info("relay link=%s device=%s bytes=%d", link,
                 self._assoc[link], len(frame))
        return "relayed", bytes(frame)


class TrustedRelay:
    """Two-leg relay, distinct security contexts (see module docstring)."""

    def __init__(self, config, gateway_id_hex=""):
        if config not in ("E2E", "trusted-gateway"):
            raise ValueError("config must be E2E or trusted-gateway")
        self._config = config
        self._gw_id = gateway_id_hex
        self._legs = {}  # leg-name -> {"peer": hex, "ctx": dict}
        self.counters = {
            "routed": 0,
            "drop_unknown": 0,
        }

    @property
    def config(self):
        """Deployment config (read-only: no runtime fallback, ever)."""
        return self._config

    def bind_leg(self, leg, peer_hex, leg_ctx=None):
        """Bind one leg (W-G or G-S) to a peer identity + context."""
        if leg not in ("W-G", "G-S"):
            raise ValueError("leg must be W-G or G-S")
        if not isinstance(peer_hex, str) or not peer_hex:
            raise ValueError("peer must be nonempty hex str")
        self._legs[leg] = {"peer": peer_hex,
                           "ctx": leg_ctx if leg_ctx is not None else {}}
        return True

    def route(self, frame, leg):
        """Route one frame on a leg. Returns (code, info|None).

        info exposes class/level/counter parsed from the header (no
        decryption — the relay holds no keys by construction). Unknown
        leg drops (no-intermix: E2E frames have no leg here either).
        """
        if not isinstance(frame, (bytes, bytearray)) or len(frame) < 78:
            return "drop-malformed", None
        if leg not in self._legs:
            self.counters["drop_unknown"] += 1
            return "drop-unknown", None
        frame = bytes(frame)
        cls, level = frame[16], frame[17]
        if cls not in (0, 1, 2) or level not in (1, 2, 3):
            return "drop-malformed", None
        counter = int.from_bytes(frame[18:26], "big")
        self.counters["routed"] += 1
        log.info("route leg=%s cls=%d level=%d counter=%d", leg, cls,
                 level, counter)
        return "routed", {"class": cls, "level": level,
                          "counter": counter,
                          "peer": self._legs[leg]["peer"]}


class GatewayRegistry:
    """Server-side gateway allowlist (B-42.5 registration)."""

    def __init__(self):
        self._allowed = set()
        self.counters = {"unknown": 0}

    def register(self, gw_id_hex):
        if not isinstance(gw_id_hex, str) or not gw_id_hex:
            raise ValueError("gateway id must be nonempty hex str")
        self._allowed.add(gw_id_hex)
        return True

    def revoke(self, gw_id_hex):
        if gw_id_hex in self._allowed:
            self._allowed.discard(gw_id_hex)
            return True
        return False

    def check(self, gw_id_hex):
        ok = gw_id_hex in self._allowed
        if not ok:
            self.counters["unknown"] += 1
        return ok


def check_gateway(device_allowed, gw_id_hex):
    """Device-side allowlist predicate (B-42.5): is this gateway OK?"""
    if not isinstance(device_allowed, (list, tuple, set)):
        raise ValueError("allowlist must be a list/tuple/set")
    return gw_id_hex in set(device_allowed)
