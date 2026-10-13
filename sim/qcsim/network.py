"""Network model (B-43.3): loss/delay/reorder/dup + B-42 transport rules.

REUSE, not rebuild (cite-don't-duplicate): MTU/fragmentation run
through qcgw.split_frame/Reassembler (B-42.4 rules verbatim), gateway
relay runs through qcgw E2ERelay/TrustedRelay (B-42.1/.2, per
configured delta, both configs supported, never intermixed). This
module owns only the PAPER-PARAM impairments and their scheduling:
per-message loss rate (per trace/scenario), connection-interval-based
delay plus jitter (PAPER-PARAM), bounded reorder/duplication window,
and link-loss intervals driven by trace ground-truth events (B-30
link-loss event records, cited).

Structural relay difference (honest, not incidental): E2E relays
FRAGMENTS byte-transparently (headers encrypted, nothing readable);
the trusted config routes whole FRAMES pre-fragment (class/level
visible per B-24.1) and refuses sub-header inputs loudly instead of
padding fakes. Frames are opaque bytes everywhere else (the network
never decrypts). Deterministic in (config, frames, seed): every draw
comes from the attacker stream (adversarial impairments are attacker
draws; device/network/generator streams stay untouched). Provisional
defaults below are PAPER-PARAM, confirmed at build.
"""

import sys
from pathlib import Path

try:
    from qcgw.transports import QC_MAX_FRAME  # noqa: F401
except ImportError:  # standalone use: resolve the repo checkout
    _ROOT = Path(__file__).resolve().parents[2]
    if str(_ROOT / "server") not in sys.path:
        sys.path.insert(0, str(_ROOT / "server"))
    from qcgw.transports import QC_MAX_FRAME  # noqa: F401

from qcgw.frag import Reassembler, split_frame  # noqa: E402
from qcgw.relay import E2ERelay, TrustedRelay  # noqa: E402

from .streams import RNGStreams  # noqa: E402

# Minimum routable frame for the trusted leg (B-24.1 header visibility:
# 74 B header + class/level/counter readable; sub-header inputs refuse
# loudly instead of being padded into fake routables).
_TRUSTED_MIN = 78

# Provisional defaults (PAPER-PARAM per trace/scenario, confirmed at
# build): loss rate, connection interval + jitter, reorder window.
DEFAULTS = {"loss_rate": 0.0, "conn_interval_us": 7500,
            "jitter_us": 500, "reorder_window": 2}


class NetworkModel:
    """Seeded link impairments over real B-42 transport behavior."""

    def __init__(self, seed_hex, config="E2E", mtu=1024,
                 loss_rate=0.0, conn_interval_us=7500, jitter_us=500,
                 reorder_window=2, max_frame=None):
        if config not in ("E2E", "trusted-gateway"):
            raise ValueError("config must be E2E or trusted-gateway")
        for name, value in (("loss_rate", loss_rate),
                            ("conn_interval_us", conn_interval_us),
                            ("jitter_us", jitter_us)):
            if not isinstance(value, (int, float)) or value < 0:
                raise ValueError(f"{name} must be non-negative")
        if loss_rate > 1.0:
            raise ValueError("loss_rate must be <= 1")
        if not isinstance(reorder_window, int) or reorder_window < 1:
            raise ValueError("reorder_window must be a positive int")
        self._streams = RNGStreams(seed_hex)
        self._config = config
        self._mtu = mtu
        self._loss = loss_rate
        self._interval = conn_interval_us
        self._jitter = jitter_us
        self._window = reorder_window
        self._max_frame = QC_MAX_FRAME if max_frame is None \
            else max_frame
        if config == "E2E":
            self._relay = E2ERelay()
            self._relay.associate("sim-link", "sim-device", verified=True)
        else:
            self._relay = TrustedRelay(config="trusted-gateway",
                                       gateway_id_hex="sim-gw")
            self._relay.bind_leg("W-G", "sim-peer")
        self.counters = {"sent": 0, "lost": 0, "delayed": 0,
                         "reordered": 0, "duplicated": 0,
                         "link_lost": 0, "relayed": 0}

    def _in_link_loss(self, tick, link_loss):
        return any(start <= tick < end for start, end in link_loss)

    def _impair(self, frame, tick, link_loss):
        """Apply loss/link-loss/delay draws. Returns (fate, delay)."""
        if self._in_link_loss(tick, link_loss):
            self.counters["link_lost"] += 1
            return "link-loss", 0
        if self._streams.next_uniform("attacker") < self._loss:
            self.counters["lost"] += 1
            return "lost", 0
        delay = self._interval + int(
            self._streams.next_uniform("attacker") * (self._jitter + 1))
        self.counters["delayed"] += 1
        return "sent", delay

    def send(self, frames, link_loss=()):
        """Run frames through impairments + relay + reassembly.

        frames: [bytes] opaque (trusted config: each >= 78 B, refused
        otherwise). link_loss: [(start_us, end_us)] from trace
        ground-truth events. Returns (delivered [bytes], log).

        Structural rule (audit-found, same poison family as the B-42
        dup-after-complete bug): each frame drains through a FRESH
        reassembler — the model knows frame boundaries, and a real
        gateway keys slots per frame, so cross-frame orphan adoption
        is structurally impossible here. Dup/reorder apply WITHIN one
        frame's frag list only (the qcgw fault shape), never across
        frames. Loss/link-loss drop whole frames; survivors deliver
        exactly, in send order.
        """
        delivered, log = [], []
        for i, frame in enumerate(frames):
            frame = bytes(frame)
            tick = i * self._interval
            fate, _ = self._impair(frame, tick, link_loss)
            if fate != "sent":
                log.append({"frame": i, "fate": fate, "ts": tick})
                continue
            if self._config == "trusted-gateway":
                if len(frame) < _TRUSTED_MIN:
                    raise ValueError(
                        "trusted leg routes whole frames (>= 78 B)")
                code, _ = self._relay.route(frame, "W-G")
                if code != "routed":
                    log.append({"frame": i, "fate": "drop-malformed",
                                "ts": tick})
                    continue
            frags = split_frame(frame, self._mtu, self._max_frame)
            if self._config == "E2E":
                relayed = []
                for frag in frags:
                    code, out = self._relay.relay(frag, "sim-link")
                    if out is None:
                        continue
                    relayed.append(out)
                    self.counters["relayed"] += 1
                frags = relayed
            else:
                self.counters["relayed"] += len(frags)
            if self._window >= 2 and \
                    self._streams.next_uniform("attacker") < 0.5:
                frags = [f for frag in frags for f in (frag, frag)]
                self.counters["duplicated"] += len(frags) // 2
            if self._window >= 2 and len(frags) >= 2:
                frags = list(frags)
                for j in range(0, len(frags) - 1, 2):
                    frags[j], frags[j + 1] = frags[j + 1], frags[j]
                self.counters["reordered"] += 1
            reasm = Reassembler(self._max_frame)
            got = None
            for frag in frags:
                status, frame_out = reasm.feed(b"sim", 0, frag, now=0.0)
                if status == "complete":
                    got = frame_out
            if got is None:
                log.append({"frame": i, "fate": "drop-incomplete",
                            "ts": tick})
                continue
            self.counters["sent"] += 1
            delivered.append(got)
            log.append({"frame": i, "fate": "sent", "ts": tick})
        return delivered, log
