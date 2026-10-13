"""Attacker scenarios (B-43.4): versioned TOML, Dolev-Yao primitives.

Schema owned here (separate from B-30 E7 traces: traces carry
environment, scenarios carry adversary). Scenario file (TOML):
scenario_id (str), version = {major, minor} uint16 pair, primitives =
ordered list of {at_us (virtual microseconds, uint64), op (one of the
PRIMITIVE_OPS below), params (op-specific table, optional)}.

Version gate mirrors the B-30 trace compat rule (cited): major
mismatch refuses; higher minor accepted (unknown fields ignored);
unknown op refuses; unknown top-level keys refuse (strict schema —
scenarios are adversary code and fail closed, unlike trace decode).

Primitives (Dolev-Yao subset; attacker NEVER breaks crypto — no
side-channel, fault, or formal scope; frames are opaque bytes here,
never parsed, never decrypted):
drop (remove), delay (defer by delay_us), replay (re-emit an earlier
frame), modify (flip bytes at seeded positions — dies at AEAD
downstream, never interpreted here), inject (insert garbage bytes),
handshake_flood (N handshake-labeled messages), reboot_reset (reset
marker + epoch note), hint_spoof (forged risk hint WITHIN B-25.4 caps
— over-cap values refused), manifest_replay (old-version marker),
gateway_compromise (E2E availability-only composite: drop/delay/
inject-detectable profile; confidentiality untouched by construction
— the player holds no keys and emits no plaintext).

Scheduling: primitives fire on the SimClock at at_us via schedule()
(monotonic virtual time, no wall-clock); ties keep file order.
Conflict rule: scenario overrides trace on conflict (e.g. a link-loss
event at the same tick a drop is scheduled) with the conflict logged
— scenario wins, trace event stays recorded, both visible.

E10 T-mapping is owned by B-53 (forward): each fired primitive logs
its op so later phases can map ops to T1-T13 without re-running.
"""

import tomllib

from .clock import SimClock
from .streams import RNGStreams

SCENARIO_MAJOR = 1
SCENARIO_MINOR = 0

PRIMITIVE_OPS = ("drop", "delay", "replay", "modify", "inject",
                 "handshake_flood", "reboot_reset", "hint_spoof",
                 "manifest_replay", "gateway_compromise")

# B-25.4 hint-spoof caps (consumed here, owned there — cited values
# recorded at build; over-cap params refuse, never clamp silently).
_HINT_CAP = 6


def parse_scenario(toml_text):
    """Parse + validate a scenario file. Returns the scenario dict."""
    if not isinstance(toml_text, (str, bytes)):
        raise ValueError("scenario must be TOML text")
    try:
        data = tomllib.loads(toml_text if isinstance(toml_text, str)
                             else toml_text.decode())
    except Exception as exc:
        raise ValueError(f"scenario TOML malformed: {exc}")
    allowed_top = {"scenario_id", "version", "primitives"}
    for key in data:
        if key not in allowed_top:
            raise ValueError(f"unknown scenario key {key!r} (strict)")
    if not isinstance(data.get("scenario_id"), str) or \
            not data["scenario_id"]:
        raise ValueError("scenario_id must be a nonempty str")
    version = data.get("version")
    if not isinstance(version, dict) or \
            not isinstance(version.get("major"), int) or \
            not isinstance(version.get("minor"), int):
        raise ValueError("version must be {major, minor} uint16 ints")
    for part in ("major", "minor"):
        if not 0 <= version[part] <= 0xFFFF:
            raise ValueError("version parts are uint16")
    if version["major"] != SCENARIO_MAJOR:
        raise ValueError("scenario major mismatch (refused)")
    prims = data.get("primitives", [])
    if not isinstance(prims, list):
        raise ValueError("primitives must be a list")
    for i, prim in enumerate(prims):
        if not isinstance(prim, dict):
            raise ValueError(f"primitive {i} must be a table")
        if prim.get("op") not in PRIMITIVE_OPS:
            raise ValueError(f"primitive {i}: unknown op (refused)")
        at = prim.get("at_us")
        if not isinstance(at, int) or at < 0 or \
                at > 0xFFFFFFFFFFFFFFFF:
            raise ValueError(f"primitive {i}: at_us must be uint64")
        params = prim.get("params", {})
        if not isinstance(params, dict):
            raise ValueError(f"primitive {i}: params must be a table")
        _check_params(prim["op"], params, i)
    return {"scenario_id": data["scenario_id"],
            "version": {"major": version["major"],
                        "minor": version["minor"]},
            "primitives": [{"at_us": p["at_us"], "op": p["op"],
                            "params": dict(p.get("params", {}))}
                           for p in prims]}


def _check_params(op, params, i):
    if op == "delay" and (not isinstance(params.get("delay_us"), int)
                          or params["delay_us"] < 0):
        raise ValueError(f"primitive {i}: delay needs delay_us >= 0")
    if op == "handshake_flood" and (
            not isinstance(params.get("count"), int)
            or params["count"] <= 0):
        raise ValueError(f"primitive {i}: flood needs count >= 1")
    if op == "hint_spoof" and (
            not isinstance(params.get("hints"), int)
            or not 1 <= params["hints"] <= _HINT_CAP):
        raise ValueError(
            f"primitive {i}: hints must be 1-{_HINT_CAP} (B-25.4 cap)")
    if op == "gateway_compromise" and params.get("profile") not in (
            "drop", "delay", "inject-detectable"):
        raise ValueError(
            f"primitive {i}: gateway profile must be drop/delay/"
            "inject-detectable (availability-only)")


def play_scenario(scenario, frames, seed_hex, trace_events=None):
    """Play primitives over opaque frames. Returns (out, log, conflicts).

    frames: [bytes] in send order (opaque — never parsed). trace_events:
    optional [(ts, kind)] trace ground-truth for conflict detection.
    Deterministic in (scenario, frames, seed). Log entries carry op +
    tick + metadata only (never frame bytes — attacker logs mirror the
    gateway-log discipline). Conflicts: [(ts, trace_kind, op)] where
    the scenario overrode a same-tick trace event.
    """
    streams = RNGStreams(seed_hex)
    clock = SimClock()
    # Schedule by primitive INDEX (file order breaks ties): duplicate ops
    # at different ticks must fire their own params, never the first one's.
    for idx, prim in enumerate(scenario["primitives"]):
        clock.schedule(max(0, prim["at_us"] - clock.now()), str(idx))
    live = list(frames)
    out, log, conflicts = [], [], []
    seen = []
    trace_at = {}
    for ts, kind in (trace_events or []):
        trace_at.setdefault(ts, []).append(kind)
    while True:
        step = clock.advance()
        if step is None:
            break
        tick, label = step
        prim = scenario["primitives"][int(label)]
        op, params = prim["op"], prim["params"]
        if tick in trace_at:
            for kind in trace_at.pop(tick):
                conflicts.append({"ts": tick, "trace": kind, "op": op})
        if op == "drop":
            hit = 1 if live else 0
            if live:
                live.pop(0)
            log.append({"op": op, "ts": tick, "dropped": hit})
        elif op == "delay":
            log.append({"op": op, "ts": tick,
                        "delay_us": params["delay_us"]})
            if live:
                live.append(live.pop(0))
        elif op == "replay":
            if seen:
                pick = seen[streams.next_u64("attacker") % len(seen)]
                live.insert(0, pick)
                log.append({"op": op, "ts": tick, "replayed": 1})
            else:
                log.append({"op": op, "ts": tick, "replayed": 0})
        elif op == "modify":
            if live:
                victim = bytearray(live.pop(0))
                for _ in range(1 + streams.next_u64("attacker") % 3):
                    victim[streams.next_u64("attacker") % len(victim)] \
                        ^= 1 << (streams.next_u64("attacker") % 8)
                live.insert(0, bytes(victim))
            log.append({"op": op, "ts": tick, "modified": 1})
        elif op == "inject":
            junk = streams.next_bytes("attacker", 16)
            live.insert(0, junk)
            log.append({"op": op, "ts": tick, "injected": len(junk)})
        elif op == "handshake_flood":
            log.append({"op": op, "ts": tick,
                        "count": params["count"]})
        elif op == "reboot_reset":
            log.append({"op": op, "ts": tick, "epoch_note": "reset"})
        elif op == "hint_spoof":
            log.append({"op": op, "ts": tick,
                        "hints": params["hints"]})
        elif op == "manifest_replay":
            log.append({"op": op, "ts": tick, "old_version": 1})
        elif op == "gateway_compromise":
            log.append({"op": op, "ts": tick,
                        "profile": params["profile"],
                        "availability_only": True})
        seen.extend(live[:1])
    out.extend(live)
    return out, log, conflicts
