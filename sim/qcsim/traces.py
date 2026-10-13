"""E7 synthetic trace generator (B-43.5): 30 traces, Markov risk, B-30 schema.

Trace records follow the B-30 field layout (core/qc_trace.h, cited
never re-valued): vector = {ver, ts, B, soc, R, S, C, M, L_rssi,
L_retries, Q, mask}; events typed 0-3 (risk/battery/load/link-loss)
with (a, b) u64 payloads. Schema version (1, 0) mirrors
QC_TRACE_MAJOR/MINOR; generator versioned alongside (GENERATOR_VERSION).

PAPER-PARAM values with provisional defaults (confirmed at build):
Markov transition matrices (2-state calm/attack) and battery/load/
link-loss profiles are per-family defaults documented below — there
is NO global default: family must name a known entry in FAMILIES.
Synthetic voltage/temperature/RSSI run metadata is emitted per trace
and marked synthetic (sim counterpart of the manuscript run rule).

Trace ID = generator-name + uint32 serial + seed hex (unique by
construction); seeds and trace IDs recorded per B-43.5.
"""

from .streams import RNGStreams

SCHEMA_VERSION = (1, 0)
GENERATOR_VERSION = (1, 0)

# Per-family PAPER-PARAM defaults (provisional, confirmed at build).
# Priors documented here (B-43.5 Markov-topology requirement):
# 2-state calm/attack; p_stay = self-loop probability per 1 s step.
FAMILIES = {
    "E7-default": {
        "p_calm_stay": 0.95,
        "p_attack_stay": 0.80,
        "steps": 64,
        "dt_us": 1_000_000,
        "soc_start": 100,
        "soc_drain_per_step": 1,
        "load_msg_per_s": 1.0,
        "link_loss_rate": 0.01,
        "voltage_mv": 3300,
        "temp_c": 22.5,
        "rssi_dbm": -60,
    },
}

_VECTOR_FIELDS = ("ver", "ts", "B", "soc", "R", "S", "C", "M",
                  "L_rssi", "L_retries", "Q", "mask")


def _markov_next(streams, state, fam):
    p = streams.next_uniform("generator")
    if state == 0:  # calm
        return 0 if p < fam["p_calm_stay"] else 1
    return 1 if p < fam["p_attack_stay"] else 0


def generate_traces(generator_name, seed_hex, n=30, family="E7-default"):
    """Generate n deterministic synthetic traces. Returns [dict]."""
    if not isinstance(generator_name, str) or not generator_name:
        raise ValueError("generator_name must be a nonempty str")
    if not isinstance(n, int) or n <= 0:
        raise ValueError("n must be a positive int")
    if family not in FAMILIES:
        raise ValueError(f"unknown family {family!r} (no global default)")
    fam = FAMILIES[family]
    streams = RNGStreams(seed_hex)
    traces = []
    for serial in range(n):
        state = 0
        soc = fam["soc_start"]
        vectors, events = [], []
        for step in range(fam["steps"]):
            state = _markov_next(streams, state, fam) \
                if step else 0
            ts = step * fam["dt_us"]
            risk = 0.1 + 0.8 * streams.next_uniform("generator") \
                if state else 0.05 * streams.next_uniform("generator")
            vec = {
                "ver": list(SCHEMA_VERSION),
                "ts": ts,
                "B": round(soc / 100.0, 4),
                "soc": max(0, soc),
                "R": round(risk, 4),
                "S": state,
                "C": round(fam["load_msg_per_s"], 3),
                "M": 1024,
                "L_rssi": fam["rssi_dbm"],
                "L_retries": 0,
                "Q": round(1.0 - risk, 4),
                "mask": 0xFFFF,
            }
            vectors.append(vec)
            if step and state != vectors[-2]["S"]:
                events.append({"ver": list(SCHEMA_VERSION), "ts": ts,
                               "type": 0, "a": vectors[-2]["S"], "b": state})
            soc = max(0, soc - fam["soc_drain_per_step"])
            if streams.next_uniform("generator") < fam["link_loss_rate"]:
                events.append({"ver": list(SCHEMA_VERSION), "ts": ts,
                               "type": 3, "a": 1, "b": 1})
        traces.append({
            "trace_id": f"{generator_name}-{serial:08d}-"
                        f"{seed_hex.lower()}",
            "generator": generator_name,
            "serial": serial,
            "seed_hex": seed_hex.lower(),
            "schema_version": list(SCHEMA_VERSION),
            "generator_version": list(GENERATOR_VERSION),
            "family": family,
            "priors": {"topology": "calm/attack",
                       "p_calm_stay": fam["p_calm_stay"],
                       "p_attack_stay": fam["p_attack_stay"]},
            "vectors": vectors,
            "events": events,
            "meta": {"voltage_mv": fam["voltage_mv"],
                     "temp_c": fam["temp_c"],
                     "rssi_dbm": fam["rssi_dbm"],
                     "synthetic": True},
        })
    return traces


def validate_trace(trace):
    """Check one trace against the B-30-shaped contract. Returns True."""
    for key in ("trace_id", "generator", "serial", "seed_hex",
                "schema_version", "vectors", "events", "meta"):
        if key not in trace:
            raise ValueError(f"trace missing {key}")
    if not trace["meta"].get("synthetic", False):
        raise ValueError("trace meta must be marked synthetic")
    for vec in trace["vectors"]:
        for field in _VECTOR_FIELDS:
            if field not in vec:
                raise ValueError(f"vector missing {field}")
    for evt in trace["events"]:
        if evt["type"] not in (0, 1, 2, 3):
            raise ValueError("event type must be 0-3")
    return True
