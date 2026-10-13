"""Experiment runner skeleton (B-43.6): order, discard, pairing, manifests.

S-definition interface owned here (system ID; fixed-profile or
controller flag; floor-bypass flag for S0/S1/S4 experiment-only;
crypto backend selector held identical across compared systems;
trace-set binding). B-44 system DEFINITIONS are a forward reference
(later phase, cited by name only) — this runner never executes
S-definitions outside the interface (no B-44 internals here).

Runner modes (E5 steady, E6 factorial, E7 policy, E10/E11
scenario-driven) are selected by experiment config owned by
B-52/B-53 (forward): accepted here as an opaque mode string and
recorded in the manifest, with no mode semantics implemented.

Device-model composition (B-43.2: protocol + controller loop with
real adapter crypto) is deferred to a later chunk: the default
step_fn below replays trace vectors deterministically (counts +
risk sums) — enough to prove order/discard/pairing/manifest
mechanics with bit-identical determinism. Full composition plugs
in as a step_fn with the same (system, trace, streams, clock)
signature; assumption-log version tracks the swap.

Hard rules: >= 10 runs (fewer refused); first trial warms and is
discarded (differs by construction: cold trial carries a warmup
marker); paired comparisons only on identical trace sets, seeds,
and backend (mismatch refused with hard error naming the offender);
output label must carry SIM (refused otherwise); per-run manifest
retention as JSON-serializable dicts (code hash, seeds per stream,
trace IDs, scenario ID/version, config, backend ID, assumption
version); stats rows are (manifest ID, system ID, trace ID, metrics).
"""

import json
import subprocess

from .clock import SimClock
from .simtag import require_sim_tag
from .streams import RNGStreams

MODES = ("E5", "E6", "E7", "E10", "E11")
ASSUMPTION_VERSION = "b43-foundations-1"


def _code_hash():
    try:
        out = subprocess.run(
            ["git", "rev-parse", "HEAD"], capture_output=True, text=True,
            timeout=30)
        if out.returncode == 0:
            return out.stdout.strip()
    except Exception:
        pass
    return "unknown-dev"


def _check_system(system):
    for key in ("system_id", "controller", "floor_bypass", "backend"):
        if key not in system:
            raise ValueError(f"system missing {key}")
    if not isinstance(system["system_id"], str) or \
            not system["system_id"]:
        raise ValueError("system_id must be a nonempty str")
    return True


def default_step_fn(system, trace, streams, clock):
    """Deterministic trace replay stub (device model deferred).

    Walks vectors on the virtual clock (1 ms per vector), sums risk,
    counts attack steps. Pure function of (system, trace, seed):
    bit-identical across runs. Cold trials (clock start 0 with no
    warmup event) carry warmup=1 so the discarded first run differs
    by construction.
    """
    total_risk, attack_steps = 0.0, 0
    for vec in trace["vectors"]:
        clock.schedule(1000, "vec")
        total_risk += vec["R"]
        attack_steps += vec["S"]
    while clock.advance() is not None:
        pass
    return {"vectors": len(trace["vectors"]),
            "risk_sum": round(total_risk, 4),
            "attack_steps": attack_steps,
            "system_id": system["system_id"]}


class ExperimentRunner:
    """Seeded multi-run harness (see module docstring)."""

    def __init__(self, seed_hex, mode="E7", output_tag="SIM-run",
                 step_fn=None, assumption_version=ASSUMPTION_VERSION,
                 code_hash=None):
        if mode not in MODES:
            raise ValueError(f"mode must be one of {MODES}")
        require_sim_tag(output_tag, "output_tag")
        self._streams = RNGStreams(seed_hex)
        self._mode = mode
        self._tag = output_tag
        self._step = step_fn or default_step_fn
        self._assumption = assumption_version
        self._code = code_hash or _code_hash()
        self.counters = {"trials": 0, "retained": 0, "discarded": 0}

    def run(self, systems, traces, runs=10, scenario=None):
        """Run systems over traces. Returns (manifests, stats)."""
        if not isinstance(runs, int) or runs < 10:
            raise ValueError("runs must be an int >= 10")
        if not systems or not traces:
            raise ValueError("systems and traces must be nonempty")
        for system in systems:
            _check_system(system)
        backends = {s["backend"] for s in systems}
        if len(backends) != 1:
            raise ValueError(
                f"compared systems must share one backend, got {backends}")
        trace_ids = [t["trace_id"] for t in traces]
        # Seeded random order over runs+1 trials (trial 0 = warmup,
        # discarded; retained trials give exactly `runs` manifests).
        order = list(range(runs + 1))
        for i in range(len(order) - 1, 0, -1):
            j = self._streams.next_u64("generator") % (i + 1)
            order[i], order[j] = order[j], order[i]
        manifests, stats = [], []
        for position, trial in enumerate(order):
            cold = position == 0
            for system in systems:
                clock = SimClock()
                if cold:
                    clock.schedule(0, "warmup")
                metrics = self._step(
                    system, traces[trial % len(traces)],
                    self._streams, clock)
                if cold:
                    metrics = dict(metrics, warmup=1)
                    self.counters["discarded"] += 1
                    continue
                manifest_id = (f"{self._tag}-t{trial:04d}-"
                               f"{system['system_id']}")
                manifest = {
                    "manifest_id": manifest_id,
                    "code_hash": self._code,
                    "seed_hex": self._streams.seed_hex,
                    "trace_ids": trace_ids,
                    "scenario": scenario,
                    "mode": self._mode,
                    "systems": [s["system_id"] for s in systems],
                    "backend": system["backend"],
                    "assumption_version": self._assumption,
                    "output_tag": self._tag,
                }
                # JSON-serializability is load-bearing (retention contract).
                json.dumps(manifest)
                json.dumps(metrics)
                manifests.append(manifest)
                stats.append({
                    "manifest_id": manifest_id,
                    "system_id": system["system_id"],
                    "trace_id": traces[trial % len(traces)]["trace_id"],
                    "metrics": metrics,
                })
                self.counters["retained"] += 1
            self.counters["trials"] += 1
        return manifests, stats


def check_pairing(manifests):
    """Refuse unpaired comparisons (trace set/seed/backend mismatch)."""
    if not manifests:
        raise ValueError("no manifests to pair")
    first = manifests[0]
    for manifest in manifests[1:]:
        if manifest["trace_ids"] != first["trace_ids"]:
            raise ValueError(
                f"unpaired trace sets: {manifest['manifest_id']}")
        if manifest["seed_hex"] != first["seed_hex"]:
            raise ValueError(
                f"unpaired seeds: {manifest['manifest_id']}")
        if manifest["backend"] != first["backend"]:
            raise ValueError(
                f"unpaired backends: {manifest['manifest_id']}")
    return True
