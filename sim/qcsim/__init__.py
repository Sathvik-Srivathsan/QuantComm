"""qcsim — deterministic simulator foundations (B-43, host side).

Five public names (surface test pins this exactly — growth is
deliberate per change, never silent): SimClock, RNGStreams,
check_sim_tag, generate_traces, ExperimentRunner.

Out of scope in this chunk (not stubs, not TODOs — deferred with
owners): B-43.2 full device-model composition (protocol + controller
with real adapter crypto; default_step_fn replays traces instead —
assumption-log version tracks the swap), B-43.3 loss/delay network
beyond trace link-loss events (B-42 frag/relay reused, not rebuilt),
B-43.4 attacker scenario TOML (B-53 owns the T-mapping; transport
faults already live in qcgw), B-44 system definitions (forward
reference; runner enforces the interface only), B-52/B-53 campaign
modes (accepted as opaque strings), B-54 column contract (rows are
manifest/system/trace/metrics dicts; columns finalized at build).

Banned by construction: wall-clock reads, os.urandom outside the
seeder, threads, unseeded random (import-time surface + grep CI gate
+ determinism self-test).
"""
from .clock import SimClock
from .runner import ExperimentRunner
from .simtag import check_sim_tag
from .streams import RNGStreams
from .traces import generate_traces

__all__ = [
    "ExperimentRunner",
    "RNGStreams",
    "SimClock",
    "check_sim_tag",
    "generate_traces",
]
