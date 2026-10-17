"""qcsim — deterministic simulator (B-43) plus baselines (B-44).

Sixteen public names (surface test pins this exactly — growth is
deliberate per change, never silent): ControlLoop, SimClock,
RNGStreams, check_sim_tag, generate_traces, ExperimentRunner,
GateRefusal, parse_scenario, play_scenario, NetworkModel, DeviceModel
(B-43) plus baseline_systems, check_comparison, select_anchor,
check_oracle_bound, h3_input_record (B-44).

GateRefusal is the B-50.4 E0-gate refusal type: raised by the runner when
a required preflight refuses, so a gated run can never degrade into an
empty result set.

Out of scope in this chunk (not stubs, not TODOs — deferred with
owners): B-43.2 full device-model composition (protocol + controller
with real adapter crypto; default_step_fn replays traces instead —
assumption-log version tracks the swap), B-43.3 loss/delay network
beyond trace link-loss events (B-42 frag/relay reused, not rebuilt),
B-43.4 E10 T-mapping and runner step_fn wiring (B-53 owns the
mapping; scenarios play standalone until then), B-44 H3-threshold application (B-55
decides; records carry numbers only), B-52/B-53 campaign
modes (accepted as opaque strings), B-54 column contract (rows are
manifest/system/trace/metrics dicts; columns finalized at build).

Banned by construction: wall-clock reads, os.urandom outside the
seeder, threads, unseeded random (import-time surface + grep CI gate
+ determinism self-test).
"""
from .campaign import (CampaignError, CampaignManifest, Cell, ModelPinChanged,
                       Registration, check_split, e5_cells,
                       h3_comparator, register_e6, run_count)
from .clock import SimClock
from .control import ControlLoop
from .device import DeviceModel
from ._guard import check_package as _check_package
from pathlib import Path as _Path

_check_package(_Path(__file__).resolve().parent)
from .network import NetworkModel
from .runner import ExperimentRunner, GateRefusal
from .scenarios import parse_scenario, play_scenario
from .simtag import check_sim_tag
from .streams import RNGStreams
from .systems import baseline_systems
from .traces import generate_traces
from .validity import (check_comparison, check_oracle_bound,
                       h3_input_record, select_anchor)

__all__ = [
    "ControlLoop",
    "CampaignError",
    "CampaignManifest",
    "Cell",
    "DeviceModel",
    "ExperimentRunner",
    "GateRefusal",
    "ModelPinChanged",
    "Registration",
    "NetworkModel",
    "RNGStreams",
    "SimClock",
    "baseline_systems",
    "check_comparison",
    "check_split",
    "check_oracle_bound",
    "check_sim_tag",
    "e5_cells",
    "generate_traces",
    "h3_comparator",
    "h3_input_record",
    "parse_scenario",
    "play_scenario",
    "register_e6",
    "run_count",
    "select_anchor",
]
