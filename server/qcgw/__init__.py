"""qcgw — gateway relay, transports, fragmentation (B-42, host side).

Eight public names (surface test pins this exactly — growth is
deliberate per change, never silent): split_frame, Reassembler,
E2ERelay, TrustedRelay, GatewayRegistry, check_gateway, loopback_pair,
tcp_pair. The qcsrv six-verb freeze is untouched (separate package).

Out of scope by spec (not stubs, not TODOs): BLE central/MTU values
(B-61 owns them), event-triggered radio fallback (explicitly future
work — no code path exists here, asserted by test), E11 config
comparison (B-53), WiFi/cellular transports (asserted absent).
"""
from .frag import Reassembler, split_frame
from .relay import E2ERelay, GatewayRegistry, TrustedRelay, check_gateway
from .transports import loopback_pair, tcp_pair

__all__ = [
    "E2ERelay",
    "GatewayRegistry",
    "Reassembler",
    "TrustedRelay",
    "check_gateway",
    "loopback_pair",
    "split_frame",
    "tcp_pair",
]
