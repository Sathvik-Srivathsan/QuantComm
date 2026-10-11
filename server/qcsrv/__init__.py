"""qcsrv — QuantComm server verbs (B-40, lean prototype service).

Six public names, one per B-40 function (surface test pins this
exactly — a seventh fails CI): Registry, AuditStore, srv_handshake,
srv_policy, srv_ingest, srv_verify. Internal helpers and the bridge
are underscore-private. Deterministic: caller clocks, explicit coins,
no wall-clock reads, no randomness in this package (live entropy lives
behind the srv_crypto servant, called only with explicit inputs).
"""
from .audit import AuditStore
from .handshake import srv_handshake
from .ingress import srv_ingest
from .policy import srv_policy
from .registry import Registry
from .verifier import srv_verify

__all__ = [
    "AuditStore",
    "Registry",
    "srv_handshake",
    "srv_ingest",
    "srv_policy",
    "srv_verify",
]
