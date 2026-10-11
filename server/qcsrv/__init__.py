"""qcsrv — QuantComm server verbs (B-40, lean prototype service).

Six public names at completion (one per B-40 function); two land now
(Registry, AuditStore), four with the pipeline/ingress/policy/verifier
chunk. The surface test pins __all__ exactly, so growth is deliberate.
Internal helpers are underscore-private. Deterministic: caller clocks,
no wall-clock reads, no randomness in this package (crypto randomness
lives behind the srv_crypto servant, owned by later verbs).
"""
from .audit import AuditStore
from .registry import Registry

__all__ = ["AuditStore", "Registry"]
