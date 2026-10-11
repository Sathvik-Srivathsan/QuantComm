"""Audit store tests (B-40.5): schema, query, export/sign, rotation.
Deterministic (fixed clocks/values; signer is a stub here — the DSA
roundtrip through the servant lives in test_srv_crypto.py).
"""
import hashlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "server"))

from qcsrv import AuditStore  # noqa: E402


def _store(tmp_path):
    return AuditStore(str(tmp_path / "audit.jsonl"))


def test_schema_exact_and_guards(tmp_path):
    st = _store(tmp_path)
    assert st.record_keys == {
        "ts", "source", "code", "id_hex", "hash_hex", "dev_seq",
        "idx",
    }
    idx = st.append(1000.0, "handshake", "drop-auth", "aa" * 16,
                    "bb" * 32, dev_seq=1)
    assert idx == 0
    assert st.append(1001.0, "cap", "queued", "aa" * 16, "bb" * 32,
                     dev_seq=2) == 1
    with pytest.raises(ValueError):
        st.append(1002.0, "", "x", "aa" * 16, "bb" * 32)
    with pytest.raises(ValueError):
        st.append(1002.0, "s", "x", "zz", "bb" * 32)
    with pytest.raises(ValueError):
        st.append(1002.0, "s", "x", "aa" * 16, "bb" * 32, dev_seq=-1)


def test_query_filters(tmp_path):
    st = _store(tmp_path)
    st.append(1.0, "a", "x", "aa" * 16, "bb" * 32, 1)
    st.append(2.0, "a", "y", "aa" * 16, "bb" * 32, 2)
    st.append(3.0, "b", "x", "cc" * 16, "bb" * 32, 3)
    assert len(st.query()) == 3
    assert len(st.query(source="a")) == 2
    assert len(st.query(code="x")) == 2
    assert len(st.query(device="cc" * 16)) == 1
    assert st.query(source="zzz") == []


def test_export_manifest_roundtrip(tmp_path):
    st = _store(tmp_path)
    st.append(1.0, "a", "x", "aa" * 16, "bb" * 32, 1)
    st.append(2.0, "b", "y", "cc" * 16, "dd" * 32, 5)
    man_path = str(tmp_path / "audit.manifest")
    man = st.export(man_path, signer=lambda d: "sig:" + d)
    raw = Path(str(tmp_path / "audit.jsonl")).read_bytes()
    assert man["records"] == 2
    assert man["sha256"] == hashlib.sha256(raw).hexdigest()
    assert man["sig"] == "sig:" + man["sha256"]
    on_disk = json.loads(Path(man_path).read_text())
    assert on_disk == man
    with pytest.raises(ValueError):
        st.export(man_path, signer=lambda d: 123)


def test_rotate_retain(tmp_path):
    st = _store(tmp_path)
    st.append(1.0, "a", "x", "aa" * 16, "bb" * 32, 1)
    p2 = st.rotate(str(tmp_path / "a2.jsonl"))
    st.append(2.0, "b", "y", "cc" * 16, "dd" * 32, 1)
    assert Path(p2).exists()
    kept = st.retain(1)
    assert kept == [p2]
    assert not Path(str(tmp_path / "audit.jsonl")).exists()
    assert len(st.query()) == 1
    with pytest.raises(ValueError):
        st.retain(0)
