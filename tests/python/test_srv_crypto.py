"""Crypto-servant bridge tests (B-40 servant): the Python service must
drive the IDENTICAL C adapters (no crypto fork). Vectors cross-check
against independent implementations (hashlib/hmac/cryptography), never
memorized constants except the FIPS 180-4 'abc' anchor. Determinism:
fixed coins twice give byte-identical output. Tamper paths assert
adapter-rc exit codes (BAD_SIG == 4 pins the mapping).

Requires the built servant at build/server/srv_crypto (CI builds the
srv_crypto target before pytest; missing binary FAILS, never skips).
Never calls `rng` (live entropy) — fixed coins only, by rule.
"""
import hashlib
import hmac as hmac_mod
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SERVANT = REPO / "build" / "server" / "srv_crypto"


def run(*args):
    assert SERVANT.exists(), f"servant missing: {SERVANT} (build it)"
    p = subprocess.run(
        [str(SERVANT), *args],
        capture_output=True, text=True, timeout=120,
    )
    return p.returncode, p.stdout.split(), p.stderr


def hx(b: bytes) -> str:
    return b.hex()


def test_sha256_anchor():
    rc, out, _ = run("sha256", hx(b"abc"))
    assert rc == 0
    assert out[0] == hashlib.sha256(b"abc").hexdigest()
    assert out[0] == ("ba7816bf8f01cfea414140de5dae2223"
                      "b00361a396177a9cb410ff61f20015ad")


def test_hmac_crosscheck():
    key, msg = bytes(range(32)), b"QuantComm-M1-test"
    rc, out, _ = run("hmac", hx(key), hx(msg))
    assert rc == 0
    assert out[0] == hmac_mod.new(key, msg, hashlib.sha256).hexdigest()


def test_hkdf_crosscheck():
    # Servant takes a 32 B PRK (HKDF-Extract output size); the manual
    # construction below is length-agnostic (audit-noted test fix).
    prk = bytes(range(32))
    info = b"QC-TEST"
    # Manual RFC 5869 Expand (independent construction).
    okm = b""
    t = b""
    for i in range(1, 4):
        t = hmac_mod.new(prk, t + info + bytes([i]),
                         hashlib.sha256).digest()
        okm += t
    want = okm[:42]
    rc, out, _ = run("hkdf-expand", hx(prk), hx(info), "42")
    assert rc == 0
    assert out[0] == want.hex()
    # Extract cross-check (RFC 5869 Extract = HMAC(salt, IKM)).
    rc, out, _ = run("hkdf-extract", hx(b"salt-01"), hx(b"ikm-material"))
    assert rc == 0
    assert out[0] == hmac_mod.new(b"salt-01", b"ikm-material",
                                  hashlib.sha256).hexdigest()


def test_aead_roundtrip_and_tamper():
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    key = bytes([0x11]) * 32
    nonce = bytes([0x22]) * 12
    aad = b"header-bytes"
    pt = b"telemetry-payload-0123456789"
    aes = AESGCM(key)
    blob = aes.encrypt(nonce, pt, aad)
    ct, tag = blob[:-16], blob[-16:]
    # Servant decrypts the independent ciphertext.
    rc, out, _ = run("aead-dec", hx(key), hx(nonce), hx(aad), hx(ct),
                     hx(tag))
    assert rc == 0 and out[0] == hx(pt)
    # Servant encrypts; independent side opens it.
    rc, out, _ = run("aead-enc", hx(key), hx(nonce), hx(aad), hx(pt))
    assert rc == 0
    sct, stag = bytes.fromhex(out[0]), bytes.fromhex(out[1])
    assert aes.decrypt(nonce, sct + stag, aad) == pt
    # Tamper anywhere fails closed (nonzero rc, no plaintext).
    bad = bytearray(ct)
    bad[0] ^= 1
    rc, out, _ = run("aead-dec", hx(key), hx(nonce), hx(aad),
                     hx(bytes(bad)), hx(tag))
    assert rc != 0 and out == []


def test_kem_all_levels():
    for level in ("512", "768", "1024"):
        coins_kg = hx(bytes([0xA0 + int(level) % 7]) * 64)
        coins_en = hx(bytes([0xB0 + int(level) % 7]) * 32)
        rc, out, _ = run("kem-keypair", level, coins_kg)
        assert rc == 0
        pk, sk = out[0], out[1]
        # Determinism: same coins, identical keys.
        rc2, out2, _ = run("kem-keypair", level, coins_kg)
        assert rc2 == 0 and out2 == out
        rc, out, _ = run("kem-encaps", level, pk, coins_en)
        assert rc == 0
        ct, ss = out[0], out[1]
        rc, out, _ = run("kem-decaps", level, ct, sk)
        assert rc == 0 and out[0] == ss
        # Tampered ct: decaps still OK (implicit rejection) but the
        # secret differs — the documented semantic, pinned by test.
        bad = bytearray(bytes.fromhex(ct))
        bad[5] ^= 1
        rc, out, _ = run("kem-decaps", level, hx(bytes(bad)), sk)
        assert rc == 0 and out[0] != ss
    rc, _, _ = run("kem-keypair", "999", hx(b"00" * 64))
    assert rc == 2


def test_dsa_all_levels():
    for level in ("44", "65", "87"):
        seed = hx(bytes([0xC0 + int(level) % 7]) * 32)
        rnd = hx(bytes([0xD0 + int(level) % 7]) * 32)
        msg = hx(f"dsa-test-message-{level}".encode())
        rc, out, _ = run("dsa-keypair", level, seed)
        assert rc == 0
        pk, sk = out[0], out[1]
        rc, out, _ = run("dsa-sign", level, sk, msg, rnd)
        assert rc == 0
        sig = out[0]
        # Determinism: same rnd, identical signature.
        rc, out, _ = run("dsa-sign", level, sk, msg, rnd)
        assert rc == 0 and out[0] == sig
        rc, _, _ = run("dsa-verify", level, pk, msg, sig)
        assert rc == 0
        # Tampered signature: BAD_SIG rc pins the mapping.
        bad = bytearray(bytes.fromhex(sig))
        bad[10] ^= 1
        rc, _, _ = run("dsa-verify", level, pk, msg, hx(bytes(bad)))
        assert rc == 4
        # Wrong message and ctx-mismatch both fail.
        rc, _, _ = run("dsa-verify", level, pk, hx(b"other"), sig)
        assert rc == 4
        rc, out, _ = run("dsa-sign", level, sk, msg, rnd, hx(b"ctx"))
        assert rc == 0
        rc, _, _ = run("dsa-verify", level, pk, msg, out[0],
                       hx(b"other-ctx"))
        assert rc == 4
    rc, _, _ = run("dsa-sign", "44", hx(b"00" * 2592), hx(b"m"),
                   hx(b"r" * 32))
    assert rc != 0


def test_empty_inputs():
    # Documented empty allowances (audit: previously unexercised).
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    key = bytes([0x33]) * 32
    nonce = bytes([0x44]) * 12
    aes = AESGCM(key)
    blob = aes.encrypt(nonce, b"", b"")
    rc, out, _ = run("aead-dec", hx(key), hx(nonce), "", hx(blob[:-16]),
                     hx(blob[-16:]))
    assert rc == 0 and out == []  # empty pt prints a bare newline
    rc, out, _ = run("aead-enc", hx(key), hx(nonce), "", "")
    assert rc == 0
    # Empty ct prints a bare line: only the tag survives split().
    assert aes.decrypt(nonce, bytes.fromhex(out[0]), b"") == b""
    seed = hx(bytes([9]) * 32)
    rnd = hx(bytes([10]) * 32)
    rc, out, _ = run("dsa-keypair", "44", seed)
    assert rc == 0
    pk = out[0]
    rc, out, _ = run("dsa-sign", "44", out[1], "", rnd)
    assert rc == 0
    rc, _, _ = run("dsa-verify", "44", pk, "", out[0])
    assert rc == 0


def test_usage_errors():
    assert run()[0] == 2
    assert run("nope")[0] == 2
    assert run("sha256", "zz")[0] == 2
    assert run("sha256", "abc")[0] == 2  # odd hex
    # Well-formed lengths but garbage key: runs verify, fails closed.
    # (Audit-noted test fix: b"00"*1312 is 2624 ASCII bytes, not 1312
    # zero bytes — the first cut tested the usage gate, not verify.)
    assert run("dsa-verify", "44", bytes(1312).hex(), hx(b"m"),
               bytes(2420).hex())[0] == 4
