"""Step-0 smoke: proves pytest collects and the harness is honest.

Convention for all later tests: one file per unit (test_<unit>.py),
L0 vectors as parametrized exact-equality asserts, no randomness
(randomized tests use a recorded seed or they do not exist).
"""
import hashlib


def test_pytest_collects_and_asserts():
    # Second test so the suite can never pass vacuously on zero tests.
    assert True


def test_sha256_known_answer():
    # Shape reference for every future L0 vector test: exact hex compare,
    # message + expected pasted from the authoritative source, no truncation.
    # Source: FIPS 180-4, Sec 8.1 ("abc").
    assert hashlib.sha256(b"abc").hexdigest() == (
        "ba7816bf8f01cfea414140de5dae2223"
        "b00361a396177a9cb410ff61f20015ad"
    )
