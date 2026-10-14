"""Controller-verb tests (B-43 bridge, Chunk 1): servant drives the
FROZEN controller units (no logic fork — same TUs, argv calling
convention). Every behavior asserted here must match the CTest suite
for the underlying unit; on disagreement the CTest wins and THIS
file is the bug (bridge, never logic).

Requires the built servant (CI builds srv_crypto before pytest;
missing binary FAILS, never skips). Exit code is ALWAYS 0 on
successful invocation (documented deviation: controller rcs occupy
2..7, colliding with the usage code); adapter rc rides stdout line 0
after the blob contract below. Usage/shape errors exit 2.

Blob contract: mutating verbs print blob hex FIRST, then rc, then
payload lines. Pure reads print values only (proving const-ness).
Floats cross as big-endian bit-copy hex (NaN bit-exact); integers
strict decimal; byte fields exact-length hex.
"""
import math
import struct
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "server"))

from qcsrv._bridge import run  # noqa: E402


def hx(b: bytes) -> str:
    return b.hex()


def f32(x: float) -> str:
    return struct.pack(">f", x).hex()


def f64(x: float) -> str:
    return struct.pack(">d", x).hex()


def u32b(*vals: int) -> str:
    out = bytearray()
    for v in vals:
        out += v.to_bytes(4, "big")
    return out.hex()


def action(profile: int, tpq: int, tr: int, ta: int, nb: int) -> str:
    return (bytes([profile]) + tpq.to_bytes(4, "big") +
            tr.to_bytes(4, "big") + ta.to_bytes(4, "big", signed=True) +
            bytes([nb])).hex()


FTABLE = bytes([1, 1, 1, 1, 1, 1]).hex()
FCFG = (3600).to_bytes(4, "big") + (600).to_bytes(4, "big") + \
    (60).to_bytes(4, "big") + bytes([8])
FCFG_H = FCFG.hex()
RES = (4096).to_bytes(4, "big") + (8192).to_bytes(4, "big") * 3 + \
    (1).to_bytes(4, "big") * 4
RES_H = RES.hex()
W6 = b"".join(struct.pack(">f", 1.0) for _ in range(6)).hex()
CMAX6 = b"".join(struct.pack(">f", 10.0) for _ in range(6)).hex()
RISKCFG = W6 + CMAX6 + f32(0.7) + f32(0.3) + (2).to_bytes(2, "big").hex() + \
    (2).to_bytes(2, "big").hex() + (2).to_bytes(2, "big").hex() + bytes([4]).hex() + \
    f32(0.3)
APREV = action(3, 3600, 1800, -1, 8)
INC0 = "00" * 24
INC_HI = u32b(10, 10, 10, 10, 10, 10)
ZERO64 = "00" * 8


def init_blob(**kw):
    args = {
        "ft": FTABLE, "fcfg": FCFG_H, "res": RES_H, "riskcfg": RISKCFG,
        "taumax": f32(100.0), "rho": f64(1.0), "frac": f32(0.5),
        "dwell": "3", "hmax": "100", "tcool": "60", "aprev": APREV,
        "lastsw": "0",
    }
    args.update(kw)
    rc, out, _ = run("ctl-init", args["ft"], args["fcfg"], args["res"],
                     args["riskcfg"], args["taumax"], args["rho"],
                     args["frac"], args["dwell"], args["hmax"],
                     args["tcool"], args["aprev"], args["lastsw"])
    assert rc == 0
    assert out[0] == "0", out
    assert len(out[1]) == 989 * 2, len(out[1])
    return out[1]


def test_init_shape_and_determinism():
    b1 = init_blob()
    b2 = init_blob()
    assert b1 == b2  # same argv twice, byte-identical
    # Bad risk cfg (lo >= hi): nonzero rc, blob absent.
    badcfg = W6 + CMAX6 + f32(0.3) + f32(0.7) + (2).to_bytes(2, "big").hex() + \
        (2).to_bytes(2, "big").hex() + (2).to_bytes(2, "big").hex() + bytes([4]).hex() + \
        f32(0.3)
    rc, out, _ = run("ctl-init", FTABLE, FCFG_H, RES_H, badcfg,
                     f32(100.0), f64(1.0), f32(0.5), "3", "100", "60",
                     APREV, "0")
    assert rc == 0 and out[0] != "0" and len(out) == 1


def test_state_samplers_and_guards():
    blob = init_blob()
    # Every comp happy path returns rc 0.
    rc, out, _ = run("ctl-state-sample", blob, "0", f32(80.0), "90",
                      "1000")
    assert rc == 0 and out[0] == "0"
    blob = out[1]
    for comp, v0, v1 in ((1, f32(0.05), "0"), (2, "1", "0"),
                         (3, f32(0.5), "0"), (4, "4096", "0"),
                         (5, "-60", "2"), (6, f32(2.0), "7"),
                         (7, INC_HI, "0")):
        rc, out, _ = run("ctl-state-sample", blob, str(comp), v0, v1,
                         "1000")
        assert rc == 0 and out[0] == "0", (comp, out)
        blob = out[1]
    # NaN risk refused (INVALID=2); S=9 refused; time regression kept.
    rc, out, _ = run("ctl-state-sample", blob, "1", f32(float("nan")),
                      "0", "1001")
    assert rc == 0 and out[0] == "2", out
    rc, out, _ = run("ctl-state-sample", blob, "2", "9", "0", "1001")
    assert rc == 0 and out[0] == "2", out
    rc, out, _ = run("ctl-state-sample", blob, "0", f32(80.0), "90",
                      "999")
    assert rc == 0 and out[0] == "3", out  # NONMONOTONIC
    # Bad comp, bad hex: usage exit 2.
    rc, _, _ = run("ctl-state-sample", blob, "8", "00", "0", "1001")
    assert rc == 2
    rc, _, _ = run("ctl-state-sample", blob, "1", "zz", "0", "1001")
    assert rc == 2


def test_state_check_and_take():
    blob = init_blob()
    rc, out, _ = run("ctl-state-check", blob, "1000", "3600", "1024",
                      "7", f32(0.01))
    assert rc == 0 and out[0] == "0" and len(out) == 3, out
    blob = out[2]  # state-check prints rc, mask, blob
    rc, out, _ = run("ctl-state-sample", blob, "2", "2", "0", "1000")
    assert out[0] == "4", out  # C2 accepted + immediate signaled
    blob = out[1]
    rc, out, _ = run("ctl-state-take-immediate", blob)
    assert rc == 0 and out[0] == "0" and out[1] == "1", out
    blob = out[2]
    rc, out, _ = run("ctl-state-take-immediate", blob)
    assert rc == 0 and out[0] == "0" and out[1] == "0", out  # cleared


def test_risk_flow_and_nan():
    blob = init_blob()
    rc, out, _ = run("ctl-risk-window", blob, INC0)
    assert rc == 0 and out[0] == "0", out
    rbits = out[2]
    assert math.isnan(struct.unpack(">f", bytes.fromhex(rbits))[0]) \
        is False  # partial first window emits unscaled (per header)
    blob = out[1]
    # Two hot closes (ne=2) enter HIGH; band reads back.
    for _ in range(2):
        rc, out, _ = run("ctl-risk-window", blob, INC_HI)
        assert out[0] == "0", out
        blob = out[1]
    assert out[3] == "1", out  # HIGH
    # Miss freezes streaks: band holds across a miss.
    rc, out, _ = run("ctl-risk-miss", blob)
    assert rc == 0 and out[0] == "0" and out[3] == "1", out
    blob = out[1]
    # Hint path runs (adds H_hint to current window).
    rc, out, _ = run("ctl-risk-hint", blob)
    assert rc == 0 and out[0] == "0", out
    blob = out[1]
    # Cold closes exit: W=4 keeps hot windows in scope, so flush (4)
    # then streak (nx=2); 6 quiet closes exit to NORMAL.
    for _ in range(6):
        rc, out, _ = run("ctl-risk-window", blob, INC0)
        blob = out[1]
    assert out[3] == "0", out


def test_floor_select_and_predicates():
    blob = init_blob()
    # Fresh init: every pair invalid incl. M -> HOLD contract, no
    # sampling needed (boot marks all invalid by construction).
    state126 = blob[12:12 + 252]  # state section of blob
    rc, out, _ = run("ctl-floor-select", state126, "0")
    assert rc == 0 and out[0] == "2", out  # HOLD on M-flag
    # Sample ALL comps good -> clean vector selects C1 basis (R via
    # sampler as the B-32-output stand-in; anything left invalid
    # would force the C2/high basis override instead).
    for comp, v0, v1 in ((0, f32(80.0), "90"), (1, f32(0.05), "0"),
                         (2, "1", "0"), (3, f32(0.5), "0"),
                         (4, "4096", "0"), (5, "-60", "2"),
                         (6, f32(2.0), "7")):
        rc, out, _ = run("ctl-state-sample", blob, str(comp), v0, v1,
                         "1000")
        assert out[0] == "0", (comp, out)
        blob = out[1]
    state126 = blob[12:12 + 252]
    rc, out, _ = run("ctl-floor-select", state126, "0")
    assert rc == 0 and out[0] == "0" and out[1] == "1" and \
        out[2] == "0", out
    # Predicates mirror tests/c/test_floor.c vectors (boundary-exact).
    rc, out, _ = run("ctl-floor-c1", "2", FTABLE, "1")
    assert rc == 0 and out[0] == "0" and out[1] == "1", out
    strict3 = "03" * 3 + "01" * 3  # min_level all 3
    rc, out, _ = run("ctl-floor-c1", "1", strict3, "1")
    assert rc == 0 and out[1] == "0", out
    for tpq, seff, want in (("3600", "1", "1"), ("600", "2", "1"),
                            ("601", "2", "0")):
        rc, out, _ = run("ctl-floor-c2", tpq, seff)
        assert rc == 0 and out[1] == want, (tpq, seff, out)
    for ta, seff, want in (("-1", "0", "1"), ("-1", "1", "0"),
                           ("-2", "1", "1"), ("-3", "1", "1"),
                           ("600", "1", "1"), ("3600", "1", "0"),
                           ("30", "1", "1"), ("60", "2", "0"),
                           ("-7", "1", "0")):
        rc, out, _ = run("ctl-floor-c3", ta, seff)
        assert rc == 0 and out[1] == want, (ta, seff, out)
    a = action(2, 3600, 1800, 600, 4)
    rc, out, _ = run("ctl-floor-c4", a, RES_H, "1000000")
    assert rc == 0 and out[0] == "0" and out[1] == "1", out
    rc, out, _ = run("ctl-floor-c5", a, RES_H, FCFG_H, "1")
    assert rc == 0 and out[0] == "0" and out[1] == "1", out


def test_floor_feasible_shapes():
    adm = "010101"
    rc, out, _ = run("ctl-floor-feasible", adm, FTABLE, "1", RES_H,
                      FCFG_H, "65536")
    assert rc == 0 and out[0] == "0", out
    n = int(out[1])
    assert n > 0 and len(out) == 2 + n, (n, len(out))
    for line in out[2:]:
        assert len(line) == 28, line  # 14 B actions
    # Nothing admitted -> empty set (caller routes fail-secure).
    rc, out, _ = run("ctl-floor-feasible", "000000", FTABLE, "1",
                      RES_H, FCFG_H, "65536")
    assert rc == 0 and out[1] == "0" and len(out) == 2, out
    # Bad cfg (nb_max 0) -> 0 with roomy memory, so the cfg alone is
    # the cause (fail-secure, never silent relaxation).
    badcfg = (3600).to_bytes(4, "big").hex() + \
        (600).to_bytes(4, "big").hex() + (60).to_bytes(4, "big").hex() \
        + "00"
    rc, out, _ = run("ctl-floor-feasible", adm, FTABLE, "1", RES_H,
                      badcfg, "65536")
    assert rc == 0 and out[1] == "0", out


def test_energy_groups_and_calibration():
    rc, out, _ = run("ctl-energy-priors")
    assert rc == 0 and out[0] == "0" and len(out[1]) == 210 * 2, out
    coeff = out[1]
    rc, out, _ = run("ctl-energy-foot-priors")
    assert rc == 0 and len(out[1]) == 42 * 2, out
    rc, out, _ = run("ctl-energy-foot-to-res", out[1])
    assert rc == 0 and out[0] == "0" and len(out[1]) == 64, out
    # Derive + eval: total equals the group sum bit-exact (same order).
    rc, out, _ = run("ctl-energy-derive", "2", f64(3600.0), f64(0.0),
                      f64(64.0), "3600", "1800", "-1", f64(0.0),
                      f64(0.0), f64(60.0), f64(100.0), f64(0.0))
    assert rc == 0 and out[0] == "0" and len(out[1]) == 182 * 2, out
    counts = out[1]
    rc, out, _ = run("ctl-energy-eval", coeff, counts, f64(0.5),
                      f64(0.2), f64(3600.0))
    assert rc == 0 and out[0] == "0", out
    groups = [struct.unpack(">d", bytes.fromhex(x))[0] for x in out[1:]]
    assert groups[4] == groups[0] + groups[1] + groups[2] + groups[3]
    rc, out, _ = run("ctl-energy-ehat", coeff, counts)
    assert rc == 0 and out[0] == "0", out
    # Calibration takes effect: two distinct AES coefficients on a
    # workload with nonzero AES bytes MUST give different evals
    # (field 8 = QC_ASSUMED_AES singleton; idx/sub ignored).
    rc, out, _ = run("ctl-energy-calibrate", coeff, "8", "0", "0",
                      f64(0.001))
    assert rc == 0 and out[0] == "0" and len(out[1]) == 210 * 2, out
    rc, out_a, _ = run("ctl-energy-eval", out[1], counts, f64(0.5),
                        f64(0.2), f64(3600.0))
    rc, out, _ = run("ctl-energy-calibrate", coeff, "8", "0", "0",
                      f64(0.002))
    assert rc == 0 and out[0] == "0", out
    rc, out_b, _ = run("ctl-energy-eval", out[1], counts, f64(0.5),
                        f64(0.2), f64(3600.0))
    assert rc == 0 and out_b[1:] != out_a[1:], (out_a, out_b)
    # KEM-family shape valid; negatives refuse (energy terms are
    # non-negative, always).
    rc, out, _ = run("ctl-energy-calibrate", coeff, "100", "1", "0",
                      f64(0.001))
    assert rc == 0 and out[0] == "0", out
    rc, out, _ = run("ctl-energy-calibrate", coeff, "100", "1", "0",
                      f64(-1.0))
    assert rc == 0 and out[0] != "0", out
    rc, out, _ = run("ctl-energy-ehs", coeff, "2", f64(3.0))
    assert rc == 0 and out[0] == "0", out
    rc, out, _ = run("ctl-energy-ehs", coeff, "9", f64(3.0))
    assert rc == 2  # profile guard (memory-safe, not policy)
    rc, out, _ = run("ctl-energy-hmax-rate", f64(1.5), f64(2.0))
    assert rc == 0 and out[0] == "0", out


def test_opt_decide_commit_flow():
    blob = init_blob()
    # Full clean vector (anything left invalid would force the C2/high
    # basis override and poison every downstream expectation).
    for comp, v0, v1 in ((0, f32(80.0), "90"), (1, f32(0.05), "0"),
                         (2, "1", "0"), (3, f32(0.5), "0"),
                         (4, "65536", "0"), (5, "-60", "2"),
                         (6, f32(2.0), "7")):
        rc, out, _ = run("ctl-state-sample", blob, str(comp), v0, v1,
                         "1000")
        assert out[0] == "0", (comp, out)
        blob = out[1]
    # Timed Ta (600): NONE is refused for C1 (carve-out is C0-only).
    cands = action(1, 3600, 1800, 600, 4) + f64(1.0) + f64(0.001) + \
        action(2, 3600, 1800, 600, 4) + f64(2.0) + f64(0.002)
    rc, out, _ = run("ctl-opt-decide", blob, "2", cands, f64(0.0),
                      f64(1000.0), f64(1.0), "1000")
    assert rc == 0 and out[0] == "0" and out[2] == "1", out
    staged_action = out[3]
    # Argmin pinned: ehat 1.0 < 2.0 at lambda 0 stages profile 1.
    assert staged_action == action(1, 3600, 1800, 600, 4), staged_action
    blob = out[1]
    rc, out, _ = run("ctl-opt-staged", blob)
    assert rc == 0 and out[0] == "0" and out[1] == "1" and \
        out[2] == staged_action, out
    rc, out, _ = run("ctl-opt-commit", blob, "1", "1001", f64(0.5),
                      staged_action, f64(600.0))
    assert rc == 0 and out[0] == "0", out
    blob = out[1]
    rc, out, _ = run("ctl-opt-counts", blob)
    assert rc == 0 and out[0] == "0" and len(out) == 8, out
    # Empty Af -> FAILSECURE(2); all-NaN -> FAILSECURE.
    rc, out, _ = run("ctl-opt-decide", blob, "0", "none", f64(0.0),
                      f64(1000.0), f64(1.0), "1002")
    assert rc == 0 and out[0] == "2" and out[2] == "0", out
    blob = out[1]
    nan = f64(float("nan"))
    cands = action(1, 3600, 1800, 600, 4) + nan + nan
    rc, out, _ = run("ctl-opt-decide", blob, "1", cands, f64(0.0),
                      f64(1000.0), f64(1.0), "1003")
    assert rc == 0 and out[0] == "2", out
    blob = out[1]
    # Handshake accounting + alarms drain to zero on second take.
    rc, out, _ = run("ctl-opt-note-handshake", blob, "1004")
    assert rc == 0 and out[0] == "0", out
    blob = out[1]
    rc, out, _ = run("ctl-opt-cap-count", blob, "1004")
    assert rc == 0 and out[0] == "0" and out[1] == "1", out
    blob = out[2]  # cap-count prints rc, count, blob
    rc, out, _ = run("ctl-opt-take-alarms", blob)
    assert rc == 0 and out[0] == "0", out
    blob = out[1]
    rc, out, _ = run("ctl-opt-take-alarms", blob)
    assert rc == 0 and out[2] == "0", out
    # Reconfigure keeps state, swaps limits.
    rc, out, _ = run("ctl-opt-reconfigure", blob, "50", "30")
    assert rc == 0 and out[0] == "0", out


def test_opt_shed_path():
    blob = init_blob(taumax=f32(0.000001))
    for comp, v0, v1 in ((0, f32(80.0), "90"), (1, f32(0.05), "0"),
                         (2, "1", "0"), (3, f32(0.5), "0"),
                         (4, "65536", "0"), (5, "-60", "2"),
                         (6, f32(2.0), "7")):
        rc, out, _ = run("ctl-state-sample", blob, str(comp), v0, v1,
                         "1000")
        blob = out[1]
    cands = action(2, 3600, 1800, 600, 4) + f64(5.0) + f64(5.0)
    rc, out, _ = run("ctl-opt-decide", blob, "1", cands, f64(0.0),
                      f64(0.000001), f64(1.0), "1000")
    assert rc == 0 and out[0] == "3" and out[2] == "1", out  # SHED (star staged)
    blob = out[1]
    # Apply failure: HOLD + APPLY_FAIL alarm + counter (mirrors the
    # CTest commit test through the CLI).
    rc, out, _ = run("ctl-opt-commit", blob, "0", "1001", f64(0.0),
                      "none", f64(600.0))
    assert rc == 0 and out[0] == "4", out  # HOLD, not OK
    blob = out[1]
    rc, out, _ = run("ctl-opt-take-alarms", blob)
    assert rc == 0 and int(out[2]) & 8, out  # APPLY_FAIL bit
    blob = out[1]
    rc, out, _ = run("ctl-opt-counts", blob)
    assert rc == 0 and out[7] == "1", out  # apply_fails


def test_gov_math_and_shed_order():
    blob = init_blob()
    rc, out, _ = run("ctl-gov-tau", blob)
    assert rc == 0 and out[0] == "0", out
    tau0 = struct.unpack(">f", bytes.fromhex(out[1]))[0]
    assert abs(tau0 - 100.0) < 1e-4
    # Equation-literal check, unsaturated so the arithmetic is real
    # (tau_max=100 would saturate and prove nothing).
    rc, out, _ = run("ctl-gov-charge", blob, f64(50.0), f64(10.0))
    assert rc == 0 and out[0] == "0", out
    blob = out[1]
    tau1 = struct.unpack(">f", bytes.fromhex(out[2]))[0]
    want = min(100.0, max(-100.0, 100.0 + 1.0 * 10.0 - 50.0))
    assert abs(tau1 - want) < 1e-4, (tau1, want)  # == 60.0
    # Shed progression: C0 rate halves toward floors first.
    a = action(2, 3600, 1800, 600, 8)
    rc, out, _ = run("ctl-gov-shed", blob, f64(4.0), a, f64(0.5),
                      "300", "1001")
    assert rc == 0 and out[0] == "0", out
    assert out[3] == "0", out  # first shed steps C0, not exhausted
    # Restore legs walk toward desired; only C0 differs here, so the
    # C0 leg fires with the rate doubled toward it.
    # Restore legs walk 0,1,2 -> 3 toward desired.
    cur, des = a, action(2, 3600, 1800, 600, 8)
    rc, out, _ = run("ctl-gov-restore-ready", blob, "1001", "3600")
    assert rc == 0 and out[0] == "0", out
    rc, out, _ = run("ctl-gov-restore-step", f64(2.0), cur, f64(4.0),
                      des)
    assert rc == 0 and out[0] == "0" and out[1] == "2" and \
        out[2] == f64(4.0), out
    rc, out, _ = run("ctl-gov-counts", blob)
    assert rc == 0 and out[0] == "0" and len(out) == 4, out


def test_decide_composite_and_consistency():
    blob = init_blob()
    for comp, v0, v1 in ((0, f32(80.0), "90"), (1, f32(0.05), "0"),
                         (2, "1", "0"), (3, f32(0.5), "0"),
                         (4, "65536", "0"), (5, "-60", "2"),
                         (6, f32(2.0), "7")):
        rc, out, _ = run("ctl-state-sample", blob, str(comp), v0, v1,
                         "1000")
        blob = out[1]
    rc, out, _ = run("ctl-energy-priors")
    coeff = out[1]
    wl = ["2", f64(3600.0), f64(0.0), f64(64.0), "3600", "1800", "60",
          f64(0.0), f64(0.0), f64(60.0), f64(100.0), f64(0.0)]
    rc, out, _ = run("ctl-decide", blob, INC0, "0", *wl, f64(0.0),
                      f64(1.0), "1000", f64(600.0), "010101", coeff,
                      f64(0.5), f64(0.2))
    assert rc == 0 and out[0] == "0" and out[2] == "1", out
    staged_a, alarms_a, blob_a = out[3], out[4], out[1]
    # Consistency: staged action sits inside the granular feasible set.
    rc, out, _ = run("ctl-floor-feasible", "010101", FTABLE, "1",
                      RES_H, FCFG_H, "65536")
    assert rc == 0 and staged_a in out[2:], (staged_a, out)
    assert alarms_a == "0", out
    # Determinism: rebuilt-from-scratch second run, byte-identical
    # blob and staged action (not self-comparison).
    blob2 = init_blob()
    for comp, v0, v1 in ((0, f32(80.0), "90"), (1, f32(0.05), "0"),
                         (2, "1", "0"), (3, f32(0.5), "0"),
                         (4, "65536", "0"), (5, "-60", "2"),
                         (6, f32(2.0), "7")):
        rc, out, _ = run("ctl-state-sample", blob2, str(comp), v0, v1,
                         "1000")
        blob2 = out[1]
    rc, out, _ = run("ctl-decide", blob2, INC0, "0", *wl, f64(0.0),
                      f64(1.0), "1000", f64(600.0), "010101", coeff,
                      f64(0.5), f64(0.2))
    assert rc == 0 and out[1] == blob_a and out[3] == staged_a, out
    # Fresh blob (M invalid) takes the HOLD path, staged 0.
    fresh = init_blob()
    rc, out, _ = run("ctl-decide", fresh, INC0, "0", *wl, f64(0.0),
                      f64(1.0), "1000", f64(600.0), "010101", coeff,
                      f64(0.5), f64(0.2))
    assert rc == 0 and out[0] == "2" and out[2] == "0", out  # HOLD


def test_misuse_battery():
    blob = init_blob()
    half = blob[: len(blob) // 2]
    rc, _, _ = run("ctl-state-sample", half, "1", f32(0.1), "0", "1")
    assert rc == 2
    rc, _, _ = run("ctl-state-sample", "XXXX" + blob[4:], "1",
                    f32(0.1), "0", "1")
    assert rc == 2
    badver = blob[:8] + "0002" + blob[12:]
    rc, _, _ = run("ctl-state-sample", badver, "1", f32(0.1), "0", "1")
    assert rc == 2
    rc, _, _ = run("ctl-state-sample", blob, "1", f32(0.1))
    assert rc == 2  # wrong argc
    rc, _, _ = run("ctl-state-sample", blob, "1", "nothex", "0", "1")
    assert rc == 2
    rc, _, _ = run("ctl-opt-decide", blob, "3",
                    action(1, 1, 1, -1, 1), f64(0.0), f64(1.0),
                    f64(1.0), "1")
    assert rc == 2  # ncands/length mismatch
    rc, _, _ = run("ctl-opt-commit", blob, "1", "1", f64(0.0),
                    "short", f64(1.0))
    assert rc == 2  # applied neither 14 B nor "none"
    rc, _, _ = run("ctl-opt-commit", blob, "1", "1", f64(0.0), "none",
                    f64(0.0))
    assert rc == 2  # dt must be > 0
    rc, _, _ = run("ctl-energy-derive", "9", f64(1.0), f64(0.0),
                    f64(64.0), "3600", "1800", "-1", f64(0.0),
                    f64(0.0), f64(60.0), f64(100.0), f64(0.0))
    assert rc == 2  # profile guard
