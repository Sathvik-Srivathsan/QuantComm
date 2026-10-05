# QuantComm — implementation (build branch)

Plan lives on the `planning` branch (`plan-rigorous.md` — the spec).
This branch is code only. Outcomes/verdicts fillable only per plan gates.

## Layout

```
core/         C11 — protocol FSM, controller/floor logic, HKDF, risk/hysteresis
crypto/       C11 — crypto backend adapters (reference + optimized tracks)
server/       Python — trust anchor, policy signer, session/replay state
gateway/      Python — untrusted BLE-to-IP relay
sim/          Python — deterministic discrete-event simulator
tests/c       C tests (Unity) — run under CTest
tests/python  Python tests (pytest)
analysis/     Python — statistics pipeline
experiments/  Experiment configs, manifests, result bundles
tools/        Build/CI helper scripts
third_party/  Vendored deps (Unity; see third_party/unity/README.md)
docs/         References (this file lives here via root README)
```

**Hard boundary:** `core/` must never call `esp_*`, NimBLE, or FreeRTOS APIs
directly — only injected interfaces (radio send/recv, crypto provider,
clock, storage). Keeps `core/` portable to a non-ESP32 wearable later.

## Build & test (C side runs in WSL — gcc/cmake present there)

```bash
# from repo root, inside WSL:
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build
ctest --test-dir build --output-on-failure
```

## Test (Python side runs on Windows)

```powershell
python -m pytest tests/python -q
```

## Test layers (per plan test contract)

- **L0 vectors**: known-answer vectors, exact byte compare, no sampling.
- **L1 isolated**: one unit alone with step-trace logging (JSONL) + deterministic RNG.
- **L2 collective**: units wired together (handshake → KDF → AEAD round-trips).
- **L3 full loop**: everything on the simulator, seeds recorded, SIM-tagged.
- No step starts until the previous step's L0+L1 are green.
