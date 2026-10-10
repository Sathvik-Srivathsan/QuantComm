/* qc_drbg.h — HMAC-DRBG-SHA-256 (NIST SP 800-90A §10.1.2, plan B-13.2).
 *
 * 256-bit strength over the B-12 suite (HMAC-SHA-256; no new primitive).
 * Per-context instances (caller-owned struct, no shared mutable state,
 * no locks — single-threaded callers). Fork safety: pid recorded at
 * init/reseed; a changed pid on generate zeroizes + reseeds (child gets
 * fresh state or a hard failure, never continued parent stream).
 *
 * Reseed policy: explicit reseed() (tests, ceremonies), provider reseed
 * (reseed_from_provider pulls 32 B via qc_entropy_poll), and automatic
 * reseed inside generate when out_total would exceed R (2^20 B) or
 * now - reseed_at reaches T (3600 s). Reseed failure -> RNG_FAIL with no
 * output (fail-closed). Single generate call capped at 2^16 B (past
 * limit fails closed, state intact). Spec 2^48 reseed_counter enforced
 * (unreachable under R/T policy; belt-and-braces).
 * Timestamps are caller `now` (opaque seconds, same convention as cache).
 *
 * KATs: NIST CAVS HMAC_DRBG vectors (test_drbg.c, committed subset +
 * nightly-full procedure). Statistical sanity (monobit/poker/runs) is a
 * caller-side check over output buffers (qc_drbg_selftest_stats), run on
 * test builds only — deterministic streams would fail by design, so the
 * harness skips it under sim-seed (documented in the test).
 *
 * Returns 0 ok, -1 RNG_FAIL (matches qc_rng convention).
 */
#ifndef QC_DRBG_H
#define QC_DRBG_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define QC_DRBG_KEY_LEN 32
#define QC_DRBG_RESEED_BYTES ((uint64_t)1 << 20)
#define QC_DRBG_RESEED_SECS 3600
#define QC_DRBG_MAX_GEN ((size_t)1 << 16)
/* Max seed material per reseed (stack-bounded; SP 800-90A imposes no
 * strict max, but unbounded input here would need heap or truncation —
 * both worse than a documented cap). */
#define QC_DRBG_MAX_SEED 256

typedef struct {
    uint8_t k[QC_DRBG_KEY_LEN];
    uint8_t v[QC_DRBG_KEY_LEN];
    uint64_t reseed_ctr;    /* SP 800-90A reseed_counter. */
    uint64_t out_total;     /* bytes since last (re)seed (R policy). */
    uint64_t reseed_at;     /* `now` of last (re)seed (T policy). */
    pid_t pid;              /* owner pid at last (re)seed (fork check). */
    uint8_t seeded;
} qc_drbg;

int qc_drbg_init(qc_drbg *d);
int qc_drbg_reseed(qc_drbg *d, const uint8_t *entropy, size_t entropy_len);
int qc_drbg_reseed_from_provider(qc_drbg *d, uint64_t now);
int qc_drbg_generate(qc_drbg *d, uint8_t *out, size_t len,
                     const uint8_t *add, size_t add_len, uint64_t now);
void qc_drbg_free(qc_drbg *d);

/* Statistical sanity over a caller buffer (N >= 2500 bytes recommended):
 * monobit |p-0.5| < 0.02. Returns 0 pass, nonzero fail. Caller-side
 * check (not a DRBG method): run on live output in test builds, never
 * as a gate on deterministic/sim streams. */
int qc_drbg_selftest_stats(const uint8_t *buf, size_t len);

#endif