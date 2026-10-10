/* qc_entropy.h — OS entropy source + health checks (plan B-13.1, host).
 *
 * Production code NEVER calls this directly for keys (it calls the DRBG
 * via qc_rng_generate); the DRBG calls here for seed/reseed material.
 * Returns 0 on success, nonzero RNG_FAIL with a non-secret audit string
 * distinguishing the cause. No caller seeding of production entropy.
 *
 * Health model (host): getrandom success + stuck-output rejection (two
 * identical consecutive 32 B blocks fail — FIPS 140-style continuous
 * test); bounded retries (<= 3) each with a fresh health check, then
 * RNG_FAIL + audit; no retry-until-success bypass. Blocking poll with
 * ATTEMPTS capped at 3 — audit correction (F5): there is NO per-call
 * timeout; getrandom(flags=0) may block pre-boot, so early-boot callers
 * must treat this as potentially-blocking. Per-call cap QC_ENTROPY_MAX
 * (sanity; callers needing more loop). ESP32 port swaps this TU for the
 * HW-RNG one (same header).
 *
 * Stuck-test history (last 32 B) is process-lifetime BSS; qc_entropy_forget()
 * wipes it (audit F6c). No auto-wipe: there is no exit hook in this TU.
 */
#ifndef QC_ENTROPY_H
#define QC_ENTROPY_H

#include <stddef.h>
#include <stdint.h>

#define QC_ENTROPY_MAX 4096
#define QC_ENTROPY_AUDIT_LEN 64

/* Fill `len` bytes. audit always NUL-terminated on return (ok or cause).
 * out NULL or len 0 or len > MAX -> RNG_FAIL ("bad-arg", no bytes).
 * On ANY failure out contents are undefined (may be partial): callers
 * must treat the buffer as unusable, same rule as qc_rng_generate. */
int qc_entropy_poll(uint8_t *out, size_t len,
                    char audit[QC_ENTROPY_AUDIT_LEN]);

/* Wipe stuck-test history (process-lifetime BSS). No output. */
void qc_entropy_forget(void);

#endif