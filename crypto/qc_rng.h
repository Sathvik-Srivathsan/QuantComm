/* qc_rng.h — RNG provider interface (B-02.2 pattern).
 *
 * Production code calls qc_rng_generate() and never knows the source.
 * Two providers exist, selected AT LINK TIME (never runtime):
 *   qc_rng_prod.c  — OS entropy (getrandom). Linked into firmware/host apps.
 *   test_rng.c     — SplitMix64, explicit seed. Linked into tests ONLY.
 * test_rng.c must never appear in a production link closure (CI scans for it).
 */
#ifndef QC_RNG_H
#define QC_RNG_H

#include <stddef.h>
#include <stdint.h>

/* Fill `len` bytes. Returns 0 on success, nonzero on failure (fail-closed:
 * caller must treat output buffer as unusable). */
int qc_rng_generate(uint8_t *out, size_t len);

#endif
