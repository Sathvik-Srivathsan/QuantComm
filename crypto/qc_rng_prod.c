/* qc_rng_prod.c — production RNG: HMAC-DRBG over OS entropy (B-13).
 * Single static DRBG instance (global provider symbol requires somewhere
 * to hold state; single-threaded callers only — same assumption as every
 * other unit here). First call implicitly instantiates from the entropy
 * provider; R/T auto-reseed + fork detection live inside the DRBG.
 * ESP-IDF port swaps this TU for the HW-RNG-backed one (same header).
 */
#include "qc_rng.h"

#include <string.h>
#include <time.h>

#include "qc_drbg.h"
#include "qc_zeroize.h"

static qc_drbg s_drbg;
static int s_live = 0;

int qc_rng_generate(uint8_t *out, size_t len) {
    size_t done = 0;

    if (out == NULL || len == 0) {
        return -1;
    }
    if (!s_live) {
        if (qc_drbg_init(&s_drbg) != 0) {
            return -1;
        }
        s_live = 1;
    }
    while (done < len) {
        size_t take = len - done;
        if (take > QC_DRBG_MAX_GEN) {
            take = QC_DRBG_MAX_GEN;
        }
        if (qc_drbg_generate(&s_drbg, out + done, take, NULL, 0,
                             (uint64_t)time(NULL)) != 0) {
            /* Fail-closed: caller must treat the buffer as unusable;
             * wipe what was already written (never release partial). */
            qc_zeroize(out, done);
            return -1;
        }
        done += take;
    }
    return 0;
}
