/* qc_entropy.c — host OS entropy via getrandom (B-13.1).
 * Single-threaded callers only (static stuck-test state, no locks —
 * same assumption as every other unit in this tree).
 */
#include "qc_entropy.h"

#include <string.h>
#include <sys/random.h>

#include "qc_zeroize.h"

/* Previous 32 B block for the stuck-output continuous test. Zero-init:
 * first call always passes the comparison (documented bootstrap). */
static uint8_t s_prev[32];
static int s_have_prev = 0;

void qc_entropy_forget(void) {
    qc_zeroize(s_prev, sizeof(s_prev));
    s_have_prev = 0;
}

static void audit_set(char audit[QC_ENTROPY_AUDIT_LEN], const char *s) {
    size_t i = 0;
    while (i + 1 < QC_ENTROPY_AUDIT_LEN && s[i] != '\0') {
        audit[i] = s[i];
        i++;
    }
    audit[i] = '\0';
}

int qc_entropy_poll(uint8_t *out, size_t len,
                    char audit[QC_ENTROPY_AUDIT_LEN]) {
    int attempt;

    if (audit != NULL) {
        audit_set(audit, "ok");
    }
    if (out == NULL || len == 0 || len > QC_ENTROPY_MAX) {
        if (audit != NULL) {
            audit_set(audit, "bad-arg");
        }
        return -1;
    }
    for (attempt = 0; attempt < 3; attempt++) {
        uint8_t block[32];
        ssize_t n;
        size_t done = 0;

        /* Bounded blocking read (getrandom flags=0 may block until the
         * kernel pool initializes; each attempt is one full read loop,
         * three attempts max, then fail — no unbounded wait). */
        while (done < len) {
            n = getrandom(out + done, len - done, 0);
            if (n <= 0) {
                break;
            }
            done += (size_t)n;
        }
        if (done != len) {
            continue;
        }
        /* Stuck-output test over the first 32 B (FIPS 140 continuous-test
         * shape: identical consecutive blocks fail). Short reads (<32 B
         * requested) skip the test — too little material to judge. */
        if (len >= 32) {
            memcpy(block, out, 32);
            if (s_have_prev && memcmp(block, s_prev, 32) == 0) {
                if (audit != NULL) {
                    audit_set(audit, "stuck-output");
                }
                return -1;
            }
            memcpy(s_prev, block, 32);
            s_have_prev = 1;
            memset(block, 0, sizeof(block));
        }
        return 0;
    }
    if (audit != NULL) {
        audit_set(audit, "short-read");
    }
    return -1;
}
