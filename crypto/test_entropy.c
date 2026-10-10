/* test_entropy.c — TEST-ONLY deterministic entropy stand-in.
 * NEVER linked into production (same rule + CI scan as test_rng.c).
 * Fixed SplitMix64 stream reseeded by test_entropy_seed(); the stream is
 * shared across calls (reseeds draw continuing bytes — models a live
 * provider deterministically). test_entropy_fail_next() forces the next
 * poll to fail (fault-injection for RNG_FAIL paths + audit strings).
 * Same seed -> identical stream, forever.
 */
#include "qc_entropy.h"

#include <string.h>

static uint64_t s_state = 0x243F6A8885A308D3ull;
static int s_fail_next = 0;

void test_entropy_seed(uint64_t seed) {
    s_state = seed;
    s_fail_next = 0;
}

void test_entropy_fail_next(void) {
    s_fail_next = 1;
}

static void audit_set(char *audit, const char *s) {
    size_t i = 0;
    while (i + 1 < QC_ENTROPY_AUDIT_LEN && s[i] != '\0') {
        audit[i] = s[i];
        i++;
    }
    audit[i] = '\0';
}

int qc_entropy_poll(uint8_t *out, size_t len,
                    char audit[QC_ENTROPY_AUDIT_LEN]) {
    size_t i = 0;

    if (audit != NULL) {
        audit_set(audit, "ok");
    }
    if (out == NULL || len == 0 || len > QC_ENTROPY_MAX) {
        if (audit != NULL) {
            audit_set(audit, "bad-arg");
        }
        return -1;
    }
    if (s_fail_next) {
        s_fail_next = 0;
        if (audit != NULL) {
            audit_set(audit, "injected-fault");
        }
        return -1;
    }
    while (i < len) {
        uint64_t z;
        s_state += 0x9E3779B97F4A7C15ull;
        z = s_state;
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
        z = z ^ (z >> 31);
        for (unsigned k = 0; k < 8 && i < len; k++, i++) {
            out[i] = (uint8_t)(z >> (8 * k));
        }
    }
    return 0;
}
