/* qc_health.c - entropy health evaluation (plan B-50.3 IID/non-IID). */
#include "qc_health.h"

#include <string.h>

#include "qc_entropy.h"

/* Thresholds come from qc_health.h (provisional, B-13 to ratify). */

static void audit_set(char *audit, const char *s) {
    if (audit == NULL) {
        return;
    }
    size_t n = strlen(s);
    if (n >= QC_HEALTH_AUDIT_LEN) {
        n = QC_HEALTH_AUDIT_LEN - 1;
    }
    memcpy(audit, s, n);
    audit[n] = '\0';
}

const char *qc_health_str(qc_health_rc rc) {
    switch (rc) {
    case QC_HEALTH_OK:          return "ok";
    case QC_HEALTH_BAD_ARG:     return "bad-arg";
    case QC_HEALTH_LOW_ONES:    return "ones-skew";
    case QC_HEALTH_BLOCK_SKEW:  return "block-skew";
    case QC_HEALTH_LONG_RUN:    return "long-run";
    case QC_HEALTH_ALPHABET:    return "alphabet-starved";
    case QC_HEALTH_TOO_SHORT:   return "too-short";
    default:                    return "unknown";
    }
}

/* Whole-sample one-bit proportion, in permille (avoids float entirely so
 * the gate stays bit-deterministic across hosts). */
static uint32_t ones_permille(const uint8_t *buf, size_t len) {
    size_t i;
    uint32_t ones = 0;
    for (i = 0; i < len; i++) {
        uint8_t b = buf[i];
        while (b) {
            ones += (uint32_t)(b & 1u);
            b = (uint8_t)(b >> 1);
        }
    }
    /* permille = ones * 1000 / (len * 8) */
    return (uint32_t)((ones * 1000u) / (uint32_t)(len * 8u));
}

/* Longest run of identical bits across the sample, bit-packed MSB-first
 * within each byte (ordering choice only shifts which run is found; the
 * bound is on run LENGTH, not position). */
static uint32_t max_bit_run(const uint8_t *buf, size_t len) {
    size_t i;
    int bit;
    uint32_t run = 0, best = 0;
    int last = -1;
    for (i = 0; i < len; i++) {
        for (bit = 7; bit >= 0; bit--) {
            int cur = (buf[i] >> bit) & 1;
            if (cur == last) {
                run++;
            } else {
                last = cur;
                run = 1;
            }
            if (run > best) {
                best = run;
            }
        }
    }
    return best;
}

static uint32_t distinct_bytes(const uint8_t *buf, size_t len) {
    uint8_t seen[256];
    size_t i;
    uint32_t n = 0;
    memset(seen, 0, sizeof(seen));
    for (i = 0; i < len; i++) {
        if (!seen[buf[i]]) {
            seen[buf[i]] = 1;
            n++;
        }
    }
    return n;
}

qc_health_rc qc_health_check(const uint8_t *buf, size_t len,
                             char audit[QC_HEALTH_AUDIT_LEN]) {
    uint32_t permille, run, distinct;
    size_t off;
    int b;

    if (audit != NULL) {
        audit[0] = '\0';
    }
    /* Caller error and insufficient-sample are distinct conditions and get
     * distinct codes: a NULL buffer is a bug in the caller, a short buffer
     * is a policy decision about sample size. Blurring them would make a
     * wiring mistake look like a weak-entropy verdict. */
    if (buf == NULL) {
        audit_set(audit, "bad-arg");
        return QC_HEALTH_BAD_ARG;
    }
    if (len < 256u) {
        audit_set(audit, "too-short");
        return QC_HEALTH_TOO_SHORT;
    }

    permille = ones_permille(buf, len);
    if (permille < QC_HEALTH_ONES_LO_PERMILLE
        || permille > QC_HEALTH_ONES_HI_PERMILLE) {
        audit_set(audit, "ones-skew");
        return QC_HEALTH_LOW_ONES;
    }

    /* Per-block skew over whole 1024-bit blocks only: a trailing partial
     * block is too small for a fair proportion and would false-flag. */
    for (off = 0; off + (QC_HEALTH_BLOCK_BITS / 8u) <= len;
         off += (QC_HEALTH_BLOCK_BITS / 8u)) {
        const uint8_t *blk = buf + off;
        uint32_t ones = 0, blkpermille;
        for (b = 0; b < (int)(QC_HEALTH_BLOCK_BITS / 8u); b++) {
            uint8_t v = blk[b];
            while (v) {
                ones += (uint32_t)(v & 1u);
                v = (uint8_t)(v >> 1);
            }
        }
        blkpermille = (uint32_t)((ones * 1000u) / QC_HEALTH_BLOCK_BITS);
        if (blkpermille < QC_HEALTH_BLOCK_ONES_LO_PERMILLE
            || blkpermille > QC_HEALTH_BLOCK_ONES_HI_PERMILLE) {
            audit_set(audit, "block-skew");
            return QC_HEALTH_BLOCK_SKEW;
        }
    }

    run = max_bit_run(buf, len);
    if (run > QC_HEALTH_MAX_RUN_BITS) {
        audit_set(audit, "long-run");
        return QC_HEALTH_LONG_RUN;
    }

    distinct = distinct_bytes(buf, len);
    if (distinct < QC_HEALTH_MIN_DISTINCT_BYTES) {
        audit_set(audit, "alphabet-starved");
        return QC_HEALTH_ALPHABET;
    }

    audit_set(audit, "ok");
    return QC_HEALTH_OK;
}

qc_health_rc qc_health_check_os(size_t len,
                               char audit[QC_HEALTH_AUDIT_LEN]) {
    uint8_t stack[QC_HEALTH_SAMPLE];
    char poll_audit[QC_ENTROPY_AUDIT_LEN];
    int rc;

    if (audit != NULL) {
        audit[0] = '\0';
    }
    if (len == 0u || len > sizeof(stack)) {
        audit_set(audit, "bad-arg");
        return QC_HEALTH_BAD_ARG;
    }
    rc = qc_entropy_poll(stack, len, poll_audit);
    if (rc != 0) {
        /* Never launder a poll failure into a health pass. */
        audit_set(audit, "poll-failed");
        return QC_HEALTH_LOW_ONES;
    }
    return qc_health_check(stack, len, audit);
}
