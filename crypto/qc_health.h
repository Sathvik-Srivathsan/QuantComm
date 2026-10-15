/* qc_health.h - entropy health evaluation (plan B-50.3 IID/non-IID).
 *
 * B-50.3 requires "stuck-source rejection plus IID/non-IID health testing
 * with B-13-documented thresholds". The stuck-output test lives inside
 * B-13's qc_entropy_poll; this module is the IID/non-IID half, owned by
 * B-50 because the gate is what consumes the verdicts.
 *
 * PROVISIONAL THRESHOLDS (task-pipeline gate 1: zero invented constants).
 * Every value below is a provisional chosen by B-50 and labeled as such.
 * Owner for ratification is B-13 (its header already claims the health
 * model). They are set to catch a genuinely broken source with certainty
 * while never flagging real OS entropy - a health gate that flakes is
 * worse than no gate, so the bands are deliberately wide and the strong
 * detections (constant source, low bit entropy, long runs, starved byte
 * alphabet) are carried by tests that are effectively never false-positive.
 *
 * SCOPE: this module EVALUATES bytes handed to it. It does not sample the
 * OS itself and does not change qc_entropy_poll's boot path. Wiring an
 * IID check into production seeding remains B-13's call; the gate samples
 * and evaluates here.
 */
#ifndef QC_HEALTH_H
#define QC_HEALTH_H

#include <stddef.h>
#include <stdint.h>

/* Provisional sample size for the whole-sample tests (bytes).
 * MUST NOT exceed QC_ENTROPY_MAX (4096, B-13's per-call poll cap) or
 * qc_health_check_os can never draw a sample - a cap mismatch here would
 * surface as "poll-failed" on every healthy host, which is exactly the
 * flake the gate must never produce. */
#define QC_HEALTH_SAMPLE 4096u

/* Provisional thresholds (B-13 to ratify; see file header). */
#define QC_HEALTH_ONES_LO_PERMILLE 400u   /* 0.400 */
#define QC_HEALTH_ONES_HI_PERMILLE 600u   /* 0.600 */
#define QC_HEALTH_BLOCK_BITS 1024u
#define QC_HEALTH_BLOCK_ONES_LO_PERMILLE 350u
#define QC_HEALTH_BLOCK_ONES_HI_PERMILLE 650u
#define QC_HEALTH_MAX_RUN_BITS 24u
#define QC_HEALTH_MIN_DISTINCT_BYTES 200u  /* of 256, over the sample */

typedef enum {
    QC_HEALTH_OK = 0,
    QC_HEALTH_BAD_ARG = 1,
    QC_HEALTH_LOW_ONES = 2,        /* IID: bit distribution skewed */
    QC_HEALTH_BLOCK_SKEW = 3,      /* IID: a 1024-bit block skewed */
    QC_HEALTH_LONG_RUN = 4,        /* non-IID: long identical-bit run */
    QC_HEALTH_ALPHABET = 5,        /* non-IID: byte values starved */
    QC_HEALTH_TOO_SHORT = 6
} qc_health_rc;

#define QC_HEALTH_AUDIT_LEN 64

/* Evaluate `len` bytes. `audit` receives a short cause string (never key
 * material, never the sampled bytes themselves). Pass NULL to skip.
 * Returns QC_HEALTH_OK only when every provisional test passes. */
qc_health_rc qc_health_check(const uint8_t *buf, size_t len,
                             char audit[QC_HEALTH_AUDIT_LEN]);

/* Sample `len` bytes from the OS entropy source and evaluate them.
 * Wraps B-13's qc_entropy_poll; any poll failure is reported as
 * LOW_ONES-adjacent infra noise only through the audit string, never as a
 * health pass. */
qc_health_rc qc_health_check_os(size_t len,
                               char audit[QC_HEALTH_AUDIT_LEN]);

const char *qc_health_str(qc_health_rc rc);

#endif
