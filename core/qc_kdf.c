/* qc_kdf.c — session key schedule over qc_hkdf + qc_sha256.
 * Boundary contracts enforced here (producer postcondition => consumer
 * precondition, fail-closed):
 *  - Extract salt  = 12 + 32 = 44 B fixed-size buffer (construction).
 *  - Extract IKM   = 5 + len(K1) + len(K2) + 32, non-empty, per-input caps
 *    make the total check wraparound-proof (runtime checks).
 *  - Expand info   = len("QC-TRANSCRIPT") + 1 + 32, L = 128 (fixed buffers
 *    plus _Static_assert; split offsets fixed likewise).
 */
#include "qc_kdf.h"

#include <string.h>

#include "qc_hkdf.h"
#include "qc_sha256.h"

qc_kdf_trace_fn qc_kdf_trace = NULL;

#define QC_KDF_LABEL_HS "QC-HS"
#define QC_KDF_LABEL_TRANSCRIPT "QC-TRANSCRIPT"

/* Per-input cap 2048 B: covers the largest level size (1568 B per the
 * B-10.1 table) with 480 B headroom. Bounds each length BEFORE any
 * addition, so the total-size check below cannot be defeated by size_t
 * wraparound. */
#define QC_KDF_MAX_IN 2048

_Static_assert(sizeof(QC_KDF_LABEL_HS) - 1 == 5, "QC-HS label width");
_Static_assert(sizeof(QC_KDF_LABEL_TRANSCRIPT) - 1 == 13, "transcript label width");
_Static_assert(QC_SHA256_DIGEST_LEN == 32, "digest width");

int qc_kdf_derive(const uint8_t nw[12], const uint8_t ns[32],
                  const uint8_t *k1, size_t k1_len,
                  const uint8_t *k2, size_t k2_len,
                  const uint8_t kdev[32],
                  const uint8_t *transcript, size_t transcript_len,
                  qc_kdf_keys *out) {
    /* IKM buffer: 5 + K1 + K2 + 32, sized from the per-input cap macro
     * (not a magic number) so changing QC_KDF_MAX_IN resizes it. */
    uint8_t ikm[5 + 2 * QC_KDF_MAX_IN];
    uint8_t salt[44];
    uint8_t prk[32];
    uint8_t info[13 + 1 + 32];
    uint8_t okm[128];
    uint8_t thash[32];
    size_t ikm_len;
    int rc;

    if (nw == NULL || ns == NULL || kdev == NULL || out == NULL) {
        return -1;
    }
    if (k1 == NULL || k1_len == 0 || k2 == NULL || k2_len == 0) {
        return -1;
    }
    /* Per-input caps FIRST: with each length <= 2048 the sum below cannot
     * wrap size_t, so the total check is a real bound, not a formality. */
    if (k1_len > QC_KDF_MAX_IN || k2_len > QC_KDF_MAX_IN) {
        return -1;
    }
    if (transcript == NULL || transcript_len == 0) {
        return -1;
    }
    /* Total check: capped max sums to 4133 > 4101, so it rejects (never
     * wraps: inputs already bounded above, sum < SIZE_MAX always). */
    if (5 + k1_len + k2_len + 32 > sizeof(ikm)) {
        return -1;
    }

    /* salt = N_W || N_S (12 + 32). */
    memcpy(salt, nw, 12);
    memcpy(salt + 12, ns, 32);

    /* IKM = "QC-HS" || K1 || K2 || Kdev. */
    memcpy(ikm, QC_KDF_LABEL_HS, 5);
    memcpy(ikm + 5, k1, k1_len);
    memcpy(ikm + 5 + k1_len, k2, k2_len);
    memcpy(ikm + 5 + k1_len + k2_len, kdev, 32);
    ikm_len = 5 + k1_len + k2_len + 32;

    rc = qc_hkdf_extract(salt, sizeof(salt), ikm, ikm_len, prk);
    /* Wipe ephemeral IKM copy immediately (stored Kdev untouched). */
    memset(ikm, 0, ikm_len);
    memset(salt, 0, sizeof(salt));
    if (rc != 0) {
        memset(prk, 0, sizeof(prk));
        return -1;
    }

    _Static_assert(sizeof(info) == 13 + 1 + 32, "info layout");
    _Static_assert(sizeof(okm) == 128, "okm length");
    _Static_assert(sizeof(okm) == 4 * 32, "split widths");
    /* info = "QC-TRANSCRIPT" || 0x00 || H(transcript). */
    qc_sha256(transcript, transcript_len, thash);
    memcpy(info, QC_KDF_LABEL_TRANSCRIPT, 13);
    info[13] = 0x00;
    memcpy(info + 14, thash, 32);

    rc = qc_hkdf_expand(prk, info, sizeof(info), okm, sizeof(okm));
    if (rc != 0) {
        memset(okm, 0, sizeof(okm));
        memset(prk, 0, sizeof(prk));
        memset(info, 0, sizeof(info));
        memset(thash, 0, sizeof(thash));
        return -1;
    }

    /* Trace BEFORE wiping (post-wipe trace would log zeros). */
    if (qc_kdf_trace != NULL) {
        qc_kdf_trace(prk, info, sizeof(info), okm);
    }
    memset(prk, 0, sizeof(prk));
    memset(info, 0, sizeof(info));
    memset(thash, 0, sizeof(thash));
    memcpy(out->k_c2s, okm, 32);
    memcpy(out->k_s2c, okm + 32, 32);
    memcpy(out->k_rat, okm + 64, 32);
    memcpy(out->k_conf, okm + 96, 32);
    memset(okm, 0, sizeof(okm));
    return 0;
}
