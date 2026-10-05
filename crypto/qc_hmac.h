/* qc_hmac.h — HMAC-SHA-256, RFC 2104/4231.
 * Contract: qc_hmac_sha256(key, key_len, msg, msg_len, out32).
 * Keys of any length incl. empty (hashed if > block, padded if short).
 * Deterministic: no RNG, no heap. Key material zeroized on stack after use.
 */
#ifndef QC_HMAC_H
#define QC_HMAC_H

#include <stddef.h>
#include <stdint.h>

#include "qc_sha256.h"

void qc_hmac_sha256(const uint8_t *key, size_t key_len,
                    const uint8_t *msg, size_t msg_len,
                    uint8_t out[32]);

/* Streaming form (key bound at init; arbitrary-length message chunks).
 * Needed by HKDF-Expand so info of any length never needs buffering. */
typedef struct {
    uint8_t k_opad[64];
    qc_sha256_ctx inner;
} qc_hmac_sha256_stream;

void qc_hmac_sha256_sinit(qc_hmac_sha256_stream *s,
                          const uint8_t *key, size_t key_len);
void qc_hmac_sha256_supdate(qc_hmac_sha256_stream *s,
                            const uint8_t *msg, size_t len);
void qc_hmac_sha256_sfinal(qc_hmac_sha256_stream *s, uint8_t out[32]);

#endif
