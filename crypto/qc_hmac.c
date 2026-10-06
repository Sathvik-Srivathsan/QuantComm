/* qc_hmac.c — HMAC-SHA-256 over qc_sha256 streaming API.
 * All key-material clearing goes through qc_zeroize (elision-resistant);
 * plain memset must never be used for wipes in this file. */
#include "qc_hmac.h"

#include <string.h>

#include "qc_sha256.h"
#include "qc_zeroize.h"

void qc_hmac_sha256(const uint8_t *key, size_t key_len,
                    const uint8_t *msg, size_t msg_len,
                    uint8_t out[32]) {
    /* Single code path: one-shot is streaming with one chunk. */
    qc_hmac_sha256_stream s;
    qc_hmac_sha256_sinit(&s, key, key_len);
    qc_hmac_sha256_supdate(&s, msg, msg_len);
    qc_hmac_sha256_sfinal(&s, out);
}

void qc_hmac_sha256_sinit(qc_hmac_sha256_stream *s,
                          const uint8_t *key, size_t key_len) {
    uint8_t kbuf[64];
    size_t i;

    if (key_len > 64) {
        qc_sha256(key, key_len, kbuf);
        qc_zeroize(kbuf + 32, 32);
    } else {
        if (key_len > 0 && key != NULL) {
            memcpy(kbuf, key, key_len);
        }
        qc_zeroize(kbuf + key_len, 64 - key_len);
    }
    for (i = 0; i < 64; i++) {
        s->k_opad[i] = kbuf[i] ^ 0x5c;
        kbuf[i] ^= 0x36;
    }
    qc_sha256_init(&s->inner);
    qc_sha256_update(&s->inner, kbuf, 64);
    qc_zeroize(kbuf, sizeof(kbuf));
}

void qc_hmac_sha256_supdate(qc_hmac_sha256_stream *s,
                            const uint8_t *msg, size_t len) {
    if (len > 0 && msg != NULL) {
        qc_sha256_update(&s->inner, msg, len);
    }
}

void qc_hmac_sha256_sfinal(qc_hmac_sha256_stream *s, uint8_t out[32]) {
    uint8_t inner[32];
    qc_sha256_ctx outer;

    qc_sha256_final(&s->inner, inner);
    qc_sha256_init(&outer);
    qc_sha256_update(&outer, s->k_opad, 64);
    qc_sha256_update(&outer, inner, 32);
    qc_sha256_final(&outer, out);
    qc_zeroize(s, sizeof(*s));
    qc_zeroize(inner, sizeof(inner));
}
