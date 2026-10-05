/* qc_hkdf.c — HKDF-SHA-256 over streaming qc_hmac_sha256. No heap. */
#include "qc_hkdf.h"

#include <string.h>

#include "qc_hmac.h"

int qc_hkdf_extract(const uint8_t *salt, size_t salt_len,
                    const uint8_t *ikm, size_t ikm_len,
                    uint8_t prk[32]) {
    static const uint8_t zeros[32] = {0};

    if (ikm == NULL || ikm_len == 0) {
        return -1;
    }
    if (salt == NULL || salt_len == 0) {
        salt = zeros;
        salt_len = 32;
    }
    /* PRK = HMAC-Hash(salt, IKM): salt is the HMAC *key*. */
    qc_hmac_sha256(salt, salt_len, ikm, ikm_len, prk);
    return 0;
}

int qc_hkdf_expand(const uint8_t prk[32],
                   const uint8_t *info, size_t info_len,
                   uint8_t *okm, size_t okm_len) {
    qc_hmac_sha256_stream hs;
    uint8_t t[32];
    size_t done = 0;
    uint8_t ctr = 1;

    if (prk == NULL) {
        return -1;
    }

    if (okm_len > 255 * 32) {
        return -1;
    }
    if (okm_len == 0) {
        return 0;
    }
    if (info == NULL) {
        info_len = 0;
    }
    /* T(0) is empty; T(i) = HMAC(PRK, T(i-1) || info || i). */
    memset(t, 0, sizeof(t));
    while (done < okm_len) {
        size_t take;
        qc_hmac_sha256_sinit(&hs, prk, 32);
        if (done > 0) {
            qc_hmac_sha256_supdate(&hs, t, sizeof(t));
        }
        qc_hmac_sha256_supdate(&hs, info, info_len);
        qc_hmac_sha256_supdate(&hs, &ctr, 1);
        qc_hmac_sha256_sfinal(&hs, t);
        take = okm_len - done;
        if (take > sizeof(t)) {
            take = sizeof(t);
        }
        memcpy(okm + done, t, take);
        done += take;
        ctr++;
    }
    memset(t, 0, sizeof(t));
    return 0;
}
