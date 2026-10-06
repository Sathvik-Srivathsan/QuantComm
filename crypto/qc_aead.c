/* qc_aead.c — AES-256-GCM over mbedTLS GCM (pruned config).
 * Key/nonce lengths enforced here (misuse taxonomy); crypto itself
 * delegated. mbedTLS context zeroized after use (keys never linger).
 *
 * This file requires mbedTLS 3.6+: the GCM backend goes through the
 * block-cipher abstraction that the pruned config auto-enables, and the
 * exact failure codes mapped below (AUTH_FAILED vs BAD_INPUT) are part
 * of that contract. Host pins 3.6.4 via vendored-source hashes; the
 * ESP-IDF target build must satisfy this floor.
 */
#include "qc_aead.h"

#include "mbedtls/build_info.h"

#if MBEDTLS_VERSION_NUMBER < 0x03060000
#error "qc_aead requires mbedTLS 3.6+ (block-cipher GCM backend)"
#endif

#include "mbedtls/gcm.h"
#include "mbedtls/platform_util.h"

static int check_common(const uint8_t *key, size_t key_len,
                        const uint8_t *nonce, size_t nonce_len) {
    if (key == NULL) {
        return QC_AEAD_BAD_KEY;
    }
    if (nonce == NULL) {
        return QC_AEAD_BAD_LENGTH;
    }
    if (key_len != QC_AEAD_KEY_LEN) {
        return QC_AEAD_BAD_KEY;
    }
    if (nonce_len != QC_AEAD_NONCE_LEN) {
        return QC_AEAD_BAD_LENGTH;
    }
    return QC_AEAD_OK;
}

int qc_aead_encrypt(const uint8_t *key, size_t key_len,
                    const uint8_t *nonce, size_t nonce_len,
                    const uint8_t *aad, size_t aad_len,
                    const uint8_t *pt, size_t pt_len,
                    uint8_t *ct, uint8_t tag[QC_AEAD_TAG_LEN]) {
    mbedtls_gcm_context ctx;
    int rc;
    int out;

    out = check_common(key, key_len, nonce, nonce_len);
    if (out != QC_AEAD_OK) {
        return out;
    }
    if ((pt_len > 0 && (pt == NULL || ct == NULL)) || tag == NULL) {
        return QC_AEAD_BAD_LENGTH;
    }
    if (aad_len > 0 && aad == NULL) {
        return QC_AEAD_BAD_LENGTH;
    }
    /* setkey cannot fail on caller input here (cipher fixed to AES,
     * keybits fixed to 256 and already length-checked): any failure is
     * a backend fault, hence INTERNAL, not BAD_KEY. Currently defensive
     * (unreachable); kept so a future backend change fails closed. */
    mbedtls_gcm_init(&ctx);
    rc = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 256);
    if (rc != 0) {
        mbedtls_gcm_free(&ctx);
        return QC_AEAD_INTERNAL;
    }
    rc = mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT, pt_len,
                                   nonce, nonce_len,
                                   aad_len > 0 ? aad : NULL, aad_len,
                                   pt_len > 0 ? pt : NULL, ct,
                                   QC_AEAD_TAG_LEN, tag);
    mbedtls_gcm_free(&ctx);
    if (rc == MBEDTLS_ERR_GCM_BAD_INPUT) {
        /* Overlapping buffers or a length over the GCM per-invocation
         * cap: caller bug. Wipe partial output with the
         * elision-resistant primitive (plain memset may be optimized
         * away). */
        if (ct != NULL && pt_len > 0) {
            mbedtls_platform_zeroize(ct, pt_len);
        }
        if (tag != NULL) {
            mbedtls_platform_zeroize(tag, QC_AEAD_TAG_LEN);
        }
        return QC_AEAD_BAD_LENGTH;
    }
    if (rc != 0) {
        /* Any other backend fault (e.g. cipher-layer failure): not caller
         * input, so INTERNAL rather than BAD_LENGTH. Unreachable with
         * fixed AES-256 short inputs; kept fail-closed. */
        if (ct != NULL && pt_len > 0) {
            mbedtls_platform_zeroize(ct, pt_len);
        }
        if (tag != NULL) {
            mbedtls_platform_zeroize(tag, QC_AEAD_TAG_LEN);
        }
        return QC_AEAD_INTERNAL;
    }
    return QC_AEAD_OK;
}

int qc_aead_decrypt(const uint8_t *key, size_t key_len,
                    const uint8_t *nonce, size_t nonce_len,
                    const uint8_t *aad, size_t aad_len,
                    const uint8_t *ct, size_t ct_len,
                    const uint8_t tag[QC_AEAD_TAG_LEN],
                    uint8_t *pt) {
    mbedtls_gcm_context ctx;
    int rc;
    int out;

    out = check_common(key, key_len, nonce, nonce_len);
    if (out != QC_AEAD_OK) {
        return out;
    }
    if ((ct_len > 0 && (ct == NULL || pt == NULL)) || tag == NULL) {
        return QC_AEAD_BAD_LENGTH;
    }
    if (aad_len > 0 && aad == NULL) {
        return QC_AEAD_BAD_LENGTH;
    }
    mbedtls_gcm_init(&ctx);
    rc = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 256);
    if (rc != 0) {
        mbedtls_gcm_free(&ctx);
        return QC_AEAD_INTERNAL;
    }
    /* auth_decrypt decrypts into pt FIRST, then compares tags in
     * constant time (mbedtls_ct_memcmp) and zeroizes pt itself on
     * mismatch. The wipe below is therefore a second layer, not the
     * only one — kept so the no-release contract does not depend on a
     * single backend behavior. */
    rc = mbedtls_gcm_auth_decrypt(&ctx, ct_len,
                                  nonce, nonce_len,
                                  aad_len > 0 ? aad : NULL, aad_len,
                                  tag, QC_AEAD_TAG_LEN,
                                  ct_len > 0 ? ct : NULL,
                                  ct_len > 0 ? pt : NULL);
    mbedtls_gcm_free(&ctx);
    if (rc == MBEDTLS_ERR_GCM_AUTH_FAILED) {
        if (pt != NULL && ct_len > 0) {
            mbedtls_platform_zeroize(pt, ct_len);
        }
        return QC_AEAD_AUTH_FAIL;
    }
    if (rc == MBEDTLS_ERR_GCM_BAD_INPUT) {
        /* Overlap or over-cap length: caller bug, not a tamper event.
         * Output still wiped. */
        if (pt != NULL && ct_len > 0) {
            mbedtls_platform_zeroize(pt, ct_len);
        }
        return QC_AEAD_BAD_LENGTH;
    }
    if (rc != 0) {
        /* Any other backend fault: INTERNAL, not caller bug. Output
         * still wiped. Unreachable with fixed params; fail-closed. */
        if (pt != NULL && ct_len > 0) {
            mbedtls_platform_zeroize(pt, ct_len);
        }
        return QC_AEAD_INTERNAL;
    }
    return QC_AEAD_OK;
}
