/* qc_aead.h — AES-256-GCM adapter over mbedTLS (F4: ESP-IDF mbedTLS build).
 * AES-256 ONLY (rejects 128/192 or other lengths: misuse taxonomy).
 * Nonce fixed 12 B (B-23 epoch+counter); tag fixed 16 B.
 * Decrypt verifies tag with constant-time compare inside mbedTLS.
 * Error taxonomy: BAD_KEY/BAD_LENGTH are caller bugs (fix the caller);
 * AUTH_FAIL is a tag mismatch (sender or tamper event); INTERNAL is a
 * library fault (not caller input, not authentication — investigate).
 */
#ifndef QC_AEAD_H
#define QC_AEAD_H

#include <stddef.h>
#include <stdint.h>

#define QC_AEAD_KEY_LEN 32
#define QC_AEAD_NONCE_LEN 12
#define QC_AEAD_TAG_LEN 16

typedef enum {
    QC_AEAD_OK = 0,
    QC_AEAD_BAD_KEY,   /* key NULL or length != 32 (caller bug). */
    QC_AEAD_BAD_LENGTH,/* NULL buffer, bad nonce length, or overlapping
                        * buffers the backend rejects (caller bug). */
    QC_AEAD_AUTH_FAIL, /* tag mismatch (sender or tamper event). */
    QC_AEAD_INTERNAL   /* backend fault unrelated to caller input or tag
                        * (defensive; unreachable with fixed AES-256). */
} qc_aead_rc;

/* Buffer contract. In-place operation (pt == ct) is supported on both
 * paths. Forward overlap (output starting inside the input region) is
 * rejected with BAD_LENGTH. Any other overlap direction is NOT
 * contracted — neither guaranteed nor rejected — so callers must not
 * rely on it. On AUTH_FAIL the output buffer is fully zeroed, including
 * when it aliases the input: in-place decrypt destroys the ciphertext
 * copy on tag mismatch (retry needs the original bytes elsewhere). */
int qc_aead_encrypt(const uint8_t *key, size_t key_len,
                    const uint8_t *nonce, size_t nonce_len,
                    const uint8_t *aad, size_t aad_len,
                    const uint8_t *pt, size_t pt_len,
                    uint8_t *ct, uint8_t tag[QC_AEAD_TAG_LEN]);

int qc_aead_decrypt(const uint8_t *key, size_t key_len,
                    const uint8_t *nonce, size_t nonce_len,
                    const uint8_t *aad, size_t aad_len,
                    const uint8_t *ct, size_t ct_len,
                    const uint8_t tag[QC_AEAD_TAG_LEN],
                    uint8_t *pt);

#endif
