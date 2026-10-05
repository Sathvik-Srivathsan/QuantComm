/* qc_hkdf.h — HKDF-SHA-256, RFC 5869.
 * qc_hkdf_extract(salt, salt_len, ikm, ikm_len, prk32):
 *   salt may be empty (NULL iff len 0 -> zeros per RFC).
 *   IKM must be non-empty (empty or NULL -> returns -1, BAD_KEY class).
 * qc_hkdf_expand(prk32, info, info_len, okm, okm_len):
 *   info may be empty; okm_len 0 -> OK, nothing written; max 255*32.
 * IKM/secret inputs wiped from stack copies on return.
 */
#ifndef QC_HKDF_H
#define QC_HKDF_H

#include <stddef.h>
#include <stdint.h>

int qc_hkdf_extract(const uint8_t *salt, size_t salt_len,
                    const uint8_t *ikm, size_t ikm_len,
                    uint8_t prk[32]);

int qc_hkdf_expand(const uint8_t prk[32],
                   const uint8_t *info, size_t info_len,
                   uint8_t *okm, size_t okm_len);

#endif
