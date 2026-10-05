/* qc_kdf.h — session key schedule (plan B-21: Extract/Expand/split order).
 * kdf_derive(nw12, ns32, k1, k2, kdev32, transcript, transcript_len, out):
 *   PRK   = Extract(salt = N_W||N_S, IKM = "QC-HS"||K1||K2||Kdev)
 *   Okm   = Expand(PRK, info = "QC-TRANSCRIPT"||0x00||SHA256(transcript), L=128)
 *   split = [K_c2s, K_s2c, K_rat, K_conf], 32 B each, canonical order.
 * All inputs fixed-size except transcript (variable). K1/K2 ephemeral copies
 * wiped post-Extract; stored Kdev untouched (caller owns it).
 * Trace hook (L2 collective visibility): qc_kdf_trace, if non-NULL, receives
 * (prk, info, info_len, okm) per derivation. Test/debug only.
 */
#ifndef QC_KDF_H
#define QC_KDF_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t k_c2s[32];
    uint8_t k_s2c[32];
    uint8_t k_rat[32];
    uint8_t k_conf[32];
} qc_kdf_keys;

typedef void (*qc_kdf_trace_fn)(const uint8_t prk[32],
                                const uint8_t *info, size_t info_len,
                                const uint8_t okm[128]);

extern qc_kdf_trace_fn qc_kdf_trace;

/* Returns 0 on success, nonzero on bad input (fail-closed, out untouched). */
int qc_kdf_derive(const uint8_t nw[12], const uint8_t ns[32],
                  const uint8_t *k1, size_t k1_len,
                  const uint8_t *k2, size_t k2_len,
                  const uint8_t kdev[32],
                  const uint8_t *transcript, size_t transcript_len,
                  qc_kdf_keys *out);

#endif
