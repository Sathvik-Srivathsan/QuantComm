/* qc_dsa.h — ML-DSA adapter over mldsa-native (B-01/B-11, FIPS 204).
 * All three parameter sets (44/65/87) via namespaced multilevel symbols.
 *
 * Two signing modes share one API, distinguished by the rnd argument:
 * - HEDGED (production default): rnd is 32 fresh bytes from the B-13
 *   provider per call. Same message signed twice yields different
 *   (both valid) signatures.
 * - DETERMINISTIC (tests / measured variant): rnd is fixed (e.g. test
 *   coins). Same inputs yield the same signature, byte-for-byte.
 * FIPS 204 permits both; the mode is a property of the rnd input, so it
 * is always explicit at the call site — never a silent default.
 *
 * Context strings (FIPS 204 §5, ctx || 0x00 prefix) are first-class:
 * sign/verify take (ctx, ctxlen); ctxlen 0 with ctx NULL means no context.
 * ctxlen > 255 is rejected (FIPS 204 bound).
 */
#ifndef QC_DSA_H
#define QC_DSA_H

#include <stddef.h>
#include <stdint.h>

typedef enum {
    QC_DSA_44 = 44,
    QC_DSA_65 = 65,
    QC_DSA_87 = 87
} qc_dsa_level;

/* Fixed sizes per level: {pk, sk, sig} bytes. Keygen seed and signing
 * randomness are 32 bytes on all levels. */
#define QC_DSA44_PK_BYTES 1312
#define QC_DSA44_SK_BYTES 2560
#define QC_DSA44_SIG_BYTES 2420
#define QC_DSA65_PK_BYTES 1952
#define QC_DSA65_SK_BYTES 4032
#define QC_DSA65_SIG_BYTES 3309
#define QC_DSA87_PK_BYTES 2592
#define QC_DSA87_SK_BYTES 4896
#define QC_DSA87_SIG_BYTES 4627
#define QC_DSA_SEED_BYTES 32
#define QC_DSA_RND_BYTES 32
#define QC_DSA_CTX_MAX_BYTES 255

typedef enum {
    QC_DSA_OK = 0,
    QC_DSA_BAD_LEVEL, /* level not 44/65/87 (caller bug). */
    QC_DSA_BAD_LENGTH,/* NULL buffer, ctxlen > 255, or ctx NULL with
                       * nonzero ctxlen (caller bug). Sizes are fixed per
                       * level; no other length parameters exist. */
    QC_DSA_BAD_KEY,   /* RESERVED, currently unreachable: the backend
                       * performs no key validation (sk is assumed valid
                       * on sign; any pk/sig mismatch on verify reports
                       * BAD_SIG). Kept for a future pk_from_sk validation
                       * path; do not treat its absence as "keys checked". */
    QC_DSA_BAD_SIG,   /* signature verification failed: wrong key, wrong
                       * message/context, malformed pk, or tampered
                       * signature. A corrupt sk on sign does NOT fail —
                       * it signs blindly (backend assumes valid keys). */
    QC_DSA_INTERNAL   /* backend fault. Reachable only on ML-DSA rejection-
                       * sampling exhaustion (negligible probability) or
                       * allocation failure (no custom allocator: impossible
                       * here); RNG/PCT paths are compiled out. Effectively
                       * defensive; kept fail-closed. */
} qc_dsa_rc;

/* Generate keypair from 32 caller seed bytes. Buffers sized per level. */
int qc_dsa_keypair(qc_dsa_level level,
                   uint8_t *pk, uint8_t *sk,
                   const uint8_t seed[QC_DSA_SEED_BYTES]);

/* Sign msg (mlen bytes, may be 0 with msg NULL) under ctx with 32 caller
 * rnd bytes. sig buffer sized per level. */
int qc_dsa_sign(qc_dsa_level level,
                uint8_t *sig,
                const uint8_t *msg, size_t msglen,
                const uint8_t *ctx, size_t ctxlen,
                const uint8_t rnd[QC_DSA_RND_BYTES],
                const uint8_t *sk);

/* Verify. Returns OK iff the signature is valid for (msg, ctx, pk). */
int qc_dsa_verify(qc_dsa_level level,
                  const uint8_t *msg, size_t msglen,
                  const uint8_t *ctx, size_t ctxlen,
                  const uint8_t *sig, const uint8_t *pk);

/* Size queries. Returns 0 for bad level. */
size_t qc_dsa_pk_bytes(qc_dsa_level level);
size_t qc_dsa_sk_bytes(qc_dsa_level level);
size_t qc_dsa_sig_bytes(qc_dsa_level level);

/* Release wrappers (B-11.4): wipe secret material with qc_zeroize.
 * Same contract as qc_kem_free_*: centralized extents, return-code
 * honesty (OK iff wiped, BAD_LEVEL otherwise — a wrong-but-valid level
 * wipes only its prefix, so the creation level is load-bearing),
 * NULL-safe no-ops. Covers sk (signing key) and rnd (per-signature
 * randomness — hedged coins must not linger after the call). Keygen seeds
 * are caller-owned: qc_zeroize them directly. Public values (pk, sig)
 * need no wrapper. Verify takes no secrets and needs no wrapper by
 * construction. */
int qc_dsa_free_sk(qc_dsa_level level, uint8_t *sk);
void qc_dsa_free_rnd(uint8_t rnd[QC_DSA_RND_BYTES]);

#endif