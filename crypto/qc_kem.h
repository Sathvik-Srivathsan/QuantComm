/* qc_kem.h — ML-KEM adapter over mlkem-native (B-01/B-10, FIPS 203).
 * All three parameter sets (512/768/1024) via namespaced multilevel symbols.
 * Derandomized API only: every randomized input arrives as caller-supplied
 * coins (tests inject the deterministic RNG; production passes B-13 output).
 * No randomness is drawn inside the KEM; RNG_FAIL is unreachable by design.
 *
 * Decapsulation has implicit rejection (FIPS 203): a tampered ciphertext
 * still returns OK but yields an unrelated shared secret. Callers MUST NOT
 * treat decaps-OK as authenticity — authenticity comes from the transcript
 * MAC (B-20/B-21), never from the KEM.
 */
#ifndef QC_KEM_H
#define QC_KEM_H

#include <stddef.h>
#include <stdint.h>

/* Parameter sets. */
typedef enum {
    QC_KEM_512 = 512,
    QC_KEM_768 = 768,
    QC_KEM_1024 = 1024
} qc_kem_level;

/* Fixed sizes per level: {pk, sk, ct} bytes. Shared secret is 32 bytes
 * and keygen/encaps coins are 64/32 bytes on all levels. */
#define QC_KEM512_PK_BYTES 800
#define QC_KEM512_SK_BYTES 1632
#define QC_KEM512_CT_BYTES 768
#define QC_KEM768_PK_BYTES 1184
#define QC_KEM768_SK_BYTES 2400
#define QC_KEM768_CT_BYTES 1088
#define QC_KEM1024_PK_BYTES 1568
#define QC_KEM1024_SK_BYTES 3168
#define QC_KEM1024_CT_BYTES 1568
#define QC_KEM_SS_BYTES 32
#define QC_KEM_KEYGEN_COINS_BYTES 64
#define QC_KEM_ENCAPS_COINS_BYTES 32

typedef enum {
    QC_KEM_OK = 0,
    QC_KEM_BAD_LEVEL, /* level not 512/768/1024 (caller bug). */
    QC_KEM_BAD_LENGTH,/* NULL buffer (caller bug). Sizes are fixed per
                       * level; no length parameters exist to get wrong. */
    QC_KEM_BAD_KEY,   /* pk fails FIPS 203 modulus check (encaps) or sk
                       * fails hash check (decaps): peer/key-store event. */
    QC_KEM_INTERNAL   /* backend fault (defensive; unreachable: no custom
                       * alloc, PCT off, derandomized API). */
} qc_kem_rc;

/* Generate keypair from 64 caller coins. pk/sk buffers sized per level. */
int qc_kem_keypair(qc_kem_level level,
                   uint8_t *pk, uint8_t *sk,
                   const uint8_t coins[QC_KEM_KEYGEN_COINS_BYTES]);

/* Encapsulate to pk with 32 caller coins. ct/ss buffers sized per level. */
int qc_kem_encaps(qc_kem_level level,
                  uint8_t *ct, uint8_t ss[QC_KEM_SS_BYTES],
                  const uint8_t *pk, const uint8_t coins[QC_KEM_ENCAPS_COINS_BYTES]);

/* Decapsulate. Returns OK even for tampered ct (implicit rejection:
 * ss is then unrelated to the encapsulator's ss — compare, don't trust). */
int qc_kem_decaps(qc_kem_level level,
                  uint8_t ss[QC_KEM_SS_BYTES],
                  const uint8_t *ct, const uint8_t *sk);

/* Size queries (for callers sizing buffers). Returns 0 for bad level. */
size_t qc_kem_pk_bytes(qc_kem_level level);
size_t qc_kem_sk_bytes(qc_kem_level level);
size_t qc_kem_ct_bytes(qc_kem_level level);

/* Release wrappers (B-10.4): wipe secret material with qc_zeroize.
 * Raw caller free/memset without these wrappers is misuse — the wrappers
 * centralize per-level extents and are the audit point for erasure
 * evidence. Returns QC_KEM_OK iff bytes were actually wiped; a bad level
 * returns QC_KEM_BAD_LEVEL and wipes nothing (wiping is impossible to do
 * safely without the level — wiping the maximum could overflow a smaller
 * buffer). Callers MUST check the return: a wrong-but-valid level wipes
 * only that level's prefix, leaving the tail live — passing the creation
 * level is load-bearing, and silence here would mean believed-erased
 * live keys. NULL is a safe no-op (returns OK: nothing to erase).
 * Public values (pk, ct) need no wrapper — there is nothing secret
 * in them to erase. Coins (keygen/encaps) are caller-owned: wipe them
 * directly with qc_zeroize; no wrapper exists because their lifetime is
 * the caller's, not the key's. */
int qc_kem_free_sk(qc_kem_level level, uint8_t *sk);
void qc_kem_free_ss(uint8_t ss[QC_KEM_SS_BYTES]);

#endif