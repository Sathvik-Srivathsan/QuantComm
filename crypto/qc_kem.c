/* qc_kem.c — ML-KEM adapter over mlkem-native SCU backends (B-10).
 * One static lib per level (qc_mlkem512/768/1024, see crypto/CMakeLists.txt);
 * this TU pulls all three APIs via the documented multilevel triple-include.
 * Coins are caller-owned throughout; the adapter holds no key material
 * beyond the call frame, so no wipe discipline is needed here (contrast
 * qc_aead, where contexts linger).
 */
#include "qc_kem.h"

#include "qc_zeroize.h"

/* Triple-include: fixed level per inclusion, namespaced symbols out.
 * MLK_CONFIG_FILE + MULTILEVEL_BUILD come from the command line / config;
 * PARAMETER_SET is set per inclusion block below. */
#define MLK_CONFIG_PARAMETER_SET 512
#include "mlkem_native.h"
#undef MLK_CONFIG_PARAMETER_SET
#undef MLK_H

#define MLK_CONFIG_PARAMETER_SET 768
#include "mlkem_native.h"
#undef MLK_CONFIG_PARAMETER_SET
#undef MLK_H

#define MLK_CONFIG_PARAMETER_SET 1024
#include "mlkem_native.h"
#undef MLK_CONFIG_PARAMETER_SET
#undef MLK_H

/* The published size macros must match our header literals. If upstream
 * ever changes sizes, this fails at compile time, not in the field. */
_Static_assert(MLKEM512_PUBLICKEYBYTES == QC_KEM512_PK_BYTES, "512 pk size");
_Static_assert(MLKEM512_SECRETKEYBYTES == QC_KEM512_SK_BYTES, "512 sk size");
_Static_assert(MLKEM512_CIPHERTEXTBYTES == QC_KEM512_CT_BYTES, "512 ct size");
_Static_assert(MLKEM768_PUBLICKEYBYTES == QC_KEM768_PK_BYTES, "768 pk size");
_Static_assert(MLKEM768_SECRETKEYBYTES == QC_KEM768_SK_BYTES, "768 sk size");
_Static_assert(MLKEM768_CIPHERTEXTBYTES == QC_KEM768_CT_BYTES, "768 ct size");
_Static_assert(MLKEM1024_PUBLICKEYBYTES == QC_KEM1024_PK_BYTES, "1024 pk size");
_Static_assert(MLKEM1024_SECRETKEYBYTES == QC_KEM1024_SK_BYTES, "1024 sk size");
_Static_assert(MLKEM1024_CIPHERTEXTBYTES == QC_KEM1024_CT_BYTES, "1024 ct size");
_Static_assert(MLKEM_BYTES == QC_KEM_SS_BYTES, "ss size");
_Static_assert(2 * MLKEM_SYMBYTES == QC_KEM_KEYGEN_COINS_BYTES, "keygen coins");
_Static_assert(MLKEM_SYMBYTES == QC_KEM_ENCAPS_COINS_BYTES, "encaps coins");

/* Published allocation budgets (MLK_TOTAL_ALLOC_*, stack-only default
 * config). These count MLK_ALLOC-accounted bytes only — upstream states
 * they are lower than true total stack use (Keccak state, spills, slots
 * extra). B-10 asserts headroom against a 16/32 KiB cap per level; a true
 * measured frame budget (e.g. -fstack-usage) belongs to B-60 porting, and
 * the ESP32 port gets its own tighter budget against these same macros. */
_Static_assert(MLK_TOTAL_ALLOC_512 < 16384, "512 stack budget");
_Static_assert(MLK_TOTAL_ALLOC_768 < 16384, "768 stack budget");
_Static_assert(MLK_TOTAL_ALLOC_1024 < 32768, "1024 stack budget");

size_t qc_kem_pk_bytes(qc_kem_level level) {
    switch (level) {
    case QC_KEM_512:
        return QC_KEM512_PK_BYTES;
    case QC_KEM_768:
        return QC_KEM768_PK_BYTES;
    case QC_KEM_1024:
        return QC_KEM1024_PK_BYTES;
    default:
        return 0;
    }
}

size_t qc_kem_sk_bytes(qc_kem_level level) {
    switch (level) {
    case QC_KEM_512:
        return QC_KEM512_SK_BYTES;
    case QC_KEM_768:
        return QC_KEM768_SK_BYTES;
    case QC_KEM_1024:
        return QC_KEM1024_SK_BYTES;
    default:
        return 0;
    }
}

size_t qc_kem_ct_bytes(qc_kem_level level) {
    switch (level) {
    case QC_KEM_512:
        return QC_KEM512_CT_BYTES;
    case QC_KEM_768:
        return QC_KEM768_CT_BYTES;
    case QC_KEM_1024:
        return QC_KEM1024_CT_BYTES;
    default:
        return 0;
    }
}

int qc_kem_free_sk(qc_kem_level level, uint8_t *sk) {
    size_t n = qc_kem_sk_bytes(level);

    if (n == 0) {
        return QC_KEM_BAD_LEVEL;
    }
    qc_zeroize(sk, n);
    return QC_KEM_OK;
}

void qc_kem_free_ss(uint8_t ss[QC_KEM_SS_BYTES]) {
    qc_zeroize(ss, QC_KEM_SS_BYTES);
}

int qc_kem_keypair(qc_kem_level level,
                   uint8_t *pk, uint8_t *sk,
                   const uint8_t coins[QC_KEM_KEYGEN_COINS_BYTES]) {
    int rc;

    if (pk == NULL || sk == NULL || coins == NULL) {
        return QC_KEM_BAD_LENGTH;
    }
    switch (level) {
    case QC_KEM_512:
        rc = qc_mlkem512_keypair_derand(pk, sk, coins);
        break;
    case QC_KEM_768:
        rc = qc_mlkem768_keypair_derand(pk, sk, coins);
        break;
    case QC_KEM_1024:
        rc = qc_mlkem1024_keypair_derand(pk, sk, coins);
        break;
    default:
        return QC_KEM_BAD_LEVEL;
    }
    /* Derandomized keygen with PCT off and no custom allocator cannot
     * fail on caller input; any nonzero return is a backend fault. */
    return rc == 0 ? QC_KEM_OK : QC_KEM_INTERNAL;
}

int qc_kem_encaps(qc_kem_level level,
                  uint8_t *ct, uint8_t ss[QC_KEM_SS_BYTES],
                  const uint8_t *pk, const uint8_t coins[QC_KEM_ENCAPS_COINS_BYTES]) {
    int rc;

    if (ct == NULL || ss == NULL || pk == NULL || coins == NULL) {
        return QC_KEM_BAD_LENGTH;
    }
    switch (level) {
    case QC_KEM_512:
        rc = qc_mlkem512_enc_derand(ct, ss, pk, coins);
        break;
    case QC_KEM_768:
        rc = qc_mlkem768_enc_derand(ct, ss, pk, coins);
        break;
    case QC_KEM_1024:
        rc = qc_mlkem1024_enc_derand(ct, ss, pk, coins);
        break;
    default:
        return QC_KEM_BAD_LEVEL;
    }
    if (rc == 0) {
        return QC_KEM_OK;
    }
    /* Modulus-check failure means the peer's public key is malformed:
     * a peer/key-store event, never a caller bug. */
    if (rc == MLK_ERR_INVALID_PK) {
        return QC_KEM_BAD_KEY;
    }
    return QC_KEM_INTERNAL;
}

int qc_kem_decaps(qc_kem_level level,
                  uint8_t ss[QC_KEM_SS_BYTES],
                  const uint8_t *ct, const uint8_t *sk) {
    int rc;

    if (ss == NULL || ct == NULL || sk == NULL) {
        return QC_KEM_BAD_LENGTH;
    }
    switch (level) {
    case QC_KEM_512:
        rc = qc_mlkem512_dec(ss, ct, sk);
        break;
    case QC_KEM_768:
        rc = qc_mlkem768_dec(ss, ct, sk);
        break;
    case QC_KEM_1024:
        rc = qc_mlkem1024_dec(ss, ct, sk);
        break;
    default:
        return QC_KEM_BAD_LEVEL;
    }
    if (rc == 0) {
        return QC_KEM_OK;
    }
    if (rc == MLK_ERR_INVALID_SK) {
        return QC_KEM_BAD_KEY;
    }
    return QC_KEM_INTERNAL;
}