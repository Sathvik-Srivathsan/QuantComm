/* qc_dsa.c — ML-DSA adapter over mldsa-native SCU backends (B-11).
 * One static lib per level (qc_mldsa44/65/87); this TU pulls all three APIs
 * via the documented multilevel triple-include. Randomness (keygen seed,
 * signing rnd) is caller-owned throughout; the adapter holds no key
 * material beyond the call frame.
 */
#include "qc_dsa.h"

#include "qc_zeroize.h"

#define MLD_CONFIG_PARAMETER_SET 44
#include "mldsa_native.h"
#undef MLD_CONFIG_PARAMETER_SET
#undef MLD_H

#define MLD_CONFIG_PARAMETER_SET 65
#include "mldsa_native.h"
#undef MLD_CONFIG_PARAMETER_SET
#undef MLD_H

#define MLD_CONFIG_PARAMETER_SET 87
#include "mldsa_native.h"
#undef MLD_CONFIG_PARAMETER_SET
#undef MLD_H

/* Published sizes must match our header literals (plan B-11.1 table). */
_Static_assert(MLDSA44_PUBLICKEYBYTES == QC_DSA44_PK_BYTES, "44 pk");
_Static_assert(MLDSA44_SECRETKEYBYTES == QC_DSA44_SK_BYTES, "44 sk");
_Static_assert(MLDSA44_BYTES == QC_DSA44_SIG_BYTES, "44 sig");
_Static_assert(MLDSA65_PUBLICKEYBYTES == QC_DSA65_PK_BYTES, "65 pk");
_Static_assert(MLDSA65_SECRETKEYBYTES == QC_DSA65_SK_BYTES, "65 sk");
_Static_assert(MLDSA65_BYTES == QC_DSA65_SIG_BYTES, "65 sig");
_Static_assert(MLDSA87_PUBLICKEYBYTES == QC_DSA87_PK_BYTES, "87 pk");
_Static_assert(MLDSA87_SECRETKEYBYTES == QC_DSA87_SK_BYTES, "87 sk");
_Static_assert(MLDSA87_BYTES == QC_DSA87_SIG_BYTES, "87 sig");
_Static_assert(MLDSA_SEEDBYTES == QC_DSA_SEED_BYTES, "seed");
_Static_assert(MLDSA_RNDBYTES == QC_DSA_RND_BYTES, "rnd");

/* Context bound matches FIPS 204 (ctx string <= 255 bytes). */
_Static_assert(QC_DSA_CTX_MAX_BYTES == 255, "ctx bound");

size_t qc_dsa_pk_bytes(qc_dsa_level level) {
    switch (level) {
    case QC_DSA_44:
        return QC_DSA44_PK_BYTES;
    case QC_DSA_65:
        return QC_DSA65_PK_BYTES;
    case QC_DSA_87:
        return QC_DSA87_PK_BYTES;
    default:
        return 0;
    }
}

size_t qc_dsa_sk_bytes(qc_dsa_level level) {
    switch (level) {
    case QC_DSA_44:
        return QC_DSA44_SK_BYTES;
    case QC_DSA_65:
        return QC_DSA65_SK_BYTES;
    case QC_DSA_87:
        return QC_DSA87_SK_BYTES;
    default:
        return 0;
    }
}

size_t qc_dsa_sig_bytes(qc_dsa_level level) {
    switch (level) {
    case QC_DSA_44:
        return QC_DSA44_SIG_BYTES;
    case QC_DSA_65:
        return QC_DSA65_SIG_BYTES;
    case QC_DSA_87:
        return QC_DSA87_SIG_BYTES;
    default:
        return 0;
    }
}

int qc_dsa_free_sk(qc_dsa_level level, uint8_t *sk) {
    size_t n = qc_dsa_sk_bytes(level);

    if (n == 0) {
        return QC_DSA_BAD_LEVEL;
    }
    qc_zeroize(sk, n);
    return QC_DSA_OK;
}

void qc_dsa_free_rnd(uint8_t rnd[QC_DSA_RND_BYTES]) {
    qc_zeroize(rnd, QC_DSA_RND_BYTES);
}

/* Build the FIPS 204 domain-separation prefix for (ctx) with the
 * CALLER'S level namespace: pure ML-DSA (no pre-hash OID), externalmu=0
 * (mu computed internally). Deliberately per-arm rather than shared: no
 * cross-level behavioral assumption, even though the encoding is
 * level-independent today. Single-evaluates its arguments; call sites
 * still pass plain lvalues only. prelen 0 happens iff ctxlen > 255,
 * which the caller rejects first — the check below is provably
 * unreachable defense-in-depth, kept so a future backend change fails
 * closed instead of signing under a truncated prefix. */
#define QC_DSA_BUILD_PRE(lvl, pre, ctx, ctxlen, prelen)                      \
    do {                                                                     \
        size_t _n = (ctxlen);                                                \
        prelen = qc_mldsa##lvl##_prepare_domain_separation_prefix(           \
            pre, NULL, 0, _n > 0 ? (ctx) : NULL, _n, MLD_PREHASH_NONE);     \
    } while (0)

int qc_dsa_keypair(qc_dsa_level level,
                   uint8_t *pk, uint8_t *sk,
                   const uint8_t seed[QC_DSA_SEED_BYTES]) {
    int rc;

    if (pk == NULL || sk == NULL || seed == NULL) {
        return QC_DSA_BAD_LENGTH;
    }
    switch (level) {
    case QC_DSA_44:
        rc = qc_mldsa44_keypair_internal(pk, sk, seed);
        break;
    case QC_DSA_65:
        rc = qc_mldsa65_keypair_internal(pk, sk, seed);
        break;
    case QC_DSA_87:
        rc = qc_mldsa87_keypair_internal(pk, sk, seed);
        break;
    default:
        return QC_DSA_BAD_LEVEL;
    }
    return rc == 0 ? QC_DSA_OK : QC_DSA_INTERNAL;
}

int qc_dsa_sign(qc_dsa_level level,
                uint8_t *sig,
                const uint8_t *msg, size_t msglen,
                const uint8_t *ctx, size_t ctxlen,
                const uint8_t rnd[QC_DSA_RND_BYTES],
                const uint8_t *sk) {
    uint8_t pre[MLD_DOMAIN_SEPARATION_MAX_BYTES];
    size_t prelen;
    int rc;

    if (sig == NULL || rnd == NULL || sk == NULL) {
        return QC_DSA_BAD_LENGTH;
    }
    if (msglen > 0 && msg == NULL) {
        return QC_DSA_BAD_LENGTH;
    }
    if (ctxlen > QC_DSA_CTX_MAX_BYTES ||
        (ctxlen > 0 && ctx == NULL)) {
        return QC_DSA_BAD_LENGTH;
    }
    switch (level) {
    case QC_DSA_44:
        QC_DSA_BUILD_PRE(44, pre, ctx, ctxlen, prelen);
        if (prelen == 0) {
            return QC_DSA_INTERNAL;
        }
        rc = qc_mldsa44_signature_internal(sig, msglen > 0 ? msg : NULL,
                                          msglen, pre, prelen, rnd, sk, 0);
        break;
    case QC_DSA_65:
        QC_DSA_BUILD_PRE(65, pre, ctx, ctxlen, prelen);
        if (prelen == 0) {
            return QC_DSA_INTERNAL;
        }
        rc = qc_mldsa65_signature_internal(sig, msglen > 0 ? msg : NULL,
                                          msglen, pre, prelen, rnd, sk, 0);
        break;
    case QC_DSA_87:
        QC_DSA_BUILD_PRE(87, pre, ctx, ctxlen, prelen);
        if (prelen == 0) {
            return QC_DSA_INTERNAL;
        }
        rc = qc_mldsa87_signature_internal(sig, msglen > 0 ? msg : NULL,
                                          msglen, pre, prelen, rnd, sk, 0);
        break;
    default:
        return QC_DSA_BAD_LEVEL;
    }
    if (rc == 0) {
        return QC_DSA_OK;
    }
    /* INVALID_KEY is not returned on this path (backend assumes valid
     * sk); the arm stays so a backend change fails closed into a
     * documented code instead of INTERNAL. */
    if (rc == MLD_ERR_INVALID_KEY) {
        return QC_DSA_BAD_KEY;
    }
    return QC_DSA_INTERNAL;
}

int qc_dsa_verify(qc_dsa_level level,
                  const uint8_t *msg, size_t msglen,
                  const uint8_t *ctx, size_t ctxlen,
                  const uint8_t *sig, const uint8_t *pk) {
    uint8_t pre[MLD_DOMAIN_SEPARATION_MAX_BYTES];
    size_t prelen;
    int rc;

    if (sig == NULL || pk == NULL) {
        return QC_DSA_BAD_LENGTH;
    }
    if (msglen > 0 && msg == NULL) {
        return QC_DSA_BAD_LENGTH;
    }
    if (ctxlen > QC_DSA_CTX_MAX_BYTES ||
        (ctxlen > 0 && ctx == NULL)) {
        return QC_DSA_BAD_LENGTH;
    }
    switch (level) {
    case QC_DSA_44:
        QC_DSA_BUILD_PRE(44, pre, ctx, ctxlen, prelen);
        if (prelen == 0) {
            return QC_DSA_INTERNAL;
        }
        rc = qc_mldsa44_verify_internal(sig, msglen > 0 ? msg : NULL,
                                        msglen, pre, prelen, pk, 0);
        break;
    case QC_DSA_65:
        QC_DSA_BUILD_PRE(65, pre, ctx, ctxlen, prelen);
        if (prelen == 0) {
            return QC_DSA_INTERNAL;
        }
        rc = qc_mldsa65_verify_internal(sig, msglen > 0 ? msg : NULL,
                                        msglen, pre, prelen, pk, 0);
        break;
    case QC_DSA_87:
        QC_DSA_BUILD_PRE(87, pre, ctx, ctxlen, prelen);
        if (prelen == 0) {
            return QC_DSA_INTERNAL;
        }
        rc = qc_mldsa87_verify_internal(sig, msglen > 0 ? msg : NULL,
                                        msglen, pre, prelen, pk, 0);
        break;
    default:
        return QC_DSA_BAD_LEVEL;
    }
    if (rc == 0) {
        return QC_DSA_OK;
    }
    if (rc == MLD_ERR_INVALID_SIGNATURE) {
        return QC_DSA_BAD_SIG;
    }
    return QC_DSA_INTERNAL;
}