/* test_dsa.c — L0/L1 for the ML-DSA adapter (B-11).
 *
 * KAT source: tests/c/mldsa_vectors.h, copied verbatim from
 * mldsa-native v2.0.0 examples/multilevel_build/
 * expected_test_vectors_multilevel.h (the examples/ tree is not vendored;
 * this copy plus green KAT byte-equality is the provenance evidence).
 * Keygen seed = test_vector_rnd; signatures over TEST_VECTOR_MSG under
 * TEST_VECTOR_CTX with rnd = test_vector_rnd (deterministic variant).
 *
 * B-11 requires hedged (default) AND deterministic (measured variant) to
 * share one API: both are exercised — fixed rnd reproduces the KAT
 * byte-for-byte, fresh rnd yields a different but valid signature.
 */
#include "unity.h"

#include <string.h>

#include "qc_dsa.h"
#include "mldsa_vectors.h"

static const uint8_t ALT_RND[32] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    0x0F, 0x1E, 0x2D, 0x3C, 0x4B, 0x5A, 0x69, 0x78,
    0x87, 0x96, 0xA5, 0xB4, 0xC3, 0xD2, 0xE1, 0xF0
};

/* One level: KAT keygen -> KAT sign -> verify, all against published
 * vectors. Then hedged/deterministic duality on the same key. */
static void run_kat(qc_dsa_level level,
                    const uint8_t *want_pk, const uint8_t *want_sk,
                    const uint8_t *want_sig, const char *label) {
    /* Max sizes cover 87; per-level lengths asserted from queries. */
    static uint8_t pk[2592], sk[4896], sig[4627], sig2[4627];
    size_t pk_len = qc_dsa_pk_bytes(level);
    size_t sk_len = qc_dsa_sk_bytes(level);
    size_t sig_len = qc_dsa_sig_bytes(level);
    const uint8_t *msg = (const uint8_t *)TEST_VECTOR_MSG;
    const uint8_t *ctx = (const uint8_t *)TEST_VECTOR_CTX;
    int rc;

    TEST_ASSERT_TRUE_MESSAGE(pk_len > 0 && sk_len > 0 && sig_len > 0, label);

    /* Deterministic keygen from the published seed. */
    rc = qc_dsa_keypair(level, pk, sk, test_vector_rnd);
    TEST_ASSERT_EQUAL_INT_MESSAGE(QC_DSA_OK, rc, label);
    TEST_ASSERT_EQUAL_UINT8_ARRAY_MESSAGE(want_pk, pk, pk_len, label);
    TEST_ASSERT_EQUAL_UINT8_ARRAY_MESSAGE(want_sk, sk, sk_len, label);

    /* Deterministic sign reproduces the published signature. */
    rc = qc_dsa_sign(level, sig, msg, TEST_VECTOR_MSG_LEN,
                     ctx, TEST_VECTOR_CTX_LEN, test_vector_rnd, sk);
    TEST_ASSERT_EQUAL_INT_MESSAGE(QC_DSA_OK, rc, label);
    TEST_ASSERT_EQUAL_UINT8_ARRAY_MESSAGE(want_sig, sig, sig_len, label);

    /* And it verifies. */
    rc = qc_dsa_verify(level, msg, TEST_VECTOR_MSG_LEN,
                       ctx, TEST_VECTOR_CTX_LEN, sig, pk);
    TEST_ASSERT_EQUAL_INT_MESSAGE(QC_DSA_OK, rc, label);

    /* Determinism: same inputs again -> identical bytes. */
    rc = qc_dsa_sign(level, sig2, msg, TEST_VECTOR_MSG_LEN,
                     ctx, TEST_VECTOR_CTX_LEN, test_vector_rnd, sk);
    TEST_ASSERT_EQUAL_INT_MESSAGE(QC_DSA_OK, rc, label);
    TEST_ASSERT_EQUAL_UINT8_ARRAY_MESSAGE(sig, sig2, sig_len, label);

    /* Hedged: fresh rnd -> different bytes, still valid. */
    rc = qc_dsa_sign(level, sig2, msg, TEST_VECTOR_MSG_LEN,
                     ctx, TEST_VECTOR_CTX_LEN, ALT_RND, sk);
    TEST_ASSERT_EQUAL_INT_MESSAGE(QC_DSA_OK, rc, label);
    TEST_ASSERT_TRUE_MESSAGE(memcmp(sig, sig2, sig_len) != 0, label);
    rc = qc_dsa_verify(level, msg, TEST_VECTOR_MSG_LEN,
                       ctx, TEST_VECTOR_CTX_LEN, sig2, pk);
    TEST_ASSERT_EQUAL_INT_MESSAGE(QC_DSA_OK, rc, label);
}

static void test_kat_44(void) {
    run_kat(QC_DSA_44, test_vector_pk_44, test_vector_sk_44,
            test_vector_sig_44, "kat44");
}

static void test_kat_65(void) {
    run_kat(QC_DSA_65, test_vector_pk_65, test_vector_sk_65,
            test_vector_sig_65, "kat65");
}

static void test_kat_87(void) {
    run_kat(QC_DSA_87, test_vector_pk_87, test_vector_sk_87,
            test_vector_sig_87, "kat87");
}

/* Wrong message / wrong context / flipped signature / wrong key must all
 * fail verification. Context mismatch is the FIPS 204 domain-separation
 * property the adapter promises. */
static void test_verify_rejects(void) {
    static uint8_t pk[1312], sk[2560], sig[2420], bad[2420];
    static const uint8_t other_ctx[] = { 'x' };
    const uint8_t *msg = (const uint8_t *)TEST_VECTOR_MSG;
    const uint8_t *ctx = (const uint8_t *)TEST_VECTOR_CTX;

    TEST_ASSERT_EQUAL_INT(QC_DSA_OK,
                          qc_dsa_keypair(QC_DSA_44, pk, sk, test_vector_rnd));
    TEST_ASSERT_EQUAL_INT(QC_DSA_OK,
                          qc_dsa_sign(QC_DSA_44, sig, msg, TEST_VECTOR_MSG_LEN,
                                      ctx, TEST_VECTOR_CTX_LEN,
                                      test_vector_rnd, sk));

    memcpy(bad, sig, sizeof(bad));
    bad[0] ^= 0x01;
    TEST_ASSERT_EQUAL_INT(QC_DSA_BAD_SIG,
                          qc_dsa_verify(QC_DSA_44, msg, TEST_VECTOR_MSG_LEN,
                                        ctx, TEST_VECTOR_CTX_LEN, bad, pk));
    memcpy(bad, sig, sizeof(bad));
    bad[sizeof(bad) - 1] ^= 0x80;
    TEST_ASSERT_EQUAL_INT(QC_DSA_BAD_SIG,
                          qc_dsa_verify(QC_DSA_44, msg, TEST_VECTOR_MSG_LEN,
                                        ctx, TEST_VECTOR_CTX_LEN, bad, pk));
    /* Flipped message byte. */
    {
        uint8_t m[64];
        memcpy(m, msg, TEST_VECTOR_MSG_LEN);
        m[0] ^= 0x01;
        TEST_ASSERT_EQUAL_INT(QC_DSA_BAD_SIG,
                              qc_dsa_verify(QC_DSA_44, m, TEST_VECTOR_MSG_LEN,
                                            ctx, TEST_VECTOR_CTX_LEN, sig, pk));
    }
    /* Wrong context, right everything else. */
    TEST_ASSERT_EQUAL_INT(QC_DSA_BAD_SIG,
                          qc_dsa_verify(QC_DSA_44, msg, TEST_VECTOR_MSG_LEN,
                                        other_ctx, sizeof(other_ctx), sig, pk));
    /* Empty context vs the KAT context. */
    TEST_ASSERT_EQUAL_INT(QC_DSA_BAD_SIG,
                          qc_dsa_verify(QC_DSA_44, msg, TEST_VECTOR_MSG_LEN,
                                        NULL, 0, sig, pk));
    /* Wrong key. */
    {
        static uint8_t pk2[1312], sk2[2560];
        TEST_ASSERT_EQUAL_INT(QC_DSA_OK,
                              qc_dsa_keypair(QC_DSA_44, pk2, sk2, ALT_RND));
        TEST_ASSERT_EQUAL_INT(QC_DSA_BAD_SIG,
                              qc_dsa_verify(QC_DSA_44, msg, TEST_VECTOR_MSG_LEN,
                                            ctx, TEST_VECTOR_CTX_LEN, sig, pk2));
    }
    /* Cross-mode: extmu and pre-hash signatures must NOT verify on the
     * pure path (backend domain separation, not just ours). */
    TEST_ASSERT_EQUAL_INT(QC_DSA_BAD_SIG,
                          qc_dsa_verify(QC_DSA_44, msg, TEST_VECTOR_MSG_LEN,
                                        ctx, TEST_VECTOR_CTX_LEN,
                                        test_vector_sig_extmu_44, pk));
    TEST_ASSERT_EQUAL_INT(QC_DSA_BAD_SIG,
                          qc_dsa_verify(QC_DSA_44, msg, TEST_VECTOR_MSG_LEN,
                                        ctx, TEST_VECTOR_CTX_LEN,
                                        test_vector_sig_pre_hash_shake256_44,
                                        pk));
    TEST_ASSERT_EQUAL_INT(QC_DSA_BAD_SIG,
                          qc_dsa_verify(QC_DSA_65, msg, TEST_VECTOR_MSG_LEN,
                                        ctx, TEST_VECTOR_CTX_LEN,
                                        test_vector_sig_extmu_65,
                                        test_vector_pk_65));
    TEST_ASSERT_EQUAL_INT(QC_DSA_BAD_SIG,
                          qc_dsa_verify(QC_DSA_87, msg, TEST_VECTOR_MSG_LEN,
                                        ctx, TEST_VECTOR_CTX_LEN,
                                        test_vector_sig_pre_hash_shake256_87,
                                        test_vector_pk_87));
    TEST_ASSERT_EQUAL_INT(QC_DSA_BAD_SIG,
                          qc_dsa_verify(QC_DSA_65, msg, TEST_VECTOR_MSG_LEN,
                                        ctx, TEST_VECTOR_CTX_LEN,
                                        test_vector_sig_pre_hash_shake256_65,
                                        test_vector_pk_65));
    TEST_ASSERT_EQUAL_INT(QC_DSA_BAD_SIG,
                          qc_dsa_verify(QC_DSA_87, msg, TEST_VECTOR_MSG_LEN,
                                        ctx, TEST_VECTOR_CTX_LEN,
                                        test_vector_sig_extmu_87,
                                        test_vector_pk_87));
    /* mu is the 64-byte internal message representative contract. */
    TEST_ASSERT_EQUAL_UINT(64, sizeof(test_vector_mu));
}

/* Empty message roundtrip (NULL, 0) with fixed rnd. */
static void test_empty_message(void) {
    static uint8_t pk[1952], sk[4032], sig[3309], sig2[3309];

    TEST_ASSERT_EQUAL_INT(QC_DSA_OK,
                          qc_dsa_keypair(QC_DSA_65, pk, sk, test_vector_rnd));
    TEST_ASSERT_EQUAL_INT(QC_DSA_OK,
                          qc_dsa_sign(QC_DSA_65, sig, NULL, 0,
                                      NULL, 0, test_vector_rnd, sk));
    TEST_ASSERT_EQUAL_INT(QC_DSA_OK,
                          qc_dsa_verify(QC_DSA_65, NULL, 0,
                                        NULL, 0, sig, pk));
    /* Deterministic on empty too. */
    TEST_ASSERT_EQUAL_INT(QC_DSA_OK,
                          qc_dsa_sign(QC_DSA_65, sig2, NULL, 0,
                                      NULL, 0, test_vector_rnd, sk));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(sig, sig2, sizeof(sig));
}

/* Misuse taxonomy on every API. */
static void test_misuse(void) {
    static uint8_t pk[1312], sk[2560], sig[2420];
    static uint8_t big_ctx[256];
    const uint8_t *msg = (const uint8_t *)TEST_VECTOR_MSG;

    TEST_ASSERT_EQUAL_INT(QC_DSA_BAD_LEVEL,
                          qc_dsa_keypair(0, pk, sk, test_vector_rnd));
    TEST_ASSERT_EQUAL_INT(QC_DSA_BAD_LEVEL,
                          qc_dsa_sign(11, sig, msg, TEST_VECTOR_MSG_LEN,
                                      NULL, 0, test_vector_rnd, sk));
    TEST_ASSERT_EQUAL_INT(QC_DSA_BAD_LEVEL,
                          qc_dsa_verify(97, msg, TEST_VECTOR_MSG_LEN,
                                        NULL, 0, sig, pk));

    TEST_ASSERT_EQUAL_INT(QC_DSA_BAD_LENGTH,
                          qc_dsa_keypair(QC_DSA_44, NULL, sk, test_vector_rnd));
    TEST_ASSERT_EQUAL_INT(QC_DSA_BAD_LENGTH,
                          qc_dsa_keypair(QC_DSA_44, pk, NULL, test_vector_rnd));
    TEST_ASSERT_EQUAL_INT(QC_DSA_BAD_LENGTH,
                          qc_dsa_keypair(QC_DSA_44, pk, sk, NULL));
    TEST_ASSERT_EQUAL_INT(QC_DSA_BAD_LENGTH,
                          qc_dsa_sign(QC_DSA_44, NULL, msg, TEST_VECTOR_MSG_LEN,
                                      NULL, 0, test_vector_rnd, sk));
    TEST_ASSERT_EQUAL_INT(QC_DSA_BAD_LENGTH,
                          qc_dsa_sign(QC_DSA_44, sig, NULL, 5,
                                      NULL, 0, test_vector_rnd, sk));
    TEST_ASSERT_EQUAL_INT(QC_DSA_BAD_LENGTH,
                          qc_dsa_sign(QC_DSA_44, sig, msg, TEST_VECTOR_MSG_LEN,
                                      NULL, 0, NULL, sk));
    TEST_ASSERT_EQUAL_INT(QC_DSA_BAD_LENGTH,
                          qc_dsa_sign(QC_DSA_44, sig, msg, TEST_VECTOR_MSG_LEN,
                                      NULL, 0, test_vector_rnd, NULL));
    TEST_ASSERT_EQUAL_INT(QC_DSA_BAD_LENGTH,
                          qc_dsa_sign(QC_DSA_44, sig, msg, TEST_VECTOR_MSG_LEN,
                                      NULL, 1, test_vector_rnd, sk));
    TEST_ASSERT_EQUAL_INT(QC_DSA_BAD_LENGTH,
                          qc_dsa_sign(QC_DSA_44, sig, msg, TEST_VECTOR_MSG_LEN,
                                      big_ctx, sizeof(big_ctx),
                                      test_vector_rnd, sk));
    TEST_ASSERT_EQUAL_INT(QC_DSA_BAD_LENGTH,
                          qc_dsa_verify(QC_DSA_44, msg, TEST_VECTOR_MSG_LEN,
                                        NULL, 0, NULL, pk));
    TEST_ASSERT_EQUAL_INT(QC_DSA_BAD_LENGTH,
                          qc_dsa_verify(QC_DSA_44, msg, TEST_VECTOR_MSG_LEN,
                                        NULL, 0, sig, NULL));
    TEST_ASSERT_EQUAL_INT(QC_DSA_BAD_LENGTH,
                          qc_dsa_verify(QC_DSA_44, NULL, 3,
                                        NULL, 0, sig, pk));
    TEST_ASSERT_EQUAL_INT(QC_DSA_BAD_LENGTH,
                          qc_dsa_verify(QC_DSA_44, msg, TEST_VECTOR_MSG_LEN,
                                        NULL, 3, sig, pk));
    /* ctxlen 255 is the FIPS bound: accepted (KAT ctx is shorter, so
     * exercise the boundary with a direct roundtrip on a fresh key). */
    {
        static uint8_t ctx255[255];
        memset(ctx255, 0x41, sizeof(ctx255));
        TEST_ASSERT_EQUAL_INT(QC_DSA_OK,
                              qc_dsa_keypair(QC_DSA_44, pk, sk,
                                             test_vector_rnd));
        TEST_ASSERT_EQUAL_INT(QC_DSA_OK,
                              qc_dsa_sign(QC_DSA_44, sig, msg,
                                          TEST_VECTOR_MSG_LEN,
                                          ctx255, sizeof(ctx255),
                                          test_vector_rnd, sk));
        TEST_ASSERT_EQUAL_INT(QC_DSA_OK,
                              qc_dsa_verify(QC_DSA_44, msg, TEST_VECTOR_MSG_LEN,
                                            ctx255, sizeof(ctx255), sig, pk));
    }

    TEST_ASSERT_EQUAL_UINT(QC_DSA44_PK_BYTES, qc_dsa_pk_bytes(QC_DSA_44));
    TEST_ASSERT_EQUAL_UINT(QC_DSA65_PK_BYTES, qc_dsa_pk_bytes(QC_DSA_65));
    TEST_ASSERT_EQUAL_UINT(QC_DSA87_PK_BYTES, qc_dsa_pk_bytes(QC_DSA_87));
    TEST_ASSERT_EQUAL_UINT(QC_DSA44_SK_BYTES, qc_dsa_sk_bytes(QC_DSA_44));
    TEST_ASSERT_EQUAL_UINT(QC_DSA65_SK_BYTES, qc_dsa_sk_bytes(QC_DSA_65));
    TEST_ASSERT_EQUAL_UINT(QC_DSA87_SK_BYTES, qc_dsa_sk_bytes(QC_DSA_87));
    TEST_ASSERT_EQUAL_UINT(QC_DSA44_SIG_BYTES, qc_dsa_sig_bytes(QC_DSA_44));
    TEST_ASSERT_EQUAL_UINT(QC_DSA65_SIG_BYTES, qc_dsa_sig_bytes(QC_DSA_65));
    TEST_ASSERT_EQUAL_UINT(QC_DSA87_SIG_BYTES, qc_dsa_sig_bytes(QC_DSA_87));
    TEST_ASSERT_EQUAL_UINT(0, qc_dsa_pk_bytes(0));
    TEST_ASSERT_EQUAL_UINT(0, qc_dsa_sk_bytes(11));
    TEST_ASSERT_EQUAL_UINT(0, qc_dsa_sig_bytes(97));
}

void setUp(void) {}
void tearDown(void) {}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_kat_44);
    RUN_TEST(test_kat_65);
    RUN_TEST(test_kat_87);
    RUN_TEST(test_verify_rejects);
    RUN_TEST(test_empty_message);
    RUN_TEST(test_misuse);
    return UNITY_END();
}