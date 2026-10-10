/* test_drbg.c — L0/L1/L2 for entropy + HMAC-DRBG (B-13.1/.2).
 *
 * KATs: NIST CAVS HMAC_DRBG SHA-256 no-PR vectors (tests/c/drbg_vectors.h
 * via tools/drbg_to_c.py): instantiate(seed) -> gen(add_a) [discard] ->
 * gen(add_b) == returned. Then: reseed policy (R bytes / T secs via
 * deterministic provider + fake clock, asserting determinism across the
 * boundary), 2^16 cap, NULL guards, fork-pid documented untested here
 * (needs real fork; noted), entropy happy/bad-arg/audit strings,
 * injected-fault RNG_FAIL, stats smoke on fixed output.
 * Links the TEST entropy provider (deterministic), never prod entropy.
 */
#include "unity.h"

#include <stdio.h>
#include <string.h>

#include "qc_drbg.h"
#include "qc_entropy.h"
#include "drbg_vectors.h"

void test_entropy_seed(uint64_t seed);
void test_entropy_fail_next(void);

static void test_kat_all(void) {
    static const struct {
        const wy_drbg_t *tab;
        size_t n;
    } groups[4] = {
        { wy_drbg_0, wy_drbg_0_n }, { wy_drbg_1, wy_drbg_1_n },
        { wy_drbg_2, wy_drbg_2_n }, { wy_drbg_3, wy_drbg_3_n }
    };
    static uint8_t seed[256], r1[64], g1[64], g2[64];
    static uint8_t got[256], want[256];
    int gi;

    for (gi = 0; gi < 4; gi++) {
        size_t i;
        for (i = 0; i < groups[gi].n; i++) {
            const wy_drbg_t *t = &groups[gi].tab[i];
            size_t k, slen, r1len, g1len, g2len, olen;
            unsigned v;
            qc_drbg d;
            /* hex decode inline (lengths vary per class). */
            slen = strlen(t->seed) / 2;
            for (k = 0; k < slen; k++) {
                TEST_ASSERT_EQUAL_INT(1, sscanf(t->seed + 2 * k,
                                                "%2x", &v));
                seed[k] = (uint8_t)v;
            }
            r1len = strlen(t->r1) / 2;
            for (k = 0; k < r1len; k++) {
                TEST_ASSERT_EQUAL_INT(1, sscanf(t->r1 + 2 * k, "%2x", &v));
                r1[k] = (uint8_t)v;
            }
            g1len = strlen(t->g1) / 2;
            for (k = 0; k < g1len; k++) {
                TEST_ASSERT_EQUAL_INT(1, sscanf(t->g1 + 2 * k, "%2x", &v));
                g1[k] = (uint8_t)v;
            }
            g2len = strlen(t->g2) / 2;
            for (k = 0; k < g2len; k++) {
                TEST_ASSERT_EQUAL_INT(1, sscanf(t->g2 + 2 * k, "%2x", &v));
                g2[k] = (uint8_t)v;
            }
            olen = strlen(t->out) / 2;
            for (k = 0; k < olen; k++) {
                TEST_ASSERT_EQUAL_INT(1, sscanf(t->out + 2 * k,
                                                "%2x", &v));
                want[k] = (uint8_t)v;
            }
            /* mbedTLS driver sequence (entropy stream split preserved
             * by tools/drbg_to_c.py: seed=ent[:48]+custom,
             * r1=ent[48:80]+add1): seed -> reseed(r1) ->
             * generate(g1) [discard] -> generate(g2) [compare]. */
            TEST_ASSERT_EQUAL_INT(0, qc_drbg_init(&d));
            TEST_ASSERT_EQUAL_INT(0,
                qc_drbg_reseed(&d, seed, slen));
            TEST_ASSERT_EQUAL_INT(0,
                qc_drbg_reseed(&d, r1, r1len));
            TEST_ASSERT_EQUAL_INT(0,
                qc_drbg_generate(&d, got, olen, g1, g1len, 1000));
            TEST_ASSERT_EQUAL_INT(0,
                qc_drbg_generate(&d, got, olen, g2, g2len, 1000));
            TEST_ASSERT_EQUAL_UINT8_ARRAY_MESSAGE(want, got, olen,
                                                  "KAT mismatch");
            qc_drbg_free(&d);
        }
    }
}

/* Reseed policy determinism: same provider seed -> identical stream
 * across an R-boundary auto-reseed AND a T-boundary auto-reseed. */
static void test_reseed_policy(void) {
    static uint8_t a[64], b[64];
    qc_drbg d1, d2;

    test_entropy_seed(0xABCDu);
    TEST_ASSERT_EQUAL_INT(0, qc_drbg_init(&d1));
    TEST_ASSERT_EQUAL_INT(0,
        qc_drbg_generate(&d1, a, 32, NULL, 0, 1000));
    /* Force R expiry: out_total near max, then generate crosses it. */
    d1.out_total = QC_DRBG_RESEED_BYTES - 16;
    TEST_ASSERT_EQUAL_INT(0,
        qc_drbg_generate(&d1, a + 32, 32, NULL, 0, 1000));
    test_entropy_seed(0xABCDu);
    TEST_ASSERT_EQUAL_INT(0, qc_drbg_init(&d2));
    TEST_ASSERT_EQUAL_INT(0,
        qc_drbg_generate(&d2, b, 32, NULL, 0, 1000));
    d2.out_total = QC_DRBG_RESEED_BYTES - 16;
    TEST_ASSERT_EQUAL_INT(0,
        qc_drbg_generate(&d2, b + 32, 32, NULL, 0, 1000));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(a, b, 64);
    /* T expiry: jump clock past reseed_at + T. */
    test_entropy_seed(0xABCDu);
    TEST_ASSERT_EQUAL_INT(0, qc_drbg_init(&d1));
    TEST_ASSERT_EQUAL_INT(0,
        qc_drbg_generate(&d1, a, 32, NULL, 0, 1000));
    TEST_ASSERT_EQUAL_INT(0,
        qc_drbg_generate(&d1, a + 32, 32, NULL, 0,
                         1000 + QC_DRBG_RESEED_SECS));
    test_entropy_seed(0xABCDu);
    TEST_ASSERT_EQUAL_INT(0, qc_drbg_init(&d2));
    TEST_ASSERT_EQUAL_INT(0,
        qc_drbg_generate(&d2, b, 32, NULL, 0, 1000));
    TEST_ASSERT_EQUAL_INT(0,
        qc_drbg_generate(&d2, b + 32, 32, NULL, 0,
                         1000 + QC_DRBG_RESEED_SECS));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(a, b, 64);
    qc_drbg_free(&d1);
    qc_drbg_free(&d2);
}

/* Guards: cap, NULLs, empty reseed, oversize seed/add. */
static void test_guards(void) {
    static uint8_t buf[64], seed[32];
    qc_drbg d;

    memset(seed, 0x33, sizeof(seed));
    TEST_ASSERT_EQUAL_INT(0, qc_drbg_init(&d));
    TEST_ASSERT_EQUAL_INT(-1, qc_drbg_init(NULL));
    TEST_ASSERT_EQUAL_INT(-1, qc_drbg_reseed(NULL, seed, 32));
    TEST_ASSERT_EQUAL_INT(-1, qc_drbg_reseed(&d, NULL, 32));
    /* Empty reseed is legal (mandatory 0x00 round; CAVS vectors use it). */
    TEST_ASSERT_EQUAL_INT(0, qc_drbg_reseed(&d, seed, 0));
    {
        static uint8_t big[QC_DRBG_MAX_SEED + 1];
        TEST_ASSERT_EQUAL_INT(-1, qc_drbg_reseed(&d, big, sizeof(big)));
    }
    TEST_ASSERT_EQUAL_INT(-1, qc_drbg_generate(NULL, buf, 32, NULL, 0, 1));
    TEST_ASSERT_EQUAL_INT(-1, qc_drbg_generate(&d, NULL, 32, NULL, 0, 1));
    TEST_ASSERT_EQUAL_INT(-1,
        qc_drbg_generate(&d, buf, QC_DRBG_MAX_GEN + 1, NULL, 0, 1));
    {
        static uint8_t bigadd[QC_DRBG_MAX_SEED + 1];
        TEST_ASSERT_EQUAL_INT(-1,
            qc_drbg_generate(&d, buf, 32, bigadd, sizeof(bigadd), 1));
    }
    TEST_ASSERT_EQUAL_INT(0, qc_drbg_generate(&d, buf, 0, NULL, 0, 1));
    TEST_ASSERT_EQUAL_INT(0, qc_drbg_reseed(&d, seed, 32));
    /* Injected provider fault -> reseed_from_provider fails. */
    test_entropy_fail_next();
    TEST_ASSERT_EQUAL_INT(-1, qc_drbg_reseed_from_provider(&d, 2000));
    qc_drbg_free(&d);
    qc_drbg_free(NULL);
}

/* Entropy provider: happy path, audit strings, bad-arg, fault. */
static void test_entropy(void) {
    static uint8_t buf[64];
    char audit[QC_ENTROPY_AUDIT_LEN];

    test_entropy_seed(0x1u);
    TEST_ASSERT_EQUAL_INT(0, qc_entropy_poll(buf, sizeof(buf), audit));
    TEST_ASSERT_EQUAL_STRING("ok", audit);
    TEST_ASSERT_EQUAL_INT(-1, qc_entropy_poll(NULL, 10, audit));
    TEST_ASSERT_EQUAL_STRING("bad-arg", audit);
    TEST_ASSERT_EQUAL_INT(-1,
        qc_entropy_poll(buf, QC_ENTROPY_MAX + 1, audit));
    test_entropy_fail_next();
    TEST_ASSERT_EQUAL_INT(-1, qc_entropy_poll(buf, sizeof(buf), audit));
    TEST_ASSERT_EQUAL_STRING("injected-fault", audit);
    TEST_ASSERT_EQUAL_INT(-1, qc_entropy_poll(buf, 0, NULL));
}

/* Stats smoke: fixed output passes/fails deterministically (validates
 * the CHECK runs, not live entropy — documented). */
static void test_stats(void) {
    static uint8_t good[2500], bad[2500];
    qc_drbg d;

    test_entropy_seed(0x99u);
    TEST_ASSERT_EQUAL_INT(0, qc_drbg_init(&d));
    TEST_ASSERT_EQUAL_INT(0,
        qc_drbg_reseed_from_provider(&d, 1000));
    TEST_ASSERT_EQUAL_INT(0,
        qc_drbg_generate(&d, good, sizeof(good), NULL, 0, 1000));
    TEST_ASSERT_EQUAL_INT(0, qc_drbg_selftest_stats(good, sizeof(good)));
    memset(bad, 0, sizeof(bad));
    TEST_ASSERT_TRUE_MESSAGE(
        qc_drbg_selftest_stats(bad, sizeof(bad)) != 0, "zeros fail");
    memset(bad, 0xFF, sizeof(bad));
    TEST_ASSERT_TRUE_MESSAGE(
        qc_drbg_selftest_stats(bad, sizeof(bad)) != 0, "ones fail");
    TEST_ASSERT_TRUE_MESSAGE(
        qc_drbg_selftest_stats(NULL, 10) != 0, "null");
    qc_drbg_free(&d);
}

void setUp(void) {
    test_entropy_seed(0x12345678u);
}

void tearDown(void) {}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_kat_all);
    RUN_TEST(test_reseed_policy);
    RUN_TEST(test_guards);
    RUN_TEST(test_entropy);
    RUN_TEST(test_stats);
    return UNITY_END();
}