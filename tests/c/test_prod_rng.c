/* test_prod_rng.c — L0/L1 for the PRODUCTION RNG path (audit F3).
 *
 * Links qc_rng_prod.c + qc_drbg.c + the REAL qc_entropy.c (live
 * getrandom) — never the test injector. This is the only TU that links
 * prod entropy: ok-path + audit strings here exercise live OS entropy
 * (Linux-only green; same code path CI runs). Deterministic parts
 * (NULL/len guards, entropy bad-arg, chunked-length success) hold on any
 * platform. NOT run against sim-seed; live output must differ call to
 * call (collision impossible in practice — documents liveness).
 */
#include "unity.h"

#include <string.h>

#include "qc_drbg.h"
#include "qc_entropy.h"
#include "qc_rng.h"

static void test_rng_guards(void) {
    static uint8_t buf[32];

    TEST_ASSERT_EQUAL_INT(-1, qc_rng_generate(NULL, 32));
    TEST_ASSERT_EQUAL_INT(-1, qc_rng_generate(buf, 0));
    TEST_ASSERT_EQUAL_INT(-1, qc_rng_generate(NULL, 0));
}

/* Multi-chunk path (len > 2^16) succeeds; consecutive outputs differ. */
static void test_rng_live(void) {
    static uint8_t a[32], b[32];
    static uint8_t big[70000];

    TEST_ASSERT_EQUAL_INT(0, qc_rng_generate(a, sizeof(a)));
    TEST_ASSERT_EQUAL_INT(0, qc_rng_generate(b, sizeof(b)));
    TEST_ASSERT_TRUE_MESSAGE(memcmp(a, b, sizeof(a)) != 0,
                             "live stream repeats");
    TEST_ASSERT_EQUAL_INT(0, qc_rng_generate(big, sizeof(big)));
}

/* Prod entropy bad-arg paths (no entropy touched — deterministic). */
static void test_entropy_guards(void) {
    static uint8_t buf[64];
    char audit[QC_ENTROPY_AUDIT_LEN];

    TEST_ASSERT_EQUAL_INT(-1, qc_entropy_poll(NULL, 10, audit));
    TEST_ASSERT_EQUAL_STRING("bad-arg", audit);
    TEST_ASSERT_EQUAL_INT(-1,
        qc_entropy_poll(buf, QC_ENTROPY_MAX + 1, audit));
    TEST_ASSERT_EQUAL_STRING("bad-arg", audit);
    TEST_ASSERT_EQUAL_INT(-1, qc_entropy_poll(buf, 0, NULL));
}

/* Prod entropy ok-path over live getrandom + NULL-audit tolerance. */
static void test_entropy_live(void) {
    static uint8_t buf[64];
    char audit[QC_ENTROPY_AUDIT_LEN];

    TEST_ASSERT_EQUAL_INT(0, qc_entropy_poll(buf, sizeof(buf), audit));
    TEST_ASSERT_EQUAL_STRING("ok", audit);
    TEST_ASSERT_EQUAL_INT(0, qc_entropy_poll(buf, sizeof(buf), NULL));
    /* Forget hook links + re-baselines (next poll still healthy). */
    qc_entropy_forget();
    TEST_ASSERT_EQUAL_INT(0, qc_entropy_poll(buf, sizeof(buf), audit));
    TEST_ASSERT_EQUAL_STRING("ok", audit);
}

void setUp(void) {}
void tearDown(void) {}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_rng_guards);
    RUN_TEST(test_rng_live);
    RUN_TEST(test_entropy_guards);
    RUN_TEST(test_entropy_live);
    return UNITY_END();
}
