/* test_entropy_health.c - B-50.3 IID/non-IID health gates.
 *
 * Two halves, both required by B-50.5 self-tests:
 *   1. the real OS source PASSES (a gate that flags healthy entropy is
 *      worse than no gate - this half is the flake guard)
 *   2. every poisoned-source shape FAILS with its own distinct rc, so a
 *      health gate that cannot fail is provably not vacuous
 */
#include <string.h>

#include "qc_health.h"
#include "unity.h"

void setUp(void) {}
void tearDown(void) {}

static void test_real_source_passes(void) {
    char audit[QC_HEALTH_AUDIT_LEN];
    /* One full QC_HEALTH_SAMPLE draw from the host OS source. The size is
     * the API cap (qc_health_check_os refuses larger), so confidence comes
     * from repetition below, not from a bigger buffer. */
    qc_health_rc rc = qc_health_check_os(QC_HEALTH_SAMPLE, audit);
    TEST_ASSERT_EQUAL_INT_MESSAGE(QC_HEALTH_OK, rc, audit);
}

static void test_repeat_is_not_flaky(void) {
    char audit[QC_HEALTH_AUDIT_LEN];
    int i;
    /* Five independent draws must all clear. One pass could be luck; five
     * consecutive passes is the evidence the bands are not mis-set. */
    for (i = 0; i < 5; i++) {
        qc_health_rc rc = qc_health_check_os(QC_HEALTH_SAMPLE, audit);
        TEST_ASSERT_EQUAL_INT_MESSAGE(QC_HEALTH_OK, rc, audit);
    }
}

/* --- poisoned sources: each must fail, each with its own signature --- */

static void test_constant_source_fails(void) {
    char audit[QC_HEALTH_AUDIT_LEN];
    uint8_t buf[QC_HEALTH_SAMPLE];
    memset(buf, 0x00, sizeof(buf));
    /* All-zero: bit proportion 0 -> ones-skew fires before the alphabet
     * test would, which is the correct ordering (cheapest, strongest). */
    TEST_ASSERT_EQUAL_INT(QC_HEALTH_LOW_ONES,
                          qc_health_check(buf, sizeof(buf), audit));
    TEST_ASSERT_EQUAL_STRING("ones-skew", audit);
}

static void test_ones_source_fails(void) {
    char audit[QC_HEALTH_AUDIT_LEN];
    uint8_t buf[QC_HEALTH_SAMPLE];
    memset(buf, 0xFF, sizeof(buf));
    TEST_ASSERT_EQUAL_INT(QC_HEALTH_LOW_ONES,
                          qc_health_check(buf, sizeof(buf), audit));
    TEST_ASSERT_EQUAL_STRING("ones-skew", audit);
}

static void test_low_entropy_bias_fails(void) {
    char audit[QC_HEALTH_AUDIT_LEN];
    uint8_t buf[QC_HEALTH_SAMPLE];
    size_t i;
    /* Two-bit alphabet, balanced: passes the ones test by construction, so
     * the failure must come from the starved-byte alphabet test. Proves the
     * alphabet check is load-bearing, not decorative. */
    for (i = 0; i < sizeof(buf); i++) {
        buf[i] = (uint8_t)((i & 1u) ? 0xAAu : 0x55u);
    }
    TEST_ASSERT_EQUAL_INT(QC_HEALTH_ALPHABET,
                          qc_health_check(buf, sizeof(buf), audit));
    TEST_ASSERT_EQUAL_STRING("alphabet-starved", audit);
}

static void test_repeating_pattern_fails(void) {
    char audit[QC_HEALTH_AUDIT_LEN];
    uint8_t buf[QC_HEALTH_SAMPLE];
    size_t i;
    /* Every 128-byte block is 64 zeros then 64 ones: each block is exactly
     * balanced (so the block test passes) and the whole sample is balanced
     * (so the ones test passes), but consecutive blocks fuse into 512-bit
     * runs at the 0xFF/0x00 seams. Only the run test can catch this. */
    for (i = 0; i < sizeof(buf); i++) {
        buf[i] = ((i % 128u) < 64u) ? 0x00u : 0xFFu;
    }
    TEST_ASSERT_EQUAL_INT(QC_HEALTH_LONG_RUN,
                          qc_health_check(buf, sizeof(buf), audit));
    TEST_ASSERT_EQUAL_STRING("long-run", audit);
}

static void test_block_skew_fails(void) {
    char audit[QC_HEALTH_AUDIT_LEN];
    uint8_t buf[QC_HEALTH_SAMPLE];
    size_t ones_bytes, start_ones;
    /* Block 0 is all zeros; the remainder is sized so the WHOLE sample still
     * lands on exactly 50% ones. Without that balance the whole-sample
     * ones test would fire first and the per-block test would never be
     * exercised - so the fixture is deliberately built to pass the earlier
     * tests and fail only this one. */
    memset(buf, 0x00, sizeof(buf));
    ones_bytes = (sizeof(buf) - 128u) / 2u;   /* remainder is 50/50 */
    start_ones = 128u;
    memset(buf + start_ones, 0xFF, ones_bytes);
    TEST_ASSERT_EQUAL_INT(QC_HEALTH_BLOCK_SKEW,
                          qc_health_check(buf, sizeof(buf), audit));
    TEST_ASSERT_EQUAL_STRING("block-skew", audit);
}

/* --- argument guards --- */

static void test_guards(void) {
    char audit[QC_HEALTH_AUDIT_LEN];
    uint8_t buf[QC_HEALTH_SAMPLE];
    memset(buf, 0x5A, sizeof(buf));
    TEST_ASSERT_EQUAL_INT(QC_HEALTH_BAD_ARG,
                          qc_health_check(NULL, sizeof(buf), audit));
    TEST_ASSERT_EQUAL_INT(QC_HEALTH_TOO_SHORT,
                          qc_health_check(buf, 0u, audit));
    TEST_ASSERT_EQUAL_INT(QC_HEALTH_TOO_SHORT,
                          qc_health_check(buf, 16u, audit));
    /* NULL audit must not crash. */
    (void)qc_health_check(buf, sizeof(buf), NULL);
    /* OS wrapper: over-cap and zero length are refused, never sampled. */
    TEST_ASSERT_EQUAL_INT(QC_HEALTH_BAD_ARG,
                          qc_health_check_os(0u, audit));
    TEST_ASSERT_EQUAL_INT(QC_HEALTH_BAD_ARG,
                          qc_health_check_os(QC_HEALTH_SAMPLE + 1u, audit));
    TEST_ASSERT_EQUAL_STRING("ok", qc_health_str(QC_HEALTH_OK));
    TEST_ASSERT_EQUAL_STRING("bad-arg", qc_health_str(QC_HEALTH_BAD_ARG));
    TEST_ASSERT_EQUAL_STRING("unknown", qc_health_str((qc_health_rc)99));
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_real_source_passes);
    RUN_TEST(test_repeat_is_not_flaky);
    RUN_TEST(test_constant_source_fails);
    RUN_TEST(test_ones_source_fails);
    RUN_TEST(test_low_entropy_bias_fails);
    RUN_TEST(test_repeating_pattern_fails);
    RUN_TEST(test_block_skew_fails);
    RUN_TEST(test_guards);
    return UNITY_END();
}
