/* test_state.c — L0/L1/L2 for the controller state vector (B-30 host).
 *
 * Covers: fail-safe boot mask (all invalid, R included), happy-path
 * sampling + mask clear, range refusals incl. NaN (last-good kept),
 * monotonicity drops (mask untouched), staleness accrue/recover,
 * R-boot rule, C2 immediate signal + consume, M minimum (+0 disable),
 * Q cross-sanity vs counters, risk snapshot, NULL/uninit guards.
 * State structs are small: static anyway (house rule).
 */
#include "unity.h"

#include <math.h>
#include <string.h>

#include "qc_state.h"

static qc_state s;

static unsigned pair_bits(uint16_t mask, int comp) {
    return (unsigned)((mask >> (2 * comp)) & 3u);
}

static float make_nan(void) {
    uint32_t u = 0x7FC00000u;
    float v;
    memcpy(&v, &u, 4);
    return v;
}

static void test_boot_mask(void) {
    int i;

    qc_state_init(&s);
    for (i = 0; i < QC_STATE_NCOMP; i++) {
        TEST_ASSERT_EQUAL_UINT(QC_STATE_F_INVALID,
                               pair_bits(s.mask, i));
    }
    TEST_ASSERT_EQUAL_UINT(0x2AAAu, s.mask);
    qc_state_init(NULL);
}

static void test_happy_path(void) {
    uint32_t risk[6] = { 1, 2, 3, 4, 5, 6 };
    uint16_t m;

    qc_state_init(&s);
    TEST_ASSERT_EQUAL_INT(QC_STATE_OK,
        qc_state_sample_b(&s, 900.0f, 80, 1000));
    TEST_ASSERT_EQUAL_INT(QC_STATE_OK,
        qc_state_sample_r(&s, 0.25f, 1000));
    TEST_ASSERT_EQUAL_INT(QC_STATE_OK,
        qc_state_sample_s(&s, 1, 1000));
    TEST_ASSERT_EQUAL_INT(QC_STATE_OK,
        qc_state_sample_c(&s, 0.5f, 1000));
    TEST_ASSERT_EQUAL_INT(QC_STATE_OK,
        qc_state_sample_m(&s, 204800u, 1000));
    TEST_ASSERT_EQUAL_INT(QC_STATE_OK,
        qc_state_sample_l(&s, -70, 3, 1000));
    TEST_ASSERT_EQUAL_INT(QC_STATE_OK,
        qc_state_sample_q(&s, 1.0f, 42, 1000));
    TEST_ASSERT_EQUAL_INT(QC_STATE_OK,
        qc_state_snapshot_risk(&s, risk, 1000));
    TEST_ASSERT_EQUAL_FLOAT(900.0f, s.b_j);
    TEST_ASSERT_EQUAL_UINT8(80, s.b_soc);
    TEST_ASSERT_EQUAL_UINT(204800u, s.m);
    TEST_ASSERT_EQUAL_INT(-70, s.l_rssi);
    TEST_ASSERT_EQUAL_UINT(3, s.l_retries);
    TEST_ASSERT_EQUAL_UINT(1, s.risk[0]);
    TEST_ASSERT_EQUAL_UINT(6, s.risk[5]);
    m = qc_state_check(&s, 1001, 100, 1024, 42, 0.01f);
    TEST_ASSERT_EQUAL_UINT(0, m);
}

static void test_range_refusals(void) {
    qc_state_init(&s);
    TEST_ASSERT_EQUAL_INT(QC_STATE_OK,
        qc_state_sample_b(&s, 900.0f, 80, 1000));
    /* Each refusal flags invalid and keeps last-good. */
    TEST_ASSERT_EQUAL_INT(QC_STATE_INVALID,
        qc_state_sample_b(&s, -1.0f, 80, 1001));
    TEST_ASSERT_EQUAL_INT(QC_STATE_INVALID,
        qc_state_sample_b(&s, 900.0f, 101, 1001));
    TEST_ASSERT_EQUAL_FLOAT(900.0f, s.b_j);
    TEST_ASSERT_EQUAL_UINT(QC_STATE_F_INVALID,
                           pair_bits(s.mask, QC_STATE_COMP_B));
    TEST_ASSERT_EQUAL_INT(QC_STATE_INVALID,
        qc_state_sample_r(&s, 1.5f, 1001));
    TEST_ASSERT_EQUAL_INT(QC_STATE_INVALID,
        qc_state_sample_r(&s, make_nan(), 1001));
    TEST_ASSERT_EQUAL_INT(QC_STATE_INVALID,
        qc_state_sample_s(&s, 3, 1001));
    TEST_ASSERT_EQUAL_INT(QC_STATE_INVALID,
        qc_state_sample_c(&s, make_nan(), 1001));
    TEST_ASSERT_EQUAL_INT(QC_STATE_INVALID,
        qc_state_sample_q(&s, -0.5f, 0, 1001));
    TEST_ASSERT_EQUAL_INT(QC_STATE_INVALID,
        qc_state_sample_b(&s, INFINITY, 80, 1001));
    TEST_ASSERT_EQUAL_INT(QC_STATE_INVALID,
        qc_state_sample_q(&s, INFINITY, 0, 1001));
    TEST_ASSERT_EQUAL_UINT(QC_STATE_F_INVALID,
                           pair_bits(s.mask, QC_STATE_COMP_Q));
    /* Recovery: one good sample clears invalid. */
    TEST_ASSERT_EQUAL_INT(QC_STATE_OK,
        qc_state_sample_b(&s, 800.0f, 70, 1002));
    TEST_ASSERT_EQUAL_UINT(QC_STATE_F_OK,
                           pair_bits(s.mask, QC_STATE_COMP_B));
}

static void test_monotonicity(void) {
    qc_state_init(&s);
    TEST_ASSERT_EQUAL_INT(QC_STATE_OK,
        qc_state_sample_c(&s, 0.5f, 1000));
    TEST_ASSERT_EQUAL_INT(QC_STATE_NONMONOTONIC,
        qc_state_sample_c(&s, 0.6f, 999));
    TEST_ASSERT_EQUAL_FLOAT(0.5f, s.c); /* dropped, last-good kept */
    TEST_ASSERT_EQUAL_UINT(QC_STATE_F_OK,
                           pair_bits(s.mask, QC_STATE_COMP_C));
    /* Equal timestamps are not regression. */
    TEST_ASSERT_EQUAL_INT(QC_STATE_OK,
        qc_state_sample_c(&s, 0.6f, 1000));
    {
        uint32_t risk[6] = { 7, 7, 7, 7, 7, 7 };
        TEST_ASSERT_EQUAL_INT(QC_STATE_OK,
            qc_state_snapshot_risk(&s, risk, 1000));
        TEST_ASSERT_EQUAL_INT(QC_STATE_NONMONOTONIC,
            qc_state_snapshot_risk(&s, risk, 999));
        TEST_ASSERT_EQUAL_UINT(7, s.risk[0]); /* dropped */
    }
}

static void test_staleness(void) {
    uint16_t m;

    qc_state_init(&s);
    TEST_ASSERT_EQUAL_INT(QC_STATE_OK,
        qc_state_sample_c(&s, 0.5f, 1000));
    m = qc_state_check(&s, 1000 + 99, 100, 0, 0, 0.01f);
    TEST_ASSERT_EQUAL_UINT(QC_STATE_F_OK, pair_bits(m, QC_STATE_COMP_C));
    m = qc_state_check(&s, 1000 + 301, 100, 0, 0, 0.01f);
    TEST_ASSERT_EQUAL_UINT(QC_STATE_F_STALE,
                           pair_bits(m, QC_STATE_COMP_C));
    /* Fresh sample + young check recovers. */
    TEST_ASSERT_EQUAL_INT(QC_STATE_OK,
        qc_state_sample_c(&s, 0.4f, 2000));
    m = qc_state_check(&s, 2001, 100, 0, 0, 0.01f);
    TEST_ASSERT_EQUAL_UINT(QC_STATE_F_OK, pair_bits(m, QC_STATE_COMP_C));
}

static void test_c2_immediate(void) {
    qc_state_init(&s);
    TEST_ASSERT_EQUAL_INT(0, qc_state_take_s_immediate(&s));
    TEST_ASSERT_EQUAL_INT(0, qc_state_take_s_immediate(NULL));
    TEST_ASSERT_EQUAL_INT(QC_STATE_OK,
        qc_state_sample_s(&s, 0, 1000));
    TEST_ASSERT_EQUAL_INT(0, qc_state_take_s_immediate(&s));
    TEST_ASSERT_EQUAL_INT(QC_STATE_C2,
        qc_state_sample_s(&s, 2, 1001));
    TEST_ASSERT_EQUAL_UINT8(2, s.s);
    TEST_ASSERT_EQUAL_INT(1, qc_state_take_s_immediate(&s));
    TEST_ASSERT_EQUAL_INT(0, qc_state_take_s_immediate(&s));
}

static void test_mem_min(void) {
    uint16_t m;

    qc_state_init(&s);
    TEST_ASSERT_EQUAL_INT(QC_STATE_OK,
        qc_state_sample_m(&s, 512, 1000));
    m = qc_state_check(&s, 1001, 10000, 1024, 0, 0.01f);
    TEST_ASSERT_EQUAL_UINT(QC_STATE_F_INVALID,
                           pair_bits(m, QC_STATE_COMP_M));
    /* 0 disables the floor: fresh sample + 0 floor stays valid. */
    qc_state_init(&s);
    TEST_ASSERT_EQUAL_INT(QC_STATE_OK,
        qc_state_sample_m(&s, 512, 1000));
    m = qc_state_check(&s, 1001, 10000, 0, 0, 0.01f);
    TEST_ASSERT_EQUAL_UINT(QC_STATE_F_OK,
                           pair_bits(m, QC_STATE_COMP_M));
}

static void test_q_cross(void) {
    uint16_t m;

    qc_state_init(&s);
    TEST_ASSERT_EQUAL_INT(QC_STATE_OK,
        qc_state_sample_q(&s, 0.0f, 10, 1000));
    /* Counters unmoved: no trip. */
    m = qc_state_check(&s, 1001, 10000, 0, 10, 0.01f);
    TEST_ASSERT_EQUAL_UINT(QC_STATE_F_OK, pair_bits(m, QC_STATE_COMP_Q));
    /* Counters advanced with zero rate: sensor fault. */
    m = qc_state_check(&s, 1001, 10000, 0, 15, 0.01f);
    TEST_ASSERT_EQUAL_UINT(QC_STATE_F_INVALID,
                           pair_bits(m, QC_STATE_COMP_Q));
    /* Healthy rate never trips, however counters move. */
    TEST_ASSERT_EQUAL_INT(QC_STATE_OK,
        qc_state_sample_q(&s, 2.0f, 15, 1002));
    m = qc_state_check(&s, 1003, 10000, 0, 99, 0.01f);
    TEST_ASSERT_EQUAL_UINT(QC_STATE_F_OK, pair_bits(m, QC_STATE_COMP_Q));
}

static void test_guards(void) {
    qc_state uninit;
    uint32_t risk[6] = { 0, 0, 0, 0, 0, 0 };

    memset(&uninit, 0, sizeof(uninit));
    TEST_ASSERT_EQUAL_INT(QC_STATE_BAD_ARG,
        qc_state_sample_b(NULL, 1.0f, 1, 1));
    TEST_ASSERT_EQUAL_INT(QC_STATE_BAD_ARG,
        qc_state_sample_b(&uninit, 1.0f, 1, 1));
    TEST_ASSERT_EQUAL_INT(QC_STATE_BAD_ARG,
        qc_state_snapshot_risk(&s, NULL, 1));
    TEST_ASSERT_EQUAL_INT(QC_STATE_BAD_ARG,
        qc_state_snapshot_risk(&uninit, risk, 1));
    TEST_ASSERT_EQUAL_UINT(0,
        qc_state_check(NULL, 1, 1, 0, 0, 0.01f));
    TEST_ASSERT_EQUAL_UINT(0, qc_state_check(&uninit, 1, 1, 0, 0, 0.01f));
}

void setUp(void) {}
void tearDown(void) {}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_boot_mask);
    RUN_TEST(test_happy_path);
    RUN_TEST(test_range_refusals);
    RUN_TEST(test_monotonicity);
    RUN_TEST(test_staleness);
    RUN_TEST(test_c2_immediate);
    RUN_TEST(test_mem_min);
    RUN_TEST(test_q_cross);
    RUN_TEST(test_guards);
    return UNITY_END();
}
