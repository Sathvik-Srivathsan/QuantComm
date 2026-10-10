/* test_trace.c — L0/L1/L2 for trace + policy-log schema (B-30.3).
 *
 * Covers: vector roundtrip (bit-exact floats, mask, ts), event
 * roundtrip all types + unknown-type decode tolerance (+encode refusal),
 * policy roundtrip (opaque action + energy), version gate (major reject,
 * minor-higher tolerant incl. trailing, same-minor trailing refused,
 * short refused), guards. Static buffers (house rule).
 */
#include "unity.h"

#include <string.h>

#include "qc_state.h"
#include "qc_trace.h"

static qc_state s;
static uint8_t rec[128];

static void craft_state(void) {
    uint32_t risk[6] = { 9, 8, 7, 6, 5, 4 };

    qc_state_init(&s);
    TEST_ASSERT_EQUAL_INT(QC_STATE_OK,
        qc_state_sample_b(&s, 812.5f, 77, 5000));
    TEST_ASSERT_EQUAL_INT(QC_STATE_OK,
        qc_state_sample_r(&s, 0.375f, 5000));
    TEST_ASSERT_EQUAL_INT(QC_STATE_OK,
        qc_state_sample_s(&s, 1, 5000));
    TEST_ASSERT_EQUAL_INT(QC_STATE_OK,
        qc_state_sample_c(&s, 0.625f, 5000));
    TEST_ASSERT_EQUAL_INT(QC_STATE_OK,
        qc_state_sample_m(&s, 300000u, 5000));
    TEST_ASSERT_EQUAL_INT(QC_STATE_OK,
        qc_state_sample_l(&s, -83, 12, 5000));
    TEST_ASSERT_EQUAL_INT(QC_STATE_OK,
        qc_state_sample_q(&s, 1.5f, 77, 5000));
    TEST_ASSERT_EQUAL_INT(QC_STATE_OK,
        qc_state_snapshot_risk(&s, risk, 5000));
}

static void test_vec_roundtrip(void) {
    qc_state back;
    uint64_t ts = 0;

    craft_state();
    TEST_ASSERT_EQUAL_INT(QC_TRACE_OK,
        qc_trace_vec_encode(&s, 6000, rec, sizeof(rec)));
    memset(&back, 0, sizeof(back));
    TEST_ASSERT_EQUAL_INT(QC_TRACE_OK,
        qc_trace_vec_decode(rec, QC_TRACE_VEC_LEN, &back, &ts));
    TEST_ASSERT_EQUAL_UINT64(6000, ts);
    TEST_ASSERT_EQUAL_FLOAT(812.5f, back.b_j);
    TEST_ASSERT_EQUAL_UINT8(77, back.b_soc);
    TEST_ASSERT_EQUAL_FLOAT(0.375f, back.r);
    TEST_ASSERT_EQUAL_UINT8(1, back.s);
    TEST_ASSERT_EQUAL_FLOAT(0.625f, back.c);
    TEST_ASSERT_EQUAL_UINT(300000u, back.m);
    TEST_ASSERT_EQUAL_INT(-83, back.l_rssi);
    TEST_ASSERT_EQUAL_UINT(12, back.l_retries);
    TEST_ASSERT_EQUAL_FLOAT(1.5f, back.q);
    TEST_ASSERT_EQUAL_UINT(s.mask, back.mask);
    TEST_ASSERT_EQUAL_UINT64(6000, back.b_at);
    /* Short buffer refused. */
    TEST_ASSERT_EQUAL_INT(QC_TRACE_BAD_ARG,
        qc_trace_vec_encode(&s, 6000, rec, QC_TRACE_VEC_LEN - 1));
}

static void test_vec_versions(void) {
    qc_state back;
    static uint8_t big[64];

    craft_state();
    TEST_ASSERT_EQUAL_INT(QC_TRACE_OK,
        qc_trace_vec_encode(&s, 6000, rec, sizeof(rec)));
    /* Unknown major rejected. */
    memcpy(big, rec, QC_TRACE_VEC_LEN);
    big[0] = 2;
    TEST_ASSERT_EQUAL_INT(QC_TRACE_BAD_VERSION,
        qc_trace_vec_decode(big, QC_TRACE_VEC_LEN, &back, NULL));
    /* Higher minor, exact length: accepted. */
    memcpy(big, rec, QC_TRACE_VEC_LEN);
    big[1] = 1;
    TEST_ASSERT_EQUAL_INT(QC_TRACE_OK,
        qc_trace_vec_decode(big, QC_TRACE_VEC_LEN, &back, NULL));
    /* Higher minor + trailing: accepted, tail ignored. */
    big[QC_TRACE_VEC_LEN] = 0xAB;
    big[QC_TRACE_VEC_LEN + 1] = 0xCD;
    TEST_ASSERT_EQUAL_INT(QC_TRACE_OK,
        qc_trace_vec_decode(big, QC_TRACE_VEC_LEN + 2, &back, NULL));
    /* Same minor + trailing: malformed. */
    memcpy(big, rec, QC_TRACE_VEC_LEN);
    TEST_ASSERT_EQUAL_INT(QC_TRACE_MALFORMED,
        qc_trace_vec_decode(big, QC_TRACE_VEC_LEN + 1, &back, NULL));
    /* Short record: malformed. */
    TEST_ASSERT_EQUAL_INT(QC_TRACE_MALFORMED,
        qc_trace_vec_decode(rec, QC_TRACE_VEC_LEN - 1, &back, NULL));
    TEST_ASSERT_EQUAL_INT(QC_TRACE_BAD_ARG,
        qc_trace_vec_decode(NULL, 10, &back, NULL));
}

static void test_evt_roundtrip(void) {
    uint64_t ts, a, b;
    uint8_t type;
    int t;

    for (t = 0; t <= 3; t++) {
        TEST_ASSERT_EQUAL_INT(QC_TRACE_OK,
            qc_trace_evt_encode(7000 + (uint64_t)t, (uint8_t)t,
                                100 + (uint64_t)t, 200 + (uint64_t)t,
                                rec, sizeof(rec)));
        TEST_ASSERT_EQUAL_INT(QC_TRACE_OK,
            qc_trace_evt_decode(rec, QC_TRACE_EVT_LEN, &ts, &type,
                                &a, &b));
        TEST_ASSERT_EQUAL_UINT64(7000 + (uint64_t)t, ts);
        TEST_ASSERT_EQUAL_UINT8((uint8_t)t, type);
        TEST_ASSERT_EQUAL_UINT64(100 + (uint64_t)t, a);
        TEST_ASSERT_EQUAL_UINT64(200 + (uint64_t)t, b);
    }
    /* Encode refuses unknown types; decode tolerates (forward-compat). */
    TEST_ASSERT_EQUAL_INT(QC_TRACE_BAD_ARG,
        qc_trace_evt_encode(7000, 9, 0, 0, rec, sizeof(rec)));
    TEST_ASSERT_EQUAL_INT(QC_TRACE_OK,
        qc_trace_evt_encode(7000, 3, 1, 2, rec, sizeof(rec)));
    rec[10] = 9;
    TEST_ASSERT_EQUAL_INT(QC_TRACE_OK,
        qc_trace_evt_decode(rec, QC_TRACE_EVT_LEN, &ts, &type, &a,
                            &b));
    TEST_ASSERT_EQUAL_UINT8(9, type);
}

static void test_pol_roundtrip(void) {
    qc_state back;
    uint64_t ts = 0;
    uint32_t action = 0;
    float energy = 0.0f;

    craft_state();
    TEST_ASSERT_EQUAL_INT(QC_TRACE_OK,
        qc_trace_pol_encode(&s, 8000, 0xDEADBEEFu, 12.25f, rec,
                            sizeof(rec)));
    memset(&back, 0, sizeof(back));
    TEST_ASSERT_EQUAL_INT(QC_TRACE_OK,
        qc_trace_pol_decode(rec, QC_TRACE_POL_LEN, &back, &ts,
                            &action, &energy));
    TEST_ASSERT_EQUAL_UINT64(8000, ts);
    TEST_ASSERT_EQUAL_UINT(0xDEADBEEFu, action);
    TEST_ASSERT_EQUAL_FLOAT(12.25f, energy);
    TEST_ASSERT_EQUAL_FLOAT(812.5f, back.b_j);
    TEST_ASSERT_EQUAL_UINT(300000u, back.m);
    /* Truncated tail refused. */
    TEST_ASSERT_EQUAL_INT(QC_TRACE_MALFORMED,
        qc_trace_pol_decode(rec, QC_TRACE_POL_LEN - 1, &back, &ts,
                            &action, &energy));
}

static void test_guards(void) {
    qc_state back;

    craft_state();
    TEST_ASSERT_EQUAL_INT(QC_TRACE_BAD_ARG,
        qc_trace_vec_encode(NULL, 0, rec, sizeof(rec)));
    TEST_ASSERT_EQUAL_INT(QC_TRACE_BAD_ARG,
        qc_trace_vec_encode(&s, 0, NULL, sizeof(rec)));
    TEST_ASSERT_EQUAL_INT(QC_TRACE_BAD_ARG,
        qc_trace_pol_encode(&s, 0, 0, 0.0f, NULL, sizeof(rec)));
    TEST_ASSERT_EQUAL_INT(QC_TRACE_BAD_ARG,
        qc_trace_evt_decode(NULL, 10, NULL, NULL, NULL, NULL));
    TEST_ASSERT_EQUAL_INT(QC_TRACE_BAD_ARG,
        qc_trace_pol_decode(NULL, 10, &back, NULL, NULL, NULL));
}

void setUp(void) {}
void tearDown(void) {}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_vec_roundtrip);
    RUN_TEST(test_vec_versions);
    RUN_TEST(test_evt_roundtrip);
    RUN_TEST(test_pol_roundtrip);
    RUN_TEST(test_guards);
    return UNITY_END();
}
