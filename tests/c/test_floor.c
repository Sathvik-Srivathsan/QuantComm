/* test_floor.c — L0/L1/L2 for floor engine + solver (B-31 host core).
 *
 * Covers: cfg defaults, basis selection (M-hold wins, flagged->C2/high,
 * clean measured/stepped, defensive S, bad threshold), C1 (floors,
 * missing-row closed, malformed row, bad profile), C2/C3 boundaries
 * (incl. none carve-out, sentinel, zero), C4/C5 boundaries + overflow
 * cap + value reporting, solver-vs-brute-force agreement on a small
 * lattice (288 actions, identical order), empty-Af, Tr prune, Nb
 * filter, guards. Static state (house rule).
 */
#include "unity.h"

#include <string.h>

#include "qc_floor.h"
#include "qc_state.h"

static qc_state s;
static qc_floor_table tab;
static qc_floor_cfg cfg;
static qc_res_tables rt;

static void setup_tab(void) {
    tab.min_level[0] = 1;
    tab.min_level[1] = 2;
    tab.min_level[2] = 3;
    tab.has[0] = tab.has[1] = tab.has[2] = 1;
    qc_floor_cfg_default(&cfg);
    memset(&rt, 0, sizeof(rt));
}

static void sample_clean(uint8_t cls, float risk, uint64_t now) {
    TEST_ASSERT_EQUAL_INT(QC_STATE_OK,
        qc_state_sample_b(&s, 900.0f, 80, now));
    TEST_ASSERT_EQUAL_INT(QC_STATE_OK,
        qc_state_sample_r(&s, risk, now));
    if (cls == 2) {
        TEST_ASSERT_EQUAL_INT(QC_STATE_C2,
            qc_state_sample_s(&s, cls, now));
        qc_state_take_s_immediate(&s);
    } else {
        TEST_ASSERT_EQUAL_INT(QC_STATE_OK,
            qc_state_sample_s(&s, cls, now));
    }
    TEST_ASSERT_EQUAL_INT(QC_STATE_OK,
        qc_state_sample_c(&s, 0.5f, now));
    TEST_ASSERT_EQUAL_INT(QC_STATE_OK,
        qc_state_sample_m(&s, 500000u, now));
    TEST_ASSERT_EQUAL_INT(QC_STATE_OK,
        qc_state_sample_l(&s, -70, 2, now));
    TEST_ASSERT_EQUAL_INT(QC_STATE_OK,
        qc_state_sample_q(&s, 1.0f, 10, now));
}

static void test_cfg_default(void) {
    qc_floor_cfg_default(&cfg);
    TEST_ASSERT_EQUAL_UINT(3600u, cfg.lmax_s[0]);
    TEST_ASSERT_EQUAL_UINT(600u, cfg.lmax_s[1]);
    TEST_ASSERT_EQUAL_UINT(60u, cfg.lmax_s[2]);
    TEST_ASSERT_EQUAL_UINT8(8, cfg.nb_max);
    qc_floor_cfg_default(NULL);
}

static void test_select(void) {
    qc_floor_basis b;

    /* M-component flag wins over everything. Poked directly: the
     * contract reads mask bits (samplers set them the same way). */
    qc_state_init(&s);
    sample_clean(0, 0.1f, 1000);
    s.mask |= (uint16_t)(2u << (2 * QC_STATE_COMP_M));
    TEST_ASSERT_EQUAL_INT(QC_FLOOR_HOLD,
        qc_floor_select(&s, 0, &b));
    /* Other-flagged pair -> C2/high regardless of measured values. */
    qc_state_init(&s);
    sample_clean(0, 0.1f, 1000);
    s.mask |= (uint16_t)(1u << (2 * QC_STATE_COMP_C));
    TEST_ASSERT_EQUAL_INT(QC_FLOOR_OK,
        qc_floor_select(&s, 0, &b));
    TEST_ASSERT_EQUAL_UINT8(2, b.s_eff);
    TEST_ASSERT_EQUAL_UINT8(1, b.r_high);
    /* Clean + machine NORMAL: measured basis, no stepping. */
    qc_state_init(&s);
    sample_clean(1, 0.2f, 1000);
    TEST_ASSERT_EQUAL_INT(QC_FLOOR_OK,
        qc_floor_select(&s, 0, &b));
    TEST_ASSERT_EQUAL_UINT8(1, b.s_eff);
    TEST_ASSERT_EQUAL_UINT8(0, b.r_high);
    /* Clean + machine HIGH: step up (C1->C2, C2 stays). */
    TEST_ASSERT_EQUAL_INT(QC_FLOOR_OK,
        qc_floor_select(&s, 1, &b));
    TEST_ASSERT_EQUAL_UINT8(2, b.s_eff);
    TEST_ASSERT_EQUAL_UINT8(1, b.r_high);
    qc_state_init(&s);
    sample_clean(2, 0.9f, 1000);
    TEST_ASSERT_EQUAL_INT(QC_FLOOR_OK,
        qc_floor_select(&s, 1, &b));
    TEST_ASSERT_EQUAL_UINT8(2, b.s_eff);
    /* Audit case: high R but machine still NORMAL (pre-enter streak)
     * must NOT step — band rules, not a re-derived threshold. */
    qc_state_init(&s);
    sample_clean(0, 0.8f, 1000);
    TEST_ASSERT_EQUAL_INT(QC_FLOOR_OK,
        qc_floor_select(&s, 0, &b));
    TEST_ASSERT_EQUAL_UINT8(0, b.s_eff);
    TEST_ASSERT_EQUAL_UINT8(0, b.r_high);
    /* Defensive S out of range -> C2/high. */
    qc_state_init(&s);
    sample_clean(0, 0.1f, 1000);
    s.s = 9;
    TEST_ASSERT_EQUAL_INT(QC_FLOOR_OK,
        qc_floor_select(&s, 0, &b));
    TEST_ASSERT_EQUAL_UINT8(2, b.s_eff);
    TEST_ASSERT_EQUAL_INT(QC_FLOOR_BAD_ARG,
        qc_floor_select(NULL, 0, &b));
    TEST_ASSERT_EQUAL_INT(QC_FLOOR_BAD_ARG,
        qc_floor_select(&s, 0, NULL));
}

static void test_c1(void) {
    setup_tab();
    TEST_ASSERT_TRUE(qc_floor_c1(1, &tab, 0));
    TEST_ASSERT_TRUE(!qc_floor_c1(1, &tab, 1)); /* floor 2 */
    TEST_ASSERT_TRUE(qc_floor_c1(2, &tab, 1));
    TEST_ASSERT_TRUE(qc_floor_c1(3, &tab, 2));
    TEST_ASSERT_TRUE(!qc_floor_c1(2, &tab, 2)); /* floor 3 */
    tab.has[1] = 0;
    TEST_ASSERT_TRUE(!qc_floor_c1(3, &tab, 1)); /* missing closed */
    tab.has[1] = 1;
    tab.min_level[1] = 0;
    TEST_ASSERT_TRUE(!qc_floor_c1(3, &tab, 1)); /* malformed closed */
    tab.min_level[1] = 2;
    TEST_ASSERT_TRUE(!qc_floor_c1(0, &tab, 0));
    TEST_ASSERT_TRUE(!qc_floor_c1(4, &tab, 0));
    TEST_ASSERT_TRUE(!qc_floor_c1(1, &tab, 3));
    TEST_ASSERT_TRUE(!qc_floor_c1(1, NULL, 0));
}

static void test_c2(void) {
    TEST_ASSERT_TRUE(qc_floor_c2(600, 2));
    TEST_ASSERT_TRUE(!qc_floor_c2(601, 2));
    TEST_ASSERT_TRUE(qc_floor_c2(3600, 1));
    TEST_ASSERT_TRUE(!qc_floor_c2(0, 0));
    TEST_ASSERT_TRUE(!qc_floor_c2(100, 3));
}

static void test_c3(void) {
    TEST_ASSERT_TRUE(qc_floor_c3(QC_TA_NONE, 0));
    TEST_ASSERT_TRUE(!qc_floor_c3(QC_TA_NONE, 1));
    TEST_ASSERT_TRUE(!qc_floor_c3(QC_TA_NONE, 2));
    TEST_ASSERT_TRUE(qc_floor_c3(600, 1));
    TEST_ASSERT_TRUE(!qc_floor_c3(3600, 1));
    TEST_ASSERT_TRUE(!qc_floor_c3(60, 2));
    TEST_ASSERT_TRUE(qc_floor_c3(QC_TA_EVENT, 2));
    TEST_ASSERT_TRUE(qc_floor_c3(QC_TA_MSG, 2));
    TEST_ASSERT_TRUE(!qc_floor_c3(0, 0));
    TEST_ASSERT_TRUE(!qc_floor_c3(-7, 1));
    TEST_ASSERT_TRUE(!qc_floor_c3(600, 3));
}

static void test_c4_c5(void) {
    qc_action a;
    uint32_t out = 0;

    memset(&rt, 0, sizeof(rt));
    rt.base_ram = 1000;
    rt.stack_ram[0] = 2000;
    rt.stack_ram[1] = 4000;
    rt.stack_ram[2] = 8000;
    rt.ram_per_byte = 2;
    rt.msg_bytes = 64;
    rt.lat_base_ms = 10;
    rt.lat_per_msg_ms = 5;
    qc_floor_cfg_default(&cfg);
    a.profile = 1;
    a.tpq_s = 3600;
    a.tr_s = 1800;
    a.ta_s = 600;
    a.nb = 4;
    /* ram = 1000+2000+2*64*4 = 3512. */
    TEST_ASSERT_TRUE(qc_floor_c4(&a, &rt, 3512, &out));
    TEST_ASSERT_EQUAL_UINT(3512u, out);
    TEST_ASSERT_TRUE(!qc_floor_c4(&a, &rt, 3511, NULL));
    /* lat = 10+5*4 = 30 ms <= 600000. */
    TEST_ASSERT_TRUE(qc_floor_c5(&a, &rt, &cfg, 1, &out));
    TEST_ASSERT_EQUAL_UINT(30u, out);
    /* Overflow saturates the report and fails closed. */
    rt.ram_per_byte = 0xFFFFFFFFu;
    TEST_ASSERT_TRUE(!qc_floor_c4(&a, &rt, 0xFFFFFFFFu, &out));
    TEST_ASSERT_EQUAL_UINT(0xFFFFFFFFu, out);
    rt.ram_per_byte = 2;
    TEST_ASSERT_TRUE(!qc_floor_c4(NULL, &rt, 999999, NULL));
    a.profile = 9;
    TEST_ASSERT_TRUE(!qc_floor_c4(&a, &rt, 999999999u, NULL));
    TEST_ASSERT_TRUE(!qc_floor_c5(&a, &rt, &cfg, 9, NULL));
    TEST_ASSERT_TRUE(!qc_floor_c5(NULL, &rt, &cfg, 1, NULL));
}

/* Collector for solver agreement. */
#define MAX_GOT 360
static qc_action got[MAX_GOT];
static size_t n_got;

static void collect_cb(const qc_action *a, void *ctx) {
    (void)ctx;
    if (n_got < MAX_GOT) {
        got[n_got++] = *a;
    }
}

static int action_eq(const qc_action *x, const qc_action *y) {
    return x->profile == y->profile && x->tpq_s == y->tpq_s &&
           x->tr_s == y->tr_s && x->ta_s == y->ta_s && x->nb == y->nb;
}

static void test_solver_agreement(void) {
    /* Independent brute force over the documented lattice, calling the
     * PUBLIC predicates (catches generation gaps, not shared typos —
     * documented limitation). s_eff=C1, all admitted, generous tables:
     * 3 prof x {3600,1800,900} x {t,t/2} x {600,60,EV,MSG} x {1,2,4,8}
     * = 192 (NONE refused by C3/C1; SL1 refused by the C1 floor-2
     * row — the agreement check exercises the C1 gate, not just the
     * lattice walk). */
    static const uint8_t admitted[3] = { 1, 1, 1 };
    static const int32_t tas[4] = { 600, 60, QC_TA_EVENT, QC_TA_MSG };
    static const uint8_t nbs[4] = { 1, 2, 4, 8 };
    static qc_action want[MAX_GOT];
    size_t n_want = 0;
    uint32_t tpq;
    int pi, ti, ri, ai, ni;
    size_t n;

    setup_tab();
    rt.base_ram = 0;
    rt.stack_ram[0] = rt.stack_ram[1] = rt.stack_ram[2] = 0;
    rt.ram_per_byte = 1;
    rt.msg_bytes = 64;
    rt.lat_base_ms = 0;
    rt.lat_per_msg_ms = 1;
    cfg.nb_max = 8;
    for (pi = 0; pi < 3; pi++) {
        for (ti = 0; ti < 3; ti++) {
            uint32_t trs[2];
            tpq = (ti == 0) ? 3600u : (ti == 1) ? 1800u : 900u;
            trs[0] = tpq;
            trs[1] = tpq / 2;
            for (ri = 0; ri < 2; ri++) {
                for (ai = 0; ai < 4; ai++) {
                    for (ni = 0; ni < 4; ni++) {
                        qc_action a;
                        a.profile = (uint8_t)(pi + 1);
                        a.tpq_s = tpq;
                        a.tr_s = trs[ri];
                        a.ta_s = tas[ai];
                        a.nb = nbs[ni];
                        if (!qc_floor_c1(a.profile, &tab, 1)) {
                            continue;
                        }
                        if (!qc_floor_c2(a.tpq_s, 1)) {
                            continue;
                        }
                        if (!qc_floor_c3(a.ta_s, 1)) {
                            continue;
                        }
                        if (!qc_floor_c4(&a, &rt, 0xFFFFFFFFu, NULL) ||
                            !qc_floor_c5(&a, &rt, &cfg, 1, NULL)) {
                            continue;
                        }
                        want[n_want++] = a;
                    }
                }
            }
        }
    }
    TEST_ASSERT_EQUAL_UINT(192u, n_want);
    n_got = 0;
    n = qc_floor_feasible(admitted, &tab, 1, &rt, &cfg, 0xFFFFFFFFu,
                          collect_cb, NULL);
    TEST_ASSERT_EQUAL_UINT(n_want, n);
    TEST_ASSERT_EQUAL_UINT(n_want, n_got);
    for (size_t k = 0; k < n_want; k++) {
        TEST_ASSERT_TRUE_MESSAGE(action_eq(&want[k], &got[k]),
                                 "enumeration diverges");
    }
    /* NOTE (audit): no sortedness assert — enumeration order follows
     * ai-index (600,60,EVENT,MSG), not numeric ta order, by design.
     * Element-wise equality above already proves the documented
     * deterministic nested order. */
    /* Empty set (nothing admitted / no memory) -> 0 for B-26.4. */
    {
        static const uint8_t none[3] = { 0, 0, 0 };
        n_got = 0;
        TEST_ASSERT_EQUAL_UINT(
            0, qc_floor_feasible(none, &tab, 1, &rt, &cfg, 0xFFFFFFFFu,
                                 collect_cb, NULL));
        n_got = 0;
        rt.base_ram = 0xFFFFFFFFu;
        TEST_ASSERT_EQUAL_UINT(
            0, qc_floor_feasible(admitted, &tab, 1, &rt, &cfg, 0,
                                 collect_cb, NULL));
        rt.base_ram = 0;
    }
    /* Nb filter + Tr prune hold over the delivered set. */
    {
        size_t k;
        cfg.nb_max = 2;
        n_got = 0;
        n = qc_floor_feasible(admitted, &tab, 1, &rt, &cfg,
                              0xFFFFFFFFu, collect_cb, NULL);
        TEST_ASSERT_TRUE(n > 0 && n < n_want);
        for (k = 0; k < n_got; k++) {
            TEST_ASSERT_TRUE(got[k].nb <= 2);
            TEST_ASSERT_TRUE(got[k].tr_s <= got[k].tpq_s);
            TEST_ASSERT_TRUE(got[k].nb == 1 || got[k].nb == 2);
        }
        cfg.nb_max = 8;
    }
    /* Invalid config yields 0 (fail-secure routing). */
    cfg.nb_max = 0;
    TEST_ASSERT_EQUAL_UINT(
        0, qc_floor_feasible(admitted, &tab, 1, &rt, &cfg, 0xFFFFFFFFu,
                             collect_cb, NULL));
    cfg.nb_max = 8;
    TEST_ASSERT_EQUAL_UINT(
        0, qc_floor_feasible(NULL, &tab, 1, &rt, &cfg, 0xFFFFFFFFu,
                             collect_cb, NULL));
}

static void test_guards(void) {
    qc_floor_basis b;
    qc_action a;

    memset(&a, 0, sizeof(a));
    TEST_ASSERT_EQUAL_INT(QC_FLOOR_BAD_ARG,
        qc_floor_select(NULL, 0.5f, &b));
    TEST_ASSERT_TRUE(!qc_floor_c1(1, NULL, 0));
    TEST_ASSERT_TRUE(!qc_floor_c4(NULL, &rt, 1, NULL));
    TEST_ASSERT_TRUE(!qc_floor_c5(&a, NULL, &cfg, 0, NULL));
    TEST_ASSERT_EQUAL_UINT(
        0, qc_floor_feasible(NULL, NULL, 0, NULL, NULL, 0, NULL, NULL));
}

void setUp(void) {}
void tearDown(void) {}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_cfg_default);
    RUN_TEST(test_select);
    RUN_TEST(test_c1);
    RUN_TEST(test_c2);
    RUN_TEST(test_c3);
    RUN_TEST(test_c4_c5);
    RUN_TEST(test_solver_agreement);
    RUN_TEST(test_guards);
    return UNITY_END();
}
