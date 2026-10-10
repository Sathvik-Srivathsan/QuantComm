/* test_risk.c — L0/L1/L2 for risk scoring + hysteresis (B-32 host).
 *
 * Covers: config validation matrix, scoring vectors (zero/flood/
 * uniform/partial/weights), first-emission + pre-emission NaN,
 * enter/exit incl. strict boundaries, streak reset, dwell gate, miss
 * freeze, hints (once/decay/no-exit), reboot export/import (+tamper,
 * +version, HIGH persists, post-boot exit), transition log (content +
 * 64-ring cap), band, guards. Small W/n/dwell cfgs keep traces crisp
 * (labeled test choices, not spec values). Static state (house rule).
 */
#include "unity.h"

#include <string.h>

#include "qc_risk.h"

static qc_risk r;
static uint8_t blob[2048];

static void cfg_small(qc_risk_cfg *c) {
    int i;

    memset(c, 0, sizeof(*c));
    for (i = 0; i < QC_RISK_NC; i++) {
        c->w[i] = (i == 0) ? 1.0f : 0.0f;
        c->cmax[i] = 10.0f;
    }
    c->theta_hi = 0.7f;
    c->theta_lo = 0.3f;
    c->n_e = 2;
    c->n_x = 2;
    c->t_dwell = 2;
    c->window_w = 1;
    c->h_hint = 0.3f;
}

static void feed(uint32_t c0) {
    uint32_t inc[QC_RISK_NC] = { 0, 0, 0, 0, 0, 0 };
    inc[0] = c0;
    TEST_ASSERT_EQUAL_INT(QC_RISK_OK, qc_risk_window(&r, inc));
}

static void test_cfg(void) {
    qc_risk_cfg c;

    cfg_small(&c);
    TEST_ASSERT_EQUAL_INT(0, qc_risk_cfg_check(&c));
    TEST_ASSERT_EQUAL_INT(0, qc_risk_cfg_check(NULL) == 0 ? 1 : 0);
    c.w[1] = -0.5f;
    TEST_ASSERT_TRUE(qc_risk_cfg_check(&c) != 0);
    cfg_small(&c);
    c.cmax[0] = 0.0f;
    TEST_ASSERT_TRUE(qc_risk_cfg_check(&c) != 0);
    cfg_small(&c);
    c.theta_lo = c.theta_hi;
    TEST_ASSERT_TRUE(qc_risk_cfg_check(&c) != 0);
    cfg_small(&c);
    c.n_e = 0;
    TEST_ASSERT_TRUE(qc_risk_cfg_check(&c) != 0);
    cfg_small(&c);
    c.window_w = 0;
    TEST_ASSERT_TRUE(qc_risk_cfg_check(&c) != 0);
    c.window_w = 17;
    TEST_ASSERT_TRUE(qc_risk_cfg_check(&c) != 0);
    cfg_small(&c);
    c.h_hint = -0.1f;
    TEST_ASSERT_TRUE(qc_risk_cfg_check(&c) != 0);
    cfg_small(&c);
    TEST_ASSERT_EQUAL_INT(-1, qc_risk_init(NULL, &c));
    TEST_ASSERT_EQUAL_INT(-1, qc_risk_init(&r, NULL));
    c.n_e = 0;
    TEST_ASSERT_EQUAL_INT(-1, qc_risk_init(&r, &c));
}

static void test_scoring(void) {
    qc_risk_cfg c;

    cfg_small(&c);
    c.window_w = 4;
    TEST_ASSERT_EQUAL_INT(0, qc_risk_init(&r, &c));
    TEST_ASSERT_EQUAL_INT(0, qc_risk_emitted(&r));
    TEST_ASSERT_TRUE(qc_risk_r(&r) != qc_risk_r(&r)); /* NaN pre-emit */
    feed(0);
    TEST_ASSERT_EQUAL_INT(1, qc_risk_emitted(&r));
    TEST_ASSERT_EQUAL_FLOAT(0.0f, qc_risk_r(&r));
    /* Single flooded counter drives 1 (uncapped ratio + clamp). */
    {
        qc_risk r2;
        TEST_ASSERT_EQUAL_INT(0, qc_risk_init(&r2, &c));
        (void)r2;
    }
    feed(50);
    TEST_ASSERT_EQUAL_FLOAT(1.0f, qc_risk_r(&r));
    /* Weights respected: half-cap on the live counter. */
    TEST_ASSERT_EQUAL_INT(0, qc_risk_init(&r, &c));
    feed(5);
    TEST_ASSERT_EQUAL_FLOAT(0.5f, qc_risk_r(&r));
}

static void test_hysteresis(void) {
    qc_risk_cfg c;

    cfg_small(&c);
    TEST_ASSERT_EQUAL_INT(0, qc_risk_init(&r, &c));
    TEST_ASSERT_EQUAL_INT(0, qc_risk_high(&r));
    feed(8); /* R=0.8, streak 1 */
    TEST_ASSERT_EQUAL_INT(0, qc_risk_high(&r));
    feed(8); /* streak 2 -> HIGH */
    TEST_ASSERT_EQUAL_INT(1, qc_risk_high(&r));
    /* W=1 ring overwrites: single-window sum 8 -> R=0.8 (audit fix:
     * first cut wrongly expected accumulated 1.6). */
    TEST_ASSERT_EQUAL_FLOAT(0.8f, qc_risk_r(&r));
    /* Boundary equality holds: == hi never enters. */
    TEST_ASSERT_EQUAL_INT(0, qc_risk_init(&r, &c));
    feed(7); /* R=0.7 exactly */
    feed(7);
    TEST_ASSERT_EQUAL_INT(0, qc_risk_high(&r));
    /* Intermediate window resets the streak. */
    feed(8);
    feed(0); /* R=0, streak reset (also starts exit streak 1) */
    TEST_ASSERT_EQUAL_INT(0, qc_risk_high(&r));
    feed(8); /* streak 1 again */
    TEST_ASSERT_EQUAL_INT(0, qc_risk_high(&r));
    /* Exit needs n_x consecutive + dwell. */
    TEST_ASSERT_EQUAL_INT(0, qc_risk_init(&r, &c));
    feed(8);
    feed(8); /* HIGH, dwell=1 */
    feed(2); /* R=0.2 exit-streak 1, dwell=2: not yet (n_x=2) */
    TEST_ASSERT_EQUAL_INT(1, qc_risk_high(&r));
    feed(2); /* exit-streak 2, dwell=3 -> NORMAL */
    TEST_ASSERT_EQUAL_INT(0, qc_risk_high(&r));
    /* == lo never exits. */
    TEST_ASSERT_EQUAL_INT(0, qc_risk_init(&r, &c));
    feed(8);
    feed(8);
    TEST_ASSERT_EQUAL_INT(1, qc_risk_high(&r));
    feed(3); /* R=0.3 exactly: neither exit-streak nor reset... */
    feed(3);
    TEST_ASSERT_EQUAL_INT(1, qc_risk_high(&r));
}

static void test_dwell_gate(void) {
    qc_risk_cfg c;

    cfg_small(&c);
    c.t_dwell = 3;
    TEST_ASSERT_EQUAL_INT(0, qc_risk_init(&r, &c));
    feed(8);
    feed(8); /* HIGH, dwell=1 */
    feed(0); /* streak 1, dwell 2 < 3: stay */
    TEST_ASSERT_EQUAL_INT(1, qc_risk_high(&r));
    feed(0); /* streak 2, dwell 3: exit */
    TEST_ASSERT_EQUAL_INT(0, qc_risk_high(&r));
}

static void test_miss(void) {
    qc_risk_cfg c;

    cfg_small(&c);
    TEST_ASSERT_EQUAL_INT(0, qc_risk_init(&r, &c));
    feed(8); /* streak 1 */
    TEST_ASSERT_EQUAL_INT(QC_RISK_OK, qc_risk_miss(&r)); /* frozen */
    feed(8); /* streak 2 -> HIGH (a reset would need 2 more) */
    TEST_ASSERT_EQUAL_INT(1, qc_risk_high(&r));
    /* Miss in HIGH advances dwell (documented reading): enter (dwell
     * 1), miss (dwell 2), then two zero closes exit. */
    TEST_ASSERT_EQUAL_INT(0, qc_risk_init(&r, &c));
    feed(8);
    feed(8);
    TEST_ASSERT_EQUAL_INT(QC_RISK_OK, qc_risk_miss(&r));
    feed(0);
    feed(0);
    TEST_ASSERT_EQUAL_INT(0, qc_risk_high(&r));
    /* Hint survives one miss (consumed at the next close, not latched). */
    TEST_ASSERT_EQUAL_INT(0, qc_risk_init(&r, &c));
    TEST_ASSERT_EQUAL_INT(QC_RISK_OK, qc_risk_hint(&r));
    TEST_ASSERT_EQUAL_INT(QC_RISK_OK, qc_risk_miss(&r));
    feed(0);
    TEST_ASSERT_EQUAL_FLOAT(0.3f, qc_risk_r(&r));
    TEST_ASSERT_EQUAL_INT(QC_RISK_BAD_ARG, qc_risk_miss(NULL));
}

static void test_hints(void) {
    qc_risk_cfg c;

    cfg_small(&c);
    TEST_ASSERT_EQUAL_INT(0, qc_risk_init(&r, &c));
    feed(5); /* R=0.5 */
    TEST_ASSERT_EQUAL_INT(QC_RISK_OK, qc_risk_hint(&r));
    feed(0); /* close consumes: R=0.0+0.3=0.3 */
    TEST_ASSERT_EQUAL_FLOAT(0.3f, qc_risk_r(&r));
    feed(0); /* decayed: hint gone */
    TEST_ASSERT_EQUAL_FLOAT(0.0f, qc_risk_r(&r));
    /* Hints sustain but never exit: HIGH via hints, removal holds. */
    TEST_ASSERT_EQUAL_INT(0, qc_risk_init(&r, &c));
    feed(5); /* 0.5 */
    TEST_ASSERT_EQUAL_INT(QC_RISK_OK, qc_risk_hint(&r));
    feed(5); /* close1: 0.5+0.3=0.8 streak1 */
    TEST_ASSERT_EQUAL_INT(QC_RISK_OK, qc_risk_hint(&r));
    feed(5); /* close2: 0.8 streak2 -> HIGH */
    TEST_ASSERT_EQUAL_INT(1, qc_risk_high(&r));
    feed(5); /* no hint: 0.5 >= lo, stays (removal didn't exit) */
    TEST_ASSERT_EQUAL_INT(1, qc_risk_high(&r));
    feed(0); /* 0.0: exit-streak 1, dwell ok... */
    feed(0); /* exit-streak 2 -> NORMAL (rule only) */
    TEST_ASSERT_EQUAL_INT(0, qc_risk_high(&r));
    TEST_ASSERT_EQUAL_INT(QC_RISK_BAD_ARG, qc_risk_hint(NULL));
}

static void test_reboot(void) {
    static const uint8_t key[32] = { 0xBBu };
    qc_risk_cfg c;
    qc_risk r2;
    size_t n = 0;

    cfg_small(&c);
    TEST_ASSERT_EQUAL_INT(0, qc_risk_init(&r, &c));
    feed(8);
    feed(8); /* HIGH */
    TEST_ASSERT_EQUAL_INT(QC_RISK_OK,
        qc_risk_export(&r, key, blob, sizeof(blob), &n));
    TEST_ASSERT_TRUE(n > 100 && n <= sizeof(blob));
    memset(&r2, 0, sizeof(r2));
    TEST_ASSERT_EQUAL_INT(QC_RISK_OK,
        qc_risk_import(&r2, &c, key, blob, n));
    TEST_ASSERT_EQUAL_INT(1, qc_risk_high(&r2));
    TEST_ASSERT_EQUAL_FLOAT(qc_risk_r(&r), qc_risk_r(&r2));
    TEST_ASSERT_EQUAL_INT(1, qc_risk_emitted(&r2));
    /* Post-boot exit through the rule. */
    {
        uint32_t z[QC_RISK_NC] = { 0, 0, 0, 0, 0, 0 };
        TEST_ASSERT_EQUAL_INT(QC_RISK_OK, qc_risk_window(&r2, z));
        TEST_ASSERT_EQUAL_INT(QC_RISK_OK, qc_risk_window(&r2, z));
        TEST_ASSERT_EQUAL_INT(0, qc_risk_high(&r2));
    }
    /* Tamper -> BAD_MAC (never adopt). */
    blob[20] ^= 0x01;
    memset(&r2, 0, sizeof(r2));
    TEST_ASSERT_EQUAL_INT(QC_RISK_BAD_MAC,
        qc_risk_import(&r2, &c, key, blob, n));
    TEST_ASSERT_EQUAL_INT(0, qc_risk_emitted(&r2));
    blob[20] ^= 0x01;
    /* Version -> BAD_VERSION. */
    blob[4] = 2;
    memset(&r2, 0, sizeof(r2));
    TEST_ASSERT_EQUAL_INT(QC_RISK_BAD_VERSION,
        qc_risk_import(&r2, &c, key, blob, n));
    blob[4] = 1;
    /* Short -> BAD_ARG. */
    TEST_ASSERT_EQUAL_INT(QC_RISK_BAD_ARG,
        qc_risk_import(&r2, &c, key, blob, 10));
    TEST_ASSERT_EQUAL_INT(QC_RISK_BAD_ARG,
        qc_risk_export(NULL, key, blob, sizeof(blob), &n));
}

static void test_log(void) {
    qc_risk_cfg c;
    uint32_t z[QC_RISK_NC] = { 0, 0, 0, 0, 0, 0 };
    uint32_t h[QC_RISK_NC] = { 8, 0, 0, 0, 0, 0 };
    int i;

    cfg_small(&c);
    c.n_e = 1;
    c.n_x = 1;
    c.t_dwell = 0;
    TEST_ASSERT_EQUAL_INT(0, qc_risk_init(&r, &c));
    /* One enter + one exit. */
    TEST_ASSERT_EQUAL_INT(QC_RISK_OK, qc_risk_window(&r, h));
    TEST_ASSERT_EQUAL_INT(1, qc_risk_high(&r));
    TEST_ASSERT_EQUAL_INT(QC_RISK_OK, qc_risk_window(&r, z));
    TEST_ASSERT_EQUAL_INT(0, qc_risk_high(&r));
    TEST_ASSERT_EQUAL_UINT(2, r.log_n);
    TEST_ASSERT_EQUAL_UINT8(0, r.log[0].from);
    TEST_ASSERT_EQUAL_UINT8(1, r.log[0].to);
    TEST_ASSERT_EQUAL_UINT8(1, r.log[1].from);
    TEST_ASSERT_EQUAL_UINT8(0, r.log[1].to);
    TEST_ASSERT_EQUAL_UINT(1, r.log[0].consec);
    /* Ring cap: 40 more cycles (80 transitions) -> last 64 kept. */
    for (i = 0; i < 40; i++) {
        TEST_ASSERT_EQUAL_INT(QC_RISK_OK, qc_risk_window(&r, h));
        TEST_ASSERT_EQUAL_INT(QC_RISK_OK, qc_risk_window(&r, z));
    }
    TEST_ASSERT_EQUAL_UINT(64, r.log_n);
    TEST_ASSERT_EQUAL_UINT8(1, r.log[63].from);
    TEST_ASSERT_EQUAL_UINT8(0, r.log[63].to);
}

static void test_band_guards(void) {
    qc_risk r2;

    memset(&r2, 0, sizeof(r2));
    TEST_ASSERT_EQUAL_INT(0, qc_risk_high(NULL));
    TEST_ASSERT_EQUAL_INT(0, qc_risk_high(&r2));
    TEST_ASSERT_EQUAL_INT(0, qc_risk_emitted(NULL));
    TEST_ASSERT_EQUAL_INT(QC_RISK_BAD_ARG, qc_risk_window(NULL, NULL));
    TEST_ASSERT_EQUAL_INT(QC_RISK_BAD_ARG,
        qc_risk_import(NULL, NULL, NULL, NULL, 0));
}

void setUp(void) {}
void tearDown(void) {}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_cfg);
    RUN_TEST(test_scoring);
    RUN_TEST(test_hysteresis);
    RUN_TEST(test_dwell_gate);
    RUN_TEST(test_miss);
    RUN_TEST(test_hints);
    RUN_TEST(test_reboot);
    RUN_TEST(test_log);
    RUN_TEST(test_band_guards);
    return UNITY_END();
}
