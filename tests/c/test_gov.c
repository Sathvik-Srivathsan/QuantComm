/* test_gov.c — L0/L1/L2 for the token-bucket governor (B-35 host).
 *
 * Covers: bucket equation vectors (debt/cap/refill/empty/init),
 * NaN-pin + negative-dt refusal, shed order walk to exhaustion
 * (C0->Nb->Ta + sentinel skip + bad floors), restore gating
 * (threshold/dwell/never-shed/regression) + reverse steps
 * (incl. sentinel adopt + int32-overflow guard), interface (tau read),
 * persist roundtrip (+tamper/version/config), guards. Float asserts
 * are exact recomputations (same TU flags => identical codegen) with
 * epsilon fallback nowhere needed — values chosen exactly
 * representable. Static state (house rule).
 */
#include "unity.h"

#include <string.h>

#include "qc_gov.h"

static qc_gov g;

static void init_gov(void) {
    TEST_ASSERT_EQUAL_INT(QC_GOV_OK,
        qc_gov_init(&g, 100.0f, 1.0, 0.5f, 3));
}

static void test_bucket(void) {
    init_gov();
    TEST_ASSERT_EQUAL_FLOAT(100.0f, qc_gov_tau(&g));
    /* tau = 100 + 1*60 - 10 = 150 -> cap 100. */
    TEST_ASSERT_EQUAL_INT(QC_GOV_OK, qc_gov_charge(&g, 10.0, 60.0));
    TEST_ASSERT_EQUAL_FLOAT(100.0f, qc_gov_tau(&g));
    /* Debt: 100 + 10 - 200 = -90 (empty: <= 0). */
    TEST_ASSERT_EQUAL_INT(QC_GOV_OK, qc_gov_charge(&g, 200.0, 10.0));
    TEST_ASSERT_EQUAL_FLOAT(-90.0f, qc_gov_tau(&g));
    TEST_ASSERT_TRUE(qc_gov_tau(&g) <= 0.0f);
    /* Debt bound: -90 + 10 - 200 = -280 -> clamp -100. */
    TEST_ASSERT_EQUAL_INT(QC_GOV_OK, qc_gov_charge(&g, 200.0, 10.0));
    TEST_ASSERT_EQUAL_FLOAT(-100.0f, qc_gov_tau(&g));
    /* Refill accrues (even from debt): -100 + 60 - 0 = -40. */
    TEST_ASSERT_EQUAL_INT(QC_GOV_OK, qc_gov_charge(&g, 0.0, 60.0));
    TEST_ASSERT_EQUAL_FLOAT(-40.0f, qc_gov_tau(&g));
    /* NaN drain pins to max debt (fail-safe, self-healing). */
    {
        uint32_t u = 0x7FC00000u;
        float nanf;
        memcpy(&nanf, &u, 4);
        TEST_ASSERT_EQUAL_INT(QC_GOV_OK, qc_gov_charge(&g, nanf, 10.0));
        TEST_ASSERT_EQUAL_FLOAT(-100.0f, qc_gov_tau(&g));
    }
    /* Negative dt refused (frozen). */
    TEST_ASSERT_EQUAL_INT(QC_GOV_BAD_ARG, qc_gov_charge(&g, 1.0, -1.0));
    TEST_ASSERT_EQUAL_FLOAT(-100.0f, qc_gov_tau(&g));
    TEST_ASSERT_EQUAL_INT(QC_GOV_BAD_ARG, qc_gov_charge(NULL, 1.0, 1.0));
    TEST_ASSERT_EQUAL_FLOAT(0.0f, qc_gov_tau(NULL));
    /* Bad init (NaN/zero max, negative rho). */
    {
        uint32_t u = 0x7FC00000u;
        float nanf;
        memcpy(&nanf, &u, 4);
        TEST_ASSERT_EQUAL_INT(QC_GOV_BAD_ARG,
            qc_gov_init(&g, nanf, 1.0, 0.5f, 3));
        TEST_ASSERT_EQUAL_INT(QC_GOV_BAD_ARG,
            qc_gov_init(&g, 0.0f, 1.0, 0.5f, 3));
        TEST_ASSERT_EQUAL_INT(QC_GOV_BAD_ARG,
            qc_gov_init(&g, 100.0f, -1.0, 0.5f, 3));
        TEST_ASSERT_EQUAL_INT(QC_GOV_BAD_ARG,
            qc_gov_init(NULL, 100.0f, 1.0, 0.5f, 3));
    }
}

static qc_shed_in shedin(double c0, uint8_t nb, int32_t ta) {
    qc_shed_in in;
    in.c0_rate = c0;
    in.action.profile = 1;
    in.action.tpq_s = 3600;
    in.action.tr_s = 1800;
    in.action.ta_s = ta;
    in.action.nb = nb;
    return in;
}

static qc_shed_floors shefloors(void) {
    qc_shed_floors f;
    f.c0_min = 1.0;
    f.ta_cap_s = 600;
    return f;
}

static void test_shed_walk(void) {
    qc_shed_in in;
    qc_shed_floors f;
    qc_shed_out out;
    qc_gov_counters c;

    init_gov();
    f = shefloors();
    /* C0 halvings to the floor. */
    in = shedin(8.0, 8, 60);
    TEST_ASSERT_EQUAL_INT(QC_GOV_OK, qc_gov_shed(&g, &in, &f, &out, 1));
    TEST_ASSERT_EQUAL_FLOAT(4.0f, (float)out.c0_directive);
    TEST_ASSERT_EQUAL_UINT8(0, out.exhausted);
    in = shedin(4.0, 8, 60);
    TEST_ASSERT_EQUAL_INT(QC_GOV_OK, qc_gov_shed(&g, &in, &f, &out, 2));
    TEST_ASSERT_EQUAL_FLOAT(2.0f, (float)out.c0_directive);
    in = shedin(2.0, 8, 60);
    TEST_ASSERT_EQUAL_INT(QC_GOV_OK, qc_gov_shed(&g, &in, &f, &out, 3));
    TEST_ASSERT_EQUAL_FLOAT(1.0f, (float)out.c0_directive);
    /* C0 floored -> Nb depth. */
    in = shedin(1.0, 8, 60);
    TEST_ASSERT_EQUAL_INT(QC_GOV_OK, qc_gov_shed(&g, &in, &f, &out, 4));
    TEST_ASSERT_EQUAL_UINT8(4, out.a_shed.nb);
    in = shedin(1.0, 4, 60);
    TEST_ASSERT_EQUAL_INT(QC_GOV_OK, qc_gov_shed(&g, &in, &f, &out, 5));
    TEST_ASSERT_EQUAL_UINT8(2, out.a_shed.nb);
    in = shedin(1.0, 2, 60);
    TEST_ASSERT_EQUAL_INT(QC_GOV_OK, qc_gov_shed(&g, &in, &f, &out, 6));
    TEST_ASSERT_EQUAL_UINT8(1, out.a_shed.nb);
    /* Nb floored -> Ta cadence doubling to the cap. */
    in = shedin(1.0, 1, 60);
    TEST_ASSERT_EQUAL_INT(QC_GOV_OK, qc_gov_shed(&g, &in, &f, &out, 7));
    TEST_ASSERT_EQUAL_INT(120, out.a_shed.ta_s);
    in = shedin(1.0, 1, 480);
    TEST_ASSERT_EQUAL_INT(QC_GOV_OK, qc_gov_shed(&g, &in, &f, &out, 8));
    TEST_ASSERT_EQUAL_INT(600, out.a_shed.ta_s); /* capped, not 960 */
    /* All floored -> unchanged + exhausted. */
    in = shedin(1.0, 1, 600);
    TEST_ASSERT_EQUAL_INT(QC_GOV_OK, qc_gov_shed(&g, &in, &f, &out, 9));
    TEST_ASSERT_EQUAL_UINT8(1, out.exhausted);
    TEST_ASSERT_EQUAL_FLOAT(1.0f, (float)out.c0_directive);
    qc_gov_counts(&g, &c);
    TEST_ASSERT_EQUAL_UINT(9, c.sheds); /* 9 walk calls above. */
    TEST_ASSERT_EQUAL_UINT(1, c.exhaustions);
    /* Sentinel Ta counts as floored (C2 evidence never shed). */
    in = shedin(1.0, 1, -2);
    TEST_ASSERT_EQUAL_INT(QC_GOV_OK, qc_gov_shed(&g, &in, &f, &out, 10));
    TEST_ASSERT_EQUAL_UINT8(1, out.exhausted);
    TEST_ASSERT_EQUAL_INT(-2, out.a_shed.ta_s);
    /* Bad floors / inputs. */
    f.c0_min = 0.0;
    TEST_ASSERT_EQUAL_INT(QC_GOV_BAD_ARG,
        qc_gov_shed(&g, &in, &f, &out, 11));
    f = shefloors();
    f.ta_cap_s = 0;
    TEST_ASSERT_EQUAL_INT(QC_GOV_BAD_ARG,
        qc_gov_shed(&g, &in, &f, &out, 11));
    f = shefloors();
    in.action.profile = 9;
    TEST_ASSERT_EQUAL_INT(QC_GOV_BAD_ARG,
        qc_gov_shed(&g, &in, &f, &out, 11));
    TEST_ASSERT_EQUAL_INT(QC_GOV_BAD_ARG,
        qc_gov_shed(NULL, &in, &f, &out, 11));
}

static void test_restore(void) {
    qc_shed_in cur, des, out;
    int leg;

    init_gov();
    /* Never shed: not eligible (harmless no-op domain). */
    TEST_ASSERT_EQUAL_INT(0, qc_gov_restore_ready(&g, 99999, 60));
    /* Shed once (stamps last_shed), drain tau below threshold. */
    {
        qc_shed_in in = shedin(8.0, 8, 60);
        qc_shed_floors f = shefloors();
        qc_shed_out o;
        TEST_ASSERT_EQUAL_INT(QC_GOV_OK,
            qc_gov_shed(&g, &in, &f, &o, 1000));
        TEST_ASSERT_EQUAL_INT(QC_GOV_OK, qc_gov_charge(&g, 1e9, 0.0));
    }
    TEST_ASSERT_EQUAL_INT(0, qc_gov_restore_ready(&g, 2000, 60));
    /* Refill to threshold but dwell short. */
    TEST_ASSERT_EQUAL_INT(QC_GOV_OK, qc_gov_charge(&g, 0.0, 60.0));
    /* tau = -100 + 60 = -40 < 50: still gated. */
    TEST_ASSERT_EQUAL_INT(0, qc_gov_restore_ready(&g, 2000, 60));
    TEST_ASSERT_EQUAL_INT(QC_GOV_OK, qc_gov_charge(&g, 0.0, 600.0));
    /* tau = -40 + 600 = 560 -> cap 100. dwell: (2060-1000)/60 = 17. */
    TEST_ASSERT_EQUAL_INT(1, qc_gov_restore_ready(&g, 2060, 60));
    /* Regression fails toward held-shed. */
    TEST_ASSERT_EQUAL_INT(0, qc_gov_restore_ready(&g, 500, 60));
    /* Reverse steps Ta -> Nb -> C0 -> done. */
    cur = shedin(1.0, 1, 240);
    des = shedin(8.0, 8, 60);
    leg = qc_gov_restore_step(&cur, &des, &out);
    TEST_ASSERT_EQUAL_INT(QC_RESTORE_TA, leg);
    TEST_ASSERT_EQUAL_INT(120, out.action.ta_s);
    cur = out;
    leg = qc_gov_restore_step(&cur, &des, &out);
    TEST_ASSERT_EQUAL_INT(QC_RESTORE_TA, leg);
    TEST_ASSERT_EQUAL_INT(60, out.action.ta_s);
    cur = out;
    leg = qc_gov_restore_step(&cur, &des, &out);
    TEST_ASSERT_EQUAL_INT(QC_RESTORE_NB, leg);
    TEST_ASSERT_EQUAL_UINT8(2, out.action.nb);
    cur = out;
    leg = qc_gov_restore_step(&cur, &des, &out);
    TEST_ASSERT_EQUAL_INT(QC_RESTORE_NB, leg);
    TEST_ASSERT_EQUAL_UINT8(4, out.action.nb);
    cur = out;
    leg = qc_gov_restore_step(&cur, &des, &out);
    TEST_ASSERT_EQUAL_INT(QC_RESTORE_NB, leg);
    TEST_ASSERT_EQUAL_UINT8(8, out.action.nb);
    cur = out;
    leg = qc_gov_restore_step(&cur, &des, &out);
    TEST_ASSERT_EQUAL_INT(QC_RESTORE_C0, leg);
    TEST_ASSERT_EQUAL_FLOAT(2.0f, (float)out.c0_rate);
    cur = out;
    leg = qc_gov_restore_step(&cur, &des, &out);
    TEST_ASSERT_EQUAL_INT(QC_RESTORE_C0, leg);
    TEST_ASSERT_EQUAL_FLOAT(4.0f, (float)out.c0_rate);
    cur = out;
    leg = qc_gov_restore_step(&cur, &des, &out);
    TEST_ASSERT_EQUAL_INT(QC_RESTORE_C0, leg);
    TEST_ASSERT_EQUAL_FLOAT(8.0f, (float)out.c0_rate);
    cur = out;
    TEST_ASSERT_EQUAL_INT(QC_RESTORE_DONE,
        qc_gov_restore_step(&cur, &des, &out));
    /* Sentinel adopt (discrete by nature). */
    cur = shedin(1.0, 1, -2);
    des = shedin(1.0, 1, 60);
    TEST_ASSERT_EQUAL_INT(QC_RESTORE_TA,
        qc_gov_restore_step(&cur, &des, &out));
    TEST_ASSERT_EQUAL_INT(60, out.action.ta_s);
    /* int32-overflow guard: 2^30 doubling jumps straight to desired. */
    cur = shedin(1.0, 1, 1073741824);
    des = shedin(1.0, 1, 2147483647);
    TEST_ASSERT_EQUAL_INT(QC_RESTORE_TA,
        qc_gov_restore_step(&cur, &des, &out));
    TEST_ASSERT_EQUAL_INT(2147483647, out.action.ta_s);
    TEST_ASSERT_EQUAL_INT(-1, qc_gov_restore_step(NULL, &des, &out));
}

static void test_persist(void) {
    static const uint8_t key[32] = { 0xCCu };
    static uint8_t blob[128];
    size_t n = 0;
    qc_gov g2;

    init_gov();
    TEST_ASSERT_EQUAL_INT(QC_GOV_OK, qc_gov_charge(&g, 50.0, 10.0));
    {
        qc_shed_in in = shedin(8.0, 8, 60);
        qc_shed_floors f = shefloors();
        qc_shed_out o;
        TEST_ASSERT_EQUAL_INT(QC_GOV_OK,
            qc_gov_shed(&g, &in, &f, &o, 3000));
    }
    TEST_ASSERT_EQUAL_INT(QC_GOV_OK,
        qc_gov_export(&g, key, blob, sizeof(blob), &n));
    TEST_ASSERT_EQUAL_UINT(67, n);
    memset(&g2, 0, sizeof(g2));
    TEST_ASSERT_EQUAL_INT(QC_GOV_OK,
        qc_gov_import(&g2, key, blob, n));
    TEST_ASSERT_EQUAL_FLOAT(qc_gov_tau(&g), qc_gov_tau(&g2));
    /* Charging continues from persisted tau. */
    TEST_ASSERT_EQUAL_INT(QC_GOV_OK, qc_gov_charge(&g2, 0.0, 10.0));
    TEST_ASSERT_EQUAL_INT(1, qc_gov_restore_ready(&g2, 99999, 60) >= 0);
    /* Tamper / version / short. */
    blob[20] ^= 0x01;
    memset(&g2, 0, sizeof(g2));
    TEST_ASSERT_EQUAL_INT(QC_GOV_BAD_MAC,
        qc_gov_import(&g2, key, blob, n));
    blob[20] ^= 0x01;
    blob[4] = 2;
    memset(&g2, 0, sizeof(g2));
    TEST_ASSERT_EQUAL_INT(QC_GOV_BAD_VERSION,
        qc_gov_import(&g2, key, blob, n));
    blob[4] = 1;
    TEST_ASSERT_EQUAL_INT(QC_GOV_BAD_ARG,
        qc_gov_import(&g2, key, blob, 10));
    TEST_ASSERT_EQUAL_INT(QC_GOV_BAD_ARG,
        qc_gov_export(NULL, key, blob, sizeof(blob), &n));
}

static void test_guards(void) {
    qc_shed_in in;
    qc_shed_floors f;
    qc_shed_out out;
    qc_gov_counters c;

    init_gov();
    in = shedin(1.0, 1, 60);
    f = shefloors();
    TEST_ASSERT_EQUAL_INT(QC_GOV_BAD_ARG,
        qc_gov_shed(&g, NULL, &f, &out, 1));
    in.action.profile = 9;
    TEST_ASSERT_EQUAL_INT(QC_GOV_BAD_ARG,
        qc_gov_shed(&g, &in, &f, &out, 1));
    in.action.profile = 1;
    f.c0_min = 0.0;
    TEST_ASSERT_EQUAL_INT(QC_GOV_BAD_ARG,
        qc_gov_shed(&g, &in, &f, &out, 1));
    TEST_ASSERT_EQUAL_INT(-1, qc_gov_restore_ready(NULL, 1, 1));
    qc_gov_counts(NULL, &c);
    qc_gov_counts(&g, NULL);
    qc_gov_counts(&g, &c);
    /* Audit fix: guards re-init g at entry, so pre-reset counters are
     * unobservable here by design (first cut asserted leaked state —
     * order-coupled AND wrong). Assert the fresh zeroing instead. */
    TEST_ASSERT_EQUAL_UINT(0, c.sheds);
    TEST_ASSERT_EQUAL_UINT(0, c.charges);
}

void setUp(void) {}
void tearDown(void) {}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_bucket);
    RUN_TEST(test_shed_walk);
    RUN_TEST(test_restore);
    RUN_TEST(test_persist);
    RUN_TEST(test_guards);
    return UNITY_END();
}
