/* test_energy.c — L0/L1/L2 for the energy model (B-33 host core).
 *
 * Covers: priors (ASSUMED all set, spec multipliers/ratios), calibrate
 * (per-family + singletons, bit clearing, refusals incl. NaN/negative,
 * invalidate-all), derive (hand-computed vector), eval term separation
 * (independent perturbation moves one group only), single-counting
 * (adapt == ectrl lump, total == sum), ehat (rate math + baseline
 * excluded bit-exactly), Ehs vectors per level, prekey/hmax (+guards),
 * foot priors + converter + calibrate bits, NULL guards.
 * Doubles compared with epsilon (no libm linkage wanted here).
 */
#include "unity.h"

#include <string.h>

#include "qc_energy.h"

#define D_EPS 1e-9
#define D_EQ(a, b) \
    TEST_ASSERT_TRUE_MESSAGE((a) > (b) - D_EPS && (a) < (b) + D_EPS, \
                             "double mismatch: " #a " vs " #b)

static qc_e_coeff c;
static qc_e_counts n;
static qc_e_groups g;

static void test_priors(void) {
    int l, o;

    qc_energy_priors(&c);
    TEST_ASSERT_EQUAL_UINT(0x1FFFu, c.assumed & 0x1FFFu);
    /* Spec multipliers preserved exactly. */
    for (o = 0; o < 3; o++) {
        D_EQ(c.e_kem[1][o], c.e_kem[0][o] * 1.6);
        D_EQ(c.e_kem[2][o], c.e_kem[0][o] * 2.4);
    }
    D_EQ(c.e_dsa_sign[0], c.e_dsa_sign[2] * 0.45);
    D_EQ(c.e_dsa_sign[1], c.e_dsa_sign[2] * 0.7);
    TEST_ASSERT_TRUE(c.eB >= 2e-6 && c.eB <= 20e-6);
    TEST_ASSERT_TRUE(c.e_dsa_sign[2] >= 26e-3 &&
                     c.e_dsa_sign[2] <= 80e-3);
    TEST_ASSERT_TRUE(c.e_kem[0][0] >= 1e-3 && c.e_kem[0][0] <= 5e-3);
    for (l = 0; l < 3; l++) {
        TEST_ASSERT_TRUE(c.e_dsa_verify[l] > 0.0);
    }
    qc_energy_priors(NULL);
}

static void test_calibrate(void) {
    qc_energy_priors(&c);
    TEST_ASSERT_EQUAL_INT(0,
        qc_energy_calibrate(&c, QC_ASSUMED_EB, 0, 0, 4e-6));
    D_EQ(4e-6, c.eB);
    TEST_ASSERT_EQUAL_UINT(0, c.assumed & (1u << QC_ASSUMED_EB));
    TEST_ASSERT_EQUAL_INT(0,
        qc_energy_calibrate(&c, QC_EFIELD_KEM, 1, 2, 7e-3));
    D_EQ(7e-3, c.e_kem[1][2]);
    TEST_ASSERT_EQUAL_UINT(0, c.assumed & (1u << QC_ASSUMED_KEM768));
    TEST_ASSERT_EQUAL_INT(0,
        qc_energy_calibrate(&c, QC_EFIELD_DSA_SIGN, 0, 0, 20e-3));
    TEST_ASSERT_EQUAL_UINT(0, c.assumed & (1u << QC_ASSUMED_DSA44));
    TEST_ASSERT_EQUAL_INT(0,
        qc_energy_calibrate(&c, QC_EFIELD_EBASE, 2, 0, 0.04));
    D_EQ(0.04, c.ebase_jps[2]);
    /* Refusals: bad field/idx, NaN, negatives (bit stays set). */
    TEST_ASSERT_EQUAL_INT(-1,
        qc_energy_calibrate(&c, 999, 0, 0, 1.0));
    TEST_ASSERT_EQUAL_INT(-1,
        qc_energy_calibrate(&c, QC_EFIELD_KEM, 3, 0, 1.0));
    TEST_ASSERT_EQUAL_INT(-1,
        qc_energy_calibrate(&c, QC_EFIELD_KEM, 0, 5, 1.0));
    TEST_ASSERT_EQUAL_INT(-1,
        qc_energy_calibrate(NULL, QC_ASSUMED_EB, 0, 0, 1.0));
    {
        uint32_t u = 0x7FC00000u;
        float nanf;
        memcpy(&nanf, &u, 4);
        TEST_ASSERT_EQUAL_INT(-1,
            qc_energy_calibrate(&c, QC_ASSUMED_EB, 0, 0, nanf));
        TEST_ASSERT_EQUAL_INT(-1,
            qc_energy_calibrate(&c, QC_ASSUMED_EB, 0, 0, -1.0));
    }
    TEST_ASSERT_TRUE((c.assumed & (1u << QC_ASSUMED_EV)) != 0);
    /* Trigger re-flags everything (values kept). */
    qc_energy_invalidate_all(&c);
    TEST_ASSERT_EQUAL_UINT(0x1FFFu, c.assumed & 0x1FFFu);
    D_EQ(4e-6, c.eB);
    qc_energy_invalidate_all(NULL);
}

static void test_derive(void) {
    qc_workload w;

    memset(&w, 0, sizeof(w));
    w.profile = 1;
    w.msg_per_h = 3600.0;
    w.resend = 0.0;
    w.msg_bytes = 64.0;
    w.tpq_s = 3600;
    w.tr_s = 3600;
    w.ta_s = 600;
    w.ta_event_per_h = 0.0;
    w.c2_per_h = 0.0;
    w.readings_per_h = 7200.0;
    w.transcript_b = 256.0;
    w.dsa_verify_per_h = 0.0;
    qc_derive_counts(&w, &n);
    D_EQ(3600.0 * 64.0, n.aes_enc_b);
    D_EQ(1.0, n.hkdf_exp);
    D_EQ(6.0, n.dsa_sign[0]);
    D_EQ(0.0, n.dsa_sign[1]);
    D_EQ(256.0 * 1.0 + 2.0 * 7200.0, n.sha_b);
    D_EQ(3600.0 * 64.0, n.bytes);
    D_EQ(3600.0, n.events);
    D_EQ(0.0, n.kem[0][0]);
    /* EVENT/MSG Ta consumes the trace estimate; NONE gives zero. */
    w.ta_s = -2;
    w.ta_event_per_h = 12.0;
    qc_derive_counts(&w, &n);
    D_EQ(12.0, n.dsa_sign[0]);
    w.ta_s = -1;
    qc_derive_counts(&w, &n);
    D_EQ(0.0, n.dsa_sign[0]);
    /* Bad profile zeroes (caller bug surfaces as zero energy). */
    w.profile = 9;
    qc_derive_counts(&w, &n);
    D_EQ(0.0, n.bytes);
    qc_derive_counts(NULL, &n);
    qc_derive_counts(&w, NULL);
}

static void test_eval_separation(void) {
    qc_e_counts base;

    qc_energy_priors(&c);
    memset(&base, 0, sizeof(base));
    base.bytes = 1000.0;
    base.events = 10.0;
    base.aes_enc_b = 1000.0;
    qc_energy_eval(&base, &c, 0.05, 0.5, 3600.0, &g);
    TEST_ASSERT_TRUE(g.base > 0.0 && g.crypto > 0.0 && g.comm > 0.0);
    D_EQ(0.5, g.adapt); /* E_ctrl lump lands whole in adapt. */
    D_EQ(g.base + g.crypto + g.comm + g.adapt, g.total);
    /* Perturb bytes only: comm moves, others frozen. */
    {
        qc_e_groups g2 = g;
        base.bytes = 2000.0;
        base.aes_enc_b = 2000.0;
        qc_energy_eval(&base, &c, 0.05, 0.5, 3600.0, &g);
        D_EQ(g2.base, g.base);
        D_EQ(g2.adapt, g.adapt);
        TEST_ASSERT_TRUE(g.comm > g2.comm && g.crypto > g2.crypto);
    }
    /* Perturb E_ctrl only: adapt moves alone (single counting). */
    {
        qc_e_groups g2 = g;
        qc_energy_eval(&base, &c, 0.05, 2.5, 3600.0, &g);
        D_EQ(g2.base, g.base);
        D_EQ(g2.crypto, g.crypto);
        D_EQ(g2.comm, g.comm);
        D_EQ(2.5, g.adapt);
    }
    qc_energy_eval(NULL, &c, 0, 0, 1, &g);
    qc_energy_eval(&base, NULL, 0, 0, 1, &g);
    qc_energy_eval(&base, &c, 0, 0, 1, NULL);
}

static void test_ehat(void) {
    qc_e_counts base;
    double e1, e2;

    qc_energy_priors(&c);
    memset(&base, 0, sizeof(base));
    base.bytes = 5000.0;
    base.events = 50.0;
    base.hkdf_exp = 2.0;
    e1 = qc_ehat_sec(&base, &c);
    TEST_ASSERT_TRUE(e1 > 0.0);
    /* Huge baseline changes nothing (excluded by construction). */
    {
        qc_e_groups g1, g2;
        qc_energy_eval(&base, &c, 1e6, 0.0, 3600.0, &g1);
        qc_energy_eval(&base, &c, 0.0, 0.0, 3600.0, &g2);
        D_EQ((g1.crypto + g1.comm + g1.adapt) / 3600.0, e1);
        D_EQ((g2.crypto + g2.comm + g2.adapt) / 3600.0, e1);
    }
    e2 = qc_ehat_sec(&base, &c);
    D_EQ(e1, e2); /* deterministic. */
    D_EQ(0.0, qc_ehat_sec(NULL, &c));
    D_EQ(0.0, qc_ehat_sec(&base, NULL));
}

static void test_ehs(void) {
    double e1, e2, e3;

    qc_energy_priors(&c);
    /* Hand math: 3*3mJ + 2336*6uJ + 2*100uJ = 0.023216. */
    e1 = qc_energy_ehs(&c, 1, 2.0);
    D_EQ(3.0 * 3e-3 + 2336.0 * 6e-6 + 2.0 * 100e-6, e1);
    e2 = qc_energy_ehs(&c, 2, 2.0);
    e3 = qc_energy_ehs(&c, 3, 2.0);
    TEST_ASSERT_TRUE(e2 > e1 && e3 > e2); /* level ordering. */
    /* prekey + hmax-rate + guards. */
    D_EQ(e1 / 3600.0, qc_energy_prekey(e1, 3600));
    D_EQ(0.0, qc_energy_prekey(e1, 0));
    D_EQ(e1 * 2.0, qc_energy_hmax_rate(e1, 2.0));
    D_EQ(0.0, qc_energy_hmax_rate(-1.0, 2.0));
    D_EQ(0.0, qc_energy_ehs(&c, 0, 2.0));
    D_EQ(0.0, qc_energy_ehs(&c, 4, 2.0));
    D_EQ(0.0, qc_energy_ehs(NULL, 1, 2.0));
    D_EQ(0.0, qc_energy_ehs(&c, 1, -1.0));
}

static void test_foot(void) {
    qc_foot_tables t;
    qc_res_tables r;

    qc_foot_priors(&t);
    TEST_ASSERT_EQUAL_UINT(0xFFu, t.assumed & 0xFFu);
    TEST_ASSERT_EQUAL_UINT(64u, t.msg_bytes);
    TEST_ASSERT_TRUE(t.stack_ram[2] > t.stack_ram[1] &&
                     t.stack_ram[1] > t.stack_ram[0]);
    qc_foot_to_res(&t, &r);
    TEST_ASSERT_EQUAL_UINT(t.base_ram, r.base_ram);
    TEST_ASSERT_EQUAL_UINT(t.stack_ram[2], r.stack_ram[2]);
    TEST_ASSERT_EQUAL_UINT(t.lat_per_msg_ms, r.lat_per_msg_ms);
    TEST_ASSERT_EQUAL_INT(0,
        qc_foot_calibrate(&t, QC_FFOOT_STACK, 2, 100000u));
    TEST_ASSERT_EQUAL_UINT(100000u, t.stack_ram[2]);
    TEST_ASSERT_EQUAL_UINT(0, t.assumed & (1u << 3));
    TEST_ASSERT_EQUAL_INT(-1, qc_foot_calibrate(&t, 99, 0, 1));
    TEST_ASSERT_EQUAL_INT(-1, qc_foot_calibrate(&t, QC_FFOOT_STACK, 5, 1));
    TEST_ASSERT_EQUAL_INT(-1, qc_foot_calibrate(NULL, 0, 0, 1));
    qc_foot_to_res(NULL, &r);
    qc_foot_to_res(&t, NULL);
    qc_foot_priors(NULL);
}

void setUp(void) {}
void tearDown(void) {}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_priors);
    RUN_TEST(test_calibrate);
    RUN_TEST(test_derive);
    RUN_TEST(test_eval_separation);
    RUN_TEST(test_ehat);
    RUN_TEST(test_ehs);
    RUN_TEST(test_foot);
    return UNITY_END();
}
