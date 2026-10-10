/* test_opt.c — L0/L1/L2 for the optimizer (B-34 host core).
 *
 * Covers: argmin vectors + sigma + lambda + ties (a_prev, profile),
 * bucket gate once (NaN-safe), gate order, cap (even-escalation hold,
 * queue, alarms, rolling window, rollover, persistence, Hmax==0),
 * cooldown (hold/bypass/sentinel legs/cap-first), Hmax-cover filter +
 * margin, queue (overwrite throttle, stale drop, fresh-wins), apply
 * failure (hold/alarm/no-charge/retry), commit paths (advance/charge/
 * applied-tracking), handshake counting, reconfig, export/import
 * (+tamper/version), NaN/empty guards. Static state (house rule).
 */
#include "unity.h"

#include <string.h>

#include "qc_opt.h"

static qc_opt o;
static double spy_spent;
static int spy_calls;

static void spy_spend(void *ctx, double joules) {
    (void)ctx;
    spy_spent += joules;
    spy_calls++;
}

static const qc_opt_hooks HOOKS = { NULL, spy_spend };

static qc_action mk(uint8_t p, uint32_t tpq, uint32_t tr, int32_t ta,
                    uint8_t nb) {
    qc_action a;
    a.profile = p;
    a.tpq_s = tpq;
    a.tr_s = tr;
    a.ta_s = ta;
    a.nb = nb;
    return a;
}

static qc_cand cand(qc_action a, double ehat, double esec) {
    qc_cand c;
    c.action = a;
    c.ehat_j = ehat;
    c.ehat_sec = esec;
    return c;
}

static void init_basic(void) {
    qc_action prev = mk(2, 3600, 1800, 600, 4);
    spy_spent = 0.0;
    spy_calls = 0;
    TEST_ASSERT_EQUAL_INT(0, qc_opt_init(&o, &prev, 10, 100, 0, &HOOKS));
}

/* Three candidates: SL1 cheap, SL2 mid (= a_prev shape), SL3 pricey. */
static void three_cands(qc_cand *c) {
    c[0] = cand(mk(1, 3600, 1800, 600, 2), 10.0, 0.01);
    c[1] = cand(mk(2, 3600, 1800, 600, 4), 12.0, 0.02);
    c[2] = cand(mk(3, 3600, 1800, 600, 4), 20.0, 0.03);
}

static void test_argmin(void) {
    qc_cand c[3];
    qc_action st;

    init_basic();
    three_cands(c);
    /* Greedy picks SL1 (switch cost 0 < 12 at lambda 0... sigma SL1 vs
     * prev SL2 = 1 -> 10+0 = 10 < 12+0. SL1 staged. */
    TEST_ASSERT_EQUAL_INT(QC_OPT_OK_STAGED,
        qc_opt_decide(&o, c, 3, 0.0, 99.0, 1.0, 10000));
    TEST_ASSERT_EQUAL_INT(1, qc_opt_staged(&o, &st));
    TEST_ASSERT_EQUAL_UINT8(1, st.profile);
    /* Lambda prices the switch away: 10+5 > 12+0. */
    TEST_ASSERT_EQUAL_INT(QC_OPT_OK_STAGED,
        qc_opt_decide(&o, c, 3, 5.0, 99.0, 1.0, 10000));
    TEST_ASSERT_EQUAL_INT(1, qc_opt_staged(&o, &st));
    TEST_ASSERT_EQUAL_UINT8(2, st.profile);
    /* Exact tie resolves toward a_prev (SL2 tied with SL1 at 12). */
    c[0] = cand(mk(1, 3600, 1800, 600, 2), 12.0, 0.01);
    TEST_ASSERT_EQUAL_INT(QC_OPT_OK_STAGED,
        qc_opt_decide(&o, c, 3, 0.0, 99.0, 1.0, 10000));
    TEST_ASSERT_EQUAL_INT(1, qc_opt_staged(&o, &st));
    TEST_ASSERT_EQUAL_UINT8(2, st.profile);
    /* a_prev not tied: lowest profile wins (SL1 == SL3 at 20... make
     * SL1 20, SL3 20, SL2 99: tie SL1/SL3 -> SL1). */
    c[0] = cand(mk(1, 3600, 1800, 600, 2), 20.0, 0.01);
    c[1] = cand(mk(2, 3600, 1800, 600, 4), 99.0, 0.02);
    c[2] = cand(mk(3, 3600, 1800, 600, 4), 20.0, 0.03);
    TEST_ASSERT_EQUAL_INT(QC_OPT_OK_STAGED,
        qc_opt_decide(&o, c, 3, 0.0, 99.0, 1.0, 10000));
    TEST_ASSERT_EQUAL_INT(1, qc_opt_staged(&o, &st));
    TEST_ASSERT_EQUAL_UINT8(1, st.profile);
    /* Bad lambda / empty / NaN degrade safely. */
    TEST_ASSERT_EQUAL_INT(QC_OPT_BAD_ARG,
        qc_opt_decide(&o, c, 3, -1.0, 99.0, 1.0, 10000));
    TEST_ASSERT_EQUAL_INT(QC_OPT_FAILSECURE,
        qc_opt_decide(&o, c, 0, 0.0, 99.0, 1.0, 10000));
    {
        qc_cand nan[1];
        uint32_t u = 0x7FC00000u;
        float nanf;
        memcpy(&nanf, &u, 4);
        nan[0] = cand(mk(1, 3600, 1800, 600, 2), nanf, 0.01);
        TEST_ASSERT_EQUAL_INT(QC_OPT_FAILSECURE,
            qc_opt_decide(&o, nan, 1, 0.0, 99.0, 1.0, 10000));
    }
    TEST_ASSERT_EQUAL_INT(QC_OPT_BAD_ARG,
        qc_opt_decide(NULL, c, 3, 0.0, 99.0, 1.0, 10000));
}

static void test_bucket_gate(void) {
    qc_cand c[3];

    init_basic();
    three_cands(c);
    /* Winner SL1 needs 0.01 but tau is 0.005 -> SHED once, staged. */
    {
        qc_action st;
        TEST_ASSERT_EQUAL_INT(QC_OPT_SHED,
            qc_opt_decide(&o, c, 3, 0.0, 0.005, 1.0, 10000));
        TEST_ASSERT_EQUAL_INT(1, qc_opt_staged(&o, &st));
        TEST_ASSERT_EQUAL_UINT8(1, st.profile);
    }
    /* NaN tau sheds (unknown budget never passes). */
    {
        uint32_t u = 0x7FC00000u;
        float nanf;
        memcpy(&nanf, &u, 4);
        TEST_ASSERT_EQUAL_INT(QC_OPT_SHED,
            qc_opt_decide(&o, c, 3, 0.0, nanf, 1.0, 10000));
    }
    /* Gate precedes cap: over-budget + cap-hit still SHEDs. Hmax stays
     * 10 (cover passes); one handshake cannot cap it. */
    TEST_ASSERT_EQUAL_INT(0, qc_opt_note_handshake(&o, 0));
    TEST_ASSERT_EQUAL_INT(QC_OPT_SHED,
        qc_opt_decide(&o, c, 3, 0.0, 0.005, 1.0, 10000));
}

static void test_cap(void) {
    qc_cand c[3];
    qc_action esc;

    init_basic();
    TEST_ASSERT_EQUAL_INT(0, qc_opt_reconfigure(&o, 2, 100));
    three_cands(c);
    /* Cover with Hmax=2, margin=1 needs tpq >= 3600 (rate+1 <= 2). */
    esc = mk(3, 3600, 1800, 300, 4); /* escalation vs SL2 prev */
    /* Two handshakes: capped. Escalation queues (cap wins). */
    TEST_ASSERT_EQUAL_INT(0, qc_opt_note_handshake(&o, 0));
    TEST_ASSERT_EQUAL_INT(0, qc_opt_note_handshake(&o, 60));
    TEST_ASSERT_EQUAL_UINT(2, qc_opt_cap_count(&o, 61));
    {
        qc_cand ce[2];
        ce[0] = cand(mk(2, 3600, 1800, 600, 4), 5.0, 0.01);
        ce[1] = cand(esc, 4.0, 0.01); /* argmin picks the escalation */
        TEST_ASSERT_EQUAL_INT(QC_OPT_QUEUED,
            qc_opt_decide(&o, ce, 2, 0.0, 99.0, 1.0, 61));
        TEST_ASSERT_EQUAL_UINT8(
            (uint8_t)(1u << QC_OPT_ALARM_CAP_ENTER),
            qc_opt_take_alarms(&o));
        TEST_ASSERT_EQUAL_UINT8(0, qc_opt_take_alarms(&o));
    }
    /* Still capped, no fresh escalation: HOLD, no new alarm. */
    {
        qc_cand ce[1];
        qc_opt_counters co;
        ce[0] = cand(mk(2, 3600, 1800, 600, 4), 5.0, 0.01);
        TEST_ASSERT_EQUAL_INT(QC_OPT_HOLD,
            qc_opt_decide(&o, ce, 1, 0.0, 99.0, 1.0, 100));
        TEST_ASSERT_EQUAL_UINT8(0, qc_opt_take_alarms(&o));
        qc_opt_counts(&o, &co);
        TEST_ASSERT_EQUAL_UINT(1, co.queued);
        TEST_ASSERT_EQUAL_UINT(1, co.holds);
    }
    /* Rollover clears: minute 61+ drops the minute-0/1 counts. */
    TEST_ASSERT_EQUAL_UINT(0, qc_opt_cap_count(&o, 61 * 60));
    /* Hmax==0 degenerates to cover-empty (rate+margin > 0 always), so
     * FAILSECURE — the fail-secure route, audit-corrected (first cut
     * wrongly expected HOLD: cover precedes cap in the gate order). */
    TEST_ASSERT_EQUAL_INT(0, qc_opt_reconfigure(&o, 0, 100));
    {
        qc_cand ce[1];
        qc_opt_counters co;
        ce[0] = cand(mk(1, 3600, 1800, 600, 2), 1.0, 0.001);
        TEST_ASSERT_EQUAL_INT(QC_OPT_FAILSECURE,
            qc_opt_decide(&o, ce, 1, 0.0, 99.0, 1.0, 20000));
        qc_opt_counts(&o, &co);
        TEST_ASSERT_EQUAL_UINT(1, co.failsecures);
    }
}

static void test_cooldown(void) {
    qc_cand c[1];

    init_basic(); /* last_switch=0, t_cool=100. prev SL2. */
    /* Blocked non-escalation holds. */
    c[0] = cand(mk(1, 7200, 3600, 600, 2), 1.0, 0.001);
    TEST_ASSERT_EQUAL_INT(QC_OPT_HOLD,
        qc_opt_decide(&o, c, 1, 0.0, 99.0, 1.0, 50));
    /* Higher profile bypasses. */
    c[0] = cand(mk(3, 7200, 3600, 600, 2), 1.0, 0.001);
    TEST_ASSERT_EQUAL_INT(QC_OPT_OK_STAGED,
        qc_opt_decide(&o, c, 1, 0.0, 99.0, 1.0, 50));
    /* Shorter Tpq at equal profile bypasses. */
    c[0] = cand(mk(2, 1800, 900, 600, 4), 1.0, 0.001);
    TEST_ASSERT_EQUAL_INT(QC_OPT_OK_STAGED,
        qc_opt_decide(&o, c, 1, 0.0, 99.0, 1.0, 50));
    /* Shorter Ta at equal profile bypasses. */
    c[0] = cand(mk(2, 3600, 1800, 300, 4), 1.0, 0.001);
    TEST_ASSERT_EQUAL_INT(QC_OPT_OK_STAGED,
        qc_opt_decide(&o, c, 1, 0.0, 99.0, 1.0, 50));
    /* Sentinel Ta never qualifies the Ta leg (profile equal, Tpq
     * equal-or-longer here: Tpq 3600 == prev 3600, not shorter). */
    c[0] = cand(mk(2, 3600, 1800, -2, 4), 1.0, 0.001);
    TEST_ASSERT_EQUAL_INT(QC_OPT_HOLD,
        qc_opt_decide(&o, c, 1, 0.0, 99.0, 1.0, 50));
    /* Past cooldown: plain switch stages. */
    c[0] = cand(mk(1, 7200, 3600, 600, 2), 1.0, 0.001);
    TEST_ASSERT_EQUAL_INT(QC_OPT_OK_STAGED,
        qc_opt_decide(&o, c, 1, 0.0, 99.0, 1.0, 50000));
}

static void test_cover(void) {
    qc_cand c[2];

    init_basic(); /* Hmax=10. */
    /* 3600/600+1 = 7 <= 10 passes; 3600/300+1 = 13 > 10 rejected. */
    c[0] = cand(mk(1, 600, 300, 600, 2), 5.0, 0.01);
    c[1] = cand(mk(2, 300, 150, 600, 4), 1.0, 0.01);
    {
        qc_action st;
        TEST_ASSERT_EQUAL_INT(QC_OPT_OK_STAGED,
            qc_opt_decide(&o, c, 2, 0.0, 99.0, 1.0, 50000));
        TEST_ASSERT_EQUAL_INT(1, qc_opt_staged(&o, &st));
        TEST_ASSERT_EQUAL_UINT8(1, st.profile); /* SL2 filtered out */
    }
    /* Boundary: rate+margin == Hmax passes. */
    c[0] = cand(mk(1, 400, 200, 600, 2), 5.0, 0.01); /* 9+1 == 10 */
    TEST_ASSERT_EQUAL_INT(QC_OPT_OK_STAGED,
        qc_opt_decide(&o, c, 1, 0.0, 99.0, 1.0, 50000));
    /* tpq==0 never survives cover. */
    c[0] = cand(mk(1, 0, 0, 600, 2), 0.0, 0.0);
    TEST_ASSERT_EQUAL_INT(QC_OPT_FAILSECURE,
        qc_opt_decide(&o, c, 1, 0.0, 99.0, 1.0, 50000));
}

static void test_queue(void) {
    qc_action esc_a, esc_b;
    qc_opt_counters co;

    /* Hmax=3, margin=1: cover needs 3600/tpq+1 <= 3 (tpq >= 1800). */
    init_basic();
    TEST_ASSERT_EQUAL_INT(0, qc_opt_reconfigure(&o, 3, 100));
    esc_a = mk(3, 1800, 900, 300, 4);
    esc_b = mk(3, 1800, 900, 60, 4);
    /* Three handshakes cap it; esc A queues. */
    TEST_ASSERT_EQUAL_INT(0, qc_opt_note_handshake(&o, 0));
    TEST_ASSERT_EQUAL_INT(0, qc_opt_note_handshake(&o, 60));
    TEST_ASSERT_EQUAL_INT(0, qc_opt_note_handshake(&o, 120));
    {
        qc_cand ce[1];
        ce[0] = cand(esc_a, 6.0, 0.01);
        TEST_ASSERT_EQUAL_INT(QC_OPT_QUEUED,
            qc_opt_decide(&o, ce, 1, 0.0, 99.0, 1.0, 181));
        qc_opt_take_alarms(&o);
    }
    /* Window clears (minute 63+); fresh esc B beats queued A: B staged,
     * A superseded silently (no alarm). */
    {
        qc_cand ce[2];
        qc_action st;
        ce[0] = cand(esc_a, 9.0, 0.01);
        ce[1] = cand(esc_b, 1.0, 0.01);
        TEST_ASSERT_EQUAL_INT(QC_OPT_OK_STAGED,
            qc_opt_decide(&o, ce, 2, 0.0, 99.0, 1.0, 63 * 60));
        TEST_ASSERT_EQUAL_INT(1, qc_opt_staged(&o, &st));
        TEST_ASSERT_EQUAL_INT(60, st.ta_s);
        qc_opt_counts(&o, &co);
        TEST_ASSERT_EQUAL_UINT(1, co.superseded);
        TEST_ASSERT_EQUAL_UINT8(0, qc_opt_take_alarms(&o));
    }
    /* Stale queued entry never applies: queue A again under cap, then
     * offer Af without A once clear. */
    TEST_ASSERT_EQUAL_INT(0, qc_opt_note_handshake(&o, 64 * 60));
    TEST_ASSERT_EQUAL_INT(0, qc_opt_note_handshake(&o, 64 * 60 + 60));
    TEST_ASSERT_EQUAL_INT(0, qc_opt_note_handshake(&o, 64 * 60 + 120));
    {
        qc_cand ce[1];
        ce[0] = cand(esc_a, 6.0, 0.01);
        TEST_ASSERT_EQUAL_INT(QC_OPT_QUEUED,
            qc_opt_decide(&o, ce, 1, 0.0, 99.0, 1.0,
                          64 * 60 + 181));
        qc_opt_take_alarms(&o);
    }
    {
        qc_cand ce[1];
        qc_action st;
        ce[0] = cand(mk(2, 3600, 1800, 600, 4), 1.0, 0.001);
        TEST_ASSERT_EQUAL_INT(QC_OPT_OK_STAGED,
            qc_opt_decide(&o, ce, 1, 0.0, 99.0, 1.0, 130 * 60));
        TEST_ASSERT_EQUAL_INT(1, qc_opt_staged(&o, &st));
        TEST_ASSERT_EQUAL_UINT8(2, st.profile);
        qc_opt_counts(&o, &co);
        TEST_ASSERT_EQUAL_UINT(1, co.stale_dropped);
    }
}

static void test_commit(void) {
    qc_cand c[3];
    qc_action st;
    qc_action y;

    init_basic();
    TEST_ASSERT_EQUAL_INT(0, qc_opt_reconfigure(&o, 10, 10000));
    three_cands(c);
    /* Stage SL1, apply: spend charged, stage cleared. */
    TEST_ASSERT_EQUAL_INT(QC_OPT_OK_STAGED,
        qc_opt_decide(&o, c, 3, 0.0, 99.0, 1.0, 50000));
    TEST_ASSERT_EQUAL_INT(QC_OPT_OK_STAGED,
        qc_opt_commit(&o, 1, 50000, 5.0, NULL));
    TEST_ASSERT_TRUE(spy_spent > 4.999 && spy_spent < 5.001);
    TEST_ASSERT_EQUAL_INT(1, spy_calls);
    TEST_ASSERT_EQUAL_INT(0, qc_opt_staged(&o, &st));
    /* last_switch advanced: an immediate different action holds. */
    {
        qc_cand ce[1];
        ce[0] = cand(mk(1, 7200, 3600, 600, 2), 1.0, 0.001);
        TEST_ASSERT_EQUAL_INT(QC_OPT_HOLD,
            qc_opt_decide(&o, ce, 1, 0.0, 99.0, 1.0, 50001));
    }
    /* Applied-tracking: commit a different action than staged; the next
     * argmin prices sigma against the APPLIED one. */
    TEST_ASSERT_EQUAL_INT(QC_OPT_OK_STAGED,
        qc_opt_decide(&o, c, 3, 0.0, 99.0, 1.0, 70000));
    y = mk(3, 3600, 1800, 600, 4);
    TEST_ASSERT_EQUAL_INT(QC_OPT_OK_STAGED,
        qc_opt_commit(&o, 1, 70000, 1.0, &y));
    {
        /* ehat X=10/Y=10 tie, lambda prices the switch: a_prev==Y must
         * win (proves Y, not staged X, is tracked). */
        qc_cand ce[2];
        qc_action got;
        ce[0] = cand(mk(1, 3600, 1800, 600, 2), 10.0, 0.01);
        ce[1] = cand(mk(3, 3600, 1800, 600, 4), 10.0, 0.01);
        TEST_ASSERT_EQUAL_INT(QC_OPT_OK_STAGED,
            qc_opt_decide(&o, ce, 2, 5.0, 99.0, 1.0, 90000));
        TEST_ASSERT_EQUAL_INT(1, qc_opt_staged(&o, &got));
        TEST_ASSERT_EQUAL_UINT8(3, got.profile);
    }
    /* Apply failure: HOLD + alarm + no charge + retry stages again. */
    {
        qc_opt_counters co;
        TEST_ASSERT_EQUAL_INT(QC_OPT_OK_STAGED,
            qc_opt_decide(&o, c, 3, 0.0, 99.0, 1.0, 100000));
        TEST_ASSERT_EQUAL_INT(QC_OPT_HOLD,
            qc_opt_commit(&o, 0, 100000, 9.0, NULL));
        TEST_ASSERT_EQUAL_UINT8(
            (uint8_t)(1u << QC_OPT_ALARM_APPLY_FAIL),
            qc_opt_take_alarms(&o));
        TEST_ASSERT_TRUE(spy_spent > 5.999 && spy_spent < 6.001);
        TEST_ASSERT_EQUAL_INT(0, qc_opt_staged(&o, &st));
        qc_opt_counts(&o, &co);
        TEST_ASSERT_EQUAL_UINT(1, co.apply_fails);
        TEST_ASSERT_EQUAL_INT(QC_OPT_OK_STAGED,
            qc_opt_decide(&o, c, 3, 0.0, 99.0, 1.0, 100001));
        TEST_ASSERT_EQUAL_INT(QC_OPT_OK_STAGED,
            qc_opt_commit(&o, 1, 100001, 0.0, NULL));
    }
    /* Commit without a stage is a caller bug (stage consumed above). */
    TEST_ASSERT_EQUAL_INT(QC_OPT_BAD_ARG,
        qc_opt_commit(&o, 1, 0, 0.0, NULL));
}

static void test_guards(void) {
    qc_action a = mk(1, 3600, 1800, 600, 2);

    TEST_ASSERT_EQUAL_INT(-1, qc_opt_init(NULL, &a, 1, 1, 0, NULL));
    TEST_ASSERT_EQUAL_INT(-1, qc_opt_init(&o, NULL, 1, 1, 0, NULL));
    a.profile = 9;
    TEST_ASSERT_EQUAL_INT(-1, qc_opt_init(&o, &a, 1, 1, 0, NULL));
    TEST_ASSERT_EQUAL_INT(-1, qc_opt_reconfigure(NULL, 1, 1));
    TEST_ASSERT_EQUAL_INT(-1, qc_opt_note_handshake(NULL, 1));
    TEST_ASSERT_EQUAL_INT(0, qc_opt_staged(NULL, &a));
    TEST_ASSERT_EQUAL_INT(QC_OPT_BAD_ARG,
        qc_opt_commit(NULL, 1, 0, 0.0, NULL));
}

void setUp(void) {}
void tearDown(void) {}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_argmin);
    RUN_TEST(test_bucket_gate);
    RUN_TEST(test_cap);
    RUN_TEST(test_cooldown);
    RUN_TEST(test_cover);
    RUN_TEST(test_queue);
    RUN_TEST(test_commit);
    RUN_TEST(test_guards);
    return UNITY_END();
}
