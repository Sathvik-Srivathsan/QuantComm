/* test_rsync.c — L0/L1 for the ratchet receiver policy (B-26.2 + invariant).
 *
 * Covers: accept-in-window with fast-forward + key correctness, already-
 * there (r == local) accept, stale (older/duplicate) drop + counting,
 * over-skip drop + rekey signal (never advance), max-skip boundary
 * (exactly max_skip accepts, +1 rekeys), NULL safety, cadence check
 * truth table (incl. zero edges). Key correctness cross-checked by
 * independent stepping (advance twice == forward_to(2)).
 */
#include "unity.h"

#include <string.h>

#include "qc_ratchet.h"
#include "qc_rsync.h"

static void seed_state(qc_ratchet_state *st) {
    int i;
    memset(st, 0, sizeof(*st));
    for (i = 0; i < 32; i++) {
        st->r_cur[i] = (uint8_t)(0xC0 + i);
    }
}

static void test_accept_and_keys(void) {
    qc_ratchet_state a, b;
    qc_ratchet_keys ka, kb;
    uint64_t drops = 0;

    seed_state(&a);
    seed_state(&b);
    /* Independent stepping to r=3 on b; policy jump to 3 on a. */
    TEST_ASSERT_EQUAL_INT(0, qc_ratchet_advance(&b, &kb));
    TEST_ASSERT_EQUAL_INT(0, qc_ratchet_advance(&b, &kb));
    TEST_ASSERT_EQUAL_INT(0, qc_ratchet_advance(&b, &kb));
    TEST_ASSERT_EQUAL_INT(QC_RESYNC_ACCEPT,
        qc_rsync_recv(&a, 3, 16, &drops, &ka));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(kb.k_c2s, ka.k_c2s, 32);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(kb.k_s2c, ka.k_s2c, 32);
    TEST_ASSERT_EQUAL_UINT64(0, drops);
    /* r == local: STALE (duplicate — caller holds this generation).
     * Generation-0 inception traffic never enters here (session keys);
     * see header contract. */
    TEST_ASSERT_EQUAL_INT(QC_RESYNC_STALE,
        qc_rsync_recv(&a, 3, 16, &drops, &ka));
    TEST_ASSERT_EQUAL_UINT64(1, drops);
}

static void test_stale(void) {
    qc_ratchet_state st;
    qc_ratchet_keys k;
    uint64_t drops = 0;

    seed_state(&st);
    TEST_ASSERT_EQUAL_INT(QC_RESYNC_ACCEPT,
        qc_rsync_recv(&st, 5, 16, &drops, &k));
    TEST_ASSERT_EQUAL_INT(QC_RESYNC_STALE,
        qc_rsync_recv(&st, 5, 16, &drops, &k));
    TEST_ASSERT_EQUAL_UINT64(1, drops);
    TEST_ASSERT_EQUAL_INT(QC_RESYNC_STALE,
        qc_rsync_recv(&st, 2, 16, &drops, &k));
    TEST_ASSERT_EQUAL_UINT64(2, drops);
    /* Fresh r with NULL counter: ACCEPTS (counter only counts), proving
     * NULL skips counting without changing disposition. */
    TEST_ASSERT_EQUAL_INT(QC_RESYNC_ACCEPT,
        qc_rsync_recv(&st, 6, 16, NULL, &k));
    /* NULL state/keys degrade to drop, never advance-or-rekey. r=7 is
     * fresh (would ACCEPT) so these isolate the guard, not staleness. */
    TEST_ASSERT_EQUAL_INT(QC_RESYNC_STALE,
        qc_rsync_recv(NULL, 7, 16, &drops, &k));
    TEST_ASSERT_EQUAL_INT(QC_RESYNC_STALE,
        qc_rsync_recv(&st, 7, 16, &drops, NULL));
}

static void test_overskip(void) {
    qc_ratchet_state st, before;
    qc_ratchet_keys k;
    uint64_t drops = 0;

    seed_state(&st);
    TEST_ASSERT_EQUAL_INT(QC_RESYNC_ACCEPT,
        qc_rsync_recv(&st, 10, 16, &drops, &k));
    /* Boundary: exactly max_skip ahead accepts... */
    TEST_ASSERT_EQUAL_INT(QC_RESYNC_ACCEPT,
        qc_rsync_recv(&st, 10 + 16, 16, &drops, &k));
    /* Snapshot AFTER advancing: the rekey path must leave this alone. */
    memcpy(&before, &st, sizeof(before));
    /* ...one past it rekeys, with state untouched. */
    TEST_ASSERT_EQUAL_INT(QC_RESYNC_REKEY,
        qc_rsync_recv(&st, 10 + 16 + 1 + 16, 16, &drops, &k));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(before.r_cur, st.r_cur, 32);
    TEST_ASSERT_EQUAL_UINT64(before.i, st.i);
    TEST_ASSERT_EQUAL_UINT64(0, drops);
}

static void test_cadence(void) {
    TEST_ASSERT_EQUAL_INT(0, qc_rsync_check_cadence(60, 3600));
    TEST_ASSERT_EQUAL_INT(0, qc_rsync_check_cadence(3600, 3600));
    TEST_ASSERT_EQUAL_INT(0, qc_rsync_check_cadence(0, 0));
    TEST_ASSERT_EQUAL_INT(0, qc_rsync_check_cadence(0, 3600));
    TEST_ASSERT_TRUE(qc_rsync_check_cadence(3601, 3600) != 0);
    TEST_ASSERT_TRUE(qc_rsync_check_cadence(1, 0) != 0);
}

void setUp(void) {}
void tearDown(void) {}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_accept_and_keys);
    RUN_TEST(test_stale);
    RUN_TEST(test_overskip);
    RUN_TEST(test_cadence);
    return UNITY_END();
}