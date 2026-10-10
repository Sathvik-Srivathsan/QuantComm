/* test_buf.c — L0/L1/L2 for outage buffering (B-24.5 host core).
 *
 * Covers: tier drain order (C2 by (epoch,counter), then chrono), score
 * helper, lowest-score/oldest-tie eviction, C2 pinning (DROPPED non-C2),
 * C2_PRESSURE + counter, TTL expiry + per-class counters, sweep, pop
 * age (stale label duty), SMALL_BUF retain, reinsert age preserve +
 * EXPIRED, mirror save/load roundtrip (age survives reboot) + absent +
 * corrupt, NULL/size guards. Buffer structs are ~17.5 KB: static, never
 * stack (house rule). Frames here are OPAQUE bytes (the buffer never
 * parses wire structure — replay safety rides on verbatim storage).
 */
#include "unity.h"

#include <stdio.h>
#include <string.h>

#include "qc_buf.h"

static const char *MPATH = "buf_mirror_t.bin";
static const char *MPATH2 = "buf_mirror_t2.bin";

static qc_buf buf;
/* Sized to QC_BUF_CAP: tests insert frames up to 9000 B. */
static uint8_t payload[16 * 1024];

static void fill(uint8_t v, size_t n) {
    memset(payload, v, n);
}

static void test_score(void) {
    TEST_ASSERT_EQUAL_UINT8(0xFF, qc_buf_score(2, 0));
    TEST_ASSERT_EQUAL_UINT8(0xFF, qc_buf_score(2, 1));
    TEST_ASSERT_EQUAL_UINT8(0x80, qc_buf_score(1, 0));
    TEST_ASSERT_EQUAL_UINT8(0xF0, qc_buf_score(1, 1));
    TEST_ASSERT_EQUAL_UINT8(0x10, qc_buf_score(0, 0));
    TEST_ASSERT_EQUAL_UINT8(0x20, qc_buf_score(0, 1));
}

static void test_drain_order(void) {
    static uint8_t out[512];
    size_t n;
    uint8_t cls;

    qc_buf_init(&buf);
    /* Insert out of order: C0, C1, C2 mix across epochs. */
    fill(0xC0, 100);
    TEST_ASSERT_EQUAL_INT(QC_BUF_OK,
        qc_buf_insert(&buf, payload, 100, 0, qc_buf_score(0, 0),
                      1, 5, 1000));
    fill(0xC1, 100);
    TEST_ASSERT_EQUAL_INT(QC_BUF_OK,
        qc_buf_insert(&buf, payload, 100, 1, qc_buf_score(1, 0),
                      1, 6, 1001));
    fill(0xA2, 100);
    TEST_ASSERT_EQUAL_INT(QC_BUF_OK,
        qc_buf_insert(&buf, payload, 100, 2, qc_buf_score(2, 0),
                      2, 0, 1002));
    fill(0xA1, 100);
    TEST_ASSERT_EQUAL_INT(QC_BUF_OK,
        qc_buf_insert(&buf, payload, 100, 2, qc_buf_score(2, 0),
                      1, 99, 1003));
    /* C2 epoch-major first: (1,99) then (2,0); then chrono C1, C0. */
    TEST_ASSERT_EQUAL_INT(QC_BUF_OK,
        qc_buf_pop(&buf, out, sizeof(out), &n, &cls, NULL, NULL, 1010));
    TEST_ASSERT_EQUAL_UINT(100, n);
    TEST_ASSERT_EQUAL_UINT8(2, cls);
    TEST_ASSERT_EQUAL_UINT8(0xA1, out[0]);
    TEST_ASSERT_EQUAL_INT(QC_BUF_OK,
        qc_buf_pop(&buf, out, sizeof(out), &n, &cls, NULL, NULL, 1010));
    TEST_ASSERT_EQUAL_UINT8(0xA2, out[0]);
    /* Non-C2 drains chronologically: C0 (at 1000) before C1 (at 1001). */
    TEST_ASSERT_EQUAL_INT(QC_BUF_OK,
        qc_buf_pop(&buf, out, sizeof(out), &n, &cls, NULL, NULL, 1010));
    TEST_ASSERT_EQUAL_UINT8(0, cls);
    TEST_ASSERT_EQUAL_UINT8(0xC0, out[0]);
    TEST_ASSERT_EQUAL_INT(QC_BUF_OK,
        qc_buf_pop(&buf, out, sizeof(out), &n, &cls, NULL, NULL, 1010));
    TEST_ASSERT_EQUAL_UINT8(1, cls);
    TEST_ASSERT_EQUAL_INT(QC_BUF_EMPTY,
        qc_buf_pop(&buf, out, sizeof(out), &n, &cls, NULL, NULL, 1010));
}

/* Lowest-score-first eviction, oldest-tie (FIFO within score). */
static void test_evict_order(void) {
    static uint8_t out[1024];
    size_t n;
    qc_buf_counters c;
    int i;

    qc_buf_init(&buf);
    /* 16 x 1024 B C0 = full cap. Distinct first bytes + ages. */
    for (i = 0; i < 16; i++) {
        fill((uint8_t)i, 1024);
        TEST_ASSERT_EQUAL_INT(QC_BUF_OK,
            qc_buf_insert(&buf, payload, 1024, 0, qc_buf_score(0, 0),
                          1, (uint64_t)i, (uint64_t)(1000 + i)));
    }
    /* C1 100 B forces eviction of the OLDEST C0 (all score 0x10). */
    fill(0xE1, 100);
    TEST_ASSERT_EQUAL_INT(QC_BUF_OK,
        qc_buf_insert(&buf, payload, 100, 1, qc_buf_score(1, 0),
                      1, 100, 2000));
    qc_buf_counts(&buf, &c);
    TEST_ASSERT_EQUAL_UINT(1, c.evicted);
    /* Oldest C0 (first byte 0) is gone: no pop yields it first... drain
     * all C0 and check byte 0 never appears. */
    {
        int seen0 = 0, total = 0;
        while (qc_buf_pop(&buf, out, sizeof(out), &n, NULL, NULL, NULL,
                          2001) == QC_BUF_OK) {
            total++;
            if (n == 1024 && out[0] == 0) {
                seen0 = 1;
            }
        }
        TEST_ASSERT_EQUAL_INT(0, seen0);
        TEST_ASSERT_EQUAL_INT(16, total); /* 15 C0 + 1 C1 */
    }
}

/* C2 pinning: non-C2 blocked by pinned C2 is DROPPED, C2 intact. */
static void test_pinning(void) {
    static uint8_t out[2048];
    size_t n;
    uint8_t cls;
    qc_buf_counters c;
    int i;

    qc_buf_init(&buf);
    for (i = 0; i < 8; i++) {
        fill((uint8_t)(0xC0 + i), 1024);
        TEST_ASSERT_EQUAL_INT(QC_BUF_OK,
            qc_buf_insert(&buf, payload, 1024, 2, qc_buf_score(2, 0),
                          1, (uint64_t)i, 1000));
    }
    TEST_ASSERT_EQUAL_UINT(QC_BUF_C2_RSV, qc_buf_used(&buf));
    fill(0xD0, 9000);
    TEST_ASSERT_EQUAL_INT(QC_BUF_DROPPED,
        qc_buf_insert(&buf, payload, 9000, 0, qc_buf_score(0, 0),
                      1, 50, 1001));
    qc_buf_counts(&buf, &c);
    TEST_ASSERT_EQUAL_UINT(1, c.dropped);
    TEST_ASSERT_EQUAL_UINT(0, c.evicted);
    /* All 8 C2 intact. */
    for (i = 0; i < 8; i++) {
        TEST_ASSERT_EQUAL_INT(QC_BUF_OK,
            qc_buf_pop(&buf, out, sizeof(out), &n, &cls, NULL, NULL,
                       1002));
        TEST_ASSERT_EQUAL_UINT8(2, cls);
    }
}

/* Mixed pinning (audit): C2 at reservation + C0 bulk — a C1 insert
 * evicts C0 only; all 8 C2 survive. */
static void test_mixed_pinning(void) {
    static uint8_t out[2048];
    size_t n;
    uint8_t cls;
    qc_buf_counters c;
    int i, nc2 = 0, total = 0;

    qc_buf_init(&buf);
    for (i = 0; i < 8; i++) {
        fill((uint8_t)(0xC0 + i), 1024);
        TEST_ASSERT_EQUAL_INT(QC_BUF_OK,
            qc_buf_insert(&buf, payload, 1024, 2, qc_buf_score(2, 0),
                          1, (uint64_t)i, 1000));
    }
    for (i = 0; i < 8; i++) {
        fill((uint8_t)i, 1024);
        TEST_ASSERT_EQUAL_INT(QC_BUF_OK,
            qc_buf_insert(&buf, payload, 1024, 0, qc_buf_score(0, 0),
                          1, (uint64_t)(100 + i), (uint64_t)(1000 + i)));
    }
    fill(0xE1, 100);
    TEST_ASSERT_EQUAL_INT(QC_BUF_OK,
        qc_buf_insert(&buf, payload, 100, 1, qc_buf_score(1, 0),
                      1, 200, 2000));
    qc_buf_counts(&buf, &c);
    TEST_ASSERT_EQUAL_UINT(1, c.evicted);
    while (qc_buf_pop(&buf, out, sizeof(out), &n, &cls, NULL, NULL,
                      2001) == QC_BUF_OK) {
        total++;
        if (cls == 2) {
            nc2++;
        }
    }
    TEST_ASSERT_EQUAL_INT(8, nc2);
    TEST_ASSERT_EQUAL_INT(16, total); /* 8 C2 + 7 C0 + 1 C1 */
}

/* Past reservation with only pinned C2 left: C2 insert -> PRESSURE. */
static void test_pressure(void) {
    qc_buf_counters c;
    int i;

    qc_buf_init(&buf);
    for (i = 0; i < 8; i++) {
        fill((uint8_t)i, 1024);
        TEST_ASSERT_EQUAL_INT(QC_BUF_OK,
            qc_buf_insert(&buf, payload, 1024, 2, qc_buf_score(2, 0),
                          1, (uint64_t)i, 1000));
    }
    fill(0xF2, 9000);
    TEST_ASSERT_EQUAL_INT(QC_BUF_C2_PRESSURE,
        qc_buf_insert(&buf, payload, 9000, 2, qc_buf_score(2, 0),
                      1, 60, 1001));
    qc_buf_counts(&buf, &c);
    TEST_ASSERT_EQUAL_UINT(1, c.pressure);
}

/* C2 past reservation IS evictable (uniform lowest-score rule). */
static void test_excess_evict(void) {
    static uint8_t out[2048];
    size_t n;
    qc_buf_counters c;
    int i;

    qc_buf_init(&buf);
    for (i = 0; i < 16; i++) {
        fill((uint8_t)i, 1024);
        TEST_ASSERT_EQUAL_INT(QC_BUF_OK,
            qc_buf_insert(&buf, payload, 1024, 2, qc_buf_score(2, 0),
                          1, (uint64_t)i, (uint64_t)(1000 + i)));
    }
    fill(0xE0, 100);
    TEST_ASSERT_EQUAL_INT(QC_BUF_OK,
        qc_buf_insert(&buf, payload, 100, 0, qc_buf_score(0, 0),
                      1, 200, 2000));
    qc_buf_counts(&buf, &c);
    TEST_ASSERT_EQUAL_UINT(1, c.evicted);
    /* Oldest C2 (byte 0) gave way to the C0. */
    {
        int seenc0 = 0, seenc2_0 = 0, total = 0;
        while (qc_buf_pop(&buf, out, sizeof(out), &n, NULL, NULL, NULL,
                          2001) == QC_BUF_OK) {
            total++;
            if (n == 100 && out[0] == 0xE0) {
                seenc0 = 1;
            }
            if (n == 1024 && out[0] == 0) {
                seenc2_0 = 1;
            }
        }
        TEST_ASSERT_EQUAL_INT(1, seenc0);
        TEST_ASSERT_EQUAL_INT(0, seenc2_0);
        TEST_ASSERT_EQUAL_INT(16, total);
    }
}

/* TTL expiry per class + sweep + pop age. */
static void test_ttl(void) {
    static uint8_t out[256];
    size_t n;
    uint64_t age;
    qc_buf_counters c;

    qc_buf_init(&buf);
    fill(0xC0, 50);
    TEST_ASSERT_EQUAL_INT(QC_BUF_OK,
        qc_buf_insert(&buf, payload, 50, 0, qc_buf_score(0, 0),
                      1, 1, 100000));
    fill(0xC2, 50);
    TEST_ASSERT_EQUAL_INT(QC_BUF_OK,
        qc_buf_insert(&buf, payload, 50, 2, qc_buf_score(2, 0),
                      1, 2, 100000));
    /* C0 TTL 6 h: alive at +1 h with age reported... */
    TEST_ASSERT_EQUAL_INT(QC_BUF_OK,
        qc_buf_pop(&buf, out, sizeof(out), &n, NULL, NULL, &age,
                   100000 + 3600));
    /* ...but pop took the C2 first (tier order); re-check by class. */
    (void)n;
    qc_buf_init(&buf);
    fill(0xC0, 50);
    TEST_ASSERT_EQUAL_INT(QC_BUF_OK,
        qc_buf_insert(&buf, payload, 50, 0, qc_buf_score(0, 0),
                      1, 1, 100000));
    TEST_ASSERT_EQUAL_INT(QC_BUF_OK,
        qc_buf_insert(&buf, payload, 50, 0, qc_buf_score(0, 0),
                      1, 2, 100000));
    TEST_ASSERT_EQUAL_INT(QC_BUF_OK,
        qc_buf_pop(&buf, out, sizeof(out), &n, NULL, NULL, &age,
                   100000 + 3600));
    TEST_ASSERT_EQUAL_UINT64(3600, age);
    /* Past C0 TTL: the remaining entry is gone, counted. */
    qc_buf_sweep(&buf, 100000 + QC_BUF_TTL_C0 + 1);
    qc_buf_counts(&buf, &c);
    TEST_ASSERT_EQUAL_UINT(1, c.expired_other);
    TEST_ASSERT_EQUAL_INT(QC_BUF_EMPTY,
        qc_buf_pop(&buf, out, sizeof(out), &n, NULL, NULL, NULL,
                   100000 + QC_BUF_TTL_C0 + 1));
    /* C2 expiry has its own counter. */
    qc_buf_init(&buf);
    fill(0xC2, 50);
    TEST_ASSERT_EQUAL_INT(QC_BUF_OK,
        qc_buf_insert(&buf, payload, 50, 2, qc_buf_score(2, 0),
                      1, 2, 100000));
    TEST_ASSERT_EQUAL_INT(QC_BUF_EMPTY,
        qc_buf_pop(&buf, out, sizeof(out), &n, NULL, NULL, NULL,
                   100000 + QC_BUF_TTL_C2 + 1));
    qc_buf_counts(&buf, &c);
    TEST_ASSERT_EQUAL_UINT(1, c.expired_c2);
}

/* SMALL_BUF retains; reinsert preserves age, refuses expired. */
static void test_pop_reinsert(void) {
    static uint8_t out[64];
    size_t n;
    uint64_t age;
    qc_buf_counters c;

    qc_buf_init(&buf);
    fill(0xAA, 100);
    TEST_ASSERT_EQUAL_INT(QC_BUF_OK,
        qc_buf_insert(&buf, payload, 100, 1, qc_buf_score(1, 0),
                      3, 7, 5000));
    TEST_ASSERT_EQUAL_INT(QC_BUF_SMALL_BUF,
        qc_buf_pop(&buf, out, 10, &n, NULL, NULL, NULL, 5001));
    TEST_ASSERT_EQUAL_UINT(100, n);
    /* Still there: full pop works. */
    {
        static uint8_t big[128];
        TEST_ASSERT_EQUAL_INT(QC_BUF_OK,
            qc_buf_pop(&buf, big, sizeof(big), &n, NULL, NULL, &age,
                       5001));
        TEST_ASSERT_EQUAL_UINT64(1, age);
    }
    /* Reinsert with old `at`: age preserved. */
    qc_buf_init(&buf);
    fill(0xBB, 60);
    TEST_ASSERT_EQUAL_INT(QC_BUF_OK,
        qc_buf_reinsert(&buf, payload, 60, 1, qc_buf_score(1, 0),
                        3, 8, 5000, 5100));
    {
        static uint8_t big[128];
        TEST_ASSERT_EQUAL_INT(QC_BUF_OK,
            qc_buf_pop(&buf, big, sizeof(big), &n, NULL, NULL, &age,
                       5100));
        TEST_ASSERT_EQUAL_UINT64(100, age);
    }
    /* Reinsert past TTL: EXPIRED + counted. */
    TEST_ASSERT_EQUAL_INT(QC_BUF_EXPIRED,
        qc_buf_reinsert(&buf, payload, 60, 1, qc_buf_score(1, 0),
                        3, 9, 5000, 5000 + QC_BUF_TTL_C1 + 1));
    qc_buf_counts(&buf, &c);
    TEST_ASSERT_EQUAL_UINT(1, c.expired_other);
}

/* Mirror roundtrip: age survives reboot; absent OK; corrupt BAD_ARG. */
static void test_mirror(void) {
    static uint8_t out[256];
    size_t n;
    uint64_t age;
    uint8_t cls;
    qc_buf_counters c;

    qc_buf_init(&buf);
    fill(0xC2, 80);
    TEST_ASSERT_EQUAL_INT(QC_BUF_OK,
        qc_buf_insert(&buf, payload, 80, 2, qc_buf_score(2, 0),
                      4, 11, 20000));
    fill(0xC0, 80);
    TEST_ASSERT_EQUAL_INT(QC_BUF_OK,
        qc_buf_insert(&buf, payload, 80, 0, qc_buf_score(0, 0),
                      4, 12, 20000));
    TEST_ASSERT_EQUAL_INT(QC_BUF_OK, qc_buf_mirror_save(&buf, MPATH));
    qc_buf_counts(&buf, &c);
    TEST_ASSERT_EQUAL_UINT(1, c.mirror_writes);
    /* Reboot into a fresh buffer at +100 s: only the C2 comes back,
     * with its original age. */
    qc_buf_init(&buf);
    TEST_ASSERT_EQUAL_INT(QC_BUF_OK,
        qc_buf_mirror_load(&buf, MPATH, 20100));
    TEST_ASSERT_EQUAL_INT(QC_BUF_OK,
        qc_buf_pop(&buf, out, sizeof(out), &n, &cls, NULL, &age,
                   20100));
    TEST_ASSERT_EQUAL_UINT8(2, cls);
    TEST_ASSERT_EQUAL_UINT8(0xC2, out[0]);
    TEST_ASSERT_EQUAL_UINT64(100, age);
    TEST_ASSERT_EQUAL_INT(QC_BUF_EMPTY,
        qc_buf_pop(&buf, out, sizeof(out), &n, &cls, NULL, NULL,
                   20100));
    /* Absent mirror: OK (nothing to repopulate). */
    remove(MPATH2);
    qc_buf_init(&buf);
    TEST_ASSERT_EQUAL_INT(QC_BUF_OK,
        qc_buf_mirror_load(&buf, MPATH2, 20100));
    /* Corrupt mirror: BAD_ARG. */
    {
        FILE *f = fopen(MPATH2, "wb");
        static const uint8_t junk[] = { 'X', 'X', 'X', 'X', 0, 9 };
        TEST_ASSERT_NOT_NULL(f);
        TEST_ASSERT_EQUAL_UINT(sizeof(junk),
                               fwrite(junk, 1, sizeof(junk), f));
        fclose(f);
    }
    TEST_ASSERT_EQUAL_INT(QC_BUF_BAD_ARG,
        qc_buf_mirror_load(&buf, MPATH2, 20100));
    remove(MPATH);
    remove(MPATH2);
}

static void test_guards(void) {
    static uint8_t out[64];
    static uint8_t big[QC_BUF_CAP + 1];
    size_t n;
    qc_buf uninit;

    memset(&uninit, 0, sizeof(uninit));
    fill(0x11, 10);
    TEST_ASSERT_EQUAL_INT(QC_BUF_BAD_ARG,
        qc_buf_insert(NULL, payload, 10, 0, 0, 1, 1, 1));
    TEST_ASSERT_EQUAL_INT(QC_BUF_BAD_ARG,
        qc_buf_insert(&uninit, payload, 10, 0, 0, 1, 1, 1));
    TEST_ASSERT_EQUAL_INT(QC_BUF_BAD_ARG,
        qc_buf_insert(&buf, NULL, 10, 0, 0, 1, 1, 1));
    TEST_ASSERT_EQUAL_INT(QC_BUF_BAD_ARG,
        qc_buf_insert(&buf, payload, 0, 0, 0, 1, 1, 1));
    TEST_ASSERT_EQUAL_INT(QC_BUF_BAD_ARG,
        qc_buf_insert(&buf, payload, 10, 9, 0, 1, 1, 1));
    qc_buf_init(&buf);
    TEST_ASSERT_EQUAL_INT(QC_BUF_BAD_ARG,
        qc_buf_insert(&buf, big, sizeof(big), 0, 0, 1, 1, 1));
    TEST_ASSERT_EQUAL_INT(QC_BUF_BAD_ARG,
        qc_buf_pop(NULL, out, sizeof(out), &n, NULL, NULL, NULL, 1));
    TEST_ASSERT_EQUAL_INT(QC_BUF_BAD_ARG,
        qc_buf_pop(&buf, out, sizeof(out), NULL, NULL, NULL, NULL, 1));
    TEST_ASSERT_EQUAL_INT(QC_BUF_BAD_ARG,
        qc_buf_mirror_save(NULL, MPATH));
    TEST_ASSERT_EQUAL_INT(QC_BUF_BAD_ARG,
        qc_buf_mirror_load(NULL, MPATH, 1));
    TEST_ASSERT_EQUAL_UINT(0, qc_buf_used(NULL));
    qc_buf_sweep(NULL, 1);
    qc_buf_init(NULL);
}

void setUp(void) {
    remove(MPATH);
    remove(MPATH2);
}
void tearDown(void) {}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_score);
    RUN_TEST(test_drain_order);
    RUN_TEST(test_evict_order);
    RUN_TEST(test_pinning);
    RUN_TEST(test_mixed_pinning);
    RUN_TEST(test_pressure);
    RUN_TEST(test_excess_evict);
    RUN_TEST(test_ttl);
    RUN_TEST(test_pop_reinsert);
    RUN_TEST(test_mirror);
    RUN_TEST(test_guards);
    return UNITY_END();
}
