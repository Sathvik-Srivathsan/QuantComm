/* test_batch.c — L0/L1/L2 for transmission batching (B-24.2 host core).
 *
 * Covers: empty-open, close-on-count, close-on-latency per class (test
 * bounds t_c0=60/t_c1=300 — LABELED TEST VALUES, not spec provisionals:
 * B-31 owns the real bounds), latency-forces-transmit (never drops),
 * C2 bypass (+counter, malformed C2 still BAD_ARG), FULL (slot + byte
 * caps), N_b change mid-batch, FIFO order + equal-at stability,
 * SMALL_BUF retain, EMPTY, guards. Batch structs are ~5 KB: static,
 * never stack (house rule).
 */
#include "unity.h"

#include <string.h>

#include "qc_batch.h"

/* Test latency bounds (NOT provisional spec values — B-31 values these;
 * any distinct pair exercises the per-class logic). */
#define T_C0 60u
#define T_C1 300u

static qc_batch b;
/* Sized to QC_BATCH_CAP: byte-cap tests insert up to 4000 B. */
static uint8_t payload[4 * 1024];

static void fill(uint8_t v, size_t n) {
    memset(payload, v, n);
}

static void test_empty_guards(void) {
    qc_batch_close reason = QC_BATCH_COUNT;
    qc_batch uninit;
    static uint8_t out[64];
    size_t n;

    memset(&uninit, 0, sizeof(uninit));
    qc_batch_init(&b);
    TEST_ASSERT_EQUAL_INT(0,
        qc_batch_ready(&b, 3, T_C0, T_C1, 1000, &reason));
    TEST_ASSERT_EQUAL_INT(QC_BATCH_OPEN, (int)reason);
    TEST_ASSERT_EQUAL_INT(-1,
        qc_batch_ready(&b, 0, T_C0, T_C1, 1000, &reason));
    TEST_ASSERT_EQUAL_INT(-1,
        qc_batch_ready(&b, 33, T_C0, T_C1, 1000, &reason));
    TEST_ASSERT_EQUAL_INT(-1,
        qc_batch_ready(NULL, 3, T_C0, T_C1, 1000, &reason));
    TEST_ASSERT_EQUAL_INT(-1,
        qc_batch_ready(&uninit, 3, T_C0, T_C1, 1000, &reason));
    TEST_ASSERT_EQUAL_INT(-1,
        qc_batch_ready(&b, 3, T_C0, T_C1, 1000, NULL));
    TEST_ASSERT_EQUAL_INT(QC_BATCH_BAD_ARG,
        qc_batch_insert(NULL, payload, 10, 0, 1000));
    TEST_ASSERT_EQUAL_INT(QC_BATCH_BAD_ARG,
        qc_batch_insert(&uninit, payload, 10, 0, 1000));
    TEST_ASSERT_EQUAL_INT(QC_BATCH_BAD_ARG,
        qc_batch_insert(&b, NULL, 10, 0, 1000));
    TEST_ASSERT_EQUAL_INT(QC_BATCH_BAD_ARG,
        qc_batch_insert(&b, payload, 0, 0, 1000));
    TEST_ASSERT_EQUAL_INT(QC_BATCH_BAD_ARG,
        qc_batch_insert(&b, payload, 10, 9, 1000));
    TEST_ASSERT_EQUAL_INT(QC_BATCH_BAD_ARG,
        qc_batch_pop(NULL, out, sizeof(out), &n, NULL, NULL, 1000));
    TEST_ASSERT_EQUAL_INT(QC_BATCH_BAD_ARG,
        qc_batch_pop(&b, out, sizeof(out), NULL, NULL, NULL, 1000));
    TEST_ASSERT_EQUAL_INT(QC_BATCH_EMPTY,
        qc_batch_pop(&b, out, sizeof(out), &n, NULL, NULL, 1000));
    qc_batch_init(NULL);
}

static void test_close_count(void) {
    static uint8_t out[64];
    size_t n;
    uint8_t cls;
    qc_batch_close reason = QC_BATCH_OPEN;

    qc_batch_init(&b);
    fill(0xA0, 20);
    TEST_ASSERT_EQUAL_INT(QC_BATCH_OK,
        qc_batch_insert(&b, payload, 20, 0, 1000));
    fill(0xA1, 20);
    TEST_ASSERT_EQUAL_INT(QC_BATCH_OK,
        qc_batch_insert(&b, payload, 20, 1, 1001));
    TEST_ASSERT_EQUAL_INT(0,
        qc_batch_ready(&b, 3, T_C0, T_C1, 1002, &reason));
    TEST_ASSERT_EQUAL_INT(QC_BATCH_OPEN, (int)reason);
    fill(0xA2, 20);
    TEST_ASSERT_EQUAL_INT(QC_BATCH_OK,
        qc_batch_insert(&b, payload, 20, 0, 1002));
    TEST_ASSERT_EQUAL_INT(1,
        qc_batch_ready(&b, 3, T_C0, T_C1, 1002, &reason));
    TEST_ASSERT_EQUAL_INT(QC_BATCH_COUNT, (int)reason);
    /* FIFO drain for framing. */
    TEST_ASSERT_EQUAL_INT(QC_BATCH_OK,
        qc_batch_pop(&b, out, sizeof(out), &n, &cls, NULL, 1003));
    TEST_ASSERT_EQUAL_UINT8(0xA0, out[0]);
    TEST_ASSERT_EQUAL_UINT8(0, cls);
    TEST_ASSERT_EQUAL_INT(QC_BATCH_OK,
        qc_batch_pop(&b, out, sizeof(out), &n, &cls, NULL, 1003));
    TEST_ASSERT_EQUAL_UINT8(0xA1, out[0]);
    TEST_ASSERT_EQUAL_UINT8(1, cls);
    TEST_ASSERT_EQUAL_INT(QC_BATCH_OK,
        qc_batch_pop(&b, out, sizeof(out), &n, NULL, NULL, 1003));
    TEST_ASSERT_EQUAL_INT(QC_BATCH_EMPTY,
        qc_batch_pop(&b, out, sizeof(out), &n, NULL, NULL, 1003));
}

static void test_close_latency(void) {
    static uint8_t out[64];
    size_t n;
    uint64_t age;
    qc_batch_close reason = QC_BATCH_OPEN;

    /* C0 bound fires; C1 with a longer bound stays open. */
    qc_batch_init(&b);
    fill(0xB0, 20);
    TEST_ASSERT_EQUAL_INT(QC_BATCH_OK,
        qc_batch_insert(&b, payload, 20, 0, 1000));
    TEST_ASSERT_EQUAL_INT(0,
        qc_batch_ready(&b, 10, T_C0, T_C1, 1000 + T_C0 - 1, &reason));
    TEST_ASSERT_EQUAL_INT(1,
        qc_batch_ready(&b, 10, T_C0, T_C1, 1000 + T_C0, &reason));
    TEST_ASSERT_EQUAL_INT(QC_BATCH_LATENCY, (int)reason);
    qc_batch_init(&b);
    fill(0xB1, 20);
    TEST_ASSERT_EQUAL_INT(QC_BATCH_OK,
        qc_batch_insert(&b, payload, 20, 1, 1000));
    TEST_ASSERT_EQUAL_INT(0,
        qc_batch_ready(&b, 10, T_C0, T_C1, 1000 + T_C0, &reason));
    TEST_ASSERT_EQUAL_INT(1,
        qc_batch_ready(&b, 10, T_C0, T_C1, 1000 + T_C1, &reason));
    TEST_ASSERT_EQUAL_INT(QC_BATCH_LATENCY, (int)reason);
    /* Over-age forces TRANSMIT (pops fine), never drops. */
    TEST_ASSERT_EQUAL_INT(QC_BATCH_OK,
        qc_batch_pop(&b, out, sizeof(out), &n, NULL, &age,
                     1000 + T_C1 + 500));
    TEST_ASSERT_EQUAL_UINT64(T_C1 + 500, age);
    TEST_ASSERT_EQUAL_UINT8(0xB1, out[0]);
}

static void test_c2_bypass(void) {
    qc_batch_counters c;

    qc_batch_init(&b);
    fill(0xC2, 20);
    TEST_ASSERT_EQUAL_INT(QC_BATCH_C2_BYPASS,
        qc_batch_insert(&b, payload, 20, 2, 1000));
    TEST_ASSERT_EQUAL_UINT(0, qc_batch_count(&b));
    /* Malformed C2 still BAD_ARG (bypass is not a loose gate). */
    TEST_ASSERT_EQUAL_INT(QC_BATCH_BAD_ARG,
        qc_batch_insert(&b, payload, 0, 2, 1000));
    TEST_ASSERT_EQUAL_INT(QC_BATCH_BAD_ARG,
        qc_batch_insert(&b, NULL, 20, 2, 1000));
    qc_batch_counts(&b, &c);
    TEST_ASSERT_EQUAL_UINT(1, c.c2_bypassed);
    TEST_ASSERT_EQUAL_UINT(0, c.inserted);
}

static void test_full(void) {
    qc_batch_counters c;
    int i;

    /* Slot cap: 32 x 10 B (bytes far below cap). */
    qc_batch_init(&b);
    for (i = 0; i < 32; i++) {
        fill((uint8_t)i, 10);
        TEST_ASSERT_EQUAL_INT(QC_BATCH_OK,
            qc_batch_insert(&b, payload, 10, 0, (uint64_t)i));
    }
    fill(0xFF, 10);
    TEST_ASSERT_EQUAL_INT(QC_BATCH_FULL,
        qc_batch_insert(&b, payload, 10, 0, 1000));
    /* Byte cap: 4000 + 200 > 4096 with free slots. */
    qc_batch_init(&b);
    fill(0xE0, 64);
    TEST_ASSERT_EQUAL_INT(QC_BATCH_OK,
        qc_batch_insert(&b, payload, 4000, 0, 1000));
    TEST_ASSERT_EQUAL_INT(QC_BATCH_FULL,
        qc_batch_insert(&b, payload, 200, 0, 1001));
    qc_batch_counts(&b, &c);
    TEST_ASSERT_EQUAL_UINT(1, c.refused_full);
    TEST_ASSERT_EQUAL_UINT(1, c.inserted);
}

static void test_nb_change_and_fifo(void) {
    static uint8_t out[64];
    size_t n;
    qc_batch_close reason = QC_BATCH_OPEN;

    /* N_b is per-decision: tightening mid-batch closes immediately. */
    qc_batch_init(&b);
    fill(0xD0, 10);
    TEST_ASSERT_EQUAL_INT(QC_BATCH_OK,
        qc_batch_insert(&b, payload, 10, 0, 5000));
    fill(0xD1, 10);
    TEST_ASSERT_EQUAL_INT(QC_BATCH_OK,
        qc_batch_insert(&b, payload, 10, 0, 5000));
    fill(0xD2, 10);
    TEST_ASSERT_EQUAL_INT(QC_BATCH_OK,
        qc_batch_insert(&b, payload, 10, 0, 5000));
    TEST_ASSERT_EQUAL_INT(0,
        qc_batch_ready(&b, 5, T_C0, T_C1, 5001, &reason));
    TEST_ASSERT_EQUAL_INT(1,
        qc_batch_ready(&b, 2, T_C0, T_C1, 5001, &reason));
    TEST_ASSERT_EQUAL_INT(QC_BATCH_COUNT, (int)reason);
    /* Equal-at FIFO: insertion order preserved. */
    TEST_ASSERT_EQUAL_INT(QC_BATCH_OK,
        qc_batch_pop(&b, out, sizeof(out), &n, NULL, NULL, 5002));
    TEST_ASSERT_EQUAL_UINT8(0xD0, out[0]);
    TEST_ASSERT_EQUAL_INT(QC_BATCH_SMALL_BUF,
        qc_batch_pop(&b, out, 5, &n, NULL, NULL, 5002));
    TEST_ASSERT_EQUAL_UINT(10, n);
    TEST_ASSERT_EQUAL_INT(QC_BATCH_OK,
        qc_batch_pop(&b, out, sizeof(out), &n, NULL, NULL, 5002));
    TEST_ASSERT_EQUAL_UINT8(0xD1, out[0]);
}

void setUp(void) {}
void tearDown(void) {}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_empty_guards);
    RUN_TEST(test_close_count);
    RUN_TEST(test_close_latency);
    RUN_TEST(test_c2_bypass);
    RUN_TEST(test_full);
    RUN_TEST(test_nb_change_and_fifo);
    return UNITY_END();
}
