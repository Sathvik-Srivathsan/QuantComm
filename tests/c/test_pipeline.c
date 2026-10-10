/* test_pipeline.c — B-24 cross-unit composition probe (audit-driven).
 *
 * Proves batch -> frame -> buffer -> drain -> open compose with order
 * and crypto intact (the clash probe found no spec/code collisions; this
 * TU proves the composition the sweep reasoned about):
 *   readings (mixed C0/C1) -> batch closes on N_b -> FIFO drain ->
 *   framed with ascending B-23 counters -> buffered (outage) ->
 *   drained -> opened: payloads, classes, counters exact and ordered.
 * Plus the cross-unit tier proof: a C2 framed directly (never batched —
 * C2_BYPASS) and enqueued LAST still drains FIRST, then the rest in
 * (epoch,counter) order. Replay-safety shape holds: wire bytes travel
 * the buffer verbatim (no re-encryption), counters strictly ascend.
 */
#include "unity.h"

#include <string.h>

#include "qc_aead.h"
#include "qc_batch.h"
#include "qc_buf.h"
#include "qc_frame.h"

static const uint8_t KEY[32] = {
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F
};

static const uint8_t IDENT[16] = {
    0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7,
    0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF
};

#define EPOCH 7u
#define N_READINGS 5

static qc_batch batch;
static qc_buf buf;
static uint8_t wire[N_READINGS + 1][256];
static size_t wire_len[N_READINGS + 1];
static uint8_t wire_cls[N_READINGS + 1];

static void test_compose(void) {
    /* Five readings: classes {0,1,0,1,0}, distinct first bytes. */
    static const uint8_t classes[N_READINGS] = { 0, 1, 0, 1, 0 };
    static const uint8_t marks[N_READINGS] = { 0xA0, 0xA1, 0xA2,
                                               0xA3, 0xA4 };
    static uint8_t reading[64], payload[64], pt[64];
    qc_batch_close reason = QC_BATCH_OPEN;
    uint64_t counter = 0;
    int i;

    qc_batch_init(&batch);
    qc_buf_init(&buf);
    for (i = 0; i < N_READINGS; i++) {
        memset(reading, marks[i], sizeof(reading));
        TEST_ASSERT_EQUAL_INT(QC_BATCH_OK,
            qc_batch_insert(&batch, reading, sizeof(reading),
                            classes[i], (uint64_t)(1000 + i)));
    }
    TEST_ASSERT_EQUAL_INT(1,
        qc_batch_ready(&batch, N_READINGS, 60, 300, 1005, &reason));
    TEST_ASSERT_EQUAL_INT(QC_BATCH_COUNT, (int)reason);
    /* Drain batch -> frame each with ascending counters -> buffer. */
    for (i = 0; i < N_READINGS; i++) {
        qc_frame_fields f;
        size_t rlen, flen;
        uint8_t cls;

        TEST_ASSERT_EQUAL_INT(QC_BATCH_OK,
            qc_batch_pop(&batch, payload, sizeof(payload), &rlen,
                         &cls, NULL, 1006));
        TEST_ASSERT_EQUAL_UINT(sizeof(reading), rlen);
        TEST_ASSERT_EQUAL_UINT8(classes[i], cls);
        memset(&f, 0, sizeof(f));
        memcpy(f.identity, IDENT, sizeof(IDENT));
        f.cls = cls;
        f.level = 1;
        f.counter = counter;
        f.payload = payload;
        f.payload_len = rlen;
        flen = qc_frame_len(rlen);
        TEST_ASSERT_TRUE(flen > 0 && flen <= sizeof(wire[0]));
        TEST_ASSERT_EQUAL_INT(QC_FRAME_OK,
            qc_frame_protect(&f, EPOCH, KEY, wire[i], flen));
        wire_len[i] = flen;
        wire_cls[i] = cls;
        TEST_ASSERT_EQUAL_INT(QC_BUF_OK,
            qc_buf_insert(&buf, wire[i], flen, cls,
                          qc_buf_score(cls, 0), EPOCH, counter,
                          (uint64_t)(1010 + i)));
        counter++;
    }
    /* Drain buffer -> open: exact payloads, classes, ascending counters. */
    for (i = 0; i < N_READINGS; i++) {
        static uint8_t frame[256];
        size_t flen;
        uint8_t cls;
        qc_frame_parsed p;

        TEST_ASSERT_EQUAL_INT(QC_BUF_OK,
            qc_buf_pop(&buf, frame, sizeof(frame), &flen, &cls,
                       NULL, NULL, 1020));
        TEST_ASSERT_EQUAL_UINT(wire_len[i], flen);
        TEST_ASSERT_EQUAL_UINT8(wire_cls[i], cls);
        TEST_ASSERT_EQUAL_INT(QC_FRAME_OK,
            qc_frame_open(frame, flen, KEY, EPOCH, pt, sizeof(pt),
                          &p));
        TEST_ASSERT_EQUAL_UINT(sizeof(reading), p.payload_len);
        TEST_ASSERT_EQUAL_UINT8(marks[i], pt[0]);
        TEST_ASSERT_EQUAL_UINT8(wire_cls[i], p.cls);
        TEST_ASSERT_EQUAL_UINT64((uint64_t)i, p.counter);
    }
    {
        static uint8_t frame[256];
        size_t flen;
        uint8_t cls;
        TEST_ASSERT_EQUAL_INT(QC_BUF_EMPTY,
            qc_buf_pop(&buf, frame, sizeof(frame), &flen, &cls, NULL,
                       NULL, 1020));
    }
}

/* C2 bypasses the batch, frames directly, buffers, yet drains first. */
static void test_c2_tier_across_units(void) {
    static uint8_t reading[32], payload[32], pt[32], frame[256];
    qc_frame_fields f;
    size_t rlen, flen;
    uint8_t cls;
    qc_frame_parsed p;
    int i;

    qc_batch_init(&batch);
    qc_buf_init(&buf);
    /* Two C0 readings batched + buffered first... */
    for (i = 0; i < 2; i++) {
        memset(reading, (uint8_t)(0xB0 + i), sizeof(reading));
        TEST_ASSERT_EQUAL_INT(QC_BATCH_OK,
            qc_batch_insert(&batch, reading, sizeof(reading), 0,
                            (uint64_t)(1000 + i)));
        TEST_ASSERT_EQUAL_INT(QC_BATCH_OK,
            qc_batch_pop(&batch, payload, sizeof(payload), &rlen,
                         NULL, NULL, 1010));
        memset(&f, 0, sizeof(f));
        memcpy(f.identity, IDENT, sizeof(IDENT));
        f.cls = 0;
        f.level = 1;
        f.counter = (uint64_t)i;
        f.payload = payload;
        f.payload_len = rlen;
        flen = qc_frame_len(rlen);
        TEST_ASSERT_EQUAL_INT(QC_FRAME_OK,
            qc_frame_protect(&f, EPOCH, KEY, wire[i], flen));
        wire_len[i] = flen;
        TEST_ASSERT_EQUAL_INT(QC_BUF_OK,
            qc_buf_insert(&buf, wire[i], flen, 0,
                          qc_buf_score(0, 0), EPOCH, (uint64_t)i,
                          1010));
    }
    /* ...then a C2 refused by the batch, framed + buffered directly. */
    memset(reading, 0xC2, sizeof(reading));
    TEST_ASSERT_EQUAL_INT(QC_BATCH_C2_BYPASS,
        qc_batch_insert(&batch, reading, sizeof(reading), 2, 1020));
    memset(&f, 0, sizeof(f));
    memcpy(f.identity, IDENT, sizeof(IDENT));
    f.cls = 2;
    f.level = 1;
    f.counter = 2;
    f.payload = reading;
    f.payload_len = sizeof(reading);
    flen = qc_frame_len(sizeof(reading));
    TEST_ASSERT_EQUAL_INT(QC_FRAME_OK,
        qc_frame_protect(&f, EPOCH, KEY, wire[2], flen));
    TEST_ASSERT_EQUAL_INT(QC_BUF_OK,
        qc_buf_insert(&buf, wire[2], flen, 2, qc_buf_score(2, 0),
                      EPOCH, 2, 1021));
    /* Drain: C2 (counter 2) first despite last enqueue, then 0, 1. */
    TEST_ASSERT_EQUAL_INT(QC_BUF_OK,
        qc_buf_pop(&buf, frame, sizeof(frame), &flen, &cls, NULL,
                   NULL, 1030));
    TEST_ASSERT_EQUAL_UINT8(2, cls);
    TEST_ASSERT_EQUAL_INT(QC_FRAME_OK,
        qc_frame_open(frame, flen, KEY, EPOCH, pt, sizeof(pt), &p));
    TEST_ASSERT_EQUAL_UINT64(2, p.counter);
    TEST_ASSERT_EQUAL_UINT8(0xC2, pt[0]);
    for (i = 0; i < 2; i++) {
        TEST_ASSERT_EQUAL_INT(QC_BUF_OK,
            qc_buf_pop(&buf, frame, sizeof(frame), &flen, &cls,
                       NULL, NULL, 1030));
        TEST_ASSERT_EQUAL_UINT8(0, cls);
        TEST_ASSERT_EQUAL_INT(QC_FRAME_OK,
            qc_frame_open(frame, flen, KEY, EPOCH, pt, sizeof(pt),
                          &p));
        TEST_ASSERT_EQUAL_UINT64((uint64_t)i, p.counter);
        TEST_ASSERT_EQUAL_UINT8((uint8_t)(0xB0 + i), pt[0]);
    }
}

void setUp(void) {}
void tearDown(void) {}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_compose);
    RUN_TEST(test_c2_tier_across_units);
    return UNITY_END();
}
