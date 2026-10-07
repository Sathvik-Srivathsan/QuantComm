/* test_frame.c — L0/L1 for telemetry framing (B-24.1).
 *
 * Covers: roundtrip (all classes, empty + max payload), header-tamper
 * per region (identity/class/level/counter/last-root/range) -> AUTH_FAIL,
 * payload/tag/plen tamper, structural rejects (short/truncated/length
 * mismatch/oversize/bad class+level), SMALL_BUF sizing path, nonce
 * consistency (header counter == nonce counter half: wrong-epoch open
 * fails), empty-payload NULL discipline.
 */
#include "unity.h"

#include <string.h>

#include "qc_frame.h"

static const uint8_t KEY[32] = {
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
    0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7,
    0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF
};

static void fill_fields(qc_frame_fields *f, const uint8_t *pt, size_t pt_len) {
    int i;
    for (i = 0; i < 16; i++) {
        f->identity[i] = (uint8_t)(0x20 + i);
    }
    f->cls = QC_CLS_C1;
    f->level = 2;
    f->counter = 41;
    memset(f->last_root, 0x52, 32);
    f->range_start = 100;
    f->range_end = 141;
    f->payload = pt;
    f->payload_len = pt_len;
}

/* Roundtrip one payload across all classes + field echo. */
static void test_roundtrip(void) {
    static const uint8_t pt[] = { 't', 'e', 'm', 'p', '=', '3', '6' };
    static uint8_t frame[128], back[128];
    qc_frame_fields f;
    qc_frame_parsed p;

    for (int cls = 0; cls <= 2; cls++) {
        fill_fields(&f, pt, sizeof(pt));
        f.cls = (uint8_t)cls;
        TEST_ASSERT_EQUAL_INT(QC_FRAME_OK,
            qc_frame_protect(&f, 7u, KEY, frame, qc_frame_len(sizeof(pt))));
        TEST_ASSERT_EQUAL_INT(QC_FRAME_OK,
            qc_frame_open(frame, qc_frame_len(sizeof(pt)), KEY, 7u,
                          back, sizeof(back), &p));
        TEST_ASSERT_EQUAL_UINT8_ARRAY(pt, back, sizeof(pt));
        TEST_ASSERT_EQUAL_UINT8((uint8_t)cls, p.cls);
        TEST_ASSERT_EQUAL_UINT(2, p.level);
        TEST_ASSERT_EQUAL_UINT64(41, p.counter);
        TEST_ASSERT_EQUAL_UINT64(100, p.range_start);
        TEST_ASSERT_EQUAL_UINT64(141, p.range_end);
        TEST_ASSERT_EQUAL_UINT(sizeof(pt), p.payload_len);
        TEST_ASSERT_EQUAL_UINT8_ARRAY(f.identity, p.identity, 16);
    }
}

/* Empty payload (NULL, 0) roundtrips. */
static void test_empty(void) {
    static uint8_t frame[128];
    qc_frame_fields f;
    qc_frame_parsed p;

    fill_fields(&f, NULL, 0);
    TEST_ASSERT_EQUAL_INT(QC_FRAME_OK,
        qc_frame_protect(&f, 7u, KEY, frame, qc_frame_len(0)));
    TEST_ASSERT_EQUAL_INT(QC_FRAME_OK,
        qc_frame_open(frame, qc_frame_len(0), KEY, 7u, NULL, 0, &p));
    TEST_ASSERT_EQUAL_UINT(0, p.payload_len);
}

/* Flip one byte in every header region + ct + tag + plen: all fail. */
static void test_tamper(void) {
    static const uint8_t pt[] = { 'x', 'y' };
    static uint8_t frame[128], mod[128], back[128];
    qc_frame_fields f;
    qc_frame_parsed p;
    /* Offsets into a 2-byte-payload frame: id 0..15, cls 16, lvl 17,
     * counter 18..25, root 26..57, range 58..73, plen 74..77,
     * ct 78..79, tag 80..95. AAD/ct/tag flips -> AUTH_FAIL; plen flips
     * change the declared length -> structural OVERSIZE (also safe).
     * (Single-bit flips of cls=1/lvl=2 stay in-range (0/3), so they
     * exercise AAD binding rather than structural reject — intended.) */
    static const size_t offs_auth[] = {
        0, 15, 16, 17, 18, 25, 26, 57, 58, 65, 66, 73, 78, 79, 80, 95
    };
    static const size_t offs_len[] = { 74, 75, 76, 77 };

    fill_fields(&f, pt, sizeof(pt));
    TEST_ASSERT_EQUAL_INT(QC_FRAME_OK,
        qc_frame_protect(&f, 7u, KEY, frame, qc_frame_len(sizeof(pt))));
    for (size_t i = 0; i < sizeof(offs_auth) / sizeof(offs_auth[0]); i++) {
        memcpy(mod, frame, qc_frame_len(sizeof(pt)));
        mod[offs_auth[i]] ^= 0x01;
        TEST_ASSERT_EQUAL_INT_MESSAGE(QC_FRAME_AUTH_FAIL,
            qc_frame_open(mod, qc_frame_len(sizeof(pt)), KEY, 7u,
                          back, sizeof(back), &p), "tamper must fail auth");
    }
    for (size_t i = 0; i < sizeof(offs_len) / sizeof(offs_len[0]); i++) {
        memcpy(mod, frame, qc_frame_len(sizeof(pt)));
        mod[offs_len[i]] ^= 0x01;
        TEST_ASSERT_EQUAL_INT_MESSAGE(QC_FRAME_OVERSIZE,
            qc_frame_open(mod, qc_frame_len(sizeof(pt)), KEY, 7u,
                          back, sizeof(back), &p), "plen tamper structural");
    }
}

/* Structural rejects: short, truncated, length-mismatch, oversize. */
static void test_structural(void) {
    static const uint8_t pt[] = { 'q' };
    static uint8_t frame[128];
    qc_frame_fields f;
    qc_frame_parsed p;

    fill_fields(&f, pt, sizeof(pt));
    TEST_ASSERT_EQUAL_INT(QC_FRAME_OK,
        qc_frame_protect(&f, 7u, KEY, frame, qc_frame_len(sizeof(pt))));
    TEST_ASSERT_EQUAL_INT(QC_FRAME_OVERSIZE,
        qc_frame_open(frame, 10, KEY, 7u, NULL, 0, &p));
    TEST_ASSERT_EQUAL_INT(QC_FRAME_OVERSIZE,
        qc_frame_open(frame, qc_frame_len(sizeof(pt)) - 1, KEY, 7u,
                      NULL, 0, &p));
    TEST_ASSERT_EQUAL_INT(QC_FRAME_OVERSIZE,
        qc_frame_open(frame, qc_frame_len(sizeof(pt)) + 1, KEY, 7u,
                      NULL, 0, &p));
    TEST_ASSERT_EQUAL_INT(QC_FRAME_OVERSIZE,
        qc_frame_parse_header(frame, 10, &p));
    /* Bad class / level on protect + parse. */
    f.cls = 9;
    TEST_ASSERT_EQUAL_INT(QC_FRAME_BAD_VALUE,
        qc_frame_protect(&f, 7u, KEY, frame, sizeof(frame)));
    f.cls = QC_CLS_C1;
    f.level = 9;
    TEST_ASSERT_EQUAL_INT(QC_FRAME_BAD_VALUE,
        qc_frame_protect(&f, 7u, KEY, frame, sizeof(frame)));
    frame[16] = 9;
    TEST_ASSERT_EQUAL_INT(QC_FRAME_BAD_VALUE,
        qc_frame_open(frame, qc_frame_len(sizeof(pt)), KEY, 7u,
                      NULL, 0, &p));
    /* Oversize payload. */
    TEST_ASSERT_EQUAL_UINT(0, qc_frame_len(QC_FRAME_MAX_PAYLOAD + 1));
    f.level = 2;
    f.payload_len = QC_FRAME_MAX_PAYLOAD + 1;
    TEST_ASSERT_EQUAL_INT(QC_FRAME_OVERSIZE,
        qc_frame_protect(&f, 7u, KEY, frame, sizeof(frame)));
    /* NULL guards. */
    TEST_ASSERT_EQUAL_INT(QC_FRAME_BAD_ARG,
        qc_frame_protect(NULL, 7u, KEY, frame, sizeof(frame)));
    TEST_ASSERT_EQUAL_INT(QC_FRAME_BAD_ARG,
        qc_frame_open(NULL, 10, KEY, 7u, NULL, 0, &p));
}

/* SMALL_BUF sizing path + epoch consistency (wrong epoch fails). */
static void test_open_edges(void) {
    static const uint8_t pt[] = { 'a', 'b', 'c' };
    static uint8_t frame[128], back[2];
    qc_frame_fields f;
    qc_frame_parsed p;

    fill_fields(&f, pt, sizeof(pt));
    TEST_ASSERT_EQUAL_INT(QC_FRAME_OK,
        qc_frame_protect(&f, 7u, KEY, frame, qc_frame_len(sizeof(pt))));
    TEST_ASSERT_EQUAL_INT(QC_FRAME_SMALL_BUF,
        qc_frame_open(frame, qc_frame_len(sizeof(pt)), KEY, 7u,
                      back, sizeof(back), &p));
    /* Right key, wrong epoch -> nonce differs -> AUTH_FAIL (proves the
     * header counter is cryptographically bound to the nonce). */
    TEST_ASSERT_EQUAL_INT(QC_FRAME_AUTH_FAIL,
        qc_frame_open(frame, qc_frame_len(sizeof(pt)), KEY, 8u,
                      back, sizeof(back) + 8, &p));
}

/* Max-payload boundary (65535): roundtrip + SMALL_BUF one short.
 * Static buffers (65 KB class) — never stack. */
static void test_max_payload(void) {
    static uint8_t big[QC_FRAME_MAX_PAYLOAD];
    static uint8_t frame[QC_FRAME_HDR_LEN + 4 + QC_FRAME_MAX_PAYLOAD + 16];
    static uint8_t back[QC_FRAME_MAX_PAYLOAD];
    qc_frame_fields f;
    qc_frame_parsed p;
    size_t flen;

    for (size_t i = 0; i < sizeof(big); i++) {
        big[i] = (uint8_t)(i & 0xFF);
    }
    fill_fields(&f, big, sizeof(big));
    flen = qc_frame_len(sizeof(big));
    TEST_ASSERT_TRUE(flen > 0);
    TEST_ASSERT_EQUAL_INT(QC_FRAME_OK,
        qc_frame_protect(&f, 1u, KEY, frame, flen));
    TEST_ASSERT_EQUAL_INT(QC_FRAME_OK,
        qc_frame_open(frame, flen, KEY, 1u, back, sizeof(back), &p));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(big, back, sizeof(big));
    TEST_ASSERT_EQUAL_INT(QC_FRAME_SMALL_BUF,
        qc_frame_open(frame, flen, KEY, 1u, back, sizeof(back) - 1, &p));
}

void setUp(void) {}
void tearDown(void) {}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_roundtrip);
    RUN_TEST(test_empty);
    RUN_TEST(test_tamper);
    RUN_TEST(test_structural);
    RUN_TEST(test_open_edges);
    RUN_TEST(test_max_payload);
    return UNITY_END();
}