/* test_alarm.c — L0/L1 for the C2 immediate path (B-24.4 mechanism).
 *
 * Covers: signed path (threshold met + key + rnd) with verify of the
 * frame-covering signature; unsigned paths (metric low, sk NULL);
 * RNG_FAIL (signing required, rnd NULL — nothing emitted); bad level /
 * short sig buffer; oversize payload; empty payload reject; NULL guards;
 * tampered frame fails open AND sig verify (both layers).
 * Deterministic: fixed coins/rnd (signing uses caller rnd, no RNG).
 */
#include "unity.h"

#include <string.h>

#include "qc_alarm.h"
#include "qc_dsa.h"
#include "qc_frame.h"

static const uint8_t DEV_ID[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};

static const uint8_t KEY[32] = {
    0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7,
    0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
    0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7,
    0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF
};

static const uint8_t SEED[32] = {
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11
};

static const uint8_t RND[32] = {
    0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
    0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
    0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
    0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22
};

static const uint8_t PAYLOAD[] = { 'f', 'a', 'l', 'l', '!' };
static uint8_t PK[1952], SK[4032];

static void setup_keys(void) {
    TEST_ASSERT_EQUAL_INT(QC_DSA_OK,
        qc_dsa_keypair(QC_DSA_65, PK, SK, SEED));
}

/* Signed path end-to-end: frame opens AND detached sig verifies. */
static void test_signed(void) {
    static uint8_t frame[512], sig[3309], pt[512];
    qc_frame_parsed p;
    size_t flen = 0, slen = 0;

    setup_keys();
    TEST_ASSERT_EQUAL_INT(QC_ALARM_SIGNED,
        qc_alarm_emit(500, 900, QC_DSA_65, SK, DEV_ID, 2, 7u, 42u, NULL, 0, 0,
                      KEY, PAYLOAD, sizeof(PAYLOAD),
                      RND, frame, sizeof(frame), &flen,
                      sig, sizeof(sig), &slen));
    TEST_ASSERT_EQUAL_UINT(qc_frame_len(sizeof(PAYLOAD)), flen);
    TEST_ASSERT_EQUAL_UINT(3309, slen);
    /* Frame opens under the traffic key... */
    TEST_ASSERT_EQUAL_INT(QC_FRAME_OK,
        qc_frame_open(frame, flen, KEY, 7u, pt, sizeof(pt), &p));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(PAYLOAD, pt, sizeof(PAYLOAD));
    TEST_ASSERT_EQUAL_UINT8(QC_CLS_C2, p.cls);
    /* ...and the detached signature covers the framed bytes. */
    TEST_ASSERT_EQUAL_INT(QC_DSA_OK,
        qc_dsa_verify(QC_DSA_65, frame, flen, NULL, 0, sig, PK));
    /* Tampered frame: open fails AND sig fails (both layers). */
    frame[80] ^= 0x01;
    TEST_ASSERT_TRUE_MESSAGE(
        qc_frame_open(frame, flen, KEY, 7u, pt, sizeof(pt), &p)
        != QC_FRAME_OK, "tamper open");
    TEST_ASSERT_EQUAL_INT(QC_DSA_BAD_SIG,
        qc_dsa_verify(QC_DSA_65, frame, flen, NULL, 0, sig, PK));
}

/* Unsigned paths: metric-low and sk-NULL. Both AEAD-valid. */
static void test_unsigned(void) {
    static uint8_t frame[512], sig[3309], pt[512];
    qc_frame_parsed p;
    size_t flen = 0, slen = 0x5A5A;

    setup_keys();
    TEST_ASSERT_EQUAL_INT(QC_ALARM_UNSIGNED,
        qc_alarm_emit(500, 100, QC_DSA_65, SK, DEV_ID, 2, 7u, 42u, NULL, 0, 0,
                      KEY, PAYLOAD, sizeof(PAYLOAD),
                      RND, frame, sizeof(frame), &flen,
                      sig, sizeof(sig), &slen));
    TEST_ASSERT_EQUAL_UINT(0, slen);
    TEST_ASSERT_EQUAL_INT(QC_FRAME_OK,
        qc_frame_open(frame, flen, KEY, 7u, pt, sizeof(pt), &p));
    TEST_ASSERT_EQUAL_INT(QC_ALARM_UNSIGNED,
        qc_alarm_emit(500, 900, QC_DSA_65, NULL, DEV_ID, 2, 7u, 43u, NULL, 0, 0,
                      KEY, PAYLOAD, sizeof(PAYLOAD),
                      RND, frame, sizeof(frame), &flen,
                      sig, sizeof(sig), &slen));
    TEST_ASSERT_EQUAL_UINT(0, slen);
    TEST_ASSERT_EQUAL_INT(QC_FRAME_OK,
        qc_frame_open(frame, flen, KEY, 7u, pt, sizeof(pt), &p));
}

/* Attestation reference flows into the frame (not silently dropped):
 * non-null root + range roundtrip through open, and flipping a root
 * byte fails authentication (AAD-bound). */
static void test_attestation_ref(void) {
    static uint8_t frame[512], sig[3309], pt[512];
    static const uint8_t root[32] = {
        0xA0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
    };
    qc_frame_parsed p;
    size_t flen = 0, slen = 0;

    setup_keys();
    TEST_ASSERT_EQUAL_INT(QC_ALARM_SIGNED,
        qc_alarm_emit(500, 900, QC_DSA_65, SK, DEV_ID, 2, 7u, 42u,
                      root, 1000, 1041,
                      KEY, PAYLOAD, sizeof(PAYLOAD),
                      RND, frame, sizeof(frame), &flen,
                      sig, sizeof(sig), &slen));
    TEST_ASSERT_EQUAL_INT(QC_FRAME_OK,
        qc_frame_open(frame, flen, KEY, 7u, pt, sizeof(pt), &p));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(root, p.last_root, 32);
    TEST_ASSERT_EQUAL_UINT64(1000, p.range_start);
    TEST_ASSERT_EQUAL_UINT64(1041, p.range_end);
    frame[30] ^= 0x01;
    TEST_ASSERT_TRUE_MESSAGE(
        qc_frame_open(frame, flen, KEY, 7u, pt, sizeof(pt), &p)
        != QC_FRAME_OK, "root tamper");
}

/* RNG_FAIL: signing required, rnd NULL — nothing emitted. */
static void test_rng_fail(void) {
    static uint8_t frame[512], sig[3309];
    size_t flen = 0x5A5A, slen = 0x5A5A;

    setup_keys();
    TEST_ASSERT_EQUAL_INT(QC_ALARM_RNG_FAIL,
        qc_alarm_emit(500, 900, QC_DSA_65, SK, DEV_ID, 2, 7u, 42u, NULL, 0, 0,
                      KEY, PAYLOAD, sizeof(PAYLOAD),
                      NULL, frame, sizeof(frame), &flen,
                      sig, sizeof(sig), &slen));
    TEST_ASSERT_EQUAL_UINT(0, flen);
    TEST_ASSERT_EQUAL_UINT(0, slen);
}

/* Sizing/edge: bad level, short sig buf, oversize, empty, NULLs. */
static void test_edges(void) {
    static uint8_t frame[512], sig[3309];
    size_t flen, slen;

    setup_keys();
    TEST_ASSERT_EQUAL_INT(QC_ALARM_OVERSIZE,
        qc_alarm_emit(500, 900, 0, SK, DEV_ID, 2, 7u, 42u, NULL, 0, 0,
                      KEY, PAYLOAD, sizeof(PAYLOAD),
                      RND, frame, sizeof(frame), &flen,
                      sig, sizeof(sig), &slen));
    TEST_ASSERT_EQUAL_INT(QC_ALARM_OVERSIZE,
        qc_alarm_emit(500, 900, QC_DSA_65, SK, DEV_ID, 2, 7u, 42u, NULL, 0, 0,
                      KEY, PAYLOAD, sizeof(PAYLOAD),
                      RND, frame, sizeof(frame), &flen,
                      sig, 10, &slen));
    {
        static uint8_t big[QC_FRAME_MAX_PAYLOAD + 1];
        memset(big, 0x99, sizeof(big));
        TEST_ASSERT_EQUAL_INT(QC_ALARM_OVERSIZE,
            qc_alarm_emit(500, 900, QC_DSA_65, SK, DEV_ID, 2, 7u, 42u, NULL, 0, 0,
                          KEY, big, sizeof(big),
                          RND, frame, sizeof(frame), &flen,
                          sig, sizeof(sig), &slen));
    }
    TEST_ASSERT_EQUAL_INT(QC_ALARM_BAD_ARG,
        qc_alarm_emit(500, 900, QC_DSA_65, SK, DEV_ID, 2, 7u, 42u, NULL, 0, 0,
                      KEY, NULL, 0,
                      RND, frame, sizeof(frame), &flen,
                      sig, sizeof(sig), &slen));
    TEST_ASSERT_EQUAL_INT(QC_ALARM_BAD_ARG,
        qc_alarm_emit(500, 900, QC_DSA_65, SK, NULL, 2, 7u, 42u, NULL, 0, 0,
                      KEY, PAYLOAD, sizeof(PAYLOAD),
                      RND, frame, sizeof(frame), &flen,
                      sig, sizeof(sig), &slen));
}

void setUp(void) {}
void tearDown(void) {}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_signed);
    RUN_TEST(test_attestation_ref);
    RUN_TEST(test_unsigned);
    RUN_TEST(test_rng_fail);
    RUN_TEST(test_edges);
    return UNITY_END();
}