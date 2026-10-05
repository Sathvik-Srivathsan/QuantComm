/* test_codec.c — L1: M1/M2 round-trips, tamper oracles, transcript rules.
 * Level sizes below are B-10.1 test constants (512: ek 800/ct 768), cited
 * here for tests only; the codec itself takes lengths as parameters.
 */
#include "unity.h"

#include <string.h>

#include "qc_codec.h"

/* B-10.1 test constants (cited, tests only). */
#define T_EK 800
#define T_CT 768

static void fill_m1(qc_m1_fields *f, uint8_t *ek, uint8_t *ct) {
    memset(f, 0, sizeof(*f));
    f->version = QC_M1_VERSION;
    for (int i = 0; i < QC_ID_LEN; i++) {
        f->identity[i] = (uint8_t)(0x10 + i);
    }
    f->level = 1;
    for (int i = 0; i < T_EK; i++) {
        ek[i] = (uint8_t)(i & 0xFF);
    }
    for (int i = 0; i < T_CT; i++) {
        ct[i] = (uint8_t)(0x80 + (i & 0x7F));
    }
    f->ek = ek;
    f->ek_len = T_EK;
    f->ct_s = ct;
    f->ct_len = T_CT;
    for (int i = 0; i < QC_NONCE_LEN; i++) {
        f->nonce[i] = (uint8_t)(0xE0 + i);
    }
    for (int i = 0; i < QC_MAC_LEN; i++) {
        f->hmac[i] = (uint8_t)(0xC0 + i);
    }
}

static void test_m1_roundtrip(void) {
    qc_m1_fields f, g;
    uint8_t ek[T_EK], ct[T_CT];
    uint8_t buf[1 + 16 + 1 + T_EK + T_CT + 12 + 32];

    fill_m1(&f, ek, ct);
    TEST_ASSERT_EQUAL_size_t(qc_m1_len(T_EK, T_CT), sizeof(buf));
    TEST_ASSERT_EQUAL_INT(QC_CODEC_OK, qc_m1_encode(&f, buf, sizeof(buf)));
    memset(&g, 0, sizeof(g));
    TEST_ASSERT_EQUAL_INT(QC_CODEC_OK,
                          qc_m1_parse(buf, sizeof(buf), T_EK, T_CT, &g));
    TEST_ASSERT_EQUAL_UINT8(g.version, f.version);
    TEST_ASSERT_EQUAL_UINT8(g.level, f.level);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(f.identity, g.identity, QC_ID_LEN);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(f.nonce, g.nonce, QC_NONCE_LEN);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(f.hmac, g.hmac, QC_MAC_LEN);
    TEST_ASSERT_EQUAL_size_t(T_EK, g.ek_len);
    TEST_ASSERT_EQUAL_size_t(T_CT, g.ct_len);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(ek, g.ek, T_EK);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(ct, g.ct_s, T_CT);
}

static void test_m1_rejects(void) {
    qc_m1_fields f, g;
    uint8_t ek[T_EK], ct[T_CT];
    uint8_t buf[1 + 16 + 1 + T_EK + T_CT + 12 + 32];
    uint8_t bad[sizeof(buf)];

    fill_m1(&f, ek, ct);
    qc_m1_encode(&f, buf, sizeof(buf));

    /* Truncation and oversize map to OVERSIZE (length != exact). */
    TEST_ASSERT_EQUAL_INT(QC_CODEC_OVERSIZE,
                          qc_m1_parse(buf, sizeof(buf) - 1, T_EK, T_CT, &g));
    TEST_ASSERT_EQUAL_INT(QC_CODEC_OVERSIZE,
                          qc_m1_parse(buf, sizeof(buf) + 1, T_EK, T_CT, &g));
    /* Unknown version. */
    memcpy(bad, buf, sizeof(buf));
    bad[0] = 0xFF;
    TEST_ASSERT_EQUAL_INT(QC_CODEC_BAD_VERSION,
                          qc_m1_parse(bad, sizeof(bad), T_EK, T_CT, &g));
    /* Wrong level sizes for this buffer: length != exact -> OVERSIZE. */
    TEST_ASSERT_EQUAL_INT(QC_CODEC_OVERSIZE,
                          qc_m1_parse(buf, sizeof(buf), T_EK + 1, T_CT, &g));
}

static void test_m2_version_mismatch(void) {
    qc_m2_fields f, g;
    uint8_t ct[T_CT];
    uint8_t buf[1 + T_CT + 32 + 32];

    memset(&f, 0, sizeof(f));
    f.version = QC_M1_VERSION;
    for (int i = 0; i < T_CT; i++) {
        ct[i] = (uint8_t)i;
    }
    f.ct_w = ct;
    f.ct_len = T_CT;
    TEST_ASSERT_EQUAL_INT(QC_CODEC_OK, qc_m2_encode(&f, buf, sizeof(buf)));
    /* Same version parses; different M1 version mismatches. */
    TEST_ASSERT_EQUAL_INT(QC_CODEC_OK,
                          qc_m2_parse(buf, sizeof(buf), T_CT, QC_M1_VERSION, &g));
    TEST_ASSERT_EQUAL_INT(QC_CODEC_VERSION_MISMATCH,
                          qc_m2_parse(buf, sizeof(buf), T_CT, 0x7F, &g));
}

static void test_m2_encode_rejects_bad_version(void) {
    qc_m2_fields f;
    uint8_t ct[T_CT];
    uint8_t buf[1 + T_CT + 32 + 32];

    memset(&f, 0, sizeof(f));
    f.version = 0x7F;
    f.ct_w = ct;
    f.ct_len = T_CT;
    TEST_ASSERT_EQUAL_INT(QC_CODEC_BAD_VERSION,
                          qc_m2_encode(&f, buf, sizeof(buf)));
}

static void test_oversize_fields_rejected(void) {
    qc_m1_fields f, g;
    uint8_t ek[T_EK], ct[T_CT];
    uint8_t buf[1 + 16 + 1 + T_EK + T_CT + 12 + 32];

    fill_m1(&f, ek, ct);
    qc_m1_encode(&f, buf, sizeof(buf));
    /* Absurd field sizes rejected as length problems (OVERSIZE family). */
    TEST_ASSERT_EQUAL_INT(QC_CODEC_OVERSIZE,
                          qc_m1_parse(buf, sizeof(buf), (size_t)-1, T_CT, &g));
}

static void test_transcript_excludes_confirm_only(void) {
    /* Two M2s differing ONLY in confirm MAC give identical transcripts;
     * any M1 byte difference changes it. Proves exclusion rule exactly. */
    qc_m1_fields f;
    qc_m2_fields m2a, m2b;
    uint8_t ek[T_EK], ct[T_CT], ctw[T_CT];
    uint8_t b1[1 + 16 + 1 + T_EK + T_CT + 12 + 32];
    uint8_t b2a[1 + T_CT + 32 + 32], b2b[1 + T_CT + 32 + 32];
    uint8_t t1[4096], t2[4096], t3[4096];
    size_t tl;

    fill_m1(&f, ek, ct);
    qc_m1_encode(&f, b1, sizeof(b1));
    memset(&m2a, 0, sizeof(m2a));
    m2a.version = QC_M1_VERSION;
    for (int i = 0; i < T_CT; i++) {
        ctw[i] = (uint8_t)(0x40 + i);
    }
    m2a.ct_w = ctw;
    m2a.ct_len = T_CT;
    memset(m2a.confirm, 0xAA, 32);
    memcpy(&m2b, &m2a, sizeof(m2b));
    memset(m2b.confirm, 0xBB, 32);
    qc_m2_encode(&m2a, b2a, sizeof(b2a));
    qc_m2_encode(&m2b, b2b, sizeof(b2b));

    tl = qc_transcript_len(sizeof(b1), sizeof(b2a));
    TEST_ASSERT_EQUAL_UINT((unsigned)sizeof(b1) + (unsigned)sizeof(b2a) - 32, (unsigned)tl);
    TEST_ASSERT_EQUAL_INT(QC_CODEC_OK,
                          qc_transcript_build(b1, sizeof(b1), b2a, sizeof(b2a), t1, tl));
    TEST_ASSERT_EQUAL_INT(QC_CODEC_OK,
                          qc_transcript_build(b1, sizeof(b1), b2b, sizeof(b2b), t2, tl));
    TEST_ASSERT_EQUAL_UINT8_ARRAY_MESSAGE(t1, t2, tl, "confirm excluded");

    /* M1 HMAC byte flip changes transcript (tag covered transitively). */
    b1[sizeof(b1) - 1] ^= 0x01;
    TEST_ASSERT_EQUAL_INT(QC_CODEC_OK,
                          qc_transcript_build(b1, sizeof(b1), b2a, sizeof(b2a), t3, tl));
    TEST_ASSERT_FALSE(memcmp(t1, t3, tl) == 0);
    /* Short M2 (no room for confirm MAC) refused in length family. */
    TEST_ASSERT_EQUAL_INT(QC_CODEC_OVERSIZE,
                          qc_transcript_build(b1, sizeof(b1), b2a, 31, t3, tl));
    TEST_ASSERT_EQUAL_UINT(0, (unsigned)qc_transcript_len(sizeof(b1), 31));
    /* Length helpers self-enforce caps (0 = invalid, never a real length). */
    TEST_ASSERT_EQUAL_UINT(0, (unsigned)qc_m1_len((size_t)-1, T_CT));
    TEST_ASSERT_EQUAL_UINT(0, (unsigned)qc_m2_len((size_t)-1));
    TEST_ASSERT_EQUAL_UINT(0, (unsigned)qc_transcript_len((size_t)-1, sizeof(b2a)));
    /* Wrong destination size refused (subtraction-form exactness). */
    TEST_ASSERT_EQUAL_INT(QC_CODEC_OVERSIZE,
                          qc_transcript_build(b1, sizeof(b1), b2a, sizeof(b2a), t3, tl - 1));
}

void setUp(void) {}
void tearDown(void) {}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_m1_roundtrip);
    RUN_TEST(test_m1_rejects);
    RUN_TEST(test_m2_version_mismatch);
    RUN_TEST(test_m2_encode_rejects_bad_version);
    RUN_TEST(test_oversize_fields_rejected);
    RUN_TEST(test_transcript_excludes_confirm_only);
    return UNITY_END();
}
