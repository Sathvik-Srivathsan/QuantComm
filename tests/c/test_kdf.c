/* test_kdf.c — L2 collective: Extract -> Expand -> split, one oracle vector.
 * Oracle: Python hashlib/hmac implementing B-21 composition independently
 * (vectors pasted from oracle output at authoring time, inputs built in code).
 * Also: reject rules (NULL/empty/oversize) and split-order check
 * (each key differs; swap detection via oracle values).
 */
#include "unity.h"

#include <string.h>

#include "qc_kdf.h"

/* Trace capture: proves L2 visibility (intermediates observable). */
static uint8_t seen_prk[32];
static uint8_t seen_okm[128];
static int seen_n;

static void cap_trace(const uint8_t prk[32], const uint8_t *info,
                      size_t info_len, const uint8_t okm[128]) {
    (void)info;
    (void)info_len;
    memcpy(seen_prk, prk, 32);
    memcpy(seen_okm, okm, 128);
    seen_n++;
}

static void fill_inputs(uint8_t nw[12], uint8_t ns[32], uint8_t k1[32],
                        uint8_t k2[32], uint8_t kdev[32]) {
    for (int i = 0; i < 12; i++) {
        nw[i] = (uint8_t)i;
    }
    for (int i = 0; i < 32; i++) {
        ns[i] = (uint8_t)(32 + i);
        k1[i] = (uint8_t)(100 + i);
        k2[i] = (uint8_t)(200 + i);
        kdev[i] = (uint8_t)(50 + i);
    }
}

static void expect_hex_n(const char *label, const uint8_t *got, size_t n,
                         const char *want_hex) {
    char buf[257];
    static const char hd[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        buf[2 * i] = hd[(got[i] >> 4) & 0xF];
        buf[2 * i + 1] = hd[got[i] & 0xF];
    }
    buf[2 * n] = '\0';
    TEST_ASSERT_EQUAL_STRING_MESSAGE(want_hex, buf, label);
}

static void test_oracle_vector(void) {
    uint8_t nw[12], ns[32], k1[32], k2[32], kdev[32];
    static const char *tr = "QUANTCOMM-TRANSCRIPT-V1";
    qc_kdf_keys out;
    int rc;

    fill_inputs(nw, ns, k1, k2, kdev);
    qc_kdf_trace = cap_trace;
    seen_n = 0;
    rc = qc_kdf_derive(nw, ns, k1, sizeof(k1), k2, sizeof(k2), kdev,
                       (const uint8_t *)tr, strlen(tr), &out);
    qc_kdf_trace = NULL;
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, rc, "derive rc");
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, seen_n, "trace fired once");

    /* Trace shows live PRK (proves pre-wipe ordering fix). */
    expect_hex_n("trace prk", seen_prk, 32,
                 "b45336437978195065e34587ef93629048d6a4c999df08b2c6bde5e4ea2ed50b");
    expect_hex_n("k_c2s", out.k_c2s, 32,
                 "93e548e0b4c6a2df6c707ef9b8acda9a3f53cce43bd6b8f385e3108b7bfe3838");
    expect_hex_n("k_s2c", out.k_s2c, 32,
                 "fca2f58a54e16379f8776e1270230ed71dc6e4cc2b6656323017013704a397b1");
    expect_hex_n("k_rat", out.k_rat, 32,
                 "7ffa6ab5d3e23f5947f3ca6a526faee4cf90ddf0925ada3e0be15464213f88a4");
    expect_hex_n("k_conf", out.k_conf, 32,
                 "8301b1e7ed24738860a2194d2f054645dcef7db77cc4afa5edb623bbc5a27299");
}

static void test_rejects(void) {
    uint8_t nw[12], ns[32], k1[32], k2[32], kdev[32];
    qc_kdf_keys out;
    static const char *tr = "T";

    fill_inputs(nw, ns, k1, k2, kdev);
    memset(&out, 0xA5, sizeof(out));
    TEST_ASSERT_EQUAL_INT(-1, qc_kdf_derive(NULL, ns, k1, 32, k2, 32, kdev,
                                            (const uint8_t *)tr, 1, &out));
    TEST_ASSERT_EQUAL_INT(-1, qc_kdf_derive(nw, ns, k1, 0, k2, 32, kdev,
                                            (const uint8_t *)tr, 1, &out));
    TEST_ASSERT_EQUAL_INT(-1, qc_kdf_derive(nw, ns, k1, 32, k2, 32, kdev,
                                            NULL, 0, &out));
    /* Overflow attempts: lengths that would wrap the total-size sum.
     * Safe to attempt: per-input caps reject before any buffer is read. */
    TEST_ASSERT_EQUAL_INT(-1, qc_kdf_derive(nw, ns, k1, (size_t)1 << 20,
                                            k2, 32, kdev,
                                            (const uint8_t *)tr, 1, &out));
    TEST_ASSERT_EQUAL_INT(-1, qc_kdf_derive(nw, ns, k1, (size_t)-1,
                                            k2, (size_t)-1, kdev,
                                            (const uint8_t *)tr, 1, &out));
    /* Output untouched on failure (fail-closed, no partial keys). */
    for (size_t i = 0; i < sizeof(out); i++) {
        TEST_ASSERT_EQUAL_UINT8_MESSAGE(0xA5, ((uint8_t *)&out)[i], "out wiped");
    }
}

void setUp(void) {}
void tearDown(void) {}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_oracle_vector);
    RUN_TEST(test_rejects);
    return UNITY_END();
}
