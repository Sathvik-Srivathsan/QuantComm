/* test_hkdf.c — L0: RFC 5869 SHA-256 vectors (A.1 basic, A.3 empty salt/info).
 * All hex copied from RFC 5869 Appendix A text. IKM/salt/info built
 * programmatically to exclude transcription error in *inputs*.
 */
#include "unity.h"

#include <string.h>

#include "qc_hkdf.h"

static void expect_hex_n(const char *label, const uint8_t *got, size_t n,
                         const char *want_hex) {
    char buf[256];
    static const char hd[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        buf[2 * i] = hd[(got[i] >> 4) & 0xF];
        buf[2 * i + 1] = hd[got[i] & 0xF];
    }
    buf[2 * n] = '\0';
    TEST_ASSERT_EQUAL_STRING_MESSAGE(want_hex, buf, label);
}

static void test_rfc5869_a1(void) {
    uint8_t ikm[22], salt[13], info[10], prk[32], okm[42];
    int rc;
    memset(ikm, 0x0b, sizeof(ikm));
    for (int i = 0; i < 13; i++) {
        salt[i] = (uint8_t)i;
    }
    for (int i = 0; i < 10; i++) {
        info[i] = (uint8_t)(0xf0 + i);
    }
    rc = qc_hkdf_extract(salt, sizeof(salt), ikm, sizeof(ikm), prk);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, rc, "a1 extract rc");
    expect_hex_n("a1 prk", prk, 32,
                 "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
    rc = qc_hkdf_expand(prk, info, sizeof(info), okm, sizeof(okm));
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, rc, "a1 expand rc");
    expect_hex_n("a1 okm", okm, 42,
                 "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                 "34007208d5b887185865");
}

static void test_rfc5869_a3_empty(void) {
    uint8_t ikm[22], prk[32], okm[42];
    int rc;
    memset(ikm, 0x0b, sizeof(ikm));
    rc = qc_hkdf_extract(NULL, 0, ikm, sizeof(ikm), prk);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, rc, "a3 extract rc");
    expect_hex_n("a3 prk", prk, 32,
                 "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04");
    rc = qc_hkdf_expand(prk, NULL, 0, okm, sizeof(okm));
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, rc, "a3 expand rc");
    expect_hex_n("a3 okm", okm, 42,
                 "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
                 "9d201395faa4b61a96c8");
}

static void test_rejects(void) {
    uint8_t prk[32], okm[8160 + 32];
    uint8_t ikm[1] = {0};
    /* Empty IKM rejected; oversize OKM rejected; zero-len OK. */
    TEST_ASSERT_EQUAL_INT(-1, qc_hkdf_extract(NULL, 0, NULL, 0, prk));
    TEST_ASSERT_EQUAL_INT(-1, qc_hkdf_extract(NULL, 0, ikm, 0, prk));
    TEST_ASSERT_EQUAL_INT(-1, qc_hkdf_expand(prk, NULL, 0, okm, 8160 + 1));
    TEST_ASSERT_EQUAL_INT(0, qc_hkdf_expand(prk, NULL, 0, okm, 0));
}

void setUp(void) {}
void tearDown(void) {}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_rfc5869_a1);
    RUN_TEST(test_rfc5869_a3_empty);
    RUN_TEST(test_rejects);
    return UNITY_END();
}
