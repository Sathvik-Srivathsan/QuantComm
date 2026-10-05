/* test_hmac.c — L0: RFC 4231 HMAC-SHA-256 vectors + edge rules.
 * Sources: RFC 4231 §4.2 (TC1), §4.3 (TC2). Copied from the RFC text.
 */
#include "unity.h"

#include <string.h>

#include "qc_hmac.h"

static void expect_hex(const char *label, const uint8_t *got,
                       const char *want_hex) {
    char buf[65];
    static const char hd[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        buf[2 * i] = hd[(got[i] >> 4) & 0xF];
        buf[2 * i + 1] = hd[got[i] & 0xF];
    }
    buf[64] = '\0';
    TEST_ASSERT_EQUAL_STRING_MESSAGE(want_hex, buf, label);
}

static void test_rfc4231_tc1(void) {
    /* Key = 20 x 0x0b; Data = "Hi There". */
    uint8_t key[20], out[32];
    memset(key, 0x0b, sizeof(key));
    qc_hmac_sha256(key, sizeof(key), (const uint8_t *)"Hi There", 8, out);
    expect_hex("tc1", out,
               "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
}

static void test_rfc4231_tc2(void) {
    /* Key = "Jefe"; Data = "what do ya want for nothing?". */
    static const char *data = "what do ya want for nothing?";
    uint8_t out[32];
    qc_hmac_sha256((const uint8_t *)"Jefe", 4,
                   (const uint8_t *)data, strlen(data), out);
    expect_hex("tc2", out,
               "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
}

static void test_empty_key_and_msg(void) {
    /* Edge per header contract: empty key + empty msg must not crash;
     * value cross-checked against Python hmac at authoring time. */
    uint8_t out[32];
    qc_hmac_sha256(NULL, 0, NULL, 0, out);
    expect_hex("empty/empty", out,
               "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad");
}

void setUp(void) {}
void tearDown(void) {}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_rfc4231_tc1);
    RUN_TEST(test_rfc4231_tc2);
    RUN_TEST(test_empty_key_and_msg);
    return UNITY_END();
}
