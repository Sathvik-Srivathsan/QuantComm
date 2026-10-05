/* test_sha256.c — L0 vectors for SHA-256 (FIPS 180-4 §8).
 * Each vector: exact input, exact expected hex. Mismatch prints both.
 * Streaming API covered (split feeds) because HKDF/HMAC will stream.
 */
#include "unity.h"

#include <string.h>

#include <string.h>

#include "qc_sha256.h"

static void expect_hex(const char *label, const uint8_t *got,
                       const char *want_hex) {
    char buf[65];
    static const char hd[] = "0123456789abcdef";
    (void)label;
    for (int i = 0; i < 32; i++) {
        buf[2 * i] = hd[(got[i] >> 4) & 0xF];
        buf[2 * i + 1] = hd[got[i] & 0xF];
    }
    buf[64] = '\0';
    TEST_ASSERT_EQUAL_STRING_MESSAGE(want_hex, buf, label);
}

static void test_empty(void) {
    uint8_t out[32];
    qc_sha256(NULL, 0, out);
    expect_hex("empty", out,
               "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

static void test_abc(void) {
    uint8_t out[32];
    qc_sha256((const uint8_t *)"abc", 3, out);
    expect_hex("abc", out,
               "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

static void test_448bit_boundary(void) {
    /* 56 bytes: fills exactly one block after padding starts (two-block message). */
    static const char *msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    uint8_t out[32];
    qc_sha256((const uint8_t *)msg, 56, out);
    expect_hex("448-bit", out,
               "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
}

static void test_streaming_split_feeds(void) {
    /* Same digest via 1-byte feeds: proves update/final chunking. */
    static const char *msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    qc_sha256_ctx ctx;
    uint8_t out[32], ref[32];
    size_t n = strlen(msg);

    qc_sha256((const uint8_t *)msg, n, ref);
    qc_sha256_init(&ctx);
    for (size_t i = 0; i < n; i++) {
        qc_sha256_update(&ctx, (const uint8_t *)msg + i, 1);
    }
    qc_sha256_final(&ctx, out);
    TEST_ASSERT_EQUAL_UINT8_ARRAY_MESSAGE(ref, out, 32, "streaming==oneshot");
}

static void test_multiblock_known(void) {
    /* 200 x 'a' (4 blocks incl. padding block): locally generated vector,
     * expected digest cross-checked against Python hashlib (independent
     * implementation) at authoring time. Exercises multi-block chaining
     * plus the padding-length block. */
    static char msg[200];
    uint8_t out[32];
    memset(msg, 'a', sizeof(msg));
    qc_sha256((const uint8_t *)msg, sizeof(msg), out);
    expect_hex("200xa", out,
               "c2a908d98f5df987ade41b5fce213067efbcc21ef2240212a41e54b5e7c28ae5");
}

void setUp(void) {}
void tearDown(void) {}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_empty);
    RUN_TEST(test_abc);
    RUN_TEST(test_448bit_boundary);
    RUN_TEST(test_streaming_split_feeds);
    RUN_TEST(test_multiblock_known);
    return UNITY_END();
}
