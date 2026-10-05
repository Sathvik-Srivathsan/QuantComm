/* test_rng.c — L1: determinism contract of the test RNG.
 * Same seed -> identical stream (replay guarantee).
 * Different seed -> different stream (sanity, not entropy claim).
 */
#include "unity.h"

#include <stdint.h>
#include <string.h>

/* From test_rng.c (test TU only — never in production closure). */
void test_rng_seed(uint64_t seed);
int qc_rng_generate(uint8_t *out, size_t len);

static void test_same_seed_same_stream(void) {
    uint8_t a[64], b[64];
    test_rng_seed(0x12345678ull);
    qc_rng_generate(a, sizeof(a));
    test_rng_seed(0x12345678ull);
    qc_rng_generate(b, sizeof(b));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(a, b, sizeof(a));
}

static void test_different_seed_differs(void) {
    uint8_t a[32], b[32];
    test_rng_seed(1);
    qc_rng_generate(a, sizeof(a));
    test_rng_seed(2);
    qc_rng_generate(b, sizeof(b));
    TEST_ASSERT_FALSE(memcmp(a, b, sizeof(a)) == 0);
}

void setUp(void) {}
void tearDown(void) {}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_same_seed_same_stream);
    RUN_TEST(test_different_seed_differs);
    return UNITY_END();
}
