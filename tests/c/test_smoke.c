/* Step-0 smoke: proves the Unity harness builds, runs, and reports.
 * Convention for all later tests: one file per unit, TEST() per vector class,
 * file-8.3-free names test_<unit>.c. Deterministic: no RNG, no time, no I/O
 * except Unity output. A failing test prints the exact byte diff. */
#include "unity.h"

#include <stdint.h>

void setUp(void) {}
void tearDown(void) {}

static void test_toolchain_is_c11_lp64(void) {
    /* uint32_t exactly 32 bits, pointers 64-bit on the build host.
     * Catches wrong-arch / wrong-stdlib builds before crypto lands. */
    TEST_ASSERT_EQUAL_UINT(4, sizeof(uint32_t));
    TEST_ASSERT_EQUAL_UINT(8, sizeof(void *));
}

static void test_harness_runs_to_completion(void) {
    /* Second test exists so "1 Tests 0 Failures" can never pass vacuously
     * on an empty runner. Runner wiring itself is under test. */
    TEST_ASSERT_TRUE(1);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_toolchain_is_c11_lp64);
    RUN_TEST(test_harness_runs_to_completion);
    return UNITY_END();
}
