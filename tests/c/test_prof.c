/* test_prof.c - B-51.3 profiling primitives (heap hooks, cycles).
 *
 * These are measurement instruments, so their own correctness is the
 * first-order concern: an instrument that always reads zero would make the
 * whole E1 campaign look like a clean result. Every test therefore drives
 * a case where the CORRECT answer is non-zero, and one where it is zero.
 *
 * No stack tests: the paint instrument was removed from qc_prof rather
 * than shipped after two silent failures (see qc_prof.h). Its return is
 * gated on having a host that can build and run the instrument, so it is
 * a named follow-up, not a passing test.
 */
#include <string.h>

#include "qc_prof.h"
#include "unity.h"

void setUp(void) {}
void tearDown(void) {}

/* Keeps the measured loop from being optimised away. */
static volatile size_t sink;

__attribute__((noinline)) static void burn(int n) {
    volatile uint8_t pad[64];
    size_t i;
    for (i = 0; i < sizeof(pad); i++) {
        pad[i] = (uint8_t)(i + (size_t)n);
    }
    sink += pad[n % sizeof(pad)];
}

static void test_heap_tracks_live_bytes(void) {
    qc_heap_stat s;

    qc_heap_track_begin();
    qc_heap_note_alloc(1000);
    qc_heap_note_alloc(24);
    s = qc_heap_stat_get();
    TEST_ASSERT_EQUAL_UINT(1024, s.live_bytes);
    TEST_ASSERT_EQUAL_UINT(2, s.total_allocs);

    qc_heap_note_free(1000);
    s = qc_heap_stat_get();
    TEST_ASSERT_EQUAL_UINT(24, s.live_bytes);
    TEST_ASSERT_EQUAL_UINT(1, s.total_frees);

    qc_heap_track_end();
}

static void test_heap_overfree_clamps_instead_of_wrapping(void) {
    qc_heap_stat s;
    qc_heap_track_begin();
    qc_heap_note_alloc(16);
    qc_heap_note_free(9999);          /* more than was ever live */
    s = qc_heap_stat_get();
    /* Unsigned underflow here would fabricate a ~2^64 "live" figure and
     * poison the whole memory column of the dataset. */
    TEST_ASSERT_EQUAL_UINT(0, s.live_bytes);
    TEST_ASSERT_EQUAL_UINT(1, s.total_frees);
    qc_heap_track_end();
}

static void test_heap_inactive_ignores_notes(void) {
    qc_heap_stat s;

    /* Own state: track_end leaves the counters from the previous test in
     * place, so this must start from an explicit begin to say anything. */
    qc_heap_track_begin();
    qc_heap_track_end();
    qc_heap_note_alloc(500);
    qc_heap_note_free(500);
    s = qc_heap_stat_get();
    TEST_ASSERT_EQUAL_UINT(0, s.total_allocs);
    TEST_ASSERT_EQUAL_UINT(0, s.total_frees);
    TEST_ASSERT_EQUAL_UINT(0, s.live_bytes);
}

static void test_heap_reset_clears_counters(void) {
    qc_heap_stat s;
    qc_heap_track_begin();
    qc_heap_note_alloc(77);
    qc_heap_reset_counters();
    s = qc_heap_stat_get();
    TEST_ASSERT_EQUAL_UINT(0, s.live_bytes);
    TEST_ASSERT_EQUAL_UINT(0, s.total_allocs);
    qc_heap_track_end();
}

static void test_heap_sees_a_real_loop(void) {
    qc_heap_stat s;
    int i;
    qc_heap_track_begin();
    for (i = 0; i < 5; i++) {
        burn(i);
    }
    s = qc_heap_stat_get();
    /* burn() allocates nothing, so the instrument must report exactly
     * zero - proving it does not invent traffic. */
    TEST_ASSERT_EQUAL_UINT(0, s.total_allocs);
    TEST_ASSERT_EQUAL_UINT(0, s.live_bytes);
    qc_heap_track_end();
}

static void test_cycles_are_monotonic_and_nonzero(void) {
    uint64_t a, b;
    int i;

    a = qc_cycles();
    for (i = 0; i < 10000; i++) {
        burn(i);
    }
    b = qc_cycles();

    TEST_ASSERT_TRUE_MESSAGE(b > a, "cycle counter must advance");
    TEST_ASSERT_TRUE_MESSAGE(sink > 0, "the measured work must not be "
                             "optimised away");
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_heap_tracks_live_bytes);
    RUN_TEST(test_heap_overfree_clamps_instead_of_wrapping);
    RUN_TEST(test_heap_inactive_ignores_notes);
    RUN_TEST(test_heap_reset_clears_counters);
    RUN_TEST(test_heap_sees_a_real_loop);
    RUN_TEST(test_cycles_are_monotonic_and_nonzero);
    return UNITY_END();
}
