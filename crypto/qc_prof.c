/* qc_prof.c - host profiling primitives (plan B-51.3 metrics).
 *
 * Stack high-water is intentionally absent - see the header for why two
 * paint implementations failed silently and why shipping a wrong memory
 * column is worse than shipping none.
 */
#include "qc_prof.h"

#include <string.h>

#if defined(__x86_64__) || defined(__i386__)
#define QC_PROF_HAVE_TSC 1
#include <x86intrin.h>
#else
#define QC_PROF_HAVE_TSC 0
#endif

/* ---- heap delta -------------------------------------------------------- */

static qc_heap_stat qc_heap;
static int qc_heap_active;

void qc_heap_track_begin(void) {
    memset(&qc_heap, 0, sizeof(qc_heap));
    qc_heap_active = 1;
}

void qc_heap_track_end(void) {
    qc_heap_active = 0;
}

qc_heap_stat qc_heap_stat_get(void) {
    qc_heap_stat s;
    s.live_bytes = qc_heap.live_bytes;
    s.total_allocs = qc_heap.total_allocs;
    s.total_frees = qc_heap.total_frees;
    return s;
}

void qc_heap_reset_counters(void) {
    memset(&qc_heap, 0, sizeof(qc_heap));
}

void qc_heap_note_alloc(size_t bytes) {
    if (!qc_heap_active) {
        return;
    }
    qc_heap.live_bytes += bytes;
    qc_heap.total_allocs++;
}

void qc_heap_note_free(size_t bytes) {
    if (!qc_heap_active) {
        return;
    }
    /* Unsigned underflow would fabricate a huge live count; clamp and let
     * the caller see the imbalance via total_frees instead. */
    qc_heap.live_bytes = (qc_heap.live_bytes >= bytes)
                       ? qc_heap.live_bytes - bytes : 0;
    qc_heap.total_frees++;
}

/* ---- cycles ------------------------------------------------------------ */

uint64_t qc_cycles(void) {
#if QC_PROF_HAVE_TSC
    /* LFENCE on both sides: nothing issued before the read may still be
     * in flight when we sample, and nothing sampled may still be in
     * flight when we return. Without them the counter measures the
     * pipeline's optimism, not the work. */
    uint64_t t;
    _mm_lfence();
    t = __rdtsc();
    _mm_lfence();
    return t;
#else
    return 0;
#endif
}
