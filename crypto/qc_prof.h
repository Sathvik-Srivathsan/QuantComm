/* qc_prof.h - host profiling primitives (plan B-51.3 metrics).
 *
 * Supplies two of the five B-51.3 metric families that need C-side
 * instrumentation:
 *   - heap delta, via hooks the caller drives
 *   - cycle count, via rdtsc with a fence
 *
 * STACK HIGH-WATER IS DELIBERATELY ABSENT. Paint instrumentation needs a
 * buffer positioned between the caller and the callee, and two attempts
 * got that wrong in ways that fail SILENTLY rather than loudly:
 *   - a file-scope static buffer lives in .bss, nowhere near the stack,
 *     so every sample read zero depth while the stack was deep;
 *   - a frame-local buffer is placed by the compiler, and in the bench
 *     frame it landed ABOVE the stack pointer, so the callee grew past it
 *     and again every sample read "untouched" (32760 bytes of paint
 *     never written).
 * Both produced plausible numbers instead of an error. Publishing a
 * memory column that is quietly wrong is worse than publishing no
 * memory column, so E1 emits the other metrics now and stack is a named
 * follow-up (recorded in the E1 manifest as pending verification) rather
 * than a row full of zeros. The correct implementation needs alloca() or
 * a dedicated measurement TU, and - critically - a machine that can build
 * and RUN it, which this host currently cannot.
 *
 * Why C-side at all: B-51.1 requires measurements taken THROUGH the
 * B-10/B-11/B-12 adapter entry points, so the number must come from the
 * same process that runs the primitive. Timing across a subprocess
 * boundary would charge process setup to every sample.
 *
 * HOST ONLY. None of this ships to the target: B-60 owns the GPIO-aligned
 * event instrumentation there, and B-62 owns the rig.
 */
#ifndef QC_PROF_H
#define QC_PROF_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- heap delta -------------------------------------------------------- */

typedef struct {
    size_t live_bytes;
    size_t total_allocs;
    size_t total_frees;
} qc_heap_stat;

void qc_heap_track_begin(void);
void qc_heap_track_end(void);
qc_heap_stat qc_heap_stat_get(void);
void qc_heap_reset_counters(void);

/* Called by the caller's allocator hooks. No-ops unless tracking is
 * active, so an instrumented allocation outside a measured region costs
 * one branch. */
void qc_heap_note_alloc(size_t bytes);
void qc_heap_note_free(size_t bytes);

/* ---- cycles ------------------------------------------------------------ */
/* TSC-based; not a validated counter on every host, so the caller records
 * the source (B-51.3 requires the source be recorded per dataset). */
#define QC_PROF_CYCLE_SOURCE "rdtsc-fenced"

uint64_t qc_cycles(void);

#ifdef __cplusplus
}
#endif

#endif
