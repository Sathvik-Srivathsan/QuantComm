/* qc_prof.h - host profiling primitives (plan B-51.3 metrics).
 *
 * Supplies host cycle and heap measurement for B-51.3. Of the five B-51.3
 * metric families (time, cycles, stack high-water, heap delta, flash per
 * track), TIME is measured by the bench itself (tools/e1_bench.c), and
 * of the two families this header owns, ONLY CYCLES IS CURRENTLY
 * REAL - heap is pending and stack/flash are absent. See below.
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
 * THREE NAMED DEFERRALS / PENDING COLUMNS (B-51.3 metric families not built:
 *   - PERF-EVENT CYCLES - DECIDED (B-51-gaps, 2026-10-16): rdtsc-with-fence is
 *     ACCEPTED as the PRIMARY cycle source for host E1, permanently. B-51.3
 *     names perf primary with rdtsc as fallback; we take the fallback
 *     deliberately, for TWO factual reasons: (1) perf_event_open is
 *     Linux-only, and E1 must be reproducible on the Windows dev host AND
 *     on Linux CI - not both are perf-capable, and a metric that cannot run
 *     where the dataset is produced cannot be re-verified later; (2) rdtsc
 *     WITH a fence is a correctly ordered counter here (lfence;rdtsc;lfence)
 *     and every dataset records cycles_source="rdtsc-fenced" so no reader can
 *     mistake these for perf numbers.
 *     WITHDRAWN (recorded, not deleted, so the reasoning survives): an earlier
 *     version also argued perf could not resolve this matrix's short calls.
 *     That was WRONG - perf_event_open in COUNTING mode, which is what B-51.3
 *     asks for, has no sampling granularity limit; multiplexing only arises
 *     with more events open than PMU counters. The quoted op-duration range
 *     was never measured and disagreed with the bench's own figure. Reasons
 *     (1) and (2) alone justify the decision.
 *     HONEST LIMIT: cycles_source names the METHOD; it does not VALIDATE the
 *     counter. There is no TSC-invariant check (no invariant_tsc /
 *     nonstop_tsc probe) anywhere in the repo, so a host with a
 *     non-invariant TSC would yield plausible but untrustworthy cycles with
 *     nothing flagging it. The probe is owed before any E1 dataset is
 *     authoritative; until then cycle columns are ORDER-OF-MAGNITUDE only.
 *     ESP32 has no TSC at all: target cycle instrumentation is B-60 (GPIO
 *     event hooks) / B-62 (firmware reporting), separate from this decision.
 *   - HEAP DELTA IS ALSO PENDING (blind audit 2026-10-16, found AFTER the E1
 *     dataset shape was already wrong): qc_heap_note_alloc/qc_heap_note_free
 *     have ZERO production callers - nothing installs the allocator hooks,
 *     because allocation happens inside vendored mlkem-native/mldsa-native
 *     whose allocator we do not intercept. So qc_heap_stat_get().live_bytes
 *     is unconditionally 0, and E1 WAS emitting that 0 as heap_live_bytes -
 *     which reads as a measurement of "this operation allocates nothing".
 *     That is false and violates the principle above in writing. Rows now
 *     emit the string "pending-verification", exactly like stack. An
 *     allocator interceptor is owed; until then there is NO heap column.
 *   - FLASH PER TRACK: linked-binary size per track, via linker-map diff
 *     against a no-crypto baseline. Owner: B-62 (the rig; size is a target
 *     measurement, not a host one). Needs a baseline link target first.
 * Recorded rather than silently absent; none is safe to fake with zeros or
 * a host stand-in.
 */
#ifndef QC_PROF_H
#define QC_PROF_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

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
